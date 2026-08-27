use crate::error::{Error, Result};
use crate::records::{
    agent_type_issuer_signature_message, allowed_intents_within_stored,
    audience_within_authorization_limit, capability_issuer_signature_message,
    chain_issuer_signature_message, instance_issuer_signature_message, is_narrower_or_equal,
    issuance_log_line_issuer_signature_message, AgentType, Capability, Chain, Instance,
    InstanceStatus, Issuer, LogEvent, PreviousIssuerKey,
};
use crate::tokens;
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub struct Store {
    root: PathBuf,
    extra_member_secret_paths: Mutex<Vec<PathBuf>>,
}

impl Store {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            extra_member_secret_paths: Mutex::new(Vec::new()),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn create_directories(&self) -> Result<()> {
        for directory_name in [
            "agent_types",
            "instances",
            "capabilities",
            "chains",
            "holders",
        ] {
            fs::create_dir_all(self.root.join(directory_name))?;
        }
        Ok(())
    }

    pub fn issuer_path(&self) -> PathBuf {
        self.root.join("issuer.json")
    }

    pub fn secret_path(&self) -> PathBuf {
        self.root.join("issuer.secret")
    }

    /// Laboratory Biscuit capability-envelope secret. This is not the identity root.
    pub fn biscuit_secret_path(&self) -> PathBuf {
        self.root.join("biscuit.secret")
    }

    /// Additional issuer member secret. Gitignored. Not biscuit.secret. Not a holder secret.
    pub fn member_secret_path(&self, public_key_hex: &str) -> PathBuf {
        let trimmed = public_key_hex.trim();
        let prefix: String = trimmed.chars().take(16).collect();
        self.root.join(format!("issuer-member-{prefix}.secret"))
    }

    pub fn save_member_secret(
        &self,
        public_key_hex: &str,
        secret_key_hexadecimal: &str,
    ) -> Result<()> {
        let path = self.member_secret_path(public_key_hex);
        std::fs::write(&path, secret_key_hexadecimal.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn register_extra_member_secret_path(&self, path: PathBuf) -> Result<()> {
        if self.path_is_inside_data_directory(&path) {
            return Err(Error::denied(
                "The --member-secret path must live outside the data directory. A path inside the data directory is refused. Stolen store files must not include member two. The check fails closed.",
            ));
        }
        let mut paths = self
            .extra_member_secret_paths
            .lock()
            .expect("member secret path lock");
        if !paths.iter().any(|existing| existing == &path) {
            paths.push(path);
        }
        Ok(())
    }

    pub fn path_is_inside_data_directory(&self, path: &Path) -> bool {
        let root = self
            .root
            .canonicalize()
            .unwrap_or_else(|_| self.root.clone());
        let candidate = if path.exists() {
            path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
        } else if let Some(parent) = path.parent() {
            let parent_resolved = if parent.as_os_str().is_empty() {
                PathBuf::from(".")
            } else {
                parent.to_path_buf()
            };
            let parent_resolved = parent_resolved.canonicalize().unwrap_or(parent_resolved);
            match path.file_name() {
                Some(name) => parent_resolved.join(name),
                None => parent_resolved,
            }
        } else {
            path.to_path_buf()
        };
        candidate.starts_with(&root)
    }

    pub fn save_member_secret_at(
        &self,
        path: &Path,
        _public_key_hex: &str,
        secret_key_hexadecimal: &str,
    ) -> Result<()> {
        if self.path_is_inside_data_directory(path) {
            return Err(Error::denied(
                "The issuer member secret path must live outside the data directory. A path inside the data directory is refused. Stolen store files must not include member two. The check fails closed.",
            ));
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(path, secret_key_hexadecimal.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        self.register_extra_member_secret_path(path.to_path_buf())?;
        Ok(())
    }

    fn secret_file_matches_public_key(&self, path: &Path, public_key_hex: &str) -> bool {
        if !path.exists() {
            return false;
        }
        let Ok(secret) = std::fs::read_to_string(path) else {
            return false;
        };
        crate::issuer_crypto::public_key_matches_secret(public_key_hex, secret.trim())
            .unwrap_or(false)
    }

    pub fn load_member_secret(&self, public_key_hex: &str) -> Result<String> {
        let path = self.member_secret_path(public_key_hex);
        if !path.exists() {
            return Err(Error::denied(format!(
                "The issuer member secret is missing for this public key. A threshold persist fails closed."
            )));
        }
        let text = std::fs::read_to_string(path)?;
        Ok(text.trim().to_string())
    }

    fn member_secret_matches_public_key(&self, public_key_hex: &str) -> bool {
        if self.secret_file_matches_public_key(
            &self.member_secret_path(public_key_hex),
            public_key_hex,
        ) {
            return true;
        }
        let extra = self
            .extra_member_secret_paths
            .lock()
            .expect("member secret path lock")
            .clone();
        extra
            .iter()
            .any(|path| self.secret_file_matches_public_key(path, public_key_hex))
    }

    fn list_additional_member_secrets(
        &self,
        issuer: &crate::records::Issuer,
    ) -> Result<Vec<(String, String)>> {
        let mut members = Vec::new();
        let current = issuer.current_public_key_hex();
        for key in issuer.trusted_signing_member_public_keys() {
            if key == current {
                continue;
            }
            if issuer.is_biscuit_envelope_key(&key) {
                continue;
            }
            let mut loaded: Option<(String, String)> = None;
            let in_store = self.member_secret_path(&key);
            if in_store.exists() {
                if let Ok(secret) = std::fs::read_to_string(&in_store) {
                    let secret = secret.trim().to_string();
                    if !secret.is_empty() {
                        if let Ok(derived) =
                            crate::issuer_crypto::public_key_hexadecimal_from_secret(&secret)
                        {
                            if derived == key {
                                loaded = Some((secret, key.clone()));
                            }
                        }
                    }
                }
            }
            if loaded.is_none() {
                let extra = self
                    .extra_member_secret_paths
                    .lock()
                    .expect("member secret path lock")
                    .clone();
                for path in extra {
                    if !path.exists() {
                        continue;
                    }
                    let Ok(secret) = std::fs::read_to_string(&path) else {
                        continue;
                    };
                    let secret = secret.trim().to_string();
                    if secret.is_empty() {
                        continue;
                    }
                    let Ok(derived) =
                        crate::issuer_crypto::public_key_hexadecimal_from_secret(&secret)
                    else {
                        continue;
                    };
                    if derived == key {
                        loaded = Some((secret, key.clone()));
                        break;
                    }
                }
            }
            if let Some(member) = loaded {
                members.push(member);
            }
        }
        Ok(members)
    }

    pub fn log_path(&self) -> PathBuf {
        self.root.join("issuance.log")
    }

    pub fn issuer_exists(&self) -> bool {
        self.issuer_path().exists()
    }

    fn write_json<T: Serialize>(&self, path: &Path, value: &T) -> Result<()> {
        if let Some(parent_directory) = path.parent() {
            fs::create_dir_all(parent_directory)?;
        }
        let temporary_path = path.with_extension("json.tmp");
        let data = serde_json::to_vec_pretty(value)?;
        fs::write(&temporary_path, data)?;
        fs::rename(temporary_path, path)?;
        Ok(())
    }

    fn read_json<T: DeserializeOwned>(&self, path: &Path) -> Result<T> {
        let data = fs::read(path)?;
        Ok(serde_json::from_slice(&data)?)
    }

    /// Persist the issuer record. The first write may leave kill_date empty.
    /// After a seal writes kill_date, a later persist must not move that time later
    /// and must not clear it. Shorten may persist. The same time may persist.
    /// Postponing or clearing the seal is a golden-ticket-class raise.
    ///
    /// After the first write, a later persist must not swap current_public_key
    /// unless issuer.secret already matches the new current (rotate writes the
    /// new secret first). A later persist must not grow public_keys with a key
    /// that is not the current key. A later persist must not remove a previous
    /// issuer key, postpone a previous-key kill_date, or add a previous key that
    /// was never this store current key. A later persist must not omit a
    /// previous key that a signed issuer_rotate note already records. Honest
    /// rotate writes the previous key before that signed line exists. That first
    /// write is not an omit. Those writes would make verify accept a foreign
    /// or stolen key.
    ///
    /// A later persist must not remove an accepted previous issuer key or
    /// postpone an accepted previous-key kill_date. Freeze is the earlier of
    /// the unsigned file kill_date and the earliest signed kill_date on a
    /// previous_key_accept note for that public key. A later persist must not
    /// omit an accepted previous key that a signed previous_key_accept note
    /// already records. Honest accept writes the accepted previous key before
    /// that signed line exists. That first write is not an omit.
    ///
    /// A later persist must not remove an accepted sealed issuer key or
    /// postpone an accepted seal kill_date. Freeze is the earlier of
    /// the unsigned file kill_date and the earliest signed kill_date on a
    /// seal_accept note for that public key. A later persist must not
    /// omit an accepted sealed key that a signed seal_accept note
    /// already records. Honest accept writes the accepted seal before
    /// that signed line exists. That first write is not an omit.
    /// Honest issuer_seal on the issuing store is not a seal_accept line.
    /// That first seal write does not require a prior seal_accept.
    ///
    /// Emptying accepted_issuer_public_keys is not allow-all: verify still uses
    /// the current key and refuses an empty combined list. threshold_n cannot
    /// be lowered. crypto_profile and issuance_log are stored fields. They do
    /// not skip verify. This is not a sixth identity record.
    pub fn save_issuer(&self, issuer: &Issuer) -> Result<()> {
        let path = self.issuer_path();
        if path.exists() {
            let stored: Issuer = self.read_json(&path)?;
            // Freeze is the earlier of the unsigned file kill_date and the
            // earliest signed issuer.kill_date on an issuer_seal note.
            // A planted later file date must not become the freeze.
            // A missing file date still freezes on the signed date, or else
            // the first issuer_seal timestamp.
            let file_date = stored.kill_date;
            let signed_date = self.signed_issuer_seal_kill_date()?;
            let stored_kill_date = match (file_date, signed_date) {
                (Some(file), Some(signed)) => Some(file.min(signed)),
                (Some(file), None) => Some(file),
                (None, Some(signed)) => Some(signed),
                (None, None) => self.earliest_issuer_seal_timestamp()?,
            };
            if let Some(stored_kill_date) = stored_kill_date {
                match issuer.kill_date {
                    None => {
                        return Err(Error::denied(
                            "The issuer seal kill_date is frozen after the first seal. A later write that clears kill_date is refused. Clearing the seal is a golden-ticket-class raise. Death cannot be postponed. This is not a sixth identity record.",
                        ));
                    }
                    Some(new_kill_date) if new_kill_date > stored_kill_date => {
                        return Err(Error::denied(
                            "The issuer seal kill_date is frozen after the first seal. A later write that moves kill_date later is refused. A later seal cannot postpone death. Only a shorter remaining life is allowed. This is not a sixth identity record.",
                        ));
                    }
                    _ => {}
                }
            }
            self.require_issuer_current_key_not_forged(&stored, issuer)?;
            self.require_issuer_public_keys_not_grown(&stored, issuer)?;
            self.require_issuer_previous_keys_not_raised(&stored, issuer)?;
            self.require_accepted_previous_keys_not_raised(&stored, issuer)?;
            self.require_accepted_sealed_keys_not_raised(&stored, issuer)?;
            self.require_biscuit_public_key_not_swapped(&stored, issuer)?;
            self.require_issuer_threshold_not_lowered(&stored, issuer)?;
            self.require_issuer_verify_threshold_not_lowered(&stored, issuer)?;
            self.require_accepted_kills_not_cleared(&stored, issuer)?;
        }
        if issuer.threshold_n < 1 {
            return Err(Error::denied(
                "The threshold_n value must be at least 1. A threshold of zero is refused. The check fails closed.",
            ));
        }
        if issuer.verify_threshold_n < 1 {
            return Err(Error::denied(
                "The verify_threshold_n value must be at least 1. A verify threshold of zero is refused. The check fails closed.",
            ));
        }
        self.write_json(&path, issuer)
    }

    /// current_public_key may change only when issuer.secret already matches the new current.
    /// Rotate writes the new secret first, then persists the new current and records the old key.
    /// A persist that swaps current to a foreign key is a forged current key.
    fn require_issuer_current_key_not_forged(
        &self,
        stored: &Issuer,
        issuer: &Issuer,
    ) -> Result<()> {
        let stored_current = stored.current_public_key_hex();
        let new_current = issuer.current_public_key_hex();
        if new_current == stored_current {
            return Ok(());
        }
        if new_current.is_empty() {
            return Err(Error::denied(
                "The current issuer public key is written by init or rotate. A later write that clears current_public_key is refused. Clearing the current key is a golden-ticket-class raise. This is not a sixth identity record.",
            ));
        }
        let secret = match self.load_secret() {
            Ok(value) => value,
            Err(_) => {
                return Err(Error::denied(
                    "The current issuer public key may change only after rotate writes the new issuer secret. A later write that swaps current_public_key without that secret is refused. A forged current key is a golden-ticket-class raise. This is not a sixth identity record.",
                ));
            }
        };
        let matches_secret =
            crate::issuer_crypto::public_key_matches_secret(&new_current, &secret).unwrap_or(false);
        if !matches_secret {
            return Err(Error::denied(
                "The current issuer public key may change only after rotate writes the new issuer secret. A later write that swaps current_public_key to a key that does not match issuer.secret is refused. A forged current key is a golden-ticket-class raise. Verify must not accept a foreign key. This is not a sixth identity record.",
            ));
        }
        if !stored_current.is_empty() {
            let old_recorded = issuer
                .previous_issuer_keys
                .iter()
                .any(|previous| previous.public_key_hex.trim() == stored_current);
            if !old_recorded {
                return Err(Error::denied(
                    "The current issuer public key may change only when rotate records the old current key on previous_issuer_keys. A later write that swaps current_public_key without recording the old key is refused. A forged current key is a golden-ticket-class raise. This is not a sixth identity record.",
                ));
            }
        }
        Ok(())
    }

    /// public_keys may hold the current key or keys already stored. Growing the list
    /// with a new attacker key would make token verify and receipt verify trust that key.
    fn require_issuer_public_keys_not_grown(&self, stored: &Issuer, issuer: &Issuer) -> Result<()> {
        let stored_current = stored.current_public_key_hex();
        let new_current = issuer.current_public_key_hex();
        for key in &issuer.public_keys {
            let trimmed = key.trim();
            if trimmed.is_empty() {
                continue;
            }
            let already_stored = stored
                .public_keys
                .iter()
                .any(|existing| existing.trim() == trimmed);
            if already_stored || trimmed == stored_current || trimmed == new_current {
                continue;
            }
            if self.member_secret_matches_public_key(trimmed) {
                continue;
            }
            return Err(Error::denied(
                "The issuer public_keys list cannot gain a key that is not the current issuer public key. A later write that grows public_keys with a foreign key is refused. Growing public_keys is a golden-ticket-class raise. Verify must not accept a foreign key. This is not a sixth identity record.",
            ));
        }
        Ok(())
    }

    /// previous_issuer_keys cannot lose a stored key, cannot postpone a stored kill_date,
    /// and cannot gain a key that was never this store current key.
    /// Freeze is the earlier of the unsigned file kill_date and the earliest
    /// signed kill_date on an issuer_rotate note for that public key.
    /// A planted later file date must not become the freeze.
    /// A persist must not omit a previous key that a signed issuer_rotate
    /// note already records. Freeze against that signed list, not only the file.
    /// A planted empty list must not become the freeze.
    /// Honest rotate writes the previous key before the signed line exists.
    /// That first write is not an omit.
    /// Removing a previous key would treat a stolen old key as never-previous.
    /// Postponing a previous-key kill_date would let that stolen key sign after death.
    fn require_issuer_previous_keys_not_raised(
        &self,
        stored: &Issuer,
        issuer: &Issuer,
    ) -> Result<()> {
        let stored_current = stored.current_public_key_hex();
        let signed_previous = self.signed_previous_issuer_key_kill_dates()?;
        for stored_previous in &stored.previous_issuer_keys {
            let stored_hex = stored_previous.public_key_hex.trim();
            let matching: Vec<_> = issuer
                .previous_issuer_keys
                .iter()
                .filter(|previous| previous.public_key_hex.trim() == stored_hex)
                .collect();
            if matching.is_empty() {
                return Err(Error::denied(
                    "A previous issuer key cannot be removed after rotate. A later write that drops a previous key is refused. Removing the key would treat a stolen old key as never-previous. That is a golden-ticket-class raise. Verify must not accept a stolen key after kill_date. This is not a sixth identity record.",
                ));
            }
            let freeze = signed_previous
                .iter()
                .find(|(key, _)| key.trim() == stored_hex)
                .map(|(_, signed)| stored_previous.kill_date.min(*signed))
                .unwrap_or(stored_previous.kill_date);
            if matching[0].kill_date > freeze {
                return Err(Error::denied(
                    "A previous issuer key kill_date is frozen after rotate. A later write that moves that kill_date later is refused. Postponing a previous-key kill_date is a golden-ticket-class raise. A stolen old key must not sign after death. Only a shorter remaining life is allowed. This is not a sixth identity record.",
                ));
            }
        }
        for (signed_hex, signed_date) in &signed_previous {
            let signed_hex = signed_hex.trim();
            if signed_hex.is_empty() {
                continue;
            }
            let matching: Vec<_> = issuer
                .previous_issuer_keys
                .iter()
                .filter(|previous| previous.public_key_hex.trim() == signed_hex)
                .collect();
            if matching.is_empty() {
                return Err(Error::denied(
                    "A signed previous issuer key cannot be omitted after rotate. A later write that drops a previous key that a signed issuer_rotate note already records is refused. Omitting the key would treat a stolen old key as never-previous. That is a golden-ticket-class raise. Verify must not accept a stolen key after kill_date. This is not a sixth identity record.",
                ));
            }
            let file_date = stored
                .previous_issuer_keys
                .iter()
                .find(|previous| previous.public_key_hex.trim() == signed_hex)
                .map(|previous| previous.kill_date);
            let freeze = match file_date {
                Some(file) => file.min(*signed_date),
                None => *signed_date,
            };
            if matching[0].kill_date > freeze {
                return Err(Error::denied(
                    "A previous issuer key kill_date is frozen after rotate. A later write that moves that kill_date later is refused. Postponing a previous-key kill_date is a golden-ticket-class raise. A stolen old key must not sign after death. Only a shorter remaining life is allowed. This is not a sixth identity record.",
                ));
            }
        }
        for new_previous in &issuer.previous_issuer_keys {
            let hex = new_previous.public_key_hex.trim();
            if hex.is_empty() {
                continue;
            }
            let was_previous = stored
                .previous_issuer_keys
                .iter()
                .any(|previous| previous.public_key_hex.trim() == hex);
            if was_previous || hex == stored_current {
                continue;
            }
            return Err(Error::denied(
                "previous_issuer_keys cannot gain a key that was never this store current key. A later write that adds a foreign previous key is refused. Adding a previous key is a golden-ticket-class raise. Verify must not accept a foreign key. This is not a sixth identity record.",
            ));
        }
        Ok(())
    }

    /// accepted_previous_issuer_keys cannot lose a stored key and cannot postpone
    /// a stored kill_date. Growing is the accept path. This is verifier state.
    /// This is not a sixth identity record.
    /// Freeze is the earlier of the unsigned file kill_date and the earliest
    /// signed kill_date on a previous_key_accept note for that public key.
    /// A planted later file date must not become the freeze.
    /// A persist must not omit a previous key that a signed previous_key_accept
    /// note already records. Freeze against that signed list, not only the file.
    /// A planted empty list must not become the freeze.
    /// Honest accept writes the accepted previous key before the signed line exists.
    /// That first write is not an omit.
    fn require_accepted_previous_keys_not_raised(
        &self,
        stored: &Issuer,
        issuer: &Issuer,
    ) -> Result<()> {
        let signed_accepted = self.signed_accepted_previous_key_kill_dates()?;
        for stored_previous in &stored.accepted_previous_issuer_keys {
            let stored_hex = stored_previous.public_key_hex.trim();
            let matching: Vec<_> = issuer
                .accepted_previous_issuer_keys
                .iter()
                .filter(|previous| previous.public_key_hex.trim() == stored_hex)
                .collect();
            if matching.is_empty() {
                return Err(Error::denied(
                    "An accepted previous issuer key cannot be removed after accept. A later write that drops an accepted previous key is refused. Removing the key would treat a stolen old key as never-previous. That is a golden-ticket-class raise. Verify must not accept a stolen key after kill_date. This is not a sixth identity record.",
                ));
            }
            let freeze = signed_accepted
                .iter()
                .find(|(key, _)| key.trim() == stored_hex)
                .map(|(_, signed)| stored_previous.kill_date.min(*signed))
                .unwrap_or(stored_previous.kill_date);
            if matching[0].kill_date > freeze {
                return Err(Error::denied(
                    "An accepted previous issuer key kill_date is frozen after accept. A later write that moves that kill_date later is refused. Postponing a previous-key kill_date is a golden-ticket-class raise. A stolen old key must not sign after death. Only a shorter remaining life is allowed. This is not a sixth identity record.",
                ));
            }
        }
        for (signed_hex, signed_date) in &signed_accepted {
            let signed_hex = signed_hex.trim();
            if signed_hex.is_empty() {
                continue;
            }
            let matching: Vec<_> = issuer
                .accepted_previous_issuer_keys
                .iter()
                .filter(|previous| previous.public_key_hex.trim() == signed_hex)
                .collect();
            if matching.is_empty() {
                return Err(Error::denied(
                    "A signed accepted previous issuer key cannot be omitted after accept. A later write that drops an accepted previous key that a signed previous_key_accept note already records is refused. Omitting the key would treat a stolen old key as never-previous. That is a golden-ticket-class raise. Verify must not accept a stolen key after kill_date. This is not a sixth identity record.",
                ));
            }
            let file_date = stored
                .accepted_previous_issuer_keys
                .iter()
                .find(|previous| previous.public_key_hex.trim() == signed_hex)
                .map(|previous| previous.kill_date);
            let freeze = match file_date {
                Some(file) => file.min(*signed_date),
                None => *signed_date,
            };
            if matching[0].kill_date > freeze {
                return Err(Error::denied(
                    "An accepted previous issuer key kill_date is frozen after accept. A later write that moves that kill_date later is refused. Postponing a previous-key kill_date is a golden-ticket-class raise. A stolen old key must not sign after death. Only a shorter remaining life is allowed. This is not a sixth identity record.",
                ));
            }
        }
        Ok(())
    }

    /// The Biscuit envelope public key is written once at init. Rotate keeps it.
    /// A later persist that swaps biscuit_public_key_hex is refused.
    fn require_biscuit_public_key_not_swapped(
        &self,
        stored: &Issuer,
        issuer: &Issuer,
    ) -> Result<()> {
        let stored_biscuit = stored.biscuit_public_key_hex.trim();
        let new_biscuit = issuer.biscuit_public_key_hex.trim();
        if stored_biscuit.is_empty() {
            return Ok(());
        }
        if new_biscuit != stored_biscuit {
            return Err(Error::denied(
                "The Biscuit envelope public key is written once at init. A later write that replaces biscuit_public_key_hex is refused. The Biscuit key is a capability-envelope key, not the identity root. Rotate keeps the Biscuit key. This is not a sixth identity record.",
            ));
        }
        Ok(())
    }

    /// threshold_n cannot be lowered. The floor is the greater of the stored
    /// file n and the highest signed issuance.log n. A planted file n of 1
    /// must not let a persist write 1 when the signed log already raised n.
    fn require_issuer_threshold_not_lowered(&self, stored: &Issuer, issuer: &Issuer) -> Result<()> {
        if issuer.threshold_n < 1 {
            return Err(Error::denied(
                "The threshold_n value must be at least 1. A threshold of zero is refused. The check fails closed.",
            ));
        }
        let floor = stored.threshold_n.max(self.highest_log_threshold_n()?);
        if issuer.threshold_n < floor {
            return Err(Error::denied(
                "The threshold_n value cannot be lowered. Lowering the threshold is a persist-raise class. The check fails closed.",
            ));
        }
        Ok(())
    }

    /// verify_threshold_n cannot be lowered. Lowering is a persist-raise class.
    /// This is not issuance threshold_n.
    /// Floor is the greater of the file n and the highest signed
    /// issuer_verify_threshold note n. A planted file at 1 cannot persist 1
    /// when the signed raise is 2.
    fn require_issuer_verify_threshold_not_lowered(
        &self,
        stored: &Issuer,
        issuer: &Issuer,
    ) -> Result<()> {
        if issuer.verify_threshold_n < 1 {
            return Err(Error::denied(
                "The verify_threshold_n value must be at least 1. A verify threshold of zero is refused. The check fails closed.",
            ));
        }
        let floor = stored
            .verify_threshold_n
            .max(1)
            .max(self.highest_log_verify_threshold_n()?);
        if issuer.verify_threshold_n < floor {
            return Err(Error::denied(
                "The verify_threshold_n value cannot be lowered. Lowering the verify threshold is a persist-raise class. A stolen single member secret must not verify a foreign act. The check fails closed.",
            ));
        }
        Ok(())
    }

    /// Accepted death on the issuer cannot be removed. Un-kill is a golden-ticket-class raise.
    /// Growing the lists is allowed. This is verifier state. This is not a sixth identity record.
    /// accepted_sealed_issuer_keys cannot lose a stored key and cannot postpone
    /// a stored kill_date. Growing is the accept path. This is verifier state.
    /// Clearing an accepted seal is a golden-ticket-class raise.
    /// Freeze is the earlier of the unsigned file kill_date and the earliest
    /// signed kill_date on a seal_accept note for that public key.
    /// A planted later file date must not become the freeze.
    /// A persist must not omit a sealed key that a signed seal_accept
    /// note already records. Freeze against that signed list, not only the file.
    /// A planted empty list must not become the freeze.
    /// Honest accept writes the accepted seal before the signed line exists.
    /// That first write is not an omit.
    /// Honest issuer_seal on the issuing store is not a seal_accept line.
    fn require_accepted_sealed_keys_not_raised(
        &self,
        stored: &Issuer,
        issuer: &Issuer,
    ) -> Result<()> {
        let signed_accepted = self.signed_accepted_seal_kill_dates()?;
        for stored_sealed in &stored.accepted_sealed_issuer_keys {
            let stored_hex = stored_sealed.public_key_hex.trim();
            let matching: Vec<_> = issuer
                .accepted_sealed_issuer_keys
                .iter()
                .filter(|previous| previous.public_key_hex.trim() == stored_hex)
                .collect();
            if matching.is_empty() {
                return Err(Error::denied(
                    "An accepted seal cannot be cleared. A later write that drops an accepted sealed issuer key is refused. Clearing an accepted seal is a golden-ticket-class raise. Seal accept is issuer death for verify. This is not a sixth identity record.",
                ));
            }
            let freeze = signed_accepted
                .iter()
                .find(|(key, _)| key.trim() == stored_hex)
                .map(|(_, signed)| stored_sealed.kill_date.min(*signed))
                .unwrap_or(stored_sealed.kill_date);
            if matching[0].kill_date > freeze {
                return Err(Error::denied(
                    "An accepted seal kill_date is frozen after accept. A later write that moves that kill_date later is refused. Postponing an accepted seal is a golden-ticket-class raise. Only a shorter remaining life is allowed. This is not a sixth identity record.",
                ));
            }
        }
        for (signed_hex, signed_date) in &signed_accepted {
            let signed_hex = signed_hex.trim();
            if signed_hex.is_empty() {
                continue;
            }
            let matching: Vec<_> = issuer
                .accepted_sealed_issuer_keys
                .iter()
                .filter(|previous| previous.public_key_hex.trim() == signed_hex)
                .collect();
            if matching.is_empty() {
                return Err(Error::denied(
                    "A signed accepted seal cannot be omitted after accept. A later write that drops an accepted sealed issuer key that a signed seal_accept note already records is refused. Omitting the key would hide issuer death. That is a golden-ticket-class raise. Seal accept is issuer death for verify. This is not a sixth identity record.",
                ));
            }
            let file_date = stored
                .accepted_sealed_issuer_keys
                .iter()
                .find(|previous| previous.public_key_hex.trim() == signed_hex)
                .map(|previous| previous.kill_date);
            let freeze = match file_date {
                Some(file) => file.min(*signed_date),
                None => *signed_date,
            };
            if matching[0].kill_date > freeze {
                return Err(Error::denied(
                    "An accepted seal kill_date is frozen after accept. A later write that moves that kill_date later is refused. Postponing an accepted seal is a golden-ticket-class raise. Only a shorter remaining life is allowed. This is not a sixth identity record.",
                ));
            }
        }
        Ok(())
    }

    fn require_accepted_kills_not_cleared(&self, stored: &Issuer, issuer: &Issuer) -> Result<()> {
        Self::require_accepted_kill_list_not_shrunk(
            &stored.accepted_killed_instance_ids,
            &issuer.accepted_killed_instance_ids,
            "accepted_killed_instance_ids",
        )?;
        Self::require_accepted_kill_list_not_shrunk(
            &stored.accepted_killed_capability_ids,
            &issuer.accepted_killed_capability_ids,
            "accepted_killed_capability_ids",
        )?;
        Self::require_accepted_kill_list_not_shrunk(
            &stored.accepted_revoke_identifiers,
            &issuer.accepted_revoke_identifiers,
            "accepted_revoke_identifiers",
        )?;
        Ok(())
    }

    fn require_accepted_kill_list_not_shrunk(
        stored: &[String],
        next: &[String],
        field_name: &str,
    ) -> Result<()> {
        for identifier in stored {
            let trimmed = identifier.trim();
            if trimmed.is_empty() {
                continue;
            }
            if !next.iter().any(|existing| existing.trim() == trimmed) {
                return Err(Error::denied(format!(
                    "An accepted kill on {field_name} cannot be cleared. Un-kill is a golden-ticket-class raise. Accepted death is verifier state on the issuer. This is not a sixth identity record. The check fails closed."
                )));
            }
        }
        Ok(())
    }

    /// Highest signed issuance threshold_n on issuance.log.
    /// Each line stores event.threshold_n. An empty log returns 1.
    /// This function must not call load_issuer.
    pub fn highest_log_threshold_n(&self) -> Result<u32> {
        let mut highest = 1u32;
        for event in self.read_log()? {
            highest = highest.max(event.threshold_n.max(1));
        }
        Ok(highest)
    }

    /// True when issuance.log already has a signed issuer_seal line.
    /// This function must not call load_issuer.
    pub fn log_has_issuer_seal(&self) -> Result<bool> {
        for event in self.read_log()? {
            if event.operation == "issuer_seal" {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Timestamp of the first signed issuer_seal line on issuance.log.
    /// This function must not call load_issuer. An empty log returns None.
    pub fn earliest_issuer_seal_timestamp(&self) -> Result<Option<DateTime<Utc>>> {
        for event in self.read_log()? {
            if event.operation == "issuer_seal" {
                return Ok(Some(event.timestamp));
            }
        }
        Ok(None)
    }

    /// Earliest parseable issuer.kill_date on a signed issuer_seal note.
    /// Walks read_log only. This function must not call load_issuer.
    /// Each issuer_seal note stores issuer.kill_date as RFC3339.
    /// Unparseable notes are skipped. No parseable note returns None.
    /// A later shorten writes a later line with an earlier date. The minimum is live.
    pub fn signed_issuer_seal_kill_date(&self) -> Result<Option<DateTime<Utc>>> {
        const PREFIX: &str = "issuer.kill_date=";
        let mut earliest: Option<DateTime<Utc>> = None;
        for event in self.read_log()? {
            if event.operation != "issuer_seal" {
                continue;
            }
            let Some(note) = event.note.as_deref() else {
                continue;
            };
            let Some(start) = note.find(PREFIX) else {
                continue;
            };
            let rest = &note[start + PREFIX.len()..];
            let token = rest
                .split_whitespace()
                .next()
                .unwrap_or(rest)
                .trim_end_matches('.');
            let Ok(parsed) = DateTime::parse_from_rfc3339(token) else {
                continue;
            };
            let parsed = parsed.with_timezone(&Utc);
            earliest = Some(match earliest {
                Some(current) => current.min(parsed),
                None => parsed,
            });
        }
        Ok(earliest)
    }

    /// Earliest parseable previous-key kill_date on a signed issuer_rotate note.
    /// Walks read_log only. This function must not call load_issuer.
    /// Each issuer_rotate note stores previous_public_key as hex and kill_date as RFC3339.
    /// The kill_date token is not the issuer.kill_date seal prefix.
    /// Unparseable notes are skipped. The same previous public key on more than
    /// one rotate line keeps the minimum date.
    pub fn signed_previous_issuer_key_kill_dates(&self) -> Result<Vec<(String, DateTime<Utc>)>> {
        let mut dates: Vec<(String, DateTime<Utc>)> = Vec::new();
        for event in self.read_log()? {
            if event.operation != "issuer_rotate" {
                continue;
            }
            let Some(note) = event.note.as_deref() else {
                continue;
            };
            let Some((public_key, kill_date)) = previous_key_and_kill_date_from_rotate_note(note)
            else {
                continue;
            };
            if let Some((_, existing)) = dates.iter_mut().find(|(key, _)| key == &public_key) {
                if kill_date < *existing {
                    *existing = kill_date;
                }
            } else {
                dates.push((public_key, kill_date));
            }
        }
        Ok(dates)
    }

    /// Signed issuer member public keys on issuer_member_add notes.
    /// Walks read_log only. This function must not call load_issuer.
    /// Each issuer_member_add note stores public_key as hex.
    /// Unparseable notes are skipped. The same public key on more than
    /// one member-add line is stored once.
    pub fn signed_issuer_member_public_keys(&self) -> Result<Vec<String>> {
        let mut keys: Vec<String> = Vec::new();
        for event in self.read_log()? {
            if event.operation != "issuer_member_add" {
                continue;
            }
            let Some(note) = event.note.as_deref() else {
                continue;
            };
            let Some(public_key) = member_public_key_from_member_add_note(note) else {
                continue;
            };
            if keys.iter().any(|existing| existing == &public_key) {
                continue;
            }
            keys.push(public_key);
        }
        Ok(keys)
    }

    /// Earliest parseable accepted-previous-key kill_date on a signed
    /// previous_key_accept note. Walks read_log only. This function must
    /// not call load_issuer.
    /// Each previous_key_accept note stores previous_public_key as hex
    /// and kill_date as RFC3339. The kill_date token is not the
    /// issuer.kill_date seal prefix.
    /// Unparseable notes are skipped. The same previous public key on
    /// more than one accept line keeps the minimum date.
    pub fn signed_accepted_previous_key_kill_dates(&self) -> Result<Vec<(String, DateTime<Utc>)>> {
        let mut dates: Vec<(String, DateTime<Utc>)> = Vec::new();
        for event in self.read_log()? {
            if event.operation != "previous_key_accept" {
                continue;
            }
            let Some(note) = event.note.as_deref() else {
                continue;
            };
            let Some((public_key, kill_date)) = previous_key_and_kill_date_from_rotate_note(note)
            else {
                continue;
            };
            if let Some((_, existing)) = dates.iter_mut().find(|(key, _)| key == &public_key) {
                if kill_date < *existing {
                    *existing = kill_date;
                }
            } else {
                dates.push((public_key, kill_date));
            }
        }
        Ok(dates)
    }

    /// Earliest parseable accepted-seal kill_date on a signed seal_accept
    /// note. Walks read_log only. This function must not call load_issuer.
    /// Each seal_accept note stores sealed_public_key as hex and kill_date
    /// as RFC3339. The kill_date token is not the issuer.kill_date seal
    /// prefix. Unparseable notes are skipped. The same sealed public key
    /// on more than one accept line keeps the minimum date.
    /// Honest issuer_seal on the issuing store is not a seal_accept line.
    pub fn signed_accepted_seal_kill_dates(&self) -> Result<Vec<(String, DateTime<Utc>)>> {
        let mut dates: Vec<(String, DateTime<Utc>)> = Vec::new();
        for event in self.read_log()? {
            if event.operation != "seal_accept" {
                continue;
            }
            let Some(note) = event.note.as_deref() else {
                continue;
            };
            let Some((public_key, kill_date)) = sealed_key_and_kill_date_from_accept_note(note)
            else {
                continue;
            };
            if let Some((_, existing)) = dates.iter_mut().find(|(key, _)| key == &public_key) {
                if kill_date < *existing {
                    *existing = kill_date;
                }
            } else {
                dates.push((public_key, kill_date));
            }
        }
        Ok(dates)
    }

    /// Highest signed verify_threshold_n on a signed issuer_verify_threshold note.
    /// Walks read_log only. This function must not call load_issuer.
    /// Each issuer_verify_threshold note stores n after "verify_threshold_n to ".
    /// Unparseable notes are skipped. No parseable note returns 1.
    pub fn highest_log_verify_threshold_n(&self) -> Result<u32> {
        const PREFIX: &str = "verify_threshold_n to ";
        let mut highest = 1u32;
        for event in self.read_log()? {
            if event.operation != "issuer_verify_threshold" {
                continue;
            }
            let Some(note) = event.note.as_deref() else {
                continue;
            };
            let Some(start) = note.find(PREFIX) else {
                continue;
            };
            let rest = &note[start + PREFIX.len()..];
            let token = rest
                .split_whitespace()
                .next()
                .unwrap_or(rest)
                .trim_end_matches('.');
            let Ok(parsed) = token.parse::<u32>() else {
                continue;
            };
            highest = highest.max(parsed);
        }
        Ok(highest)
    }

    /// Load issuer.json. If the unsigned file threshold_n is lower than the
    /// highest signed issuance.log n, set the in-memory n to that log n.
    /// Do not write the file. A planted lower n is not live.
    /// If the unsigned file kill_date is missing and a signed issuer_seal
    /// line already exists, set the in-memory kill_date to that first seal
    /// timestamp. Do not write the file. A planted clear is not live.
    /// If the unsigned file kill_date is later than the earliest signed
    /// issuer.kill_date on an issuer_seal note, set the in-memory kill_date
    /// to that signed date. Do not write the file. A planted later date is
    /// not live.
    /// If a previous_issuer_keys kill_date is later than the earliest signed
    /// kill_date on an issuer_rotate note for that public key, set the
    /// in-memory previous-key kill_date to that signed date. Do not write
    /// the file. A planted later previous-key date is not live.
    /// If a signed issuer_rotate note records a previous public key that
    /// is not in the file, restore that previous key in memory. Do not
    /// write the file. A planted drop is not live.
    /// If the unsigned file verify_threshold_n is lower than the
    /// highest signed issuer_verify_threshold note n, set the
    /// in-memory n to that log n. Do not write the file. A planted
    /// lower n is not live.
    /// If an accepted_previous_issuer_keys kill_date is later than the
    /// earliest signed kill_date on a previous_key_accept note for that
    /// public key, set the in-memory accepted previous-key kill_date to
    /// that signed date. Do not write the file. A planted later accepted
    /// previous-key date is not live.
    /// If a signed previous_key_accept note records a previous public key
    /// that is not in the file, restore that accepted previous key in
    /// memory. Do not write the file. A planted drop is not live.
    /// If an accepted_sealed_issuer_keys kill_date is later than the
    /// earliest signed kill_date on a seal_accept note for that
    /// public key, set the in-memory accepted seal kill_date to
    /// that signed date. Do not write the file. A planted later
    /// remaining life is not live.
    /// If a signed seal_accept note records a sealed public key
    /// that is not in the file, restore that accepted seal in
    /// memory. Do not write the file. A planted drop is not live.
    /// Honest issuer_seal on the issuing store is not a seal_accept
    /// line. That first seal write does not require a prior seal_accept.
    /// If unsigned issuer.json public_keys holds a key that is not the
    /// current public key and is not a signed issuer_member_add public key,
    /// drop that extra in memory. Do not write the file. A planted extra
    /// is not a live verify key.
    /// If unsigned issuer.json current_public_key does not match
    /// issuer.secret, set the in-memory current public key to the secret
    /// public key. Do not write the file. A planted current is not a live
    /// verify key.
    pub fn load_issuer(&self) -> Result<Issuer> {
        if !self.issuer_path().exists() {
            return Err(Error::kernel(
                "The issuer record is missing. Run the init command first.",
            ));
        }
        let mut issuer: Issuer = self.read_json(&self.issuer_path())?;
        let log_n = self.highest_log_threshold_n()?;
        if issuer.threshold_n < log_n {
            issuer.threshold_n = log_n;
        }
        if issuer.kill_date.is_none() {
            if let Some(seal_timestamp) = self.earliest_issuer_seal_timestamp()? {
                issuer.kill_date = Some(seal_timestamp);
            }
        }
        if let (Some(file_date), Some(signed_date)) =
            (issuer.kill_date, self.signed_issuer_seal_kill_date()?)
        {
            if file_date > signed_date {
                issuer.kill_date = Some(signed_date);
            }
        }
        let signed_previous = self.signed_previous_issuer_key_kill_dates()?;
        for entry in &mut issuer.previous_issuer_keys {
            let hex = entry.public_key_hex.trim();
            let Some((_, signed)) = signed_previous.iter().find(|(key, _)| key.trim() == hex)
            else {
                continue;
            };
            if entry.kill_date > *signed {
                entry.kill_date = *signed;
            }
        }
        for (public_key_hex, kill_date) in &signed_previous {
            let hex = public_key_hex.trim();
            let already_present = issuer
                .previous_issuer_keys
                .iter()
                .any(|entry| entry.public_key_hex.trim() == hex);
            if already_present {
                continue;
            }
            issuer.previous_issuer_keys.push(PreviousIssuerKey {
                public_key_hex: hex.to_string(),
                kill_date: *kill_date,
            });
        }
        let log_verify_n = self.highest_log_verify_threshold_n()?;
        if issuer.verify_threshold_n < log_verify_n {
            issuer.verify_threshold_n = log_verify_n;
        }
        let signed_accepted_previous = self.signed_accepted_previous_key_kill_dates()?;
        for entry in &mut issuer.accepted_previous_issuer_keys {
            let hex = entry.public_key_hex.trim();
            let Some((_, signed)) = signed_accepted_previous
                .iter()
                .find(|(key, _)| key.trim() == hex)
            else {
                continue;
            };
            if entry.kill_date > *signed {
                entry.kill_date = *signed;
            }
        }
        for (public_key_hex, kill_date) in &signed_accepted_previous {
            let hex = public_key_hex.trim();
            let already_present = issuer
                .accepted_previous_issuer_keys
                .iter()
                .any(|entry| entry.public_key_hex.trim() == hex);
            if already_present {
                continue;
            }
            issuer
                .accepted_previous_issuer_keys
                .push(PreviousIssuerKey {
                    public_key_hex: hex.to_string(),
                    kill_date: *kill_date,
                });
        }
        let signed_accepted_seal = self.signed_accepted_seal_kill_dates()?;
        for entry in &mut issuer.accepted_sealed_issuer_keys {
            let hex = entry.public_key_hex.trim();
            let Some((_, signed)) = signed_accepted_seal
                .iter()
                .find(|(key, _)| key.trim() == hex)
            else {
                continue;
            };
            if entry.kill_date > *signed {
                entry.kill_date = *signed;
            }
        }
        for (public_key_hex, kill_date) in &signed_accepted_seal {
            let hex = public_key_hex.trim();
            let already_present = issuer
                .accepted_sealed_issuer_keys
                .iter()
                .any(|entry| entry.public_key_hex.trim() == hex);
            if already_present {
                continue;
            }
            issuer.accepted_sealed_issuer_keys.push(PreviousIssuerKey {
                public_key_hex: hex.to_string(),
                kill_date: *kill_date,
            });
        }
        if let Ok(secret) = self.load_secret() {
            if let Ok(from_secret) =
                crate::issuer_crypto::public_key_hexadecimal_from_secret(&secret)
            {
                let from_secret = from_secret.trim().to_string();
                if !from_secret.is_empty() && issuer.current_public_key.trim() != from_secret {
                    issuer.current_public_key = from_secret;
                }
            }
        }
        let signed_members = self.signed_issuer_member_public_keys()?;
        let current = issuer.current_public_key.trim().to_string();
        issuer.public_keys.retain(|key| {
            let trimmed = key.trim();
            if trimmed.is_empty() {
                return false;
            }
            if !current.is_empty() && trimmed == current {
                return true;
            }
            signed_members
                .iter()
                .any(|signed| signed.trim() == trimmed)
        });
        Ok(issuer)
    }

    pub fn save_secret(&self, private_key_hexadecimal: &str) -> Result<()> {
        fs::write(self.secret_path(), private_key_hexadecimal.as_bytes())?;
        Ok(())
    }

    pub fn load_secret(&self) -> Result<String> {
        let text = fs::read_to_string(self.secret_path())?;
        Ok(text.trim().to_string())
    }

    pub fn save_biscuit_secret(&self, private_key_hexadecimal: &str) -> Result<()> {
        fs::write(
            self.biscuit_secret_path(),
            private_key_hexadecimal.as_bytes(),
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                self.biscuit_secret_path(),
                fs::Permissions::from_mode(0o600),
            )?;
        }
        Ok(())
    }

    pub fn load_biscuit_secret(&self) -> Result<String> {
        let path = self.biscuit_secret_path();
        if !path.exists() {
            return Err(Error::denied(
                "The Biscuit envelope secret is missing. Capability tokens cannot be minted. The Biscuit key is a capability-envelope key, not the identity root. The check fails closed.",
            ));
        }
        let text = fs::read_to_string(path)?;
        let trimmed = text.trim().to_string();
        if trimmed.is_empty() {
            return Err(Error::denied(
                "The Biscuit envelope secret is empty. Capability tokens cannot be minted. The check fails closed.",
            ));
        }
        Ok(trimmed)
    }

    /// Persist an agent type. The first write sets authorization_limit, allowed_intents, max_delegation_depth, and lifetime_seconds.
    /// Any later persist whose authorization_limit is a raise versus the stored value is refused.
    /// Any later persist whose allowed_intents is not a subset of the stored set is refused.
    /// Any later persist whose max_delegation_depth is greater than the stored depth is refused.
    /// Any later persist whose lifetime_seconds is greater than the stored lifetime is refused.
    /// A raise is a new limit that is not allowed by the stored limit, a new intent that is not in the stored set, a greater depth, or a longer lifetime.
    /// The authorization-limit comparison is audience_within_authorization_limit: the same function mint and spawn use.
    /// The allowed-intents comparison is allowed_intents_within_stored: every new intent string must already sit in the stored set.
    /// Narrowing is allowed. The same value is allowed.
    /// Raise is refused even when no instance of this type exists.
    /// After freeze checks pass, the kernel re-signs with the current issuer secret.
    /// A caller-supplied signature is overwritten. Freeze raises still refuse before a signature is written.
    /// An existing file whose stored issuer signature is missing, wrong, or untrusted is refused.
    /// Rotate must not launder a planted file. This is not a sixth identity record.
    pub fn save_agent_type(&self, agent_type: &AgentType) -> Result<()> {
        let path = self
            .root
            .join("agent_types")
            .join(format!("{}.json", agent_type.id));
        if path.exists() {
            let stored: AgentType = self.read_json(&path)?;
            self.require_stored_record_trusted("agent type", |issuer| {
                tokens::require_trusted_agent_type_issuer_signature(&stored, issuer, Utc::now())
            })?;
            if !audience_within_authorization_limit(
                &agent_type.authorization_limit,
                &stored.authorization_limit,
            ) {
                return Err(Error::denied(
                    "The authorization limit is frozen after the first write. A later write that raises authorization_limit is refused. If the new limit is not allowed by the stored limit, it is a raise. The type must not become more powerful than at birth. This is not a sixth identity record.",
                ));
            }
            if !allowed_intents_within_stored(&agent_type.allowed_intents, &stored.allowed_intents)
            {
                return Err(Error::denied(
                    "The allowed intents are frozen after the first write. A later write that adds an intent is refused. Adding an intent is a golden-ticket-class raise. The type must not become more powerful than at birth. This is not a sixth identity record.",
                ));
            }
            if agent_type.max_delegation_depth > stored.max_delegation_depth {
                return Err(Error::denied(
                    "The maximum delegation depth is frozen after the first write. A later write that raises max_delegation_depth is refused. Raising the depth is a golden-ticket-class raise. The type must not become more powerful than at birth. This is not a sixth identity record.",
                ));
            }
            if agent_type.lifetime_seconds > stored.lifetime_seconds {
                return Err(Error::denied(
                    "The lifetime in seconds is frozen after the first write. A later write that raises lifetime_seconds is refused. Raising the lifetime is a golden-ticket-class raise. The type must not become more powerful than at birth. This is not a sixth identity record.",
                ));
            }
        }
        let mut signed = agent_type.clone();
        self.sign_agent_type_record(&mut signed)?;
        self.write_json(&path, &signed)
    }

    pub fn load_agent_type(&self, identifier: &str) -> Result<AgentType> {
        let path = self
            .root
            .join("agent_types")
            .join(format!("{identifier}.json"));
        if !path.exists() {
            return Err(Error::kernel(format!(
                "The agent type does not exist: {identifier}"
            )));
        }
        self.read_json(&path)
    }

    /// Load threshold_n member secrets. One secret when n=1 (issuer.secret).
    /// When n>1, issuer.secret plus additional issuer-member-*.secret files.
    /// If only one secret is present when n=2, refuse.
    pub fn member_secrets_for_threshold_sign(
        &self,
        persist_name: &str,
    ) -> Result<Vec<(String, String)>> {
        let issuer = self.load_issuer()?;
        self.member_secrets_for_named_threshold(persist_name, issuer.threshold_n)
    }

    /// Load member secrets for a named issuance n. Used when a persist will
    /// write a new threshold_n and then sign at that new n. Check this n
    /// before any write. append_log later would refuse, but save_issuer
    /// would already have written the new threshold_n.
    pub fn member_secrets_for_named_threshold(
        &self,
        persist_name: &str,
        threshold_n: u32,
    ) -> Result<Vec<(String, String)>> {
        let issuer = self.load_issuer()?;
        if threshold_n < 1 {
            return Err(Error::denied(format!(
                "The threshold_n value must be at least 1. A {persist_name} persist fails closed."
            )));
        }
        let secret = self.load_secret()?;
        if secret.trim().is_empty() {
            return Err(Error::denied(format!(
                "The issuer secret is empty. A {persist_name} persist fails closed."
            )));
        }
        let signing_public_key = crate::issuer_crypto::public_key_hexadecimal_from_secret(&secret)?;
        let current_public_key = issuer.current_public_key_hex();
        if current_public_key.is_empty() {
            return Err(Error::denied(format!(
                "The current issuer public key is empty. A {persist_name} persist fails closed."
            )));
        }
        if signing_public_key != current_public_key {
            return Err(Error::denied(format!(
                "The issuer secret does not match the current public key. A {persist_name} persist must use the current issuer secret. The check fails closed."
            )));
        }
        if issuer.is_biscuit_envelope_key(&signing_public_key) {
            return Err(Error::denied(format!(
                "The Biscuit envelope key is not a threshold member. A {persist_name} persist fails closed."
            )));
        }
        let mut members = vec![(secret, current_public_key.clone())];
        if threshold_n == 1 {
            return Ok(members);
        }
        for extra in self.list_additional_member_secrets(&issuer)? {
            if extra.1 == current_public_key {
                continue;
            }
            if issuer.is_biscuit_envelope_key(&extra.1) {
                continue;
            }
            members.push(extra);
        }
        if (members.len() as u32) < threshold_n {
            return Err(Error::denied(format!(
                "The threshold_n value is {0} but only {1} issuer member secret is present. Mint, birth, spawn, and save-sign refuse when only one secret is present and threshold_n is 2. The check fails closed.",
                threshold_n,
                members.len()
            )));
        }
        Ok(members)
    }

    fn apply_member_signatures(
        &self,
        persist_name: &str,
        message: &str,
        issuer_public_key_hex: &mut String,
        issuer_signature_hex: &mut String,
        issuer_signatures: &mut Vec<crate::records::IssuerMemberSignature>,
    ) -> Result<()> {
        let issuer = self.load_issuer()?;
        let members = self.member_secrets_for_threshold_sign(persist_name)?;
        let current_public_key = issuer.current_public_key_hex();
        *issuer_public_key_hex = current_public_key.clone();
        let signatures = crate::threshold::sign_message_with_member_secrets(&members, message)?;
        if issuer.threshold_n <= 1 {
            *issuer_signature_hex =
                crate::threshold::signature_hex_for_public_key(&signatures, &current_public_key);
            issuer_signatures.clear();
        } else {
            *issuer_signature_hex =
                crate::threshold::signature_hex_for_public_key(&signatures, &current_public_key);
            *issuer_signatures = signatures;
        }
        Ok(())
    }

    /// An existing on-disk record may be persisted only when its stored issuer
    /// signature is already trusted. A planted file with a missing, wrong, or
    /// untrusted signature cannot be re-signed. Rotate must not launder a planted
    /// record. First write still has no stored signature and may persist.
    fn require_stored_record_trusted(
        &self,
        persist_name: &str,
        verify: impl FnOnce(&crate::records::Issuer) -> crate::error::Result<()>,
    ) -> Result<()> {
        let issuer = self.load_issuer()?;
        verify(&issuer).map_err(|_| {
            Error::denied(format!(
                "The stored {persist_name} issuer signature is missing, wrong, or untrusted. A planted file cannot be persisted or re-signed. Rotate must not launder a planted record. The store JSON is not enough. The check fails closed."
            ))
        })
    }

    /// Sign an agent type record with the current issuer secret.
    /// The caller-supplied signature is overwritten. A planted file that never
    /// passed this persist cannot hold a trusted signature without issuer.secret.
    fn sign_agent_type_record(&self, agent_type: &mut AgentType) -> Result<()> {
        let issuer = self.load_issuer()?;
        agent_type.issuer_public_key_hex = issuer.current_public_key_hex();
        agent_type.issuer_signature_hex.clear();
        agent_type.issuer_signatures.clear();
        let message = agent_type_issuer_signature_message(agent_type);
        self.apply_member_signatures(
            "agent type",
            &message,
            &mut agent_type.issuer_public_key_hex,
            &mut agent_type.issuer_signature_hex,
            &mut agent_type.issuer_signatures,
        )
    }

    /// Sign an instance record with the current issuer secret.
    /// The caller-supplied signature is overwritten. A planted file that never
    /// passed this persist cannot hold a trusted signature without issuer.secret.
    fn sign_instance_record(&self, instance: &mut Instance) -> Result<()> {
        let issuer = self.load_issuer()?;
        instance.issuer_public_key_hex = issuer.current_public_key_hex();
        instance.issuer_signature_hex.clear();
        instance.issuer_signatures.clear();
        let message = instance_issuer_signature_message(instance);
        self.apply_member_signatures(
            "instance",
            &message,
            &mut instance.issuer_public_key_hex,
            &mut instance.issuer_signature_hex,
            &mut instance.issuer_signatures,
        )
    }

    /// Sign a capability record with the current issuer secret.
    /// The caller-supplied signature is overwritten. A planted file that never
    /// passed this persist cannot hold a trusted signature without issuer.secret.
    fn sign_capability_record(&self, capability: &mut Capability) -> Result<()> {
        let issuer = self.load_issuer()?;
        capability.issuer_public_key_hex = issuer.current_public_key_hex();
        capability.issuer_signature_hex.clear();
        capability.issuer_signatures.clear();
        let message = capability_issuer_signature_message(capability);
        self.apply_member_signatures(
            "capability",
            &message,
            &mut capability.issuer_public_key_hex,
            &mut capability.issuer_signature_hex,
            &mut capability.issuer_signatures,
        )
    }

    /// Sign a chain record with the current issuer secret.
    /// The caller-supplied signature is overwritten. A planted file that never
    /// passed this persist cannot hold a trusted signature without issuer.secret.
    fn sign_chain_record(&self, chain: &mut Chain) -> Result<()> {
        let issuer = self.load_issuer()?;
        chain.issuer_public_key_hex = issuer.current_public_key_hex();
        chain.issuer_signature_hex.clear();
        chain.issuer_signatures.clear();
        let message = chain_issuer_signature_message(chain);
        self.apply_member_signatures(
            "chain",
            &message,
            &mut chain.issuer_public_key_hex,
            &mut chain.issuer_signature_hex,
            &mut chain.issuer_signatures,
        )
    }

    /// Persist an instance. A new instance may set holder_public_key, expires, agent_type_id, and parent_instance_id once.
    /// Any later persist whose holder_public_key differs from the stored value is refused.
    /// Any later persist whose expires is later than the stored value is refused.
    /// Any later persist whose agent_type_id differs from the stored value is refused.
    /// Any later persist whose parent_instance_id differs from the stored value is refused.
    /// Any later persist that sets a revoked instance back to live is refused.
    /// A later persist that creates a new instance file after birth is already recorded
    /// is refused. Birth is the holder-secret file or an issuance-log mention of the identifier.
    /// The first binder is written once at birth. Identity is not the key.
    /// After freeze checks pass, the kernel re-signs with the current issuer secret.
    /// A caller-supplied signature is overwritten. An existing file whose stored
    /// issuer signature is missing, wrong, or untrusted is refused. Rotate must
    /// not launder a planted file. This is not a remote proof-of-possession
    /// protocol. This is not SPIFFE.
    pub fn save_instance(&self, instance: &Instance) -> Result<()> {
        if instance.holder_public_key.trim().is_empty() {
            return Err(Error::denied(
                "The holder public key must not be empty. The first binder is written once at birth. A name is not a key. This is not SPIFFE.",
            ));
        }
        let path = self
            .root
            .join("instances")
            .join(format!("{}.json", instance.id));
        if path.exists() {
            let stored: Instance = self.read_json(&path)?;
            self.require_stored_record_trusted("instance", |issuer| {
                tokens::require_trusted_instance_issuer_signature(&stored, issuer, Utc::now())
            })?;
            if stored.holder_public_key != instance.holder_public_key {
                return Err(Error::denied(
                    "The first binder is written once at birth. A later write that replaces holder_public_key is refused. Identity is not the key. The holder public key is not replaceable. This is not a remote proof-of-possession protocol. This is not SPIFFE.",
                ));
            }
            if instance.expires > stored.expires {
                return Err(Error::denied(
                    "The instance expiry is frozen after the first write. A later write that moves expires later is refused. An extension is a golden-ticket-class extension. The instance must not outlive the birth. This is not a sixth identity record.",
                ));
            }
            if instance.agent_type_id != stored.agent_type_id {
                return Err(Error::denied(
                    "The agent type identifier is written once at birth. A later write that replaces agent_type_id is refused. Swapping the type is a golden-ticket-class raise. The instance must not become a more powerful type than at birth. This is not a sixth identity record.",
                ));
            }
            if instance.parent_instance_id != stored.parent_instance_id {
                return Err(Error::denied(
                    "The parent instance identifier is written once at birth. A later write that clears or replaces parent_instance_id is refused. Clearing the parent is a golden-ticket-class raise. The instance must not leave the parent kill tree. This is not a sixth identity record.",
                ));
            }
            if stored.status == InstanceStatus::Revoked && instance.status == InstanceStatus::Live {
                return Err(Error::denied(
                    "The instance status cannot return to live after revoke. A later write that sets a revoked instance to live is refused. Un-revoking is a golden-ticket-class raise. This is not a sixth identity record.",
                ));
            }
        } else if self.instance_already_born(&instance.id)? {
            return Err(Error::denied(
                "The first binder is written once at birth. A later write that creates a new instance file for an identifier that was already born is refused. Identity is not the key. The holder public key is not replaceable. This is not a remote proof-of-possession protocol. This is not SPIFFE.",
            ));
        }
        let mut signed = instance.clone();
        self.sign_instance_record(&mut signed)?;
        self.write_json(&path, &signed)
    }

    /// True when this identifier was already born. Birth evidence is the holder-secret
    /// file or an issuance-log mention. A missing instance file is not a new birth.
    fn instance_already_born(&self, instance_id: &str) -> Result<bool> {
        if self.holder_secret_path(instance_id).exists() {
            return Ok(true);
        }
        let trimmed = instance_id.trim();
        if trimmed.is_empty() {
            return Ok(false);
        }
        let events = self.read_log()?;
        Ok(events.iter().any(|event| {
            event.instance_id.as_deref() == Some(trimmed)
                || event
                    .killed_instance_ids
                    .iter()
                    .any(|identifier| identifier.trim() == trimmed)
        }))
    }

    /// Load instance.json. If a signed kill_instance issuance.log line already
    /// records this instance, set the in-memory status to revoked. Do not write
    /// the file. A planted live status is not live.
    pub fn load_instance(&self, identifier: &str) -> Result<Instance> {
        let path = self
            .root
            .join("instances")
            .join(format!("{identifier}.json"));
        if !path.exists() {
            return Err(Error::kernel(format!(
                "The instance does not exist: {identifier}"
            )));
        }
        let mut instance: Instance = self.read_json(&path)?;
        self.overlay_instance_status_from_signed_kill(&mut instance)?;
        Ok(instance)
    }

    /// If a signed kill_instance issuance.log line already records this
    /// instance, set in-memory status to revoked. Do not write the file.
    /// A planted live status is not live. Parent-cascade identifiers live on
    /// killed_instance_ids.
    fn overlay_instance_status_from_signed_kill(&self, instance: &mut Instance) -> Result<()> {
        if self.signed_kill_hits_instance(&instance.id)? {
            instance.status = InstanceStatus::Revoked;
        }
        Ok(())
    }

    /// True when issuance.log has a kill_instance line for this identifier.
    /// Matches event.instance_id or killed_instance_ids. Walks read_log only.
    /// This function must not call load_issuer.
    fn signed_kill_hits_instance(&self, instance_id: &str) -> Result<bool> {
        let trimmed = instance_id.trim();
        if trimmed.is_empty() {
            return Ok(false);
        }
        for event in self.read_log()? {
            if event.operation != "kill_instance" {
                continue;
            }
            if event.instance_id.as_deref() == Some(trimmed) {
                return Ok(true);
            }
            if event
                .killed_instance_ids
                .iter()
                .any(|identifier| identifier.trim() == trimmed)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// True when issuance.log has a kill_capability or kill_instance line for
    /// this capability identifier. Matches event.capability_id or
    /// killed_capability_ids. Walks read_log only. This function must not
    /// call load_issuer.
    pub(crate) fn signed_kill_hits_capability(&self, capability_id: &str) -> Result<bool> {
        let trimmed = capability_id.trim();
        if trimmed.is_empty() {
            return Ok(false);
        }
        for event in self.read_log()? {
            if event.operation != "kill_capability" && event.operation != "kill_instance" {
                continue;
            }
            if event.capability_id.as_deref() == Some(trimmed) {
                return Ok(true);
            }
            if event
                .killed_capability_ids
                .iter()
                .any(|identifier| identifier.trim() == trimmed)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn holder_secret_path(&self, instance_id: &str) -> PathBuf {
        self.root
            .join("holders")
            .join(format!("{instance_id}.secret"))
    }

    /// Laboratory holder secret file. A secret holder is out of scope. Sanctum can hold secrets later.
    pub fn save_holder_secret(
        &self,
        instance_id: &str,
        private_key_hexadecimal: &str,
    ) -> Result<()> {
        let path = self.holder_secret_path(instance_id);
        if let Some(parent_directory) = path.parent() {
            fs::create_dir_all(parent_directory)?;
        }
        fs::write(&path, private_key_hexadecimal.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn load_holder_secret(&self, instance_id: &str) -> Result<String> {
        let path = self.holder_secret_path(instance_id);
        if !path.exists() {
            return Err(Error::kernel(format!(
                "The holder secret file does not exist for this instance: {instance_id}"
            )));
        }
        let text = fs::read_to_string(path)?;
        Ok(text.trim().to_string())
    }

    /// Persist a capability. The first write sets expires, intent, audience,
    /// on_behalf_of, instance_id, and token bytes.
    /// Any later persist whose expires is later than the stored value is refused.
    /// Any later persist whose intent is not narrower or equal is refused.
    /// Any later persist whose audience is not narrower or equal is refused.
    /// Any later persist whose on_behalf_of differs is refused.
    /// Any later persist whose instance_id differs is refused.
    /// Any later persist whose biscuit (token bytes) differs is refused.
    /// An earlier (shorter) expiry may persist. A narrower intent or audience may persist.
    /// The same values may persist.
    /// Widening intent or audience, changing act authority, swapping the instance,
    /// or replacing the token is a golden-ticket-class raise.
    /// Present copies intent and audience from the record. A widened record would
    /// present those wider fields even when the original token stays narrow.
    /// A wider token plus a matching widened record would pass verify and check.
    /// After freeze checks pass, the kernel re-signs with the current issuer secret.
    /// A caller-supplied signature is overwritten.
    /// An existing file whose stored issuer signature is missing, wrong, or untrusted is refused.
    /// Rotate must not launder a planted file. This is not a sixth identity record.
    pub fn save_capability(&self, capability: &Capability) -> Result<()> {
        let path = self
            .root
            .join("capabilities")
            .join(format!("{}.json", capability.id));
        if path.exists() {
            let stored: Capability = self.read_json(&path)?;
            self.require_stored_record_trusted("capability", |issuer| {
                tokens::require_trusted_capability_issuer_signature(&stored, issuer, Utc::now())
            })?;
            if capability.expires > stored.expires {
                return Err(Error::denied(
                    "The capability expiry is frozen after the first write. A later write that moves expires later is refused. An extension is a golden-ticket-class extension. The capability must not outlive the mint. This is not a sixth identity record.",
                ));
            }
            if !is_narrower_or_equal(&capability.intent, &stored.intent) {
                return Err(Error::denied(
                    "The capability intent is frozen after the first write. A later write that widens intent is refused. Widening intent is a golden-ticket-class raise. The capability must not become more powerful than at mint. This is not a sixth identity record.",
                ));
            }
            if !is_narrower_or_equal(&capability.audience, &stored.audience) {
                return Err(Error::denied(
                    "The capability audience is frozen after the first write. A later write that widens audience is refused. Widening audience is a golden-ticket-class raise. The capability must not become more powerful than at mint. This is not a sixth identity record.",
                ));
            }
            if capability.on_behalf_of != stored.on_behalf_of {
                return Err(Error::denied(
                    "The capability act authority is written once at mint. A later write that replaces on_behalf_of is refused. Changing the act authority is a golden-ticket-class raise. A named user must not become autonomous. A user must not become another user. This is not a sixth identity record.",
                ));
            }
            if capability.instance_id != stored.instance_id {
                return Err(Error::denied(
                    "The capability instance identifier is written once at mint. A later write that replaces instance_id is refused. Swapping the instance is a golden-ticket-class raise. The capability must not leave the instance that received it. This is not a sixth identity record.",
                ));
            }
            if capability.biscuit != stored.biscuit {
                return Err(Error::denied(
                    "The capability token bytes are written once at mint. A later write that replaces biscuit is refused. Swapping the token is a golden-ticket-class raise. A wider token must not replace the minted token. This is not a sixth identity record.",
                ));
            }
        }
        let mut signed = capability.clone();
        self.sign_capability_record(&mut signed)?;
        self.write_json(&path, &signed)
    }

    pub fn load_capability(&self, identifier: &str) -> Result<Capability> {
        let path = self
            .root
            .join("capabilities")
            .join(format!("{identifier}.json"));
        if !path.exists() {
            return Err(Error::kernel(format!(
                "The capability does not exist: {identifier}"
            )));
        }
        self.read_json(&path)
    }

    pub fn list_capabilities(&self) -> Result<Vec<Capability>> {
        self.list_json_records("capabilities")
    }

    pub fn list_instances(&self) -> Result<Vec<Instance>> {
        let mut records: Vec<Instance> = self.list_json_records("instances")?;
        for instance in &mut records {
            self.overlay_instance_status_from_signed_kill(instance)?;
        }
        Ok(records)
    }

    pub fn list_agent_types(&self) -> Result<Vec<AgentType>> {
        self.list_json_records("agent_types")
    }

    pub fn list_chains(&self) -> Result<Vec<Chain>> {
        self.list_json_records("chains")
    }

    fn list_json_records<T: DeserializeOwned>(&self, directory_name: &str) -> Result<Vec<T>> {
        let directory = self.root.join(directory_name);
        if !directory.exists() {
            return Ok(Vec::new());
        }
        let mut records = Vec::new();
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("");
            if path.extension().and_then(|value| value.to_str()) == Some("json")
                && !name.ends_with(".tmp")
            {
                records.push(self.read_json(&path)?);
            }
        }
        Ok(records)
    }

    /// Persist a chain. The first write sets hop_index, parent_capability_id, and revoke_from_here.
    /// Any later persist whose hop_index is less than the stored hop index is refused.
    /// Any later persist whose parent_capability_id differs from the stored value is refused.
    /// Any later persist that clears revoke_from_here after it is true is refused.
    /// Decreasing the hop index, clearing the parent, or clearing the kill flag is a golden-ticket-class raise.
    /// After freeze checks pass, the kernel re-signs with the current issuer secret.
    /// A caller-supplied signature is overwritten. Freeze raises still refuse before a signature is written.
    /// An existing file whose stored issuer signature is missing, wrong, or untrusted is refused.
    /// Rotate must not launder a planted file. This is not a sixth identity record.
    pub fn save_chain(&self, chain: &Chain) -> Result<()> {
        let path = self
            .root
            .join("chains")
            .join(format!("{}.json", chain.capability_id));
        if path.exists() {
            let stored: Chain = self.read_json(&path)?;
            self.require_stored_record_trusted("chain", |issuer| {
                tokens::require_trusted_chain_issuer_signature(&stored, issuer, Utc::now())
            })?;
            if chain.hop_index < stored.hop_index {
                return Err(Error::denied(
                    "The chain hop index is frozen after the first write. A later write that decreases hop_index is refused. Decreasing the hop index is a golden-ticket-class raise. The chain must not gain hops after birth. This is not a sixth identity record.",
                ));
            }
            if chain.parent_capability_id != stored.parent_capability_id {
                return Err(Error::denied(
                    "The parent capability identifier is written once at birth. A later write that clears or replaces parent_capability_id is refused. Clearing the parent is a golden-ticket-class raise. The chain must not leave the parent kill walk. This is not a sixth identity record.",
                ));
            }
            if stored.revoke_from_here && !chain.revoke_from_here {
                return Err(Error::denied(
                    "The revoke-from-here flag cannot return to false after it is true. A later write that clears revoke_from_here is refused. Clearing the flag is a golden-ticket-class raise. A killed chain must not return to live. This is not a sixth identity record.",
                ));
            }
        }
        let mut signed = chain.clone();
        self.sign_chain_record(&mut signed)?;
        self.write_json(&path, &signed)
    }

    pub fn load_chain(&self, capability_id: &str) -> Result<Chain> {
        let path = self
            .root
            .join("chains")
            .join(format!("{capability_id}.json"));
        if !path.exists() {
            return Err(Error::kernel(format!(
                "The chain record does not exist for this capability: {capability_id}"
            )));
        }
        self.read_json(&path)
    }

    /// Last non-empty raw issuance-log line, without the trailing newline.
    pub fn last_nonempty_log_line(&self) -> Result<Option<String>> {
        let text = self.log_text()?;
        Ok(text
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .map(|line| line.to_string()))
    }

    /// Seal previous_line_hash and line_hash, then sign with the current issuer secret.
    /// Return the exact JSON line that must be written.
    /// line_hash excludes issuer_signature_hex. The signature is over line_hash and
    /// issuer_public_key_hex. A caller cannot persist an arbitrary signature.
    pub fn sealed_log_line(&self, event: &LogEvent) -> Result<String> {
        let previous = self.last_nonempty_log_line()?;
        let mut event = event.clone();
        event.issuer_signature_hex.clear();
        event.issuer_signatures.clear();
        let issuer = self.load_issuer()?;
        let current_public_key = issuer.current_public_key_hex();
        event.issuer_public_key_hex = current_public_key.clone();
        crate::log_chain::seal_log_event(&mut event, previous.as_deref())?;
        let message = issuance_log_line_issuer_signature_message(&event);
        self.apply_member_signatures(
            "issuance log line",
            &message,
            &mut event.issuer_public_key_hex,
            &mut event.issuer_signature_hex,
            &mut event.issuer_signatures,
        )?;
        let _ = current_public_key;
        Ok(serde_json::to_string(&event)?)
    }

    /// Seal and append one issuance-log line. After the append the Merkle root
    /// can be computed from the sequence of line_hash values. The root is derived,
    /// not stored. This is not a sixth record.
    pub fn append_log(&self, event: &LogEvent) -> Result<()> {
        let line = self.sealed_log_line(event)?;
        self.append_log_line(&line)
    }

    /// Walk the local SHA-256 hash chain and each line issuer signature. A break fails closed.
    pub fn verify_log_chain(&self) -> Result<()> {
        let issuer = self.load_issuer()?;
        let trusted_keys = issuer.trusted_issuer_keys_for_issuance_log();
        crate::log_chain::verify_issuance_log_text_with_threshold(
            &self.log_text()?,
            &trusted_keys,
            issuer.threshold_n,
            &issuer.biscuit_public_key_hex,
        )
    }

    /// line_hash values in order after the hash chain and line signatures verify.
    pub fn issuance_log_line_hashes(&self) -> Result<Vec<String>> {
        let issuer = self.load_issuer()?;
        let trusted_keys = issuer.trusted_issuer_keys_for_issuance_log();
        crate::log_chain::issuance_log_line_hashes_with_threshold(
            &self.log_text()?,
            &trusted_keys,
            issuer.threshold_n,
            &issuer.biscuit_public_key_hex,
        )
    }

    /// Merkle root over those line_hash values. Derived after each append. Not a stored record.
    pub fn issuance_log_merkle_root(&self) -> Result<crate::log_proof::IssuanceLogMerkleRoot> {
        let line_hashes = self.issuance_log_line_hashes()?;
        crate::log_proof::merkle_root_from_line_hashes(&line_hashes)
    }

    /// Write one exact JSON line to issuance.log. The receipt stores this same line.
    pub fn append_log_line(&self, line: &str) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log_path())?;
        file.write_all(line.as_bytes())?;
        if !line.ends_with('\n') {
            file.write_all(b"\n")?;
        }
        file.flush()?;
        Ok(())
    }

    /// Return true when `line` is present as a raw issuance.log line.
    /// An empty value is never present. This check fails closed.
    pub fn issuance_log_contains_line(&self, line: &str) -> Result<bool> {
        if line.is_empty() {
            return Ok(false);
        }
        let text = self.log_text()?;
        Ok(text.lines().any(|existing| existing == line))
    }

    pub fn read_log(&self) -> Result<Vec<LogEvent>> {
        let path = self.log_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(path)?;
        let mut events = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            events.push(serde_json::from_str(&line)?);
        }
        Ok(events)
    }

    pub fn log_text(&self) -> Result<String> {
        let path = self.log_path();
        if !path.exists() {
            return Ok(String::new());
        }
        Ok(fs::read_to_string(path)?)
    }

    /// Read issuance-log text from an explicit path. A missing file fails closed.
    pub fn log_text_from_path(path: &Path) -> Result<String> {
        if !path.exists() {
            return Err(Error::denied(format!(
                "The issuance log does not exist at {}. The receipt check fails closed.",
                path.display()
            )));
        }
        Ok(fs::read_to_string(path)?)
    }

    /// Return true when `line` is present as a raw line in `text`.
    /// An empty value is never present. This check fails closed.
    pub fn issuance_log_text_contains_line(text: &str, line: &str) -> bool {
        if line.is_empty() {
            return false;
        }
        text.lines().any(|existing| existing == line)
    }

    pub fn extra_member_secret_paths(&self) -> Vec<PathBuf> {
        self.extra_member_secret_paths
            .lock()
            .expect("member secret path lock")
            .clone()
    }

    fn resolved_path(path: &Path) -> PathBuf {
        if path.exists() {
            path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
        } else if let Some(parent) = path.parent() {
            let parent_resolved = if parent.as_os_str().is_empty() {
                PathBuf::from(".")
            } else {
                parent.to_path_buf()
            };
            let parent_resolved = parent_resolved.canonicalize().unwrap_or(parent_resolved);
            match path.file_name() {
                Some(name) => parent_resolved.join(name),
                None => parent_resolved,
            }
        } else {
            path.to_path_buf()
        }
    }

    fn path_is_inside_or_equal(candidate: &Path, container: &Path) -> bool {
        let candidate = Self::resolved_path(candidate);
        let container = Self::resolved_path(container);
        candidate == container || candidate.starts_with(&container)
    }

    fn is_member_two_secret_name(name: &str) -> bool {
        let trimmed = name.trim();
        trimmed.starts_with("issuer-member-") && trimmed.ends_with(".secret")
    }

    fn dest_is_inside_member_two_custody(&self, dest: &Path) -> bool {
        for extra in self.extra_member_secret_paths() {
            if Self::path_is_inside_or_equal(dest, &extra) {
                return true;
            }
            if let Some(parent) = extra.parent() {
                if parent.as_os_str().is_empty() {
                    continue;
                }
                if Self::path_is_inside_or_equal(dest, parent) {
                    return true;
                }
            }
        }
        false
    }

    fn dest_looks_like_member_two_custody(dest: &Path) -> Result<bool> {
        if !dest.exists() || !dest.is_dir() {
            return Ok(false);
        }
        for entry in fs::read_dir(dest)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "member-two.secret"
                || name == "member-three.secret"
                || Self::is_member_two_secret_name(&name)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn backup_file_names() -> &'static [&'static str] {
        &[
            "issuer.secret",
            "biscuit.secret",
            "issuer.json",
            "issuance.log",
        ]
    }

    fn backup_directory_names() -> &'static [&'static str] {
        &[
            "agent_types",
            "instances",
            "capabilities",
            "chains",
            "holders",
        ]
    }

    fn copy_backup_file(source: &Path, dest: &Path) -> Result<()> {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(source, dest)?;
        #[cfg(unix)]
        {
            if dest
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.ends_with(".secret"))
                .unwrap_or(false)
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(dest, fs::Permissions::from_mode(0o600))?;
            }
        }
        Ok(())
    }

    fn copy_backup_allow_list(source_root: &Path, dest_root: &Path) -> Result<()> {
        for file_name in Self::backup_file_names() {
            let source = source_root.join(file_name);
            if !source.exists() {
                continue;
            }
            Self::copy_backup_file(&source, &dest_root.join(file_name))?;
        }
        for directory_name in Self::backup_directory_names() {
            let source_directory = source_root.join(directory_name);
            let dest_directory = dest_root.join(directory_name);
            fs::create_dir_all(&dest_directory)?;
            if !source_directory.exists() {
                continue;
            }
            for entry in fs::read_dir(&source_directory)? {
                let entry = entry?;
                let name = entry.file_name();
                let name_text = name.to_string_lossy();
                if Self::is_member_two_secret_name(&name_text) {
                    continue;
                }
                if entry.path().is_dir() {
                    continue;
                }
                Self::copy_backup_file(&entry.path(), &dest_directory.join(name))?;
            }
        }
        Ok(())
    }

    fn refuse_tainted_member_two_backup(backup: &Path) -> Result<()> {
        if !backup.exists() || !backup.is_dir() {
            return Ok(());
        }
        for entry in fs::read_dir(backup)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if Self::is_member_two_secret_name(&name) {
                return Err(Error::denied(
                    "The backup contains an issuer-member secret. A tainted backup must not install member two. Member two stays in outside custody. The check fails closed.",
                ));
            }
        }
        Ok(())
    }

    /// Copy issuer.secret plus the issuance ledger to a path outside this store.
    /// Do not copy issuer-member-*.secret. This is operator disk copy, not mint.
    /// Do not append issuance.log. This is not a sixth identity record.
    /// Do not require issuer seal. A dead computer may be unsealed.
    pub fn export_issuer_backup(&self, dest: &Path) -> Result<()> {
        if Self::path_is_inside_or_equal(dest, self.root())
            || self.path_is_inside_data_directory(dest)
        {
            return Err(Error::denied(
                "The backup path must live outside the data directory. A path inside the data directory is refused. The check fails closed.",
            ));
        }
        if self.dest_is_inside_member_two_custody(dest) {
            return Err(Error::denied(
                "The backup path must not be the member-two custody path and must not live inside that custody directory. Member two stays in outside custody. The check fails closed.",
            ));
        }
        if dest.exists() {
            if dest.is_file() {
                return Err(Error::denied(
                    "The backup path must be a directory. A file path is refused. The check fails closed.",
                ));
            }
            let issuer_at_dest = dest.join("issuer.json");
            let secret_at_dest = dest.join("issuer.secret");
            let is_empty = dest.read_dir()?.next().is_none();
            if !is_empty {
                if issuer_at_dest.exists() {
                    let other: crate::records::Issuer = self.read_json(&issuer_at_dest)?;
                    let this = self.load_issuer()?;
                    if other.current_public_key_hex() != this.current_public_key_hex() {
                        return Err(Error::denied(
                            "The backup path is a non-empty directory of a different store. A different issuer is refused. The check fails closed.",
                        ));
                    }
                } else if secret_at_dest.exists() {
                    return Err(Error::denied(
                        "The backup path is a non-empty directory of a different store. A destination that already holds issuer.secret without this issuer is refused. The check fails closed.",
                    ));
                } else {
                    return Err(Error::denied(
                        "The backup path is a non-empty directory of a different store. The check fails closed.",
                    ));
                }
            }
        } else {
            fs::create_dir_all(dest)?;
        }
        if !self.issuer_path().exists() || !self.secret_path().exists() {
            return Err(Error::denied(
                "The issuer record or issuer.secret is missing. A backup without the key and the ledger is refused. The check fails closed.",
            ));
        }
        Self::copy_backup_allow_list(&self.root, dest)?;
        Ok(())
    }

    /// Copy a laboratory backup of issuer.secret plus the ledger onto an empty issuing store.
    /// Do not copy issuer-member-*.secret. This is operator disk copy, not mint.
    /// Do not append issuance.log. This is not a sixth identity record.
    /// Do not require issuer seal. A dead computer may be unsealed.
    pub fn restore_issuer_backup(backup: &Path, dest_root: &Path) -> Result<()> {
        if !backup.exists() || !backup.is_dir() {
            return Err(Error::denied(
                "The backup path must be a directory that holds issuer.secret and issuer.json. The check fails closed.",
            ));
        }
        let backup_secret = backup.join("issuer.secret");
        let backup_issuer = backup.join("issuer.json");
        if !backup_secret.exists() {
            return Err(Error::denied(
                "The backup is missing issuer.secret. Restore is key plus ledger. The check fails closed.",
            ));
        }
        if !backup_issuer.exists() {
            return Err(Error::denied(
                "The backup is missing issuer.json. Restore is key plus ledger. The check fails closed.",
            ));
        }
        if Self::path_is_inside_or_equal(dest_root, backup) {
            return Err(Error::denied(
                "The restore destination must not live inside the backup path. The check fails closed.",
            ));
        }
        if Self::dest_looks_like_member_two_custody(dest_root)? {
            return Err(Error::denied(
                "The restore destination must not be a member-two custody path. Member two stays in outside custody. The check fails closed.",
            ));
        }
        if dest_root.join("issuer.json").exists() || dest_root.join("issuer.secret").exists() {
            return Err(Error::denied(
                "The restore destination already has an issuer. Restore onto a live issuing store is refused. This is not a second live Create Agent Principal. The check fails closed.",
            ));
        }
        Self::refuse_tainted_member_two_backup(backup)?;
        if !dest_root.exists() {
            fs::create_dir_all(dest_root)?;
        }
        Self::copy_backup_allow_list(backup, dest_root)?;
        Ok(())
    }
}

/// Parse public_key from an issuer_member_add note.
/// Skip previous_public_key and current_public_key. Skip a note that does not parse.
/// Do not panic.
fn member_public_key_from_member_add_note(note: &str) -> Option<String> {
    const PREFIX: &str = "public_key=";
    let start = note.find(PREFIX)?;
    if start >= "previous_".len() && note[..start].ends_with("previous_") {
        return None;
    }
    if start >= "current_".len() && note[..start].ends_with("current_") {
        return None;
    }
    let rest = &note[start + PREFIX.len()..];
    let public_key = rest
        .split_whitespace()
        .next()
        .unwrap_or(rest)
        .trim_end_matches('.')
        .trim()
        .to_string();
    if public_key.is_empty() {
        return None;
    }
    Some(public_key)
}

/// Parse previous_public_key and kill_date from an issuer_rotate note.
/// Skip issuer.kill_date. Skip a note that does not parse. Do not panic.
fn previous_key_and_kill_date_from_rotate_note(note: &str) -> Option<(String, DateTime<Utc>)> {
    const PUBLIC_PREFIX: &str = "previous_public_key=";
    let start = note.find(PUBLIC_PREFIX)?;
    let rest = &note[start + PUBLIC_PREFIX.len()..];
    let public_key = rest
        .split_whitespace()
        .next()
        .unwrap_or(rest)
        .trim_end_matches('.')
        .trim()
        .to_string();
    if public_key.is_empty() {
        return None;
    }
    let mut search = note;
    let kill_token = loop {
        let Some(at) = search.find("kill_date=") else {
            return None;
        };
        let before = &search[..at];
        if before.ends_with("issuer.") {
            search = &search[at + "kill_date=".len()..];
            continue;
        }
        let after = &search[at + "kill_date=".len()..];
        let token = after
            .split_whitespace()
            .next()
            .unwrap_or(after)
            .trim_end_matches('.');
        break token;
    };
    let parsed = DateTime::parse_from_rfc3339(kill_token).ok()?;
    Some((public_key, parsed.with_timezone(&Utc)))
}

fn sealed_key_and_kill_date_from_accept_note(note: &str) -> Option<(String, DateTime<Utc>)> {
    const PUBLIC_PREFIX: &str = "sealed_public_key=";
    let start = note.find(PUBLIC_PREFIX)?;
    let rest = &note[start + PUBLIC_PREFIX.len()..];
    let public_key = rest
        .split_whitespace()
        .next()
        .unwrap_or(rest)
        .trim_end_matches('.')
        .trim()
        .to_string();
    if public_key.is_empty() {
        return None;
    }
    let mut search = note;
    let kill_token = loop {
        let Some(at) = search.find("kill_date=") else {
            return None;
        };
        let before = &search[..at];
        if before.ends_with("issuer.") {
            search = &search[at + "kill_date=".len()..];
            continue;
        }
        let after = &search[at + "kill_date=".len()..];
        let token = after
            .split_whitespace()
            .next()
            .unwrap_or(after)
            .trim_end_matches('.');
        break token;
    };
    let parsed = DateTime::parse_from_rfc3339(kill_token).ok()?;
    Some((public_key, parsed.with_timezone(&Utc)))
}
