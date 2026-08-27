use crate::error::{Error, Result};
use crate::records::{
    audience_within_authorization_limit, is_narrower_or_equal, new_identifier, AgentType,
    Capability, Chain, Instance, InstanceStatus, Issuer, LogEvent, PreviousIssuerKey,
};
use crate::store::Store;
use crate::tokens;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Laboratory holder proof. This is not a production proof of possession.
#[derive(Debug, Clone)]
pub enum HolderProof {
    /// Path to the holder secret file. The program derives the public key from the secret.
    SecretPath(PathBuf),
    /// Hexadecimal Ed25519 signature of the laboratory holder challenge.
    SignatureHexadecimal(String),
}

/// Instance and first capability created as one issuance.
#[derive(Debug, Clone, Serialize)]
pub struct BirthWrite {
    pub instance: Instance,
    pub capability: Capability,
    pub holder_secret_path: String,
}

/// Child instance and narrower capability created as one issuance.
#[derive(Debug, Clone, Serialize)]
pub struct SpawnWrite {
    pub instance: Instance,
    pub capability: Capability,
    pub parent_instance_id: String,
    pub parent_capability_id: String,
    pub holder_secret_path: String,
}

/// One-time holder challenge. This is log state, not a sixth identity record.
#[derive(Debug, Clone, Serialize)]
pub struct HolderChallenge {
    pub nonce: String,
    pub instance_id: String,
    pub issued: DateTime<Utc>,
    pub expires: DateTime<Utc>,
    pub challenge_message: String,
}

/// Short-lived verifier-host holder challenge. This is an artifact, not a record.
/// The nonce lives in this host process only. This is not a sixth identity record.
#[derive(Debug, Clone, Serialize)]
pub struct VerifierChallenge {
    pub nonce: String,
    pub issued: DateTime<Utc>,
    pub expires: DateTime<Utc>,
    pub challenge_message: String,
}

/// Process-memory slot for one verifier challenge. This is not an instance record.
#[derive(Debug, Clone)]
struct VerifierChallengeSlot {
    issued: DateTime<Utc>,
    expires: DateTime<Utc>,
    spent: bool,
}

/// Tool-boundary decision. A host uses this result to allow or refuse a tool action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckDecision {
    pub result: String,
    pub instance_id: String,
    pub capability_id: Option<String>,
    pub intent: String,
    pub audience: String,
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_nonce: Option<String>,
    /// Act authority of the named capability: a user identifier or autonomous.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
    /// Laboratory signed decision receipt. This is not a sixth identity record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<DecisionReceipt>,
}

/// Signed decision receipt. A third party can check allow or refuse without trusting only the local JSON log.
/// This is a laboratory Module-Lattice Digital Signature Algorithm signature. This is not a public transparency log. This is not threshold issuance. This is not a production FIPS module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionReceipt {
    pub instance_id: String,
    pub capability_id: String,
    /// Signed ancestor instance identifiers. Walk order: parent first.
    /// Empty for a root act. The receipt instance stays in instance_id.
    /// This is not a sixth identity record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ancestor_instance_ids: Vec<String>,
    /// Signed ancestor capability identifiers. Walk order: parent first.
    /// Empty for a root act. The receipt capability stays in capability_id.
    /// This is not a sixth identity record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ancestor_capability_ids: Vec<String>,
    pub intent: String,
    pub audience: String,
    pub on_behalf_of: String,
    pub result: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_nonce: Option<String>,
    pub issued: DateTime<Utc>,
    /// Exact JSON line of the check or verify event as written to issuance.log.
    /// This is a local log binding. This is not a public transparency log.
    #[serde(default)]
    pub issuance_log_line: String,
    pub signature: String,
    /// Distinct trusted member signatures over the documented receipt concatenation.
    /// Empty when threshold_n is 1 and the single signature field is used.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuer_signatures: Vec<crate::records::IssuerMemberSignature>,
}

impl DecisionReceipt {
    pub fn canonical_message(&self) -> String {
        tokens::decision_receipt_message(
            &self.instance_id,
            &self.capability_id,
            &self.intent,
            &self.audience,
            &self.on_behalf_of,
            &self.result,
            self.reason.as_deref().unwrap_or(""),
            self.challenge_nonce.as_deref().unwrap_or(""),
            self.issued,
            &self.issuance_log_line,
            &self.ancestor_instance_ids,
            &self.ancestor_capability_ids,
        )
    }
}

/// Laboratory operator view of one store. This is a derived view. This is not a sixth identity record.
/// This view must not include issuer.secret, biscuit.secret, or holder secrets.
#[derive(Debug, Clone, Serialize)]
pub struct StoreStatus {
    pub crypto_profile: String,
    pub current_issuer_public_key_hex: String,
    pub current_issuer_public_key_hexadecimal_length: usize,
    pub honest_line: String,
    pub threshold_n: u32,
    pub verify_threshold_n: u32,
    pub member_count: u32,
    pub sealed: bool,
    pub kill_date: Option<DateTime<Utc>>,
    pub agent_type_count: usize,
    pub instance_live_count: usize,
    pub instance_revoked_count: usize,
    pub capability_count: usize,
    pub chain_count: usize,
    pub issuance_log_leaf_count: u64,
    pub issuance_log_merkle_root: String,
    pub check_host_bind: String,
}

impl StoreStatus {
    pub const HONEST_LINE: &'static str = "The identity root is Module-Lattice Digital Signature Algorithm 65. The Biscuit envelope is laboratory Ed25519 and is not a threshold member.";

    fn truncated_public_key_hex(hexadecimal: &str) -> String {
        let trimmed = hexadecimal.trim();
        if trimmed.len() <= 16 {
            return trimmed.to_string();
        }
        format!("{}...{}", &trimmed[..8], &trimmed[trimmed.len() - 8..])
    }

    /// STE100 operator view. Secrets are not printed.
    pub fn format_human(&self) -> String {
        let kill_date = match self.kill_date {
            Some(time) => time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            None => "none".to_string(),
        };
        let sealed = if self.sealed { "yes" } else { "no" };
        let public_key = Self::truncated_public_key_hex(&self.current_issuer_public_key_hex);
        format!(
            "Prometheus store status\n\
This is a laboratory operator view. This is not a secrets dump. This is not a sixth identity record.\n\
\n\
crypto_profile: {crypto_profile}\n\
current_issuer_public_key: {public_key}\n\
current_issuer_public_key_hexadecimal_length: {key_length}\n\
The human view shows the first eight and last eight hexadecimal characters.\n\
\n\
{honest_line}\n\
\n\
threshold_n: {threshold_n}\n\
verify_threshold_n: {verify_threshold_n}\n\
member_count: {member_count}\n\
sealed: {sealed}\n\
kill_date: {kill_date}\n\
\n\
agent_types: {agent_types}\n\
instances: {live} live, {revoked} revoked\n\
capabilities: {capabilities}\n\
chains: {chains}\n\
\n\
issuance_log_leaf_count: {leaf_count}\n\
issuance_log_merkle_root: {merkle_root}\n\
\n\
The check host must bind to 127.0.0.1 only. Binding to all interfaces is not permitted.\n",
            crypto_profile = self.crypto_profile,
            public_key = public_key,
            key_length = self.current_issuer_public_key_hexadecimal_length,
            honest_line = self.honest_line,
            threshold_n = self.threshold_n,
            verify_threshold_n = self.verify_threshold_n,
            member_count = self.member_count,
            sealed = sealed,
            kill_date = kill_date,
            agent_types = self.agent_type_count,
            live = self.instance_live_count,
            revoked = self.instance_revoked_count,
            capabilities = self.capability_count,
            chains = self.chain_count,
            leaf_count = self.issuance_log_leaf_count,
            merkle_root = self.issuance_log_merkle_root,
        )
    }
}


/// Laboratory report after restore. This is not a record. This is not a sixth identity record.
/// This report must not include issuer.secret, biscuit.secret, holder secrets, or member-two secrets.
#[derive(Debug, Clone, Serialize)]
pub struct RestoreDiagnostics {
    pub restore_succeeded: bool,
    pub operation_normal: bool,
    pub same_issuer_public_key: bool,
    pub issuer_secret_matches_current: bool,
    pub issuance_log_chain_ok: bool,
    pub member_two_absent_from_store: bool,
    pub ledger_present: bool,
    pub instance_live_count: usize,
    pub issuance_log_leaf_count: u64,
}

impl RestoreDiagnostics {
    fn yes_no(value: bool) -> &'static str {
        if value {
            "yes"
        } else {
            "no"
        }
    }

    pub fn first_failed_check(&self) -> Option<&'static str> {
        if !self.restore_succeeded {
            return Some("restore_succeeded");
        }
        if !self.same_issuer_public_key {
            return Some("same_issuer_public_key");
        }
        if !self.issuer_secret_matches_current {
            return Some("issuer_secret_matches_current");
        }
        if !self.issuance_log_chain_ok {
            return Some("issuance_log_chain_ok");
        }
        if !self.member_two_absent_from_store {
            return Some("member_two_absent_from_store");
        }
        if !self.ledger_present {
            return Some("ledger_present");
        }
        if !self.operation_normal {
            return Some("operation_normal");
        }
        None
    }

    /// STE100 operator view. Secrets are not printed.
    pub fn format_human(&self) -> String {
        format!(
            "Prometheus restore diagnostics\n\
This is a laboratory operator view. This is not a secrets dump. This is not a sixth identity record.\n\
\n\
restore_succeeded: {restore_succeeded}\n\
operation_normal: {operation_normal}\n\
same_issuer_public_key: {same_issuer_public_key}\n\
issuer_secret_matches_current: {issuer_secret_matches_current}\n\
issuance_log_chain_ok: {issuance_log_chain_ok}\n\
member_two_absent_from_store: {member_two_absent_from_store}\n\
ledger_present: {ledger_present}\n\
instance_live_count: {instance_live_count}\n\
issuance_log_leaf_count: {issuance_log_leaf_count}\n",
            restore_succeeded = Self::yes_no(self.restore_succeeded),
            operation_normal = Self::yes_no(self.operation_normal),
            same_issuer_public_key = Self::yes_no(self.same_issuer_public_key),
            issuer_secret_matches_current = Self::yes_no(self.issuer_secret_matches_current),
            issuance_log_chain_ok = Self::yes_no(self.issuance_log_chain_ok),
            member_two_absent_from_store = Self::yes_no(self.member_two_absent_from_store),
            ledger_present = Self::yes_no(self.ledger_present),
            instance_live_count = self.instance_live_count,
            issuance_log_leaf_count = self.issuance_log_leaf_count,
        )
    }
}

const CHALLENGE_WINDOW_SECONDS: u64 = 60;

/// Short laboratory window after rotate before the old issuer key is past its kill date.
/// This is laboratory single-key rotate. This is not threshold issuance.
pub const LABORATORY_ISSUER_ROTATE_KILL_AFTER_SECONDS: u64 = 300;

const ISSUANCE_OPERATIONS: &[&str] = &["mint", "birth_write", "spawn", "attenuate"];

pub struct Kernel {
    store: Store,
    now_override: Mutex<Option<DateTime<Utc>>>,
    /// Verifier challenge nonces for this host process. Memory only.
    /// This is not a sixth identity record.
    verifier_challenges: Mutex<HashMap<String, VerifierChallengeSlot>>,
}

impl Kernel {
    pub fn open(data_directory: impl AsRef<Path>) -> Self {
        Self::open_with_member_secrets(data_directory, Vec::new())
            .expect("an empty extra member secret list cannot refuse")
    }

    pub fn open_with_member_secrets(
        data_directory: impl AsRef<Path>,
        extra_member_secret_paths: Vec<PathBuf>,
    ) -> Result<Self> {
        let store = Store::new(data_directory);
        for path in extra_member_secret_paths {
            store.register_extra_member_secret_path(path)?;
        }
        Ok(Self {
            store,
            now_override: Mutex::new(None),
            verifier_challenges: Mutex::new(HashMap::new()),
        })
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Replace the clock for laboratory tests. Production commands do not call this.
    pub fn set_now_for_test(&self, now: DateTime<Utc>) {
        *self.now_override.lock().expect("clock lock") = Some(now);
    }

    fn now(&self) -> DateTime<Utc> {
        self.now_override
            .lock()
            .expect("clock lock")
            .unwrap_or_else(Utc::now)
    }

    pub fn initialize(&self) -> Result<Issuer> {
        self.initialize_with_crypto_profile(crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE)
    }

    /// Create the issuer Module-Lattice key pair and the laboratory Biscuit envelope key.
    /// Profile lab-ed25519 as the only issuer signature algorithm is refused.
    pub fn initialize_with_crypto_profile(&self, crypto_profile: &str) -> Result<Issuer> {
        if self.store.issuer_exists() {
            return Err(Error::kernel(
                "The data directory already contains an issuer. Do not run the init command again.",
            ));
        }
        crate::issuer_crypto::require_not_classical_only_issuer_profile(crypto_profile)?;
        if crypto_profile.trim() != crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE {
            return Err(Error::denied(
                "Issuer init only accepts lab-ml-dsa-65-hybrid-biscuit-ed25519. A classical-only or unknown issuer profile is refused. The identity root must be Module-Lattice Digital Signature Algorithm. The check fails closed.",
            ));
        }
        self.store.create_directories()?;
        let issuer_pair = crate::issuer_crypto::generate_module_lattice_key_pair()?;
        let biscuit_pair = tokens::generate_keypair();
        let biscuit_public_key = tokens::public_key_hexadecimal(&biscuit_pair);
        let issuer = Issuer {
            public_keys: vec![issuer_pair.public_key_hexadecimal.clone()],
            current_public_key: issuer_pair.public_key_hexadecimal.clone(),
            previous_issuer_keys: Vec::new(),
            accepted_issuer_public_keys: vec![issuer_pair.public_key_hexadecimal.clone()],
            accepted_previous_issuer_keys: Vec::new(),
            accepted_sealed_issuer_keys: Vec::new(),
            biscuit_public_key_hex: biscuit_public_key,
            crypto_profile: crypto_profile.trim().to_string(),
            kill_date: None,
            threshold_n: 1,
            verify_threshold_n: 1,
            accepted_killed_instance_ids: Vec::new(),
            accepted_killed_capability_ids: Vec::new(),
            accepted_revoke_identifiers: Vec::new(),
            issuance_log: "issuance.log".to_string(),
        };
        crate::issuer_crypto::require_issuer_identity_root_is_module_lattice(&issuer)?;
        self.store.save_issuer(&issuer)?;
        self.store
            .save_secret(&issuer_pair.secret_key_hexadecimal)?;
        self.store
            .save_biscuit_secret(&tokens::private_key_hexadecimal(&biscuit_pair))?;
        std::fs::write(self.store.log_path(), b"")?;
        Ok(issuer)
    }

    /// Create a new laboratory Module-Lattice issuer key pair. The Biscuit envelope key stays.
    /// The old public key stays on the accept list until kill_date.
    /// issuer.secret is replaced with the new Module-Lattice key only. New mint, birth, spawn, and receipts sign with the new key.
    /// Old capabilities verify until capability expiry. This is laboratory single-key rotate.
    /// Threshold_n is unchanged. Additional member keys stay. The previous key remains
    /// trusted for verify until kill_date. This is not a Shamir split.
    /// This is not a production FIPS module. This is not a post-quantum Biscuit.
    pub fn rotate_issuer_key(&self, kill_after_seconds: u64) -> Result<Issuer> {
        let mut issuer = self.store.load_issuer()?;
        crate::issuer_crypto::require_issuer_identity_root_is_module_lattice(&issuer)?;
        if issuer.kill_date.is_some() {
            return Err(Error::denied(
                "The issuer is already sealed. Rotate writes a new issuer key. After issuer seal this rotate is refused. The check fails closed.",
            ));
        }
        let current_secret = self.store.load_secret()?;
        if current_secret.is_empty() {
            return Err(Error::kernel(
                "The issuer secret is empty. Rotation fails closed.",
            ));
        }
        let current_public_key =
            crate::issuer_crypto::public_key_hexadecimal_from_secret(&current_secret)?;
        let recorded_current = issuer.current_public_key_hex();
        if !recorded_current.is_empty() && recorded_current != current_public_key {
            return Err(Error::kernel(
                "The issuer secret does not match the current public key. Rotation fails closed.",
            ));
        }
        // Stolen member one at issuance n=2 must not replace issuer.secret.
        // Check member secrets before any write. append_log later would refuse,
        // but save_secret and save_issuer would already have swapped the current key.
        self.store
            .member_secrets_for_threshold_sign("issuer rotate")?;
        let new_pair = crate::issuer_crypto::generate_module_lattice_key_pair()?;
        let new_public_key = new_pair.public_key_hexadecimal.clone();
        if new_public_key == current_public_key {
            return Err(Error::kernel(
                "The new issuer public key equals the current public key. Rotation fails closed. Retry the rotate command.",
            ));
        }
        let kill_date = self.now() + Duration::seconds(kill_after_seconds as i64);
        issuer.previous_issuer_keys.push(PreviousIssuerKey {
            public_key_hex: current_public_key.clone(),
            kill_date,
        });
        let additional_members: Vec<String> = issuer
            .public_keys
            .iter()
            .map(|key| key.trim().to_string())
            .filter(|key| {
                !key.is_empty()
                    && key != &current_public_key
                    && key != &new_public_key
                    && !issuer.is_biscuit_envelope_key(key)
            })
            .collect();
        issuer.current_public_key = new_public_key.clone();
        issuer.public_keys = additional_members;
        issuer.public_keys.push(new_public_key.clone());
        if !issuer
            .accepted_issuer_public_keys
            .iter()
            .any(|existing| existing == &current_public_key)
        {
            issuer
                .accepted_issuer_public_keys
                .push(current_public_key.clone());
        }
        if !issuer
            .accepted_issuer_public_keys
            .iter()
            .any(|existing| existing == &new_public_key)
        {
            issuer
                .accepted_issuer_public_keys
                .push(new_public_key.clone());
        }
        // Write the new secret first so save_issuer can require current_public_key
        // matches issuer.secret. A persist that swaps current without that secret is refused.
        self.store.save_secret(&new_pair.secret_key_hexadecimal)?;
        self.store.save_issuer(&issuer)?;
        let new_secret = self.store.load_secret()?;
        if new_secret == current_secret {
            return Err(Error::kernel(
                "The issuer secret was not replaced with the new key. Rotation fails closed.",
            ));
        }
        if crate::issuer_crypto::public_key_hexadecimal_from_secret(&new_secret)? != new_public_key
        {
            return Err(Error::kernel(
                "The written issuer secret does not match the new public key. Rotation fails closed.",
            ));
        }
        self.resign_store_records()?;
        self.store.append_log(&self.issuance_event(
            "issuer_rotate",
            None,
            None,
            None,
            None,
            None,
            None,
            Some(format!(
                "Laboratory Module-Lattice rotate of the current key. The Biscuit envelope key stays. threshold_n is unchanged. previous_public_key={current_public_key} current_public_key={new_public_key} kill_date={}. New acts use the new current key plus any remaining members. The previous key remains trusted for verify until kill_date. This is not a Shamir split. This is not FROST. This is not a production FIPS module. This is not a post-quantum Biscuit.",
                kill_date.to_rfc3339()
            )),
        ))?;
        Ok(issuer)
    }

    /// Install a second Module-Lattice Digital Signature Algorithm member key pair.
    /// The member secret path is required and must live outside the data directory.
    /// A missing path is refused. A path inside the data directory is refused.
    /// Need two members before --n 2.
    /// The Biscuit envelope key is not a member. This is not a sixth identity record.
    pub fn add_issuer_member(&self) -> Result<Issuer> {
        self.add_issuer_member_with_secret_path(None)
    }

    pub fn add_issuer_member_with_secret_path(&self, secret_path: Option<&Path>) -> Result<Issuer> {
        let mut issuer = self.store.load_issuer()?;
        if issuer.kill_date.is_some() {
            return Err(Error::denied(
                "The issuer is already sealed. After issuer seal this member-two write is refused. The check fails closed.",
            ));
        }
        self.require_loaded_issuer_not_sealed(&issuer)?;
        crate::issuer_crypto::require_issuer_identity_root_is_module_lattice(&issuer)?;
        // Stolen member one at issuance n=2 must not add a member they control.
        // Check member secrets before any write. append_log later would refuse,
        // but save_member_secret and save_issuer would already have grown public_keys
        // with a new key whose secret lives in the data directory. The next mint
        // would then meet threshold_n with member one plus that new secret.
        self.store
            .member_secrets_for_threshold_sign("issuer member add")?;
        let pair = crate::issuer_crypto::generate_module_lattice_key_pair()?;
        let public_key = pair.public_key_hexadecimal.clone();
        if public_key == issuer.current_public_key_hex()
            || issuer
                .public_keys
                .iter()
                .any(|key| key.trim() == public_key)
            || issuer.is_biscuit_envelope_key(&public_key)
        {
            return Err(Error::denied(
                "The new issuer member public key is already a member or is the Biscuit envelope key. The check fails closed.",
            ));
        }
        let path = secret_path.ok_or_else(|| {
            Error::denied(
                "The issuer member secret path is required. A missing path writes issuer-member-*.secret under the data directory. Stolen store files must not include member two. The check fails closed.",
            )
        })?;
        self.store.save_member_secret_at(
            path,
            &public_key,
            &pair.secret_key_hexadecimal,
        )?;
        issuer.public_keys.push(public_key.clone());
        if !issuer
            .accepted_issuer_public_keys
            .iter()
            .any(|key| key.trim() == public_key)
        {
            issuer.accepted_issuer_public_keys.push(public_key.clone());
        }
        self.store.save_issuer(&issuer)?;
        self.store.append_log(&self.issuance_event(
            "issuer_member_add",
            None,
            None,
            None,
            None,
            None,
            None,
            Some(format!(
                "Added a Module-Lattice Digital Signature Algorithm issuer member. public_key={public_key}. The Biscuit envelope key is not a member. This is multi-signature issuance. This is not a Shamir split. This is not FROST. This is not Federal Information Processing Standard 204 threshold Module-Lattice Digital Signature Algorithm. This is not a sixth identity record."
            )),
        ))?;
        Ok(issuer)
    }

    /// Set threshold_n. Refuse K < 1. Refuse K greater than the member count.
    /// Refuse lowering. Raising is allowed.
    pub fn set_issuer_threshold(&self, threshold_n: u32) -> Result<Issuer> {
        if threshold_n < 1 {
            return Err(Error::denied(
                "The threshold_n value must be at least 1. A threshold of zero is refused. The check fails closed.",
            ));
        }
        let mut issuer = self.store.load_issuer()?;
        if issuer.kill_date.is_some() {
            return Err(Error::denied(
                "The issuer is already sealed. After issuer seal this issuer-threshold write is refused. The check fails closed.",
            ));
        }
        self.require_loaded_issuer_not_sealed(&issuer)?;
        crate::issuer_crypto::require_issuer_identity_root_is_module_lattice(&issuer)?;
        let member_count = issuer.signing_member_count();
        if threshold_n > member_count {
            return Err(Error::denied(format!(
                "The threshold_n value {threshold_n} is greater than the number of trusted Module-Lattice Digital Signature Algorithm member keys ({member_count}). Add a member first. Need two members before --n 2. Need three members before --n 3. The check fails closed."
            )));
        }
        if threshold_n < issuer.threshold_n {
            return Err(Error::denied(
                "The threshold_n value cannot be lowered. Lowering the threshold is a persist-raise class. The check fails closed.",
            ));
        }
        if threshold_n == issuer.threshold_n {
            return Ok(issuer);
        }
        // Raising n is a signed persist at the new n. Check member secrets
        // for the new n before any write. append_log later would refuse,
        // but save_issuer would already have written the new threshold_n.
        self.store
            .member_secrets_for_named_threshold("issuer threshold", threshold_n)?;
        issuer.threshold_n = threshold_n;
        self.store.save_issuer(&issuer)?;
        self.store.append_log(&self.issuance_event(
            "issuer_threshold",
            None,
            None,
            None,
            None,
            None,
            None,
            Some(format!(
                "Raised threshold_n to {threshold_n}. A mint, birth, spawn, save-sign, log-append, receipt, or tree-head now needs {threshold_n} distinct trusted Module-Lattice Digital Signature Algorithm member signatures. This is multi-signature issuance. This is not a Shamir split. This is not FROST. This is not Federal Information Processing Standard 204 threshold Module-Lattice Digital Signature Algorithm."
            )),
        ))?;
        Ok(issuer)
    }

    /// Set verify_threshold_n for foreign act, receipt, presentation, and tree-head checks.
    /// This is not issuance threshold_n. Refuse K < 1. Refuse lowering.
    pub fn set_verify_threshold(&self, verify_threshold_n: u32) -> Result<Issuer> {
        if verify_threshold_n < 1 {
            return Err(Error::denied(
                "The verify_threshold_n value must be at least 1. A verify threshold of zero is refused. The check fails closed.",
            ));
        }
        let mut issuer = self.store.load_issuer()?;
        if issuer.kill_date.is_some() {
            return Err(Error::denied(
                "The issuer is already sealed. After issuer seal this verify-threshold write is refused. The check fails closed.",
            ));
        }
        self.require_loaded_issuer_not_sealed(&issuer)?;
        crate::issuer_crypto::require_issuer_identity_root_is_module_lattice(&issuer)?;
        if verify_threshold_n < issuer.verify_threshold_n.max(1) {
            return Err(Error::denied(
                "The verify_threshold_n value cannot be lowered. Lowering the verify threshold is a persist-raise class. The check fails closed.",
            ));
        }
        if verify_threshold_n == issuer.verify_threshold_n {
            return Ok(issuer);
        }
        // Stolen member one at issuance n=2 must not raise verify_threshold_n.
        // Check member secrets before any write. append_log later would refuse,
        // but save_issuer would already have written the new verify_threshold_n.
        self.store
            .member_secrets_for_threshold_sign("issuer verify threshold")?;
        issuer.verify_threshold_n = verify_threshold_n;
        self.store.save_issuer(&issuer)?;
        self.store.append_log(&self.issuance_event(
            "issuer_verify_threshold",
            None,
            None,
            None,
            None,
            None,
            None,
            Some(format!(
                "Raised verify_threshold_n to {verify_threshold_n}. A foreign act, receipt, presentation, or tree head now needs {verify_threshold_n} distinct accepted issuer signatures. This is not issuance threshold_n. This is not a sixth identity record."
            )),
        ))?;
        Ok(issuer)
    }

    /// Pre-committed store-wide issuer death. Sets issuer.kill_date to now plus after_seconds.
    /// Refuse after_seconds of zero. Refuse a later or equal death time (cannot postpone).
    /// A later seal that only shortens the remaining life is allowed.
    /// This is realm death on the issuer record. This is not a previous-key kill_date.
    /// This is not a network partition detector. This is not a liveness probe. This is not a multi-witness clock.
    pub fn seal_issuer(&self, after_seconds: u64) -> Result<Issuer> {
        if after_seconds == 0 {
            return Err(Error::denied(
                "The after_seconds value must be greater than zero. An issuer seal cannot be empty or zero. The check fails closed.",
            ));
        }
        let mut issuer = self.store.load_issuer()?;
        let kill_date = self.now() + Duration::seconds(after_seconds as i64);
        if let Some(existing) = issuer.kill_date {
            if kill_date >= existing {
                return Err(Error::denied(
                    "The issuer is already sealed. A later seal cannot postpone death. Only a shorter remaining life is allowed. The check fails closed.",
                ));
            }
        }
        // Stolen member one at issuance n=2 must not persist issuer.kill_date.
        // Check member secrets before any write. append_log later would refuse,
        // but save_issuer would already have written kill_date (set death or shorten).
        self.store
            .member_secrets_for_threshold_sign("issuer seal")?;
        issuer.kill_date = Some(kill_date);
        self.store.save_issuer(&issuer)?;
        self.store.append_log(&self.issuance_event(
            "issuer_seal",
            None,
            None,
            None,
            None,
            None,
            None,
            Some(format!(
                "Store-wide issuer seal. issuer.kill_date={}. After this time the store refuses new mint, birth, and spawn, and refuses act. Historical receipt signature check may still succeed. This is not a previous-key kill_date. This is not a network partition detector.",
                kill_date.to_rfc3339()
            )),
        ))?;
        Ok(issuer)
    }

    /// Refuse when the store-wide issuer.kill_date has been reached.
    /// This is realm death. This is not a previous-key kill_date.
    /// Historical receipt signature check is not this check.
    pub fn require_issuer_not_sealed(&self) -> Result<()> {
        let issuer = self.store.load_issuer()?;
        self.require_loaded_issuer_not_sealed(&issuer)
    }

    fn require_loaded_issuer_not_sealed(&self, issuer: &Issuer) -> Result<()> {
        crate::issuer_crypto::require_issuer_identity_root_is_module_lattice(issuer)?;
        if issuer.is_sealed_at(self.now()) {
            return Err(Error::denied(
                "The issuer seal kill_date has been reached. This store refuses new mint, birth, and spawn, and refuses act. Historical receipt signature check may still succeed. This is a pre-committed issuer death. This is not a network partition detector.",
            ));
        }
        Ok(())
    }

    fn refused_decision_for_issuer_seal(
        &self,
        instance_id: &str,
        capability_id: Option<&str>,
        intent: &str,
        audience: &str,
        challenge_nonce: Option<&str>,
        on_behalf_of: Option<&str>,
        error: Error,
    ) -> CheckDecision {
        CheckDecision {
            result: "refused".to_string(),
            instance_id: instance_id.to_string(),
            capability_id: capability_id.map(|value| value.to_string()),
            intent: intent.to_string(),
            audience: audience.to_string(),
            reason: Some(error.to_string()),
            challenge_nonce: challenge_nonce.map(|value| value.to_string()),
            on_behalf_of: on_behalf_of.map(|value| value.to_string()),
            receipt: None,
        }
    }

    pub fn add_agent_type(
        &self,
        owner: String,
        allowed_intents: Vec<String>,
        authorization_limit: String,
        max_delegation_depth: u32,
        crypto_profile: String,
        lifetime_seconds: u64,
    ) -> Result<AgentType> {
        self.require_issuer_not_sealed()?;
        if allowed_intents.is_empty() {
            return Err(Error::kernel(
                "An agent type must include at least one allowed intent.",
            ));
        }
        if lifetime_seconds == 0 {
            return Err(Error::kernel(
                "The lifetime_seconds value must be greater than zero.",
            ));
        }
        if crypto_profile.trim().is_empty() {
            return Err(Error::kernel(
                "The crypto_profile value must not be empty. A later issuer may use a different profile, including a non-classical profile.",
            ));
        }
        self.require_safe_label(&authorization_limit, "authorization limit")?;
        for intent in &allowed_intents {
            self.require_safe_label(intent, "intent")?;
        }
        let agent_type = AgentType {
            id: new_identifier(),
            owner,
            allowed_intents,
            authorization_limit,
            max_delegation_depth,
            crypto_profile,
            lifetime_seconds,
            issuer_public_key_hex: String::new(),
            issuer_signature_hex: String::new(),
            issuer_signatures: Vec::new(),
        };
        self.store.save_agent_type(&agent_type)?;
        self.store.load_agent_type(&agent_type.id)
    }

    /// Always refuse. The authorization limit is frozen after the first write.
    /// A raise is a golden-ticket-class raise. There is no type-limit raise that succeeds.
    /// This is not a sixth identity record.
    pub fn raise_authorization_limit(
        &self,
        agent_type_id: &str,
        _authorization_limit: &str,
    ) -> Result<AgentType> {
        let _agent_type = self.store.load_agent_type(agent_type_id)?;
        Err(Error::denied(
            "The authorization limit is frozen after the first write. A later write that raises authorization_limit is refused. If the new limit is not allowed by the stored limit, it is a raise. The type must not become more powerful than at birth. This is not a sixth identity record.",
        ))
    }

    /// Always refuse. The allowed intents are frozen after the first write.
    /// Adding an intent is a golden-ticket-class raise. There is no add-intent that succeeds.
    /// This is not a sixth identity record.
    pub fn add_allowed_intent(&self, agent_type_id: &str, _intent: &str) -> Result<AgentType> {
        let _agent_type = self.store.load_agent_type(agent_type_id)?;
        Err(Error::denied(
            "The allowed intents are frozen after the first write. A later write that adds an intent is refused. Adding an intent is a golden-ticket-class raise. The type must not become more powerful than at birth. This is not a sixth identity record.",
        ))
    }

    /// Always refuse. The capability expiry is frozen after the first write.
    /// An extension is a golden-ticket-class extension. There is no expiry extend that succeeds.
    /// This is not a sixth identity record.
    pub fn extend_capability_expiry(
        &self,
        capability_id: &str,
        _expires_at: &str,
    ) -> Result<Capability> {
        let _capability = self.store.load_capability(capability_id)?;
        Err(Error::denied(
            "The capability expiry is frozen after the first write. A later write that moves expires later is refused. An extension is a golden-ticket-class extension. The capability must not outlive the mint. This is not a sixth identity record.",
        ))
    }

    pub fn birth_instance(
        &self,
        agent_type_id: &str,
        owner: String,
        attributes: BTreeMap<String, String>,
        parent_instance_id: Option<String>,
    ) -> Result<Instance> {
        self.require_issuer_not_sealed()?;
        let agent_type = self.load_trusted_agent_type(agent_type_id)?;
        self.create_live_instance(&agent_type, owner, attributes, parent_instance_id)
    }

    /// Create an instance and the first capability as one issuance.
    /// Identity starts as an authorized act. A name is not a key.
    pub fn birth_write(
        &self,
        agent_type_id: &str,
        owner: String,
        attributes: BTreeMap<String, String>,
        intent: &str,
        audience: &str,
        on_behalf_of: Option<String>,
    ) -> Result<BirthWrite> {
        self.require_issuer_not_sealed()?;
        let agent_type = self.load_trusted_agent_type(agent_type_id)?;
        self.require_mint_allowed(&agent_type, intent, audience)?;
        let instance = self.create_live_instance(&agent_type, owner, attributes, None)?;
        let (capability, _chain) = self.issue_capability_record(
            &instance,
            &agent_type,
            intent,
            audience,
            on_behalf_of,
            None,
            0,
            "issuer",
        )?;
        self.store.append_log(&self.issuance_event(
            "birth_write",
            Some(capability.id.clone()),
            None,
            Some(instance.id.clone()),
            Some(capability.revoke_identifier.clone()),
            Some(intent.to_string()),
            Some(audience.to_string()),
            Some("One issuance: instance and first capability. A name is not a key.".to_string()),
        ))?;
        Ok(BirthWrite {
            holder_secret_path: self
                .store
                .holder_secret_path(&instance.id)
                .display()
                .to_string(),
            instance,
            capability,
        })
    }

    /// A live instance births a child instance and a narrower capability as one issuance.
    /// The child cannot gain rights that the parent does not have.
    pub fn spawn_child(
        &self,
        parent_instance_id: &str,
        parent_capability_id: &str,
        owner: String,
        attributes: BTreeMap<String, String>,
        intent: &str,
        audience: &str,
        on_behalf_of: Option<String>,
        holder_proof: Option<&HolderProof>,
        challenge_nonce: Option<&str>,
    ) -> Result<SpawnWrite> {
        self.require_issuer_not_sealed()?;
        let parent_instance = self.store.load_instance(parent_instance_id)?;
        self.require_trusted_instance_issuer_signature(&parent_instance)?;
        self.require_live_instance(&parent_instance)?;
        self.require_holder_proof(&parent_instance, holder_proof, challenge_nonce)?;
        let parent_capability = self.store.load_capability(parent_capability_id)?;
        self.require_trusted_capability_issuer_signature(&parent_capability)?;
        if parent_capability.instance_id != parent_instance.id {
            return Err(Error::kernel(
                "The parent capability does not belong to the parent instance.",
            ));
        }
        self.require_capability_not_revoked(&parent_capability)?;
        self.require_present_in_issuance_log(&parent_capability.id)?;
        let agent_type = self.load_trusted_agent_type(&parent_instance.agent_type_id)?;
        self.require_mint_allowed(&agent_type, intent, audience)?;
        if !is_narrower_or_equal(audience, &parent_capability.audience) {
            return Err(Error::kernel(format!(
                "The child audience '{audience}' exceeds the parent audience '{}'. A child cannot gain rights that the parent does not have.",
                parent_capability.audience
            )));
        }
        if !is_narrower_or_equal(intent, &parent_capability.intent) {
            return Err(Error::kernel(format!(
                "The child intent '{intent}' exceeds the parent intent '{}'. A child cannot gain rights that the parent does not have.",
                parent_capability.intent
            )));
        }
        let child_on_behalf_of = on_behalf_of.unwrap_or_else(|| "autonomous".to_string());
        require_child_act_authority_compatible(
            &parent_capability.on_behalf_of,
            &child_on_behalf_of,
        )?;
        let parent_chain = self.load_trusted_chain(parent_capability_id)?;
        let hop_index = parent_chain.hop_index + 1;
        if hop_index > agent_type.max_delegation_depth {
            return Err(Error::kernel(format!(
                "The hop index {hop_index} is greater than the max_delegation_depth {} of the agent type.",
                agent_type.max_delegation_depth
            )));
        }
        let child = self.create_live_instance(
            &agent_type,
            owner,
            attributes,
            Some(parent_instance.id.clone()),
        )?;
        let (capability, _chain) = self.issue_capability_record(
            &child,
            &agent_type,
            intent,
            audience,
            Some(child_on_behalf_of),
            Some(parent_capability.id.clone()),
            hop_index,
            "parent",
        )?;
        self.store.append_log(&self.issuance_event(
            "spawn",
            Some(capability.id.clone()),
            Some(parent_capability.id.clone()),
            Some(child.id.clone()),
            Some(capability.revoke_identifier.clone()),
            Some(intent.to_string()),
            Some(audience.to_string()),
            Some(format!(
                "One issuance: child instance and narrower capability. parent_instance={}",
                parent_instance.id
            )),
        ))?;
        Ok(SpawnWrite {
            holder_secret_path: self
                .store
                .holder_secret_path(&child.id)
                .display()
                .to_string(),
            parent_instance_id: parent_instance.id,
            parent_capability_id: parent_capability.id,
            instance: child,
            capability,
        })
    }

    pub fn mint_capability(
        &self,
        instance_id: &str,
        intent: &str,
        audience: &str,
        on_behalf_of: Option<String>,
    ) -> Result<Capability> {
        self.require_issuer_not_sealed()?;
        let instance = self.store.load_instance(instance_id)?;
        self.require_trusted_instance_issuer_signature(&instance)?;
        self.require_live_instance(&instance)?;
        let agent_type = self.load_trusted_agent_type(&instance.agent_type_id)?;
        self.require_mint_allowed(&agent_type, intent, audience)?;
        let (capability, _chain) = self.issue_capability_record(
            &instance,
            &agent_type,
            intent,
            audience,
            on_behalf_of,
            None,
            0,
            "issuer",
        )?;
        self.store.append_log(&self.issuance_event(
            "mint",
            Some(capability.id.clone()),
            None,
            Some(instance.id),
            Some(capability.revoke_identifier.clone()),
            Some(intent.to_string()),
            Some(audience.to_string()),
            None,
        ))?;
        Ok(capability)
    }

    pub fn attenuate_capability(
        &self,
        capability_id: &str,
        audience: &str,
        intent: Option<&str>,
    ) -> Result<Capability> {
        self.require_issuer_not_sealed()?;
        let parent = self.store.load_capability(capability_id)?;
        self.require_trusted_capability_issuer_signature(&parent)?;
        let parent_chain = self.load_trusted_chain(capability_id)?;
        let instance = self.store.load_instance(&parent.instance_id)?;
        self.require_trusted_instance_issuer_signature(&instance)?;
        self.require_live_instance(&instance)?;
        self.require_capability_not_revoked(&parent)?;
        self.require_present_in_issuance_log(&parent.id)?;
        let agent_type = self.load_trusted_agent_type(&instance.agent_type_id)?;
        self.require_safe_label(audience, "audience")?;
        if !is_narrower_or_equal(audience, &parent.audience) {
            return Err(Error::kernel(format!(
                "Attenuation can only reduce the audience. '{audience}' is not equal to '{}' and is not a child path.",
                parent.audience
            )));
        }
        let next_intent = intent.unwrap_or(parent.intent.as_str());
        self.require_safe_label(next_intent, "intent")?;
        if !agent_type
            .allowed_intents
            .iter()
            .any(|value| value == next_intent)
        {
            return Err(Error::kernel(format!(
                "The intent '{next_intent}' is not in the allowed intents of the agent type. Attenuation cannot add an intent."
            )));
        }
        if !is_narrower_or_equal(next_intent, &parent.intent) {
            return Err(Error::kernel(format!(
                "Attenuation can only reduce the intent. '{next_intent}' is not equal to '{}' and is not a child path.",
                parent.intent
            )));
        }
        if !audience_within_authorization_limit(audience, &agent_type.authorization_limit) {
            return Err(Error::kernel(format!(
                "The audience '{audience}' is above the authorization limit '{}' of the agent type.",
                agent_type.authorization_limit
            )));
        }
        let next_hop = parent_chain.hop_index + 1;
        if next_hop > agent_type.max_delegation_depth {
            return Err(Error::kernel(format!(
                "The hop index {next_hop} is greater than the max_delegation_depth {} of the agent type.",
                agent_type.max_delegation_depth
            )));
        }
        let issued = self.now();
        if issued >= parent.expires {
            return Err(Error::kernel(
                "The parent capability has expired. Attenuation is not permitted.",
            ));
        }
        let issuer = self.store.load_issuer()?;
        let parent_bytes = hex::decode(&parent.biscuit).map_err(|error| {
            Error::kernel(format!(
                "The parent capability token is not valid hexadecimal: {error}"
            ))
        })?;
        let root_public_key = tokens::first_public_key_that_parses_token(
            &issuer.token_verify_public_key_hex_list(),
            &parent_bytes,
        )?;
        let expires_system_time: std::time::SystemTime = parent.expires.into();
        let intent_for_token = if intent.is_some() && next_intent != parent.intent {
            Some(next_intent)
        } else {
            intent
        };
        let (token_bytes, revoke_identifier) = tokens::attenuate_token(
            root_public_key,
            &parent_bytes,
            audience,
            intent_for_token,
            expires_system_time,
        )?;
        let new_identifier_value = new_identifier();
        let capability = Capability {
            id: new_identifier_value.clone(),
            instance_id: parent.instance_id.clone(),
            on_behalf_of: parent.on_behalf_of.clone(),
            intent: next_intent.to_string(),
            audience: audience.to_string(),
            caveats: parent.caveats.clone(),
            issued,
            expires: parent.expires,
            revoke_identifier: revoke_identifier.clone(),
            biscuit: hex::encode(&token_bytes),
            issuer_public_key_hex: String::new(),
            issuer_signature_hex: String::new(),
            issuer_signatures: Vec::new(),
        };
        require_child_capability_expiry_not_after_parent(capability.expires, parent.expires)?;
        let chain = Chain {
            capability_id: new_identifier_value.clone(),
            parent_capability_id: Some(parent.id.clone()),
            hop_index: next_hop,
            attenuated_by: "holder".to_string(),
            revoke_from_here: false,
            issuer_public_key_hex: String::new(),
            issuer_signature_hex: String::new(),
            issuer_signatures: Vec::new(),
        };
        self.store.save_capability(&capability)?;
        self.store.save_chain(&chain)?;
        let capability = self.store.load_capability(&capability.id)?;
        self.store.append_log(&self.issuance_event(
            "attenuate",
            Some(new_identifier_value),
            Some(parent.id),
            Some(parent.instance_id),
            Some(revoke_identifier),
            Some(next_intent.to_string()),
            Some(audience.to_string()),
            None,
        ))?;
        Ok(capability)
    }

    pub fn verify_capability(
        &self,
        capability_id: &str,
        audience: &str,
        intent: &str,
        holder_proof: Option<&HolderProof>,
        challenge_nonce: Option<&str>,
        on_behalf_of: Option<&str>,
    ) -> Result<()> {
        self.require_issuer_not_sealed()?;
        let requested_act_authority = require_named_act_authority(on_behalf_of)?;
        let capability = self.store.load_capability(capability_id)?;
        let instance = self.store.load_instance(&capability.instance_id)?;
        self.require_holder_proof(&instance, holder_proof, challenge_nonce)?;
        if requested_act_authority != capability.on_behalf_of {
            return Err(Error::denied(format!(
                "The act authority '{requested_act_authority}' does not match the capability on_behalf_of '{}'. A mismatch fails closed.",
                capability.on_behalf_of
            )));
        }
        self.evaluate_capability(
            &capability,
            &instance,
            audience,
            intent,
            requested_act_authority,
        )
    }

    /// Verify a capability and always return a signed decision receipt. Allow and refuse both issue a receipt.
    pub fn verify_capability_decision(
        &self,
        capability_id: &str,
        audience: &str,
        intent: &str,
        holder_proof: Option<&HolderProof>,
        challenge_nonce: Option<&str>,
        on_behalf_of: Option<&str>,
    ) -> Result<CheckDecision> {
        if let Err(error) = self.require_issuer_not_sealed() {
            let instance_id = self
                .store
                .load_capability(capability_id)
                .ok()
                .map(|capability| capability.instance_id)
                .unwrap_or_default();
            return Ok(self.refused_decision_for_issuer_seal(
                &instance_id,
                Some(capability_id),
                intent,
                audience,
                challenge_nonce,
                on_behalf_of,
                error,
            ));
        }
        let loaded = self.store.load_capability(capability_id).ok();
        let instance_id = loaded
            .as_ref()
            .map(|capability| capability.instance_id.clone())
            .unwrap_or_default();
        let capability_on_behalf_of = loaded
            .as_ref()
            .map(|capability| capability.on_behalf_of.clone());
        let verify_result = self.verify_capability(
            capability_id,
            audience,
            intent,
            holder_proof,
            challenge_nonce,
            on_behalf_of,
        );
        let (result, reason) = match verify_result {
            Ok(()) => ("allowed".to_string(), None),
            Err(error) => ("refused".to_string(), Some(error.to_string())),
        };
        let mut decision = CheckDecision {
            result,
            instance_id,
            capability_id: Some(capability_id.to_string()),
            intent: intent.to_string(),
            audience: audience.to_string(),
            reason,
            challenge_nonce: challenge_nonce.map(|value| value.to_string()),
            on_behalf_of: capability_on_behalf_of
                .or_else(|| on_behalf_of.map(|value| value.to_string())),
            receipt: None,
        };
        self.record_decision_receipt(&mut decision, "verify")?;
        Ok(decision)
    }

    /// Write a one-time holder challenge for an instance. The nonce is spent on the first valid proof.
    /// This appends a signed issuance.log line. After remaining life this write is refused.
    /// After instance Decommission this write is refused. A missing instance is refused.
    pub fn issue_holder_challenge(&self, instance_id: &str) -> Result<HolderChallenge> {
        self.issue_holder_challenge_with_lifetime(instance_id, CHALLENGE_WINDOW_SECONDS)
    }

    pub fn issue_holder_challenge_with_lifetime(
        &self,
        instance_id: &str,
        lifetime_seconds: u64,
    ) -> Result<HolderChallenge> {
        self.require_issuer_not_sealed()?;
        if lifetime_seconds == 0 {
            return Err(Error::kernel(
                "The challenge lifetime_seconds value must be greater than zero.",
            ));
        }
        let instance = self.store.load_instance(instance_id)?;
        if instance.status != InstanceStatus::Live {
            return Err(Error::denied(
                "The instance was revoked. A challenge is refused. The check fails closed.",
            ));
        }
        let issued = self.now();
        let expires = issued + Duration::seconds(lifetime_seconds as i64);
        let nonce = new_identifier();
        let challenge_message =
            tokens::holder_challenge_message(&nonce, &instance.id, issued, expires);
        let challenge = HolderChallenge {
            nonce: nonce.clone(),
            instance_id: instance.id.clone(),
            issued,
            expires,
            challenge_message,
        };
        self.store.append_log(&LogEvent {
            operation: "challenge".to_string(),
            timestamp: issued,
            capability_id: None,
            parent_capability_id: None,
            instance_id: Some(instance.id),
            revoke_identifier: None,
            intent: None,
            audience: None,
            note: Some(
                "One-time holder challenge. The nonce is spent on the first valid proof."
                    .to_string(),
            ),
            result: None,
            challenge_nonce: Some(nonce),
            challenge_expires: Some(expires),
            on_behalf_of: None,
            killed_instance_ids: Vec::new(),
            killed_capability_ids: Vec::new(),
            previous_line_hash: String::new(),
            line_hash: String::new(),
            issuer_public_key_hex: String::new(),
            issuer_signature_hex: String::new(),
            threshold_n: self.issuance_log_threshold_n(),
            issuer_signatures: Vec::new(),
        })?;
        Ok(challenge)
    }

    /// Issue a short-lived verifier challenge. Do not look up an instance.
    /// Do not write an instance record. Do not accept or store holder secrets.
    /// The nonce lives in this host process only. This is an artifact.
    pub fn issue_verifier_challenge(&self) -> Result<VerifierChallenge> {
        self.issue_verifier_challenge_with_lifetime(CHALLENGE_WINDOW_SECONDS)
    }

    pub fn issue_verifier_challenge_with_lifetime(
        &self,
        lifetime_seconds: u64,
    ) -> Result<VerifierChallenge> {
        if lifetime_seconds == 0 {
            return Err(Error::kernel(
                "The verifier challenge lifetime_seconds value must be greater than zero.",
            ));
        }
        let issued = self.now();
        let expires = issued + Duration::seconds(lifetime_seconds as i64);
        let nonce = new_identifier();
        let challenge_message = tokens::verifier_challenge_message(&nonce);
        let mut slots = self
            .verifier_challenges
            .lock()
            .expect("verifier challenge lock");
        slots.insert(
            nonce.clone(),
            VerifierChallengeSlot {
                issued,
                expires,
                spent: false,
            },
        );
        Ok(VerifierChallenge {
            nonce,
            issued,
            expires,
            challenge_message,
        })
    }

    /// Sign a verifier challenge message with a local holder secret path.
    /// The host process reads that path. Secret bytes are not returned.
    /// This helper does not write a record. This store must already hold
    /// the matching local live instance. A verifier store with no instance
    /// is refused and does not open the typed path. A revoked local instance
    /// is refused and does not open the typed path. After issuer seal this
    /// sign is refused. Source of truth names seal refuse for mint, birth,
    /// spawn, present, check, and agent-type add. Signing a nonce is
    /// holder-key use, not mint. Seal is silent on that sign. This store
    /// refuses after seal to stay fail-closed.
    pub fn sign_holder_nonce(
        &self,
        challenge_message: &str,
        holder_secret_path: impl AsRef<Path>,
    ) -> Result<String> {
        self.require_issuer_not_sealed()?;
        let message = challenge_message.trim();
        if message.is_empty() {
            return Err(Error::denied(
                "A verifier challenge message is required. The check fails closed.",
            ));
        }
        let requested = holder_secret_path.as_ref();
        let instances = self.store.list_instances()?;
        let matched = instances
            .iter()
            .find(|instance| self.store.holder_secret_path(&instance.id) == requested);
        let Some(instance) = matched else {
            return Err(Error::denied(
                "This store has no matching local instance. Sign the verifier nonce on the issuing store that holds the instance. The holder secret does not live on the verifier. The check fails closed.",
            ));
        };
        if instance.status == InstanceStatus::Revoked {
            return Err(Error::denied(
                "This store's own records say this instance is revoked. Signing a verifier nonce after local kill is refused. Death wins. The check fails closed.",
            ));
        }
        let secret = std::fs::read_to_string(requested).map_err(|_| {
            Error::denied("The holder secret file could not be read. A holder proof is required.")
        })?;
        if secret.trim().is_empty() {
            return Err(Error::denied(
                "The holder secret file is empty. A holder proof is required.",
            ));
        }
        tokens::sign_holder_challenge(secret.trim(), message)
    }

    /// Allow or refuse a tool action for an instance. This method fails closed.
    pub fn check_tool_action(
        &self,
        instance_id: &str,
        capability_id: Option<&str>,
        intent: &str,
        audience: &str,
        holder_proof: Option<&HolderProof>,
        challenge_nonce: Option<&str>,
        on_behalf_of: Option<&str>,
    ) -> Result<CheckDecision> {
        if let Err(error) = self.require_issuer_not_sealed() {
            return Ok(self.refused_decision_for_issuer_seal(
                instance_id,
                capability_id,
                intent,
                audience,
                challenge_nonce,
                on_behalf_of,
                error,
            ));
        }
        let mut decision = self.evaluate_check(
            instance_id,
            capability_id,
            intent,
            audience,
            holder_proof,
            challenge_nonce,
            on_behalf_of,
        );
        self.record_decision_receipt(&mut decision, "check")?;
        Ok(decision)
    }

    pub fn kill_capability(&self, capability_id: &str) -> Result<Capability> {
        let capability = self.store.load_capability(capability_id)?;
        // Stolen member one at issuance n=2 must not persist revoke. Check member
        // secrets before any write. append_log later would refuse, but save_chain
        // would already have written revoke_from_here.
        self.store
            .member_secrets_for_threshold_sign("kill capability")?;
        let chains = self.store.list_chains()?;
        let mut capability_identifiers = Vec::new();
        self.collect_capability_tree(&chains, capability_id, &mut capability_identifiers);
        let mut chain = self.store.load_chain(capability_id)?;
        chain.revoke_from_here = true;
        self.store.save_chain(&chain)?;
        let mut event = self.issuance_event(
            "kill_capability",
            Some(capability.id.clone()),
            chain.parent_capability_id.clone(),
            Some(capability.instance_id.clone()),
            Some(capability.revoke_identifier.clone()),
            Some(capability.intent.clone()),
            Some(capability.audience.clone()),
            Some("revoke_from_here=true".to_string()),
        );
        event.killed_capability_ids = capability_identifiers;
        self.store.append_log(&event)?;
        Ok(capability)
    }

    pub fn kill_instance(&self, instance_id: &str) -> Result<Instance> {
        // Stolen member one at issuance n=2 must not persist revoke. Check member
        // secrets before any write. append_log later would refuse, but save_instance
        // would already have written status=revoked.
        self.store
            .member_secrets_for_threshold_sign("kill instance")?;
        let instances = self.store.list_instances()?;
        let mut instance_identifiers = Vec::new();
        self.collect_instance_tree(&instances, instance_id, &mut instance_identifiers);
        let killed_instances: HashSet<String> = instance_identifiers.iter().cloned().collect();
        let capabilities = self.store.list_capabilities()?;
        let chains = self.store.list_chains()?;
        let mut capability_identifiers: HashSet<String> = capabilities
            .iter()
            .filter(|capability| killed_instances.contains(&capability.instance_id))
            .map(|capability| capability.id.clone())
            .collect();
        let mut changed = true;
        while changed {
            changed = false;
            for chain in &chains {
                if let Some(parent_capability_id) = &chain.parent_capability_id {
                    if capability_identifiers.contains(parent_capability_id)
                        && capability_identifiers.insert(chain.capability_id.clone())
                    {
                        changed = true;
                    }
                }
            }
        }
        for identifier in &instance_identifiers {
            let mut instance = self.store.load_instance(identifier)?;
            instance.status = InstanceStatus::Revoked;
            self.store.save_instance(&instance)?;
            let note = if identifier == instance_id {
                format!(
                    "instance status is revoked. parent kill cascade. child_count={}",
                    instance_identifiers.len().saturating_sub(1)
                )
            } else {
                "instance status is revoked. parent kill cascade.".to_string()
            };
            let mut event = self.issuance_event(
                "kill_instance",
                None,
                None,
                Some(instance.id.clone()),
                None,
                None,
                None,
                Some(note),
            );
            if identifier == instance_id {
                event.killed_instance_ids = instance_identifiers.clone();
                let mut capability_ids: Vec<String> =
                    capability_identifiers.iter().cloned().collect();
                capability_ids.sort();
                event.killed_capability_ids = capability_ids;
            }
            self.store.append_log(&event)?;
        }
        for capability_identifier in &capability_identifiers {
            let capability = self.store.load_capability(capability_identifier)?;
            let mut chain = self.store.load_chain(capability_identifier)?;
            chain.revoke_from_here = true;
            self.store.save_chain(&chain)?;
            self.store.append_log(&self.issuance_event(
                "kill_capability",
                Some(capability.id.clone()),
                chain.parent_capability_id.clone(),
                Some(capability.instance_id.clone()),
                Some(capability.revoke_identifier.clone()),
                Some(capability.intent.clone()),
                Some(capability.audience.clone()),
                Some("revoke_from_here=true. parent kill cascade.".to_string()),
            ))?;
        }
        self.store.load_instance(instance_id)
    }

    /// Load an instance record. The printed holder_public_key is the first binder.
    pub fn show_instance(&self, instance_id: &str) -> Result<Instance> {
        self.store.load_instance(instance_id)
    }

    /// Always refuse. The first binder is written once at birth.
    /// There is no holder-key rotate and no holder-key reset.
    /// This is not a remote proof-of-possession protocol. This is not SPIFFE.
    pub fn rebind_holder_public_key(
        &self,
        instance_id: &str,
        _public_key_hex: &str,
    ) -> Result<Instance> {
        let _instance = self.store.load_instance(instance_id)?;
        Err(Error::denied(
            "The first binder is written once at birth. A later write that replaces holder_public_key is refused. Identity is not the key. The holder public key is not replaceable. This is not a remote proof-of-possession protocol. This is not SPIFFE.",
        ))
    }

    pub fn show_log(&self) -> Result<String> {
        let _issuer = self.store.load_issuer()?;
        self.store.log_text()
    }

    /// Add a hexadecimal public key to the accepted issuer list and persist issuer.json.
    /// Empty is refused. This store's own public key always remains on the list.
    /// This is an accept list. This is not a global name system. This is not SPIFFE federation.
    pub fn accept_issuer_public_key(&self, public_key_hexadecimal: &str) -> Result<Issuer> {
        self.require_issuer_not_sealed()?;
        let trimmed = public_key_hexadecimal.trim();
        if trimmed.is_empty() {
            return Err(Error::denied(
                "The public key is empty. An empty issuer public key cannot be accepted. The check fails closed.",
            ));
        }
        crate::issuer_crypto::require_module_lattice_public_key(trimmed).map_err(|_| {
            Error::denied(
                "The public key is not a valid Module-Lattice Digital Signature Algorithm hexadecimal public key. Accept-list keys are identity-root public keys. The check fails closed.",
            )
        })?;
        let mut issuer = self.store.load_issuer()?;
        let mut own_keys = issuer.public_keys.clone();
        let current = issuer.current_public_key_hex();
        if !current.is_empty() {
            own_keys.push(current);
        }
        for own in &own_keys {
            let own = own.trim();
            if own.is_empty() {
                continue;
            }
            if !issuer
                .accepted_issuer_public_keys
                .iter()
                .any(|existing| existing == own)
            {
                issuer.accepted_issuer_public_keys.push(own.to_string());
            }
        }
        if !issuer
            .accepted_issuer_public_keys
            .iter()
            .any(|existing| existing == trimmed)
        {
            issuer.accepted_issuer_public_keys.push(trimmed.to_string());
        }
        self.store.save_issuer(&issuer)?;
        Ok(issuer)
    }

    /// Pin a foreign previous issuer public key with its kill date.
    /// After kill_date, a wrap or act signed only by that key is refused on this store.
    /// After persist, this store appends a signed previous_key_accept issuance.log line.
    /// The signed kill date is live. This is verifier state on the issuer record.
    /// This is not a sixth identity record. This is not a public transparency log.
    /// This store does not copy issuer.secret.
    pub fn accept_previous_issuer_key(
        &self,
        public_key_hexadecimal: &str,
        kill_date: DateTime<Utc>,
    ) -> Result<Issuer> {
        self.accept_issuer_public_key(public_key_hexadecimal)?;
        let trimmed = public_key_hexadecimal.trim();
        let mut issuer = self.store.load_issuer()?;
        if let Some(existing) = issuer
            .accepted_previous_issuer_keys
            .iter_mut()
            .find(|previous| previous.public_key_hex.trim() == trimmed)
        {
            if kill_date > existing.kill_date {
                return Err(Error::denied(
                    "An accepted previous issuer key kill_date is frozen after accept. A later write that moves that kill_date later is refused. Postponing a previous-key kill_date is a golden-ticket-class raise. A stolen old key must not sign after death. Only a shorter remaining life is allowed. This is not a sixth identity record.",
                ));
            }
            existing.kill_date = kill_date;
        } else {
            issuer
                .accepted_previous_issuer_keys
                .push(PreviousIssuerKey {
                    public_key_hex: trimmed.to_string(),
                    kill_date,
                });
        }
        // Stolen Store B without member secrets must not write accepted
        // previous-key death. Check member secrets before any write.
        // append_log later would refuse, but save_issuer would already
        // have written the accepted previous key.
        self.store
            .member_secrets_for_threshold_sign("previous key accept")?;
        self.store.save_issuer(&issuer)?;
        self.store.append_log(&self.issuance_event(
            "previous_key_accept",
            None,
            None,
            None,
            None,
            None,
            None,
            Some(format!(
                "Laboratory previous-key accept. This store pins a foreign previous issuer public key and its kill date. previous_public_key={trimmed} kill_date={}. After kill_date a wrap or act signed only by that key is refused on this store. This is verifier state. This is not a sixth identity record. This is not a public transparency log. This store does not copy issuer.secret.",
                kill_date.to_rfc3339()
            )),
        ))?;
        Ok(issuer)
    }

    /// Verify a decision receipt against the store accept list and an issuance log.
    /// If `issuance_log_path` is omitted, this store's issuance.log is used.
    /// The signing key must be in accepted_issuer_public_keys (always including this store's own key).
    /// The issuance log at the chosen path must hash-chain verify and contain the bound line.
    /// A valid signature is not enough. An unknown issuer key is refused.
    /// This is an accept list. This is not a global name system. This is not SPIFFE federation.
    pub fn verify_decision_receipt(&self, receipt: &DecisionReceipt) -> Result<()> {
        self.verify_decision_receipt_against_issuance_log(receipt, None)
    }

    /// Verify a decision receipt against the store accept list and an explicit issuance log path.
    pub fn verify_decision_receipt_against_issuance_log(
        &self,
        receipt: &DecisionReceipt,
        issuance_log_path: Option<&Path>,
    ) -> Result<()> {
        if receipt.signature.trim().is_empty() && receipt.issuer_signatures.is_empty() {
            return Err(Error::denied("The receipt is missing a signature."));
        }
        if receipt.result != "allowed" && receipt.result != "refused" {
            return Err(Error::denied(
                "The receipt result must be allowed or refused.",
            ));
        }
        if receipt.issuance_log_line.trim().is_empty() {
            return Err(Error::denied(
                "The receipt is missing an issuance-log line. A signature alone is not enough. The check fails closed.",
            ));
        }
        let issuer = self.store.load_issuer()?;
        let now = self.now();
        let accepted_issuer_public_keys = issuer.accepted_issuer_public_keys_for_verify_at(now);
        if accepted_issuer_public_keys.is_empty() {
            return Err(Error::denied(
                "The issuer accept list is empty. The receipt check fails closed.",
            ));
        }
        let message = receipt.canonical_message();
        self.require_accepted_artifact_signatures(
            &issuer,
            &receipt.issuer_signatures,
            "",
            &receipt.signature,
            &message,
            "decision receipt",
        )?;
        let signed_by_previous_key_past_kill_date =
            match tokens::matching_accepted_issuer_public_key(
                &accepted_issuer_public_keys,
                &message,
                &receipt.signature,
            ) {
                Ok(_) => false,
                Err(accept_error) => {
                    let previous_past_kill = issuer.previous_issuer_public_keys_past_kill_date(now);
                    match tokens::matching_accepted_issuer_public_key(
                        &previous_past_kill,
                        &message,
                        &receipt.signature,
                    ) {
                        Ok(_) => true,
                        Err(_) => return Err(accept_error),
                    }
                }
            };
        let log_text = match issuance_log_path {
            Some(path) => Store::log_text_from_path(path)?,
            None => {
                let path = self.store.log_path();
                if !path.exists() {
                    return Err(Error::denied(
                        "The issuance log does not exist. The receipt check fails closed.",
                    ));
                }
                self.store.log_text()?
            }
        };
        let trusted_log_keys = match issuance_log_path {
            Some(_) => issuer.accepted_issuer_public_keys_for_verify_at(now),
            None => issuer.trusted_issuer_keys_for_issuance_log(),
        };
        let log_threshold = if issuance_log_path.is_some() {
            issuer.verify_threshold_n.max(1)
        } else {
            issuer.threshold_n
        };
        crate::log_chain::verify_issuance_log_text_with_threshold(
            &log_text,
            &trusted_log_keys,
            log_threshold,
            &issuer.biscuit_public_key_hex,
        )?;
        let line_present =
            Store::issuance_log_text_contains_line(&log_text, receipt.issuance_log_line.trim());
        if signed_by_previous_key_past_kill_date && !line_present {
            return Err(Error::denied(
                "The previous issuer key is past its kill date. A new capability or receipt signed with a stolen old secret is refused, even if the signature is valid. The new capability is not in the issuance log. The check fails closed.",
            ));
        }
        if !line_present {
            return Err(Error::denied(
                "The issuance-log line is not present in the issuance log. A signature alone is not enough. The check fails closed.",
            ));
        }
        crate::log_chain::require_bound_issuance_log_line_issuer_signature_with_threshold(
            receipt.issuance_log_line.trim(),
            &trusted_log_keys,
            log_threshold,
            &issuer.biscuit_public_key_hex,
        )?;
        Ok(())
    }

    /// Bind a receipt to the exact check or verify JSON line, then append that line.
    fn record_decision_receipt(&self, decision: &mut CheckDecision, operation: &str) -> Result<()> {
        let event = LogEvent {
            operation: operation.to_string(),
            timestamp: self.now(),
            capability_id: decision.capability_id.clone(),
            parent_capability_id: None,
            instance_id: Some(decision.instance_id.clone()),
            revoke_identifier: None,
            intent: Some(decision.intent.clone()),
            audience: Some(decision.audience.clone()),
            note: decision.reason.clone(),
            result: Some(decision.result.clone()),
            challenge_nonce: decision.challenge_nonce.clone(),
            challenge_expires: None,
            on_behalf_of: decision.on_behalf_of.clone(),
            killed_instance_ids: Vec::new(),
            killed_capability_ids: Vec::new(),
            previous_line_hash: String::new(),
            line_hash: String::new(),
            issuer_public_key_hex: String::new(),
            issuer_signature_hex: String::new(),
            threshold_n: self.issuance_log_threshold_n(),
            issuer_signatures: Vec::new(),
        };
        let line = self.store.sealed_log_line(&event)?;
        let receipt = self.sign_check_decision(decision, &line)?;
        decision.receipt = Some(receipt);
        self.store.append_log_line(&line)?;
        Ok(())
    }

    fn sign_check_decision(
        &self,
        decision: &CheckDecision,
        issuance_log_line: &str,
    ) -> Result<DecisionReceipt> {
        let issued = DateTime::<Utc>::from_timestamp(self.now().timestamp(), 0)
            .unwrap_or_else(|| self.now());
        let capability_id = decision.capability_id.clone().unwrap_or_default();
        let on_behalf_of = decision.on_behalf_of.clone().unwrap_or_default();
        let (ancestor_instance_ids, ancestor_capability_ids) =
            self.ancestor_lists_for_decision_receipt(&decision.instance_id, &capability_id)?;
        let mut receipt = DecisionReceipt {
            instance_id: decision.instance_id.clone(),
            capability_id,
            ancestor_instance_ids,
            ancestor_capability_ids,
            intent: decision.intent.clone(),
            audience: decision.audience.clone(),
            on_behalf_of,
            result: decision.result.clone(),
            reason: decision.reason.clone(),
            challenge_nonce: decision.challenge_nonce.clone(),
            issued,
            issuance_log_line: issuance_log_line.to_string(),
            signature: String::new(),
            issuer_signatures: Vec::new(),
        };
        let message = receipt.canonical_message();
        let issuer = self.store.load_issuer()?;
        let members = self
            .store
            .member_secrets_for_threshold_sign("decision receipt")?;
        let signatures = crate::threshold::sign_message_with_member_secrets(&members, &message)?;
        let current = issuer.current_public_key_hex();
        receipt.signature = crate::threshold::signature_hex_for_public_key(&signatures, &current);
        receipt.issuer_signatures = if issuer.threshold_n <= 1 {
            Vec::new()
        } else {
            signatures
        };
        Ok(receipt)
    }

    /// Fill signed ancestor lists for a decision receipt. Reuse the present parent walk.
    /// The receipt instance and capability stay in the existing fields.
    /// A root act has empty lists. A missing instance or capability keeps empty lists.
    /// A damaged parent tree fails closed. This is not a sixth identity record.
    fn ancestor_lists_for_decision_receipt(
        &self,
        instance_id: &str,
        capability_id: &str,
    ) -> Result<(Vec<String>, Vec<String>)> {
        let ancestor_instance_ids = match self.store.load_instance(instance_id) {
            Ok(instance) => self.ancestor_instance_ids_from_parent_walk(&instance)?,
            Err(_) => Vec::new(),
        };
        let ancestor_capability_ids = if capability_id.trim().is_empty() {
            Vec::new()
        } else {
            // Receipt write still happens after a refused check. Walk store
            // parent_capability_id pointers. Do not require a trusted chain
            // signature here. Present still uses the trusted walk.
            self.walk_capability_ancestors(capability_id, false)?
        };
        Ok((ancestor_instance_ids, ancestor_capability_ids))
    }

    fn evaluate_check(
        &self,
        instance_id: &str,
        capability_id: Option<&str>,
        intent: &str,
        audience: &str,
        holder_proof: Option<&HolderProof>,
        challenge_nonce: Option<&str>,
        on_behalf_of: Option<&str>,
    ) -> CheckDecision {
        let refuse = |reason: String,
                      capability_id: Option<String>,
                      on_behalf_of: Option<String>| CheckDecision {
            result: "refused".to_string(),
            instance_id: instance_id.to_string(),
            capability_id,
            intent: intent.to_string(),
            audience: audience.to_string(),
            reason: Some(reason),
            challenge_nonce: challenge_nonce.map(|value| value.to_string()),
            on_behalf_of,
            receipt: None,
        };
        let Some(capability_id) = capability_id.filter(|value| !value.is_empty()) else {
            return refuse(
                "A check must name the capability identifier. The kernel does not guess which capability.".to_string(),
                None,
                None,
            );
        };
        let requested_act_authority = match require_named_act_authority(on_behalf_of) {
            Ok(value) => value,
            Err(error) => return refuse(error.to_string(), Some(capability_id.to_string()), None),
        };
        let instance = match self.store.load_instance(instance_id) {
            Ok(instance) => instance,
            Err(error) => return refuse(error.to_string(), Some(capability_id.to_string()), None),
        };
        if let Err(error) = self.require_holder_proof(&instance, holder_proof, challenge_nonce) {
            return refuse(error.to_string(), Some(capability_id.to_string()), None);
        }
        let capability = match self.store.load_capability(capability_id) {
            Ok(capability) => capability,
            Err(error) => return refuse(error.to_string(), Some(capability_id.to_string()), None),
        };
        if capability.instance_id != instance.id {
            return refuse(
                "The named capability does not belong to this instance.".to_string(),
                Some(capability.id),
                Some(capability.on_behalf_of),
            );
        }
        if requested_act_authority != capability.on_behalf_of {
            return refuse(
                format!(
                    "The act authority '{requested_act_authority}' does not match the capability on_behalf_of '{}'. A mismatch fails closed.",
                    capability.on_behalf_of
                ),
                Some(capability.id.clone()),
                Some(capability.on_behalf_of.clone()),
            );
        }
        let agent_type = match self.load_trusted_agent_type(&instance.agent_type_id) {
            Ok(agent_type) => agent_type,
            Err(error) => {
                return refuse(
                    error.to_string(),
                    Some(capability.id),
                    Some(capability.on_behalf_of),
                )
            }
        };
        if !agent_type
            .allowed_intents
            .iter()
            .any(|value| value == intent)
        {
            return refuse(
                format!("The intent '{intent}' is not in the allowed intents of the agent type."),
                Some(capability.id),
                Some(capability.on_behalf_of),
            );
        }
        if !audience_within_authorization_limit(audience, &agent_type.authorization_limit) {
            return refuse(
                format!(
                    "The audience '{audience}' is above the authorization limit '{}' of the agent type.",
                    agent_type.authorization_limit
                ),
                Some(capability.id),
                Some(capability.on_behalf_of),
            );
        }
        if instance.status != InstanceStatus::Live {
            return refuse(
                "The instance was revoked.".to_string(),
                Some(capability.id),
                Some(capability.on_behalf_of),
            );
        }
        if self.now() > instance.expires {
            return refuse(
                "The instance has expired.".to_string(),
                Some(capability.id),
                Some(capability.on_behalf_of),
            );
        }
        match self.evaluate_capability(
            &capability,
            &instance,
            audience,
            intent,
            requested_act_authority,
        ) {
            Ok(()) => CheckDecision {
                result: "allowed".to_string(),
                instance_id: instance.id,
                capability_id: Some(capability.id),
                intent: intent.to_string(),
                audience: audience.to_string(),
                reason: None,
                challenge_nonce: challenge_nonce.map(|value| value.to_string()),
                on_behalf_of: Some(capability.on_behalf_of),
                receipt: None,
            },
            Err(error) => refuse(
                error.to_string(),
                Some(capability.id),
                Some(capability.on_behalf_of),
            ),
        }
    }

    fn evaluate_capability(
        &self,
        capability: &Capability,
        instance: &Instance,
        audience: &str,
        intent: &str,
        on_behalf_of: &str,
    ) -> Result<()> {
        let issuer = self.store.load_issuer()?;
        tokens::require_trusted_instance_issuer_signature(instance, &issuer, self.now())?;
        tokens::require_trusted_capability_issuer_signature(capability, &issuer, self.now())?;
        let agent_type = self.store.load_agent_type(&instance.agent_type_id)?;
        tokens::require_trusted_agent_type_issuer_signature(&agent_type, &issuer, self.now())?;
        self.require_capability_in_issuance_log_or_refuse_stolen_old_key(capability, &issuer)?;
        let events = self.store.read_log()?;
        if events.iter().any(|event| {
            event.operation == "kill_capability"
                && event.capability_id.as_deref() == Some(capability.id.as_str())
        }) {
            return Err(Error::denied("This capability was revoked."));
        }
        if instance.status == InstanceStatus::Revoked
            || events.iter().any(|event| {
                event.operation == "kill_instance"
                    && event.instance_id.as_deref() == Some(instance.id.as_str())
            })
        {
            return Err(Error::denied("The instance was revoked."));
        }
        self.require_loaded_issuer_not_sealed(&issuer)?;
        if self.now() > instance.expires {
            return Err(Error::denied("The instance has expired."));
        }
        if self.now() > capability.expires {
            return Err(Error::denied("The capability has expired."));
        }
        if self.chain_has_revoke_from_here(&capability.id)? {
            return Err(Error::denied(
                "An ancestor chain record has revoke_from_here set to true.",
            ));
        }
        if self.chain_exceeds_depth(&capability.id)? {
            return Err(Error::denied(
                "The chain hop index is greater than the max_delegation_depth of the agent type.",
            ));
        }
        self.require_request_within_capability(capability, intent, audience)?;
        let token_bytes = hex::decode(&capability.biscuit).map_err(|error| {
            Error::denied(format!(
                "The capability token is not valid hexadecimal: {error}"
            ))
        })?;
        let root_public_key = tokens::first_public_key_that_parses_token(
            &issuer.token_verify_public_key_hex_list(),
            &token_bytes,
        )?;
        let killed_identifiers: HashSet<String> = events
            .iter()
            .filter(|event| event.operation == "kill_capability")
            .filter_map(|event| event.revoke_identifier.clone())
            .collect();
        let token_identifiers = tokens::revocation_identifier_list(root_public_key, &token_bytes)?;
        if token_identifiers
            .iter()
            .any(|identifier| killed_identifiers.contains(identifier))
        {
            return Err(Error::denied(
                "A revocation identifier on this capability token is revoked.",
            ));
        }
        tokens::require_token_facts_agree_with_record(
            root_public_key,
            &token_bytes,
            &capability.instance_id,
            &capability.intent,
            &capability.audience,
            &capability.on_behalf_of,
        )?;
        tokens::authorize_token(
            root_public_key,
            &token_bytes,
            intent,
            audience,
            on_behalf_of,
        )?;
        Ok(())
    }

    fn require_request_within_capability(
        &self,
        capability: &Capability,
        intent: &str,
        audience: &str,
    ) -> Result<()> {
        if !is_narrower_or_equal(intent, &capability.intent) {
            return Err(Error::denied(format!(
                "The requested intent '{intent}' exceeds the capability intent '{}'. A request must sit inside the capability. A string prefix that is not a child path is a raise. The check fails closed.",
                capability.intent
            )));
        }
        if !is_narrower_or_equal(audience, &capability.audience) {
            return Err(Error::denied(format!(
                "The requested audience '{audience}' exceeds the capability audience '{}'. A request must sit inside the capability. A string prefix that is not a child path is a raise. The check fails closed.",
                capability.audience
            )));
        }
        Ok(())
    }

    fn require_trusted_instance_issuer_signature(&self, instance: &Instance) -> Result<()> {
        let issuer = self.store.load_issuer()?;
        tokens::require_trusted_instance_issuer_signature(instance, &issuer, self.now())
    }

    fn require_trusted_capability_issuer_signature(&self, capability: &Capability) -> Result<()> {
        let issuer = self.store.load_issuer()?;
        tokens::require_trusted_capability_issuer_signature(capability, &issuer, self.now())
    }

    fn require_trusted_agent_type_issuer_signature(&self, agent_type: &AgentType) -> Result<()> {
        let issuer = self.store.load_issuer()?;
        tokens::require_trusted_agent_type_issuer_signature(agent_type, &issuer, self.now())
    }

    fn require_trusted_chain_issuer_signature(&self, chain: &Chain) -> Result<()> {
        let issuer = self.store.load_issuer()?;
        tokens::require_trusted_chain_issuer_signature(chain, &issuer, self.now())
    }

    /// Load an agent type and refuse a missing, wrong, or untrusted issuer signature.
    fn load_trusted_agent_type(&self, identifier: &str) -> Result<AgentType> {
        let agent_type = self.store.load_agent_type(identifier)?;
        self.require_trusted_agent_type_issuer_signature(&agent_type)?;
        Ok(agent_type)
    }

    /// Load a chain and refuse a missing, wrong, or untrusted issuer signature.
    /// Spawn, attenuate, evaluate, and present use this before hop_index or
    /// revoke_from_here can grant or refuse an act.
    fn load_trusted_chain(&self, capability_id: &str) -> Result<Chain> {
        let chain = self.store.load_chain(capability_id)?;
        self.require_trusted_chain_issuer_signature(&chain)?;
        Ok(chain)
    }

    /// Re-sign every trusted agent type, instance, capability, and chain with the current issuer secret.
    /// Rotate calls this after issuer.secret is the new key only, so old records
    /// keep a trusted signature after a previous-key kill_date.
    /// A planted file whose stored signature is missing, wrong, or untrusted is skipped.
    /// Rotate must not launder a planted record. This is not a sixth identity record.
    fn resign_store_records(&self) -> Result<()> {
        let issuer = self.store.load_issuer()?;
        let now = self.now();
        for agent_type in self.store.list_agent_types()? {
            if tokens::require_trusted_agent_type_issuer_signature(&agent_type, &issuer, now)
                .is_err()
            {
                continue;
            }
            self.store.save_agent_type(&agent_type)?;
        }
        for instance in self.store.list_instances()? {
            if tokens::require_trusted_instance_issuer_signature(&instance, &issuer, now).is_err() {
                continue;
            }
            self.store.save_instance(&instance)?;
        }
        for capability in self.store.list_capabilities()? {
            if tokens::require_trusted_capability_issuer_signature(&capability, &issuer, now)
                .is_err()
            {
                continue;
            }
            self.store.save_capability(&capability)?;
        }
        for chain in self.store.list_chains()? {
            if tokens::require_trusted_chain_issuer_signature(&chain, &issuer, now).is_err() {
                continue;
            }
            self.store.save_chain(&chain)?;
        }
        Ok(())
    }

    fn create_live_instance(
        &self,
        agent_type: &AgentType,
        owner: String,
        attributes: BTreeMap<String, String>,
        parent_instance_id: Option<String>,
    ) -> Result<Instance> {
        let born = self.now();
        let expires = born + Duration::seconds(agent_type.lifetime_seconds as i64);
        let holder_key_pair = tokens::generate_keypair();
        let holder_public_key = tokens::public_key_hexadecimal(&holder_key_pair);
        let identifier = new_identifier();
        if identifier == holder_public_key {
            return Err(Error::kernel(
                "The instance identifier equals the holder public key. A name is not a key. Retry the birth command.",
            ));
        }
        let instance = Instance {
            id: identifier,
            agent_type_id: agent_type.id.clone(),
            owner,
            born,
            expires,
            holder_public_key,
            status: InstanceStatus::Live,
            parent_instance_id,
            attributes,
            issuer_public_key_hex: String::new(),
            issuer_signature_hex: String::new(),
            issuer_signatures: Vec::new(),
        };
        self.store.save_instance(&instance)?;
        // A secret holder is out of scope. Sanctum can hold secrets later.
        self.store.save_holder_secret(
            &instance.id,
            &tokens::private_key_hexadecimal(&holder_key_pair),
        )?;
        self.store.load_instance(&instance.id)
    }

    fn issue_capability_record(
        &self,
        instance: &Instance,
        agent_type: &AgentType,
        intent: &str,
        audience: &str,
        on_behalf_of: Option<String>,
        parent_capability_id: Option<String>,
        hop_index: u32,
        attenuated_by: &str,
    ) -> Result<(Capability, Chain)> {
        let issued = self.now();
        let mut expires = issued + Duration::seconds(agent_type.lifetime_seconds as i64);
        if expires > instance.expires {
            expires = instance.expires;
        }
        let on_behalf_of = on_behalf_of.unwrap_or_else(|| "autonomous".to_string());
        self.require_safe_label(&on_behalf_of, "on_behalf_of")?;
        let capability_id = new_identifier();
        let root = tokens::keypair_from_private_hexadecimal(&self.store.load_biscuit_secret()?)?;
        let expires_system_time: std::time::SystemTime = expires.into();
        let (token_bytes, revoke_identifier) = tokens::mint_token(
            &root,
            &capability_id,
            &instance.id,
            intent,
            audience,
            &on_behalf_of,
            expires_system_time,
        )?;
        let mut caveats = BTreeMap::new();
        caveats.insert(
            "authorization_limit".to_string(),
            serde_json::Value::String(agent_type.authorization_limit.clone()),
        );
        let capability = Capability {
            id: capability_id.clone(),
            instance_id: instance.id.clone(),
            on_behalf_of,
            intent: intent.to_string(),
            audience: audience.to_string(),
            caveats,
            issued,
            expires,
            revoke_identifier,
            biscuit: hex::encode(&token_bytes),
            issuer_public_key_hex: String::new(),
            issuer_signature_hex: String::new(),
            issuer_signatures: Vec::new(),
        };
        let chain = Chain {
            capability_id: capability_id.clone(),
            parent_capability_id,
            hop_index,
            attenuated_by: attenuated_by.to_string(),
            revoke_from_here: false,
            issuer_public_key_hex: String::new(),
            issuer_signature_hex: String::new(),
            issuer_signatures: Vec::new(),
        };
        self.store.save_capability(&capability)?;
        self.store.save_chain(&chain)?;
        let capability = self.store.load_capability(&capability.id)?;
        Ok((capability, chain))
    }

    fn require_mint_allowed(
        &self,
        agent_type: &AgentType,
        intent: &str,
        audience: &str,
    ) -> Result<()> {
        if !agent_type
            .allowed_intents
            .iter()
            .any(|value| value == intent)
        {
            return Err(Error::kernel(format!(
                "The intent '{intent}' is not in the allowed intents of the agent type."
            )));
        }
        self.require_safe_label(intent, "intent")?;
        self.require_safe_label(audience, "audience")?;
        if !audience_within_authorization_limit(audience, &agent_type.authorization_limit) {
            return Err(Error::kernel(format!(
                "The audience '{audience}' is above the authorization limit '{}' of the agent type.",
                agent_type.authorization_limit
            )));
        }
        Ok(())
    }

    fn require_holder_proof(
        &self,
        instance: &Instance,
        holder_proof: Option<&HolderProof>,
        challenge_nonce: Option<&str>,
    ) -> Result<()> {
        let Some(holder_proof) = holder_proof else {
            return Err(Error::denied(
                "A holder proof is required. Pass a holder secret path or a holder signature. A capability token is not accepted as a bearer token.",
            ));
        };
        let Some(challenge_nonce) = challenge_nonce.filter(|value| !value.is_empty()) else {
            return Err(Error::denied(
                "A challenge nonce is required. The static laboratory challenge is not accepted.",
            ));
        };
        let (challenge_message, challenge_instance_id) =
            self.require_unused_challenge(challenge_nonce)?;
        if challenge_instance_id != instance.id {
            return Err(Error::denied(
                "The challenge nonce does not belong to this instance.",
            ));
        }
        match holder_proof {
            HolderProof::SecretPath(path) => {
                let secret = std::fs::read_to_string(path).map_err(|_| {
                    Error::denied(
                        "The holder secret file could not be read. A holder proof is required.",
                    )
                })?;
                let matches =
                    tokens::public_key_matches_secret(&instance.holder_public_key, secret.trim())?;
                if !matches {
                    return Err(Error::denied(
                        "The holder proof is not valid. The derived public key does not match the instance holder public key.",
                    ));
                }
                let signature = tokens::sign_holder_challenge(secret.trim(), &challenge_message)?;
                tokens::verify_holder_signature(
                    &instance.holder_public_key,
                    &challenge_message,
                    &signature,
                )?;
            }
            HolderProof::SignatureHexadecimal(signature) => {
                tokens::verify_holder_signature(
                    &instance.holder_public_key,
                    &challenge_message,
                    signature,
                )?;
            }
        }
        self.store.append_log(&LogEvent {
            operation: "challenge_spent".to_string(),
            timestamp: self.now(),
            capability_id: None,
            parent_capability_id: None,
            instance_id: Some(instance.id.clone()),
            revoke_identifier: None,
            intent: None,
            audience: None,
            note: Some("The challenge nonce was spent after a valid holder proof.".to_string()),
            result: None,
            challenge_nonce: Some(challenge_nonce.to_string()),
            challenge_expires: None,
            on_behalf_of: None,
            killed_instance_ids: Vec::new(),
            killed_capability_ids: Vec::new(),
            previous_line_hash: String::new(),
            line_hash: String::new(),
            issuer_public_key_hex: String::new(),
            issuer_signature_hex: String::new(),
            threshold_n: self.issuance_log_threshold_n(),
            issuer_signatures: Vec::new(),
        })?;
        Ok(())
    }

    fn require_unused_challenge(&self, challenge_nonce: &str) -> Result<(String, String)> {
        let events = self.store.read_log()?;
        let event = events
            .iter()
            .find(|event| {
                event.operation == "challenge"
                    && event.challenge_nonce.as_deref() == Some(challenge_nonce)
            })
            .ok_or_else(|| Error::denied("The challenge nonce is not present."))?;
        let spent = events.iter().any(|event| {
            event.operation == "challenge_spent"
                && event.challenge_nonce.as_deref() == Some(challenge_nonce)
        });
        if spent {
            return Err(Error::denied("This challenge nonce was already spent."));
        }
        let expires = event.challenge_expires.ok_or_else(|| {
            Error::denied("The challenge record is missing an expiry. The check fails closed.")
        })?;
        if self.now() > expires {
            return Err(Error::denied("This challenge is past its time window."));
        }
        if self.now() < event.timestamp {
            return Err(Error::denied(
                "The clock is before the challenge issued time. The check fails closed.",
            ));
        }
        let instance_id = event.instance_id.clone().ok_or_else(|| {
            Error::denied("The challenge record is missing an instance identifier.")
        })?;
        let message = tokens::holder_challenge_message(
            challenge_nonce,
            &instance_id,
            event.timestamp,
            expires,
        );
        Ok((message, instance_id))
    }

    /// Walk parent_instance_id on store A. Do not include the presented or receipt instance.
    /// A root present or root act has an empty ancestor list. This is not a sixth identity record.
    fn ancestor_instance_ids_from_parent_walk(&self, instance: &Instance) -> Result<Vec<String>> {
        let mut ancestors = Vec::new();
        let mut current = instance.parent_instance_id.clone();
        let mut guard = 0u32;
        while let Some(identifier) = current {
            guard += 1;
            if guard > 64 {
                return Err(Error::denied(
                    "The instance parent walk exceeded 64 hops. A damaged parent tree fails closed.",
                ));
            }
            let trimmed = identifier.trim().to_string();
            if trimmed.is_empty() {
                break;
            }
            if ancestors.iter().any(|existing| existing == &trimmed) || trimmed == instance.id {
                return Err(Error::denied(
                    "The instance parent walk repeated an identifier. A cycle fails closed.",
                ));
            }
            let parent = self.store.load_instance(&trimmed)?;
            ancestors.push(parent.id.clone());
            current = parent.parent_instance_id.clone();
        }
        Ok(ancestors)
    }

    /// Walk parent_capability_id on store A. Do not include the presented or receipt capability.
    /// A root present or root act has an empty ancestor list. This is not a sixth identity record.
    fn ancestor_capability_ids_from_parent_walk(&self, capability_id: &str) -> Result<Vec<String>> {
        self.walk_capability_ancestors(capability_id, true)
    }

    /// Shared parent-capability walk. Present requires a trusted chain.
    /// Receipt write walks store parent pointers so a refused check still
    /// signs a receipt. A missing start chain yields an empty list.
    /// A cycle or a hop limit fails closed. This is not a sixth identity record.
    fn walk_capability_ancestors(
        &self,
        capability_id: &str,
        require_trusted: bool,
    ) -> Result<Vec<String>> {
        let start = if require_trusted {
            self.load_trusted_chain(capability_id)?
        } else {
            match self.store.load_chain(capability_id) {
                Ok(chain) => chain,
                Err(_) => return Ok(Vec::new()),
            }
        };
        let mut ancestors = Vec::new();
        let mut current = start.parent_capability_id;
        let mut guard = 0u32;
        while let Some(identifier) = current {
            guard += 1;
            if guard > 64 {
                return Err(Error::denied(
                    "The capability parent walk exceeded 64 hops. A damaged parent tree fails closed.",
                ));
            }
            let trimmed = identifier.trim().to_string();
            if trimmed.is_empty() {
                break;
            }
            if ancestors.iter().any(|existing| existing == &trimmed) || trimmed == capability_id {
                return Err(Error::denied(
                    "The capability parent walk repeated an identifier. A cycle fails closed.",
                ));
            }
            let parent_chain = if require_trusted {
                self.load_trusted_chain(&trimmed)?
            } else {
                self.store.load_chain(&trimmed)?
            };
            ancestors.push(parent_chain.capability_id.clone());
            current = parent_chain.parent_capability_id;
        }
        Ok(ancestors)
    }

    fn collect_instance_tree(
        &self,
        instances: &[Instance],
        root_id: &str,
        output: &mut Vec<String>,
    ) {
        if output.iter().any(|identifier| identifier == root_id) {
            return;
        }
        output.push(root_id.to_string());
        for instance in instances {
            if instance.parent_instance_id.as_deref() == Some(root_id) {
                self.collect_instance_tree(instances, &instance.id, output);
            }
        }
    }

    /// Collect the named capability and every descendant reached through
    /// parent_capability_id. Do not add the parent of the named capability.
    fn collect_capability_tree(&self, chains: &[Chain], root_id: &str, output: &mut Vec<String>) {
        if output.iter().any(|identifier| identifier == root_id) {
            return;
        }
        output.push(root_id.to_string());
        for chain in chains {
            if chain.parent_capability_id.as_deref() == Some(root_id) {
                self.collect_capability_tree(chains, &chain.capability_id, output);
            }
        }
    }

    fn require_capability_in_issuance_log_or_refuse_stolen_old_key(
        &self,
        capability: &Capability,
        issuer: &Issuer,
    ) -> Result<()> {
        match self.require_present_in_issuance_log(&capability.id) {
            Ok(()) => Ok(()),
            Err(log_error) => {
                let Ok(token_bytes) = hex::decode(&capability.biscuit) else {
                    return Err(log_error);
                };
                let previous_past_kill =
                    issuer.previous_issuer_public_keys_past_kill_date(self.now());
                if previous_past_kill.is_empty() {
                    return Err(log_error);
                }
                if tokens::first_public_key_that_parses_token(&previous_past_kill, &token_bytes)
                    .is_ok()
                {
                    return Err(Error::denied(
                        "The previous issuer key is past its kill date. A new capability signed with a stolen old secret is refused, even if the signature is valid. The new capability is not in the issuance log. The check fails closed.",
                    ));
                }
                Err(log_error)
            }
        }
    }

    fn require_present_in_issuance_log(&self, capability_id: &str) -> Result<()> {
        let events = self.store.read_log()?;
        let present = events.iter().any(|event| {
            event.capability_id.as_deref() == Some(capability_id)
                && ISSUANCE_OPERATIONS.contains(&event.operation.as_str())
        });
        if !present {
            return Err(Error::denied(
                "The capability identifier is not present in the issuance log.",
            ));
        }
        Ok(())
    }

    fn require_live_instance(&self, instance: &Instance) -> Result<()> {
        if instance.status != InstanceStatus::Live {
            return Err(Error::kernel(
                "The instance is revoked. A new capability is not permitted.",
            ));
        }
        if self.now() > instance.expires {
            return Err(Error::kernel(
                "The instance has expired. A new capability is not permitted.",
            ));
        }
        Ok(())
    }

    fn require_capability_not_revoked(&self, capability: &Capability) -> Result<()> {
        let events = self.store.read_log()?;
        if events.iter().any(|event| {
            event.operation == "kill_capability"
                && event.capability_id.as_deref() == Some(capability.id.as_str())
        }) {
            return Err(Error::kernel(
                "The parent capability was revoked. Attenuation is not permitted.",
            ));
        }
        Ok(())
    }

    fn chain_has_revoke_from_here(&self, capability_id: &str) -> Result<bool> {
        let mut current = Some(capability_id.to_string());
        let mut guard = 0u32;
        while let Some(identifier) = current {
            guard += 1;
            if guard > 64 {
                return Err(Error::kernel(
                    "The chain walk exceeded 64 hops. The store may be damaged.",
                ));
            }
            let chain = self.load_trusted_chain(&identifier)?;
            if chain.revoke_from_here {
                return Ok(true);
            }
            current = chain.parent_capability_id;
        }
        Ok(false)
    }

    fn chain_exceeds_depth(&self, capability_id: &str) -> Result<bool> {
        let capability = self.store.load_capability(capability_id)?;
        let instance = self.store.load_instance(&capability.instance_id)?;
        let agent_type = self.load_trusted_agent_type(&instance.agent_type_id)?;
        let chain = self.load_trusted_chain(capability_id)?;
        Ok(chain.hop_index > agent_type.max_delegation_depth)
    }

    fn require_safe_label(&self, value: &str, field_name: &str) -> Result<()> {
        if value.is_empty() {
            return Err(Error::kernel(format!(
                "The {field_name} value must not be empty."
            )));
        }
        let allowed = value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '/' | '.')
        });
        if !allowed {
            return Err(Error::kernel(format!(
                "The {field_name} value may contain only letters, digits, underscore, hyphen, slash, and period."
            )));
        }
        Ok(())
    }

    fn issuance_log_threshold_n(&self) -> u32 {
        self.store
            .load_issuer()
            .map(|issuer| issuer.threshold_n.max(1))
            .unwrap_or(1)
    }

    fn issuance_event(
        &self,
        operation: &str,
        capability_id: Option<String>,
        parent_capability_id: Option<String>,
        instance_id: Option<String>,
        revoke_identifier: Option<String>,
        intent: Option<String>,
        audience: Option<String>,
        note: Option<String>,
    ) -> LogEvent {
        LogEvent {
            operation: operation.to_string(),
            timestamp: self.now(),
            capability_id,
            parent_capability_id,
            instance_id,
            revoke_identifier,
            intent,
            audience,
            note,
            result: None,
            challenge_nonce: None,
            challenge_expires: None,
            on_behalf_of: None,
            killed_instance_ids: Vec::new(),
            killed_capability_ids: Vec::new(),
            previous_line_hash: String::new(),
            line_hash: String::new(),
            issuer_public_key_hex: String::new(),
            issuer_signature_hex: String::new(),
            threshold_n: self.issuance_log_threshold_n(),
            issuer_signatures: Vec::new(),
        }
    }

    /// Walk the local SHA-256 issuance-log hash chain and each line issuer signature.
    /// A break fails closed. This is a local hash chain. This is not a public
    /// append-only service. This is still a local log. This is not Certificate Transparency.
    pub fn verify_log_chain(&self) -> Result<()> {
        let _issuer = self.store.load_issuer()?;
        self.store.verify_log_chain()
    }

    /// Local Merkle root over the sequence of issuance-log line_hash values.
    /// The hash chain must verify first. Proofs are derived from existing lines.
    /// This is not a sixth record. This is not a public transparency log.
    pub fn issuance_log_merkle_root(&self) -> Result<crate::log_proof::IssuanceLogMerkleRoot> {
        let _issuer = self.store.load_issuer()?;
        self.store.issuance_log_merkle_root()
    }

    /// Prove that one line_hash is in this issuance log. Fail closed if it is not.
    /// A second store can check the proof against a known root without copying the log.
    pub fn prove_issuance_log_inclusion(
        &self,
        line_hash: &str,
    ) -> Result<crate::log_proof::IssuanceLogInclusionProof> {
        let _issuer = self.store.load_issuer()?;
        let line_hashes = self.store.issuance_log_line_hashes()?;
        crate::log_proof::prove_inclusion(&line_hashes, line_hash)
    }

    /// Recompute the Merkle root from an inclusion proof.
    /// If `expected_root` is omitted, this store's current root is used.
    /// A supplied root lets a second store check a proof without this log.
    pub fn check_issuance_log_inclusion_proof(
        &self,
        proof: &crate::log_proof::IssuanceLogInclusionProof,
        expected_root: Option<&str>,
    ) -> Result<()> {
        let expected = match expected_root {
            Some(root) => {
                crate::log_proof::require_sha256_hexadecimal_digest(root, "root")?;
                root.trim().to_string()
            }
            None => self.issuance_log_merkle_root()?.root,
        };
        crate::log_proof::check_inclusion_proof(proof, &expected)
    }

    /// Sign the current local Merkle root with the current issuer secret only.
    /// Previous keys past kill_date cannot sign a new tree head.
    /// Remaining life does not refuse this sign. Seal-export and kill-export
    /// must still produce a document a verifier can accept after remaining life.
    /// This is a locally signed Merkle root. This is not Certificate Transparency.
    /// This is not a sixth record. The signed tree head is derived from issuer plus issuance.log.
    pub fn sign_issuance_log_tree_head(&self) -> Result<crate::log_tree_head::SignedTreeHead> {
        let issuer = self.store.load_issuer()?;
        crate::issuer_crypto::require_issuer_identity_root_is_module_lattice(&issuer)?;
        let issuer_secret = self.store.load_secret()?;
        if issuer_secret.trim().is_empty() {
            return Err(Error::denied(
                "The issuer secret is empty. A new signed tree head fails closed.",
            ));
        }
        let signing_public_key =
            crate::issuer_crypto::public_key_hexadecimal_from_secret(&issuer_secret)?;
        let current_public_key = issuer.current_public_key_hex();
        if current_public_key.is_empty() {
            return Err(Error::denied(
                "The current issuer public key is empty. A new signed tree head fails closed.",
            ));
        }
        if signing_public_key != current_public_key {
            return Err(Error::denied(
                "The issuer secret does not match the current public key. A new signed tree head must use the current issuer secret only. The check fails closed.",
            ));
        }
        if issuer.is_previous_issuer_key_past_kill_date(&signing_public_key, self.now()) {
            return Err(Error::denied(
                "A previous issuer key past its kill date cannot sign a new tree head. The check fails closed.",
            ));
        }
        let root = self.store.issuance_log_merkle_root()?;
        if root.root.trim().is_empty() {
            return Err(Error::denied(
                "The Merkle root is empty. A new signed tree head fails closed.",
            ));
        }
        let signed_at = DateTime::<Utc>::from_timestamp(self.now().timestamp(), 0)
            .unwrap_or_else(|| self.now());
        let message = crate::log_tree_head::signed_tree_head_message(
            &root.root,
            root.leaf_count,
            signed_at,
            &current_public_key,
        );
        let members = self
            .store
            .member_secrets_for_threshold_sign("signed tree head")?;
        let signatures = crate::threshold::sign_message_with_member_secrets(&members, &message)?;
        let signature_hex =
            crate::threshold::signature_hex_for_public_key(&signatures, &current_public_key);
        let issuer_signatures = if issuer.threshold_n <= 1 {
            Vec::new()
        } else {
            signatures
        };
        let tree_head = crate::log_tree_head::SignedTreeHead {
            merkle_root: root.root,
            leaf_count: root.leaf_count,
            signed_at,
            issuer_public_key_hex: current_public_key,
            signature_hex,
            issuer_signatures,
        };
        crate::log_tree_head::require_signed_tree_head_fields(&tree_head)?;
        Ok(tree_head)
    }

    /// Check a locally signed Merkle tree head.
    /// Signature must verify with the key in the file. That key must be this issuer's
    /// current key, a previous key, or a key on the accept list.
    /// A tree head signed before a previous key's kill_date remains a historical pin.
    /// A previous key used to sign after its kill_date is refused.
    /// Default: signature plus accept list so a second store can pin a foreign tree head.
    /// If require_current_root is true, also require this store's current Merkle root and leaf count.
    pub fn check_issuance_log_tree_head(
        &self,
        tree_head: &crate::log_tree_head::SignedTreeHead,
        require_current_root: bool,
    ) -> Result<()> {
        crate::log_tree_head::verify_signed_tree_head_signature(tree_head)?;
        let issuer = self.store.load_issuer()?;
        self.require_accepted_artifact_signatures(
            &issuer,
            &tree_head.issuer_signatures,
            &tree_head.issuer_public_key_hex,
            &tree_head.signature_hex,
            &tree_head.canonical_message(),
            "signed tree head",
        )?;
        let key = tree_head.issuer_public_key_hex.trim();
        let is_current = issuer.current_public_key_hex() == key;
        let previous = issuer
            .previous_issuer_keys
            .iter()
            .chain(issuer.accepted_previous_issuer_keys.iter())
            .find(|entry| entry.public_key_hex.trim() == key);
        let is_accepted = issuer
            .accepted_issuer_public_keys
            .iter()
            .any(|existing| existing.trim() == key);
        if !is_current && previous.is_none() && !is_accepted {
            return Err(Error::denied(
                "The signed tree head issuer public key is not on this store accept list. An unknown issuer key is refused. The check fails closed.",
            ));
        }
        if let Some(previous) = previous {
            if tree_head.signed_at >= previous.kill_date {
                return Err(Error::denied(
                    "A previous issuer key signed this tree head after its kill date. The check fails closed.",
                ));
            }
        }
        if require_current_root {
            let current = self.issuance_log_merkle_root()?;
            if tree_head.merkle_root.trim() != current.root {
                return Err(Error::denied(
                    "The signed tree head Merkle root is not this store's current Merkle root. The check fails closed.",
                ));
            }
            if tree_head.leaf_count != current.leaf_count {
                return Err(Error::denied(
                    "The signed tree head leaf_count does not match this store's current leaf count. The check fails closed.",
                ));
            }
        }
        Ok(())
    }

    /// Export a local act bundle: the signed decision receipt, a Merkle inclusion
    /// proof for its bound issuance-log line, and a signed tree head.
    ///
    /// This is a local export of three existing artifacts. It is not a global name
    /// system, not SPIFFE federation, not Certificate Transparency gossip.
    /// The second store must already have the first issuer public key on its accept list.
    /// This is not a sixth record.
    ///
    /// Refuse if the receipt does not verify against this store issuance.log.
    /// Refuse if the receipt result is not allowed. A failed check cannot be exported.
    /// Refuse if the bound line is not in this store log (prove already refuses).
    ///
    /// Build the three public act artifacts. This is the same export the CLI writes.
    /// This is not a second export path. This is not a sixth identity record.
    pub fn build_act_bundle(
        &self,
        receipt: &DecisionReceipt,
    ) -> Result<crate::act_bundle::ActBundle> {
        self.verify_decision_receipt(receipt)?;
        if receipt.result != "allowed" {
            return Err(Error::denied(
                "Act export requires a successful check. A refused receipt cannot be exported. The act export fails closed.",
            ));
        }
        let line_hash = crate::act_bundle::line_hash_from_bound_issuance_log_line(
            receipt.issuance_log_line.trim(),
        )?;
        let proof = self.prove_issuance_log_inclusion(&line_hash)?;
        let tree_head = self.sign_issuance_log_tree_head()?;
        if proof.root.trim() != tree_head.merkle_root.trim() {
            return Err(Error::denied(
                "The inclusion proof root does not match the signed tree head Merkle root. The act export fails closed.",
            ));
        }
        Ok(crate::act_bundle::ActBundle {
            receipt: receipt.clone(),
            proof,
            tree_head,
        })
    }

    pub fn export_act_bundle(
        &self,
        receipt: &DecisionReceipt,
        output_directory: &Path,
    ) -> Result<crate::act_bundle::ActBundle> {
        if output_directory.as_os_str().is_empty() {
            return Err(Error::denied(
                "The output directory is empty. The act export fails closed.",
            ));
        }
        let bundle = self.build_act_bundle(receipt)?;
        crate::act_bundle::write_act_bundle(output_directory, &bundle)?;
        Ok(bundle)
    }

    /// Accept a foreign act bundle. Verify-only: do not mint, do not create
    /// instance records, and do not write a second issuance.log line.
    ///
    /// The second store must already have the first issuer public key on its accept list.
    /// The second store does not become a second identity kernel.
    ///
    /// Fail-closed design:
    /// - Missing receipt.json, proof.json, or tree-head.json refuses.
    /// - check-root uses signature plus accept list. This is a foreign pin.
    ///   Do not require this store current Merkle root.
    /// - check-proof uses the tree-head merkle_root, not this store current root.
    /// - Receipt signature uses this store current accept list.
    /// - proof.line_hash must match the receipt bound line_hash.
    /// - proof.root must match tree-head.merkle_root.
    /// - A previous key past kill_date is not on the current accept list.
    ///   Those old receipts stay on the historical receipt-verify path against a copied issuance.log.
    ///   Act accept is not a second historical-audit kernel.
    pub fn accept_act_bundle(&self, bundle_directory: &Path) -> Result<()> {
        if bundle_directory.as_os_str().is_empty() {
            return Err(Error::denied(
                "The bundle directory is empty. The act accept fails closed.",
            ));
        }
        let bundle = crate::act_bundle::load_act_bundle(bundle_directory)?;
        self.accept_act_bundle_artifacts(&bundle)
    }

    /// Accept the three public act artifacts. The loopback host reuses this path.
    /// Do not invent a second accept path. Verify-only: do not mint, do not create
    /// instance records, and do not write a second issuance.log line.
    pub fn accept_act_bundle_artifacts(&self, bundle: &crate::act_bundle::ActBundle) -> Result<()> {
        if bundle.proof.root.trim() != bundle.tree_head.merkle_root.trim() {
            return Err(Error::denied(
                "The inclusion proof root does not match the signed tree head Merkle root. The act accept fails closed.",
            ));
        }
        let bound_line_hash = crate::act_bundle::line_hash_from_bound_issuance_log_line(
            bundle.receipt.issuance_log_line.trim(),
        )?;
        if bundle.proof.line_hash.trim() != bound_line_hash {
            return Err(Error::denied(
                "The inclusion proof line_hash does not match the receipt bound line. The act accept fails closed.",
            ));
        }
        self.check_issuance_log_tree_head(&bundle.tree_head, false)?;
        self.check_issuance_log_inclusion_proof(
            &bundle.proof,
            Some(bundle.tree_head.merkle_root.trim()),
        )?;
        self.verify_decision_receipt_signature_against_accept_list(&bundle.receipt)?;
        self.refuse_if_accepted_seal_for_act(&bundle.receipt)?;
        self.refuse_if_accepted_kill_for_act(&bundle.receipt)?;
        Ok(())
    }

    /// Receipt signature against this store current accept list.
    /// This does not consult this store issuance.log. Act accept uses Merkle
    /// inclusion plus a signed tree head instead of copying the foreign log.
    fn verify_decision_receipt_signature_against_accept_list(
        &self,
        receipt: &DecisionReceipt,
    ) -> Result<()> {
        if receipt.signature.trim().is_empty() && receipt.issuer_signatures.is_empty() {
            return Err(Error::denied("The receipt is missing a signature."));
        }
        if receipt.result != "allowed" && receipt.result != "refused" {
            return Err(Error::denied(
                "The receipt result must be allowed or refused.",
            ));
        }
        if receipt.issuance_log_line.trim().is_empty() {
            return Err(Error::denied(
                "The receipt is missing an issuance-log line. A signature alone is not enough. The check fails closed.",
            ));
        }
        let issuer = self.store.load_issuer()?;
        let now = self.now();
        let accepted_issuer_public_keys = issuer.accepted_issuer_public_keys_for_verify_at(now);
        if accepted_issuer_public_keys.is_empty() {
            return Err(Error::denied(
                "The issuer accept list is empty. The receipt check fails closed.",
            ));
        }
        self.require_accepted_artifact_signatures(
            &issuer,
            &receipt.issuer_signatures,
            "",
            &receipt.signature,
            &receipt.canonical_message(),
            "decision receipt",
        )?;
        if receipt.issuer_signatures.is_empty() {
            tokens::matching_accepted_issuer_public_key(
                &accepted_issuer_public_keys,
                &receipt.canonical_message(),
                &receipt.signature,
            )?;
        }
        Ok(())
    }

    /// Build the three public kill artifacts. This is the same export the CLI writes.
    /// This is not a second export path. This is not a sixth identity record.
    pub fn build_kill_bundle(
        &self,
        instance_id: Option<&str>,
        capability_id: Option<&str>,
    ) -> Result<crate::kill_bundle::KillBundle> {
        let (event, issuance_log_line) =
            self.find_kill_issuance_log_line(instance_id, capability_id)?;
        if !crate::kill_bundle::is_kill_event(event.operation.trim()) {
            return Err(Error::denied(
                "The issuance-log line is not a kill_instance or kill_capability event. The kill export fails closed.",
            ));
        }
        let line_hash =
            crate::act_bundle::line_hash_from_bound_issuance_log_line(&issuance_log_line)?;
        let proof = self.prove_issuance_log_inclusion(&line_hash)?;
        let tree_head = self.sign_issuance_log_tree_head()?;
        if proof.root.trim() != tree_head.merkle_root.trim() {
            return Err(Error::denied(
                "The inclusion proof root does not match the signed tree head Merkle root. The kill export fails closed.",
            ));
        }
        let document =
            crate::kill_bundle::kill_document_from_issuance_log_line(&issuance_log_line)?;
        Ok(crate::kill_bundle::KillBundle {
            document,
            proof,
            tree_head,
        })
    }

    /// Export a kill bundle for one kill issuance-log line.
    ///
    /// This is a local export of existing artifacts. It is not a sixth identity record.
    /// The line must be a kill_instance or kill_capability event.
    /// Refuse an empty output directory.
    pub fn export_kill_bundle(
        &self,
        instance_id: Option<&str>,
        capability_id: Option<&str>,
        output_directory: &Path,
    ) -> Result<crate::kill_bundle::KillBundle> {
        if output_directory.as_os_str().is_empty() {
            return Err(Error::denied(
                "The output directory is empty. The kill export fails closed.",
            ));
        }
        let bundle = self.build_kill_bundle(instance_id, capability_id)?;
        crate::kill_bundle::write_kill_bundle(output_directory, &bundle)?;
        Ok(bundle)
    }

    /// Accept a foreign kill bundle. Verify-only: do not mint, do not create
    /// instance records, and do not write a second issuance.log line.
    ///
    /// Persist accepted death on this store issuer record as verifier state.
    /// Growing the accepted-kill lists is allowed. Clearing an accepted kill is refused.
    /// This is not a sixth identity record. The second store does not become a second identity kernel.
    pub fn accept_kill_bundle(&self, bundle_directory: &Path) -> Result<Issuer> {
        if bundle_directory.as_os_str().is_empty() {
            return Err(Error::denied(
                "The bundle directory is empty. The kill accept fails closed.",
            ));
        }
        let bundle = crate::kill_bundle::load_kill_bundle(bundle_directory)?;
        self.accept_kill_bundle_artifacts(&bundle)
    }

    /// Accept the three public kill artifacts. The loopback host reuses this path.
    /// Do not invent a second accept path. Verify-only: do not mint, do not create
    /// instance records, and do not write a second issuance.log line.
    pub fn accept_kill_bundle_artifacts(
        &self,
        bundle: &crate::kill_bundle::KillBundle,
    ) -> Result<Issuer> {
        if !crate::kill_bundle::is_kill_event(bundle.document.event.trim()) {
            return Err(Error::denied(
                "The kill bundle event is not a kill_instance or kill_capability event. The kill accept fails closed.",
            ));
        }
        let event =
            crate::kill_bundle::require_kill_issuance_log_line(&bundle.document.issuance_log_line)?;
        crate::kill_bundle::require_kill_document_agrees_with_line(&bundle.document, &event)?;
        if bundle.proof.root.trim() != bundle.tree_head.merkle_root.trim() {
            return Err(Error::denied(
                "The inclusion proof root does not match the signed tree head Merkle root. The kill accept fails closed.",
            ));
        }
        let bound_line_hash = crate::act_bundle::line_hash_from_bound_issuance_log_line(
            bundle.document.issuance_log_line.trim(),
        )?;
        if bundle.proof.line_hash.trim() != bound_line_hash {
            return Err(Error::denied(
                "The inclusion proof line_hash does not match the kill bound line. The kill accept fails closed.",
            ));
        }
        self.check_issuance_log_tree_head(&bundle.tree_head, false)?;
        self.check_issuance_log_inclusion_proof(
            &bundle.proof,
            Some(bundle.tree_head.merkle_root.trim()),
        )?;
        let mut issuer = self.store.load_issuer()?;
        self.apply_accepted_kills_from_bound_line(&mut issuer, &event);
        self.store.save_issuer(&issuer)?;
        Ok(issuer)
    }

    fn apply_accepted_kills_from_bound_line(&self, issuer: &mut Issuer, event: &LogEvent) {
        if event.operation == crate::kill_bundle::KILL_INSTANCE_EVENT {
            if let Some(instance_id) = event.instance_id.as_deref() {
                Issuer::push_unique_public_key(
                    &mut issuer.accepted_killed_instance_ids,
                    instance_id,
                );
            }
        }
        for instance_id in &event.killed_instance_ids {
            Issuer::push_unique_public_key(&mut issuer.accepted_killed_instance_ids, instance_id);
        }
        if event.operation == crate::kill_bundle::KILL_CAPABILITY_EVENT {
            if let Some(capability_id) = event.capability_id.as_deref() {
                Issuer::push_unique_public_key(
                    &mut issuer.accepted_killed_capability_ids,
                    capability_id,
                );
            }
            if let Some(revoke_identifier) = event.revoke_identifier.as_deref() {
                Issuer::push_unique_public_key(
                    &mut issuer.accepted_revoke_identifiers,
                    revoke_identifier,
                );
            }
        }
        for capability_id in &event.killed_capability_ids {
            Issuer::push_unique_public_key(
                &mut issuer.accepted_killed_capability_ids,
                capability_id,
            );
        }
    }

    /// Build the three public seal artifacts. This is the same export the host returns.
    /// This is not a second export path. This is not a sixth identity record.
    /// Refuse a live (unsealed) issuer. A live issuer has no store-wide kill_date.
    pub fn build_seal_bundle(&self) -> Result<crate::seal_bundle::SealBundle> {
        let issuer = self.store.load_issuer()?;
        let kill_date = issuer.kill_date.ok_or_else(|| {
            Error::denied(
                "The issuer is still live. Export the seal bundle after local seal. A live issuer has no store-wide kill_date. The check fails closed.",
            )
        })?;
        let (event, issuance_log_line) = self.find_seal_issuance_log_line()?;
        if !crate::seal_bundle::is_seal_event(event.operation.trim()) {
            return Err(Error::denied(
                "The issuance-log line is not an issuer_seal event. The seal export fails closed.",
            ));
        }
        let line_hash =
            crate::act_bundle::line_hash_from_bound_issuance_log_line(&issuance_log_line)?;
        let proof = self.prove_issuance_log_inclusion(&line_hash)?;
        let tree_head = self.sign_issuance_log_tree_head()?;
        if proof.root.trim() != tree_head.merkle_root.trim() {
            return Err(Error::denied(
                "The inclusion proof root does not match the signed tree head Merkle root. The seal export fails closed.",
            ));
        }
        let document = crate::seal_bundle::seal_document_from_issuance_log_line(
            &issuance_log_line,
            kill_date,
        )?;
        Ok(crate::seal_bundle::SealBundle {
            document,
            proof,
            tree_head,
        })
    }

    /// Export a seal bundle for the local issuer_seal issuance-log line.
    /// This is a local export of existing artifacts. It is not a sixth identity record.
    pub fn export_seal_bundle(
        &self,
        output_directory: &Path,
    ) -> Result<crate::seal_bundle::SealBundle> {
        if output_directory.as_os_str().is_empty() {
            return Err(Error::denied(
                "The output directory is empty. The seal export fails closed.",
            ));
        }
        let bundle = self.build_seal_bundle()?;
        crate::seal_bundle::write_seal_bundle(output_directory, &bundle)?;
        Ok(bundle)
    }

    /// Accept a foreign seal bundle. Verify-only: do not mint, do not create
    /// instance records, and do not write a second issuance.log line.
    /// Persist accepted seal on this store issuer record as verifier state.
    /// This store does not copy issuer.secret. Clearing an accepted seal is refused.
    pub fn accept_seal_bundle(&self, bundle_directory: &Path) -> Result<Issuer> {
        if bundle_directory.as_os_str().is_empty() {
            return Err(Error::denied(
                "The bundle directory is empty. The seal accept fails closed.",
            ));
        }
        let bundle = crate::seal_bundle::load_seal_bundle(bundle_directory)?;
        self.accept_seal_bundle_artifacts(&bundle)
    }

    /// Accept the three public seal artifacts. The loopback host reuses this path.
    /// Do not invent a second accept path. Verify-only: do not mint, do not create
    /// instance records, and do not write a second issuance.log line.
    pub fn accept_seal_bundle_artifacts(
        &self,
        bundle: &crate::seal_bundle::SealBundle,
    ) -> Result<Issuer> {
        if !crate::seal_bundle::is_seal_event(bundle.document.event.trim()) {
            return Err(Error::denied(
                "The seal bundle event is not an issuer_seal event. The seal accept fails closed.",
            ));
        }
        let event =
            crate::seal_bundle::require_seal_issuance_log_line(&bundle.document.issuance_log_line)?;
        crate::seal_bundle::require_seal_document_agrees_with_line(&bundle.document, &event)?;
        if bundle.document.issuer_public_key_hex.trim()
            != bundle.tree_head.issuer_public_key_hex.trim()
        {
            return Err(Error::denied(
                "The seal document issuer public key does not match the signed tree head. The seal accept fails closed.",
            ));
        }
        if bundle.proof.root.trim() != bundle.tree_head.merkle_root.trim() {
            return Err(Error::denied(
                "The inclusion proof root does not match the signed tree head Merkle root. The seal accept fails closed.",
            ));
        }
        let bound_line_hash = crate::act_bundle::line_hash_from_bound_issuance_log_line(
            bundle.document.issuance_log_line.trim(),
        )?;
        if bundle.proof.line_hash.trim() != bound_line_hash {
            return Err(Error::denied(
                "The inclusion proof line_hash does not match the seal bound line. The seal accept fails closed.",
            ));
        }
        self.check_issuance_log_tree_head(&bundle.tree_head, false)?;
        self.check_issuance_log_inclusion_proof(
            &bundle.proof,
            Some(bundle.tree_head.merkle_root.trim()),
        )?;
        let public_key_hex = bundle.document.issuer_public_key_hex.trim();
        let kill_date = bundle.document.kill_date;
        let mut issuer = self.store.load_issuer()?;
        if let Some(existing) = issuer
            .accepted_sealed_issuer_keys
            .iter_mut()
            .find(|previous| previous.public_key_hex.trim() == public_key_hex)
        {
            if kill_date > existing.kill_date {
                return Err(Error::denied(
                    "An accepted seal kill_date is frozen after accept. A later write that moves that kill_date later is refused. Postponing an accepted seal is a golden-ticket-class raise. Only a shorter remaining life is allowed. This is not a sixth identity record.",
                ));
            }
            existing.kill_date = kill_date;
        } else {
            issuer.accepted_sealed_issuer_keys.push(PreviousIssuerKey {
                public_key_hex: public_key_hex.to_string(),
                kill_date,
            });
        }
        self.store.save_issuer(&issuer)?;
        Ok(issuer)
    }

    fn find_seal_issuance_log_line(&self) -> Result<(LogEvent, String)> {
        let text = self.store.log_text()?;
        let mut found = None;
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let event: LogEvent = match serde_json::from_str(trimmed) {
                Ok(value) => value,
                Err(_) => continue,
            };
            if !crate::seal_bundle::is_seal_event(event.operation.trim()) {
                continue;
            }
            found = Some((event, trimmed.to_string()));
        }
        found.ok_or_else(|| {
            Error::denied(
                "No issuer_seal issuance-log line was found. Export the seal bundle after local seal. The seal export fails closed.",
            )
        })
    }

    fn refuse_if_accepted_seal_for_presentation(
        &self,
        presentation: &crate::presentation::Presentation,
    ) -> Result<()> {
        let issuer = self.store.load_issuer()?;
        if issuer.has_accepted_sealed_issuer(&presentation.issuer_public_key_hex) {
            return Err(Error::denied(
                "This store accepted a seal for this issuer public key. Present verify is refused after seal accept. Seal accept is issuer death for verify. The check fails closed.",
            ));
        }
        Ok(())
    }

    fn refuse_if_accepted_seal_for_act(&self, receipt: &DecisionReceipt) -> Result<()> {
        let issuer = self.store.load_issuer()?;
        if let Ok(event) = serde_json::from_str::<LogEvent>(receipt.issuance_log_line.trim()) {
            if issuer.has_accepted_sealed_issuer(&event.issuer_public_key_hex) {
                return Err(Error::denied(
                    "This store accepted a seal for this issuer public key. Act accept is refused after seal accept. Seal accept is issuer death for verify. The check fails closed.",
                ));
            }
        }
        Ok(())
    }

    fn find_kill_issuance_log_line(
        &self,
        instance_id: Option<&str>,
        capability_id: Option<&str>,
    ) -> Result<(LogEvent, String)> {
        let instance_id = instance_id.map(str::trim).filter(|value| !value.is_empty());
        let capability_id = capability_id
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if instance_id.is_none() && capability_id.is_none() {
            return Err(Error::denied(
                "The kill export requires an instance identifier or a capability identifier. The check fails closed.",
            ));
        }
        let text = self.store.log_text()?;
        let mut found = None;
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let event: LogEvent = match serde_json::from_str(trimmed) {
                Ok(value) => value,
                Err(_) => continue,
            };
            if !crate::kill_bundle::is_kill_event(event.operation.trim()) {
                continue;
            }
            if let Some(capability_id) = capability_id {
                if event.operation != crate::kill_bundle::KILL_CAPABILITY_EVENT {
                    continue;
                }
                if event.capability_id.as_deref() != Some(capability_id) {
                    continue;
                }
                if let Some(instance_id) = instance_id {
                    if event.instance_id.as_deref() != Some(instance_id) {
                        continue;
                    }
                }
                found = Some((event, trimmed.to_string()));
                continue;
            }
            if let Some(instance_id) = instance_id {
                if event.operation != crate::kill_bundle::KILL_INSTANCE_EVENT {
                    continue;
                }
                if event.instance_id.as_deref() != Some(instance_id) {
                    continue;
                }
                found = Some((event, trimmed.to_string()));
            }
        }
        found.ok_or_else(|| {
            Error::denied(
                "No matching kill_instance or kill_capability issuance-log line was found. The kill export fails closed.",
            )
        })
    }

    fn refuse_if_accepted_kill_for_presentation(
        &self,
        presentation: &crate::presentation::Presentation,
    ) -> Result<()> {
        let issuer = self.store.load_issuer()?;
        if issuer.has_accepted_killed_instance(&presentation.instance_id) {
            return Err(Error::denied(
                "This store accepted a kill for this instance. Present verify is refused after kill accept. Death travels as a kill bundle. The check fails closed.",
            ));
        }
        for ancestor_instance_id in &presentation.ancestor_instance_ids {
            if issuer.has_accepted_killed_instance(ancestor_instance_id) {
                return Err(Error::denied(
                    "This store accepted a kill for a signed ancestor instance identifier. Present verify is refused after kill accept. The ancestor rule refuses a present whose signed ancestor-id set contains an accepted kill identifier. The check fails closed.",
                ));
            }
        }
        if issuer.has_accepted_killed_capability(&presentation.capability_id)
            || issuer.has_accepted_revoke_identifier(&presentation.capability_id)
        {
            return Err(Error::denied(
                "This store accepted a kill for this capability. Present verify is refused after kill accept. Death travels as a kill bundle. The check fails closed.",
            ));
        }
        for ancestor_capability_id in &presentation.ancestor_capability_ids {
            if issuer.has_accepted_killed_capability(ancestor_capability_id)
                || issuer.has_accepted_revoke_identifier(ancestor_capability_id)
            {
                return Err(Error::denied(
                    "This store accepted a kill for a signed ancestor capability identifier. Present verify is refused after kill accept. The ancestor rule refuses a present whose signed ancestor-id set contains an accepted kill identifier. The check fails closed.",
                ));
            }
        }
        Ok(())
    }

    /// Refuse when this store's own records say the instance is revoked or the
    /// capability or chain is killed. Local kill does not need a kill-accept
    /// bundle. Missing records mean this store is not the issuer of that
    /// instance. This is not a sixth identity record.
    fn refuse_if_local_death_for_presentation(
        &self,
        presentation: &crate::presentation::Presentation,
    ) -> Result<()> {
        if let Some(instance) = self.try_load_local_instance(&presentation.instance_id)? {
            if instance.status == InstanceStatus::Revoked {
                return Err(Error::denied(
                    "This store's own records say this instance is revoked. Present verify is refused after local kill. Death on the issuing store does not require a kill-accept bundle. The check fails closed.",
                ));
            }
        }
        for ancestor_instance_id in &presentation.ancestor_instance_ids {
            if let Some(instance) = self.try_load_local_instance(ancestor_instance_id)? {
                if instance.status == InstanceStatus::Revoked {
                    return Err(Error::denied(
                        "This store's own records say a signed ancestor instance is revoked. Present verify is refused after local kill. Death on the issuing store does not require a kill-accept bundle. The check fails closed.",
                    ));
                }
            }
        }
        let events = self.store.read_log()?;
        if Self::local_kill_log_hits_instance(&events, &presentation.instance_id) {
            return Err(Error::denied(
                "This store's issuance log records a local kill for this instance. Present verify is refused after local kill. Death on the issuing store does not require a kill-accept bundle. The check fails closed.",
            ));
        }
        for ancestor_instance_id in &presentation.ancestor_instance_ids {
            if Self::local_kill_log_hits_instance(&events, ancestor_instance_id) {
                return Err(Error::denied(
                    "This store's issuance log records a local kill for a signed ancestor instance. Present verify is refused after local kill. Death on the issuing store does not require a kill-accept bundle. The check fails closed.",
                ));
            }
        }
        if Self::local_kill_log_hits_capability(&events, &presentation.capability_id) {
            return Err(Error::denied(
                "This store's issuance log records a local kill for this capability. Present verify is refused after local kill. Death on the issuing store does not require a kill-accept bundle. The check fails closed.",
            ));
        }
        for ancestor_capability_id in &presentation.ancestor_capability_ids {
            if Self::local_kill_log_hits_capability(&events, ancestor_capability_id) {
                return Err(Error::denied(
                    "This store's issuance log records a local kill for a signed ancestor capability. Present verify is refused after local kill. Death on the issuing store does not require a kill-accept bundle. The check fails closed.",
                ));
            }
        }
        if self.local_chain_has_revoke_from_here(&presentation.capability_id)? {
            return Err(Error::denied(
                "This store's own chain record has revoke_from_here set. Present verify is refused after local kill. Death on the issuing store does not require a kill-accept bundle. The check fails closed.",
            ));
        }
        Ok(())
    }

    fn try_load_local_instance(&self, instance_id: &str) -> Result<Option<Instance>> {
        let path = self
            .store
            .root()
            .join("instances")
            .join(format!("{instance_id}.json"));
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(self.store.load_instance(instance_id)?))
    }

    fn local_chain_has_revoke_from_here(&self, capability_id: &str) -> Result<bool> {
        let path = self
            .store
            .root()
            .join("chains")
            .join(format!("{capability_id}.json"));
        if !path.exists() {
            return Ok(false);
        }
        self.chain_has_revoke_from_here(capability_id)
    }

    fn local_kill_log_hits_instance(events: &[LogEvent], instance_id: &str) -> bool {
        let trimmed = instance_id.trim();
        if trimmed.is_empty() {
            return false;
        }
        events.iter().any(|event| {
            event.operation == "kill_instance"
                && (event.instance_id.as_deref() == Some(trimmed)
                    || event
                        .killed_instance_ids
                        .iter()
                        .any(|identifier| identifier.trim() == trimmed))
        })
    }

    fn local_kill_log_hits_capability(events: &[LogEvent], capability_id: &str) -> bool {
        let trimmed = capability_id.trim();
        if trimmed.is_empty() {
            return false;
        }
        events.iter().any(|event| {
            crate::kill_bundle::is_kill_event(event.operation.trim())
                && (event.capability_id.as_deref() == Some(trimmed)
                    || event
                        .killed_capability_ids
                        .iter()
                        .any(|identifier| identifier.trim() == trimmed))
        })
    }

    fn refuse_if_accepted_kill_for_act(&self, receipt: &DecisionReceipt) -> Result<()> {
        let issuer = self.store.load_issuer()?;
        if issuer.has_accepted_killed_instance(&receipt.instance_id) {
            return Err(Error::denied(
                "This store accepted a kill for this instance. Act accept is refused after kill accept. Death stops act. The check fails closed.",
            ));
        }
        for ancestor_instance_id in &receipt.ancestor_instance_ids {
            if issuer.has_accepted_killed_instance(ancestor_instance_id) {
                return Err(Error::denied(
                    "This store accepted a kill for a signed ancestor instance identifier. Act accept is refused after kill accept. The ancestor rule refuses an act whose signed ancestor-id set contains an accepted kill identifier. The check fails closed.",
                ));
            }
        }
        if issuer.has_accepted_killed_capability(&receipt.capability_id)
            || issuer.has_accepted_revoke_identifier(&receipt.capability_id)
        {
            return Err(Error::denied(
                "This store accepted a kill for this capability. Act accept is refused after kill accept. Death stops act. The check fails closed.",
            ));
        }
        for ancestor_capability_id in &receipt.ancestor_capability_ids {
            if issuer.has_accepted_killed_capability(ancestor_capability_id)
                || issuer.has_accepted_revoke_identifier(ancestor_capability_id)
            {
                return Err(Error::denied(
                    "This store accepted a kill for a signed ancestor capability identifier. Act accept is refused after kill accept. The ancestor rule refuses an act whose signed ancestor-id set contains an accepted kill identifier. The check fails closed.",
                ));
            }
        }
        if let Ok(event) = serde_json::from_str::<LogEvent>(receipt.issuance_log_line.trim()) {
            if let Some(revoke_identifier) = event.revoke_identifier.as_deref() {
                if issuer.has_accepted_revoke_identifier(revoke_identifier) {
                    return Err(Error::denied(
                        "This store accepted a kill for this revoke identifier. Act accept is refused after kill accept. Death stops act. The check fails closed.",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Write a signed presentation document from a live instance and an unexpired capability.
    ///
    /// This is a signed presentation document, not a name. This is not a SPIFFE SVID.
    /// This is not an X.509 certificate. This is not a WIMSE token. This is not a
    /// Transaction Token. The instance identifier must not become a certificate subject.
    /// This is not a sixth record.
    ///
    /// Present requires a one-time challenge nonce and a holder proof. Present is not
    /// a bearer document. The challenge is spent on a valid proof.
    ///
    /// Present does not write a sixth identity record. Holder proof reuses the existing
    /// challenge_spent log line. The document is derived from the instance, capability,
    /// and issuer records.
    ///
    /// Present fills ancestor_instance_ids and ancestor_capability_ids by a parent walk
    /// on store A. The presented instance and capability stay in the existing fields.
    /// A root present has empty ancestor lists. Ancestor fields are signed.
    /// This is not a sixth identity record.
    ///
    /// Refuse a revoked instance, an expired capability, a capability that does not
    /// belong to the instance, a sealed issuer, and a missing or spent challenge.
    pub fn present_capability(
        &self,
        instance_id: &str,
        capability_id: &str,
        holder_proof: Option<&HolderProof>,
        challenge_nonce: Option<&str>,
    ) -> Result<crate::presentation::Presentation> {
        let issuer = self.store.load_issuer()?;
        self.require_loaded_issuer_not_sealed(&issuer)?;
        let instance = self.store.load_instance(instance_id)?;
        if instance.status != InstanceStatus::Live {
            return Err(Error::denied(
                "The instance was revoked. A presentation is refused. The check fails closed.",
            ));
        }
        if self.now() > instance.expires {
            return Err(Error::denied(
                "The instance has expired. A presentation is refused. The check fails closed.",
            ));
        }
        if instance.holder_public_key.trim().is_empty() {
            return Err(Error::denied(
                "The instance holder public key is empty. A presentation is refused. The check fails closed.",
            ));
        }
        let capability = self.store.load_capability(capability_id)?;
        tokens::require_trusted_instance_issuer_signature(&instance, &issuer, self.now())?;
        tokens::require_trusted_capability_issuer_signature(&capability, &issuer, self.now())?;
        if capability.instance_id != instance.id {
            return Err(Error::denied(
                "The named capability does not belong to this instance. A presentation is refused. The check fails closed.",
            ));
        }
        if self.now() > capability.expires {
            return Err(Error::denied(
                "The capability has expired. A presentation is refused. The check fails closed.",
            ));
        }
        let events = self.store.read_log()?;
        if events.iter().any(|event| {
            event.operation == "kill_capability"
                && event.capability_id.as_deref() == Some(capability.id.as_str())
        }) {
            return Err(Error::denied(
                "This capability was revoked. A presentation is refused. The check fails closed.",
            ));
        }
        if self.chain_has_revoke_from_here(&capability.id)? {
            return Err(Error::denied(
                "An ancestor chain record has revoke_from_here set to true. A presentation is refused. The check fails closed.",
            ));
        }
        self.require_present_in_issuance_log(&capability.id)?;
        let token_bytes = hex::decode(&capability.biscuit).map_err(|error| {
            Error::denied(format!(
                "The capability token is not valid hexadecimal: {error}"
            ))
        })?;
        let root_public_key = tokens::first_public_key_that_parses_token(
            &issuer.token_verify_public_key_hex_list(),
            &token_bytes,
        )?;
        tokens::require_token_facts_agree_with_record(
            root_public_key,
            &token_bytes,
            &capability.instance_id,
            &capability.intent,
            &capability.audience,
            &capability.on_behalf_of,
        )?;
        self.require_holder_proof(&instance, holder_proof, challenge_nonce)?;
        let issuer_secret = self.store.load_secret()?;
        if issuer_secret.trim().is_empty() {
            return Err(Error::denied(
                "The issuer secret is empty. A presentation fails closed.",
            ));
        }
        let signing_public_key =
            crate::issuer_crypto::public_key_hexadecimal_from_secret(&issuer_secret)?;
        let current_public_key = issuer.current_public_key_hex();
        if current_public_key.is_empty() {
            return Err(Error::denied(
                "The current issuer public key is empty. A presentation fails closed.",
            ));
        }
        if signing_public_key != current_public_key {
            return Err(Error::denied(
                "The issuer secret does not match the current public key. A presentation must use the current issuer secret only. The check fails closed.",
            ));
        }
        if issuer.is_previous_issuer_key_past_kill_date(&signing_public_key, self.now()) {
            return Err(Error::denied(
                "A previous issuer key past its kill date cannot sign a new presentation. The check fails closed.",
            ));
        }
        let presented_at = DateTime::<Utc>::from_timestamp(self.now().timestamp(), 0)
            .unwrap_or_else(|| self.now());
        let window_end = presented_at
            + Duration::seconds(crate::presentation::LABORATORY_PRESENTATION_WINDOW_SECONDS as i64);
        let capability_expires = DateTime::<Utc>::from_timestamp(capability.expires.timestamp(), 0)
            .unwrap_or(capability.expires);
        let expires_at = if capability_expires < window_end {
            capability_expires
        } else {
            window_end
        };
        if presented_at >= expires_at {
            return Err(Error::denied(
                "The presentation window is empty. The capability expiry is not after the presentation time. The check fails closed.",
            ));
        }
        let ancestor_instance_ids = self.ancestor_instance_ids_from_parent_walk(&instance)?;
        let ancestor_capability_ids =
            self.ancestor_capability_ids_from_parent_walk(&capability.id)?;
        let laboratory_envelope_public_key_hex = issuer.biscuit_public_key_hex.trim().to_string();
        if laboratory_envelope_public_key_hex.is_empty() {
            return Err(Error::denied(
                "The laboratory Ed25519 envelope public key is empty. A presentation fails closed.",
            ));
        }
        let unsigned = crate::presentation::Presentation {
            instance_id: instance.id.clone(),
            agent_type_id: instance.agent_type_id.clone(),
            capability_id: capability.id.clone(),
            ancestor_instance_ids,
            ancestor_capability_ids,
            on_behalf_of: capability.on_behalf_of.clone(),
            intent: capability.intent.clone(),
            audience: capability.audience.clone(),
            holder_public_key: instance.holder_public_key.clone(),
            issuer_public_key_hex: current_public_key,
            laboratory_envelope_public_key_hex,
            presented_at,
            expires_at,
            signature_hex: String::new(),
            issuer_signatures: Vec::new(),
        };
        let members = self
            .store
            .member_secrets_for_threshold_sign("presentation")?;
        let signatures = crate::threshold::sign_message_with_member_secrets(
            &members,
            &unsigned.canonical_message(),
        )?;
        let signature_hex = crate::threshold::signature_hex_for_public_key(
            &signatures,
            &unsigned.issuer_public_key_hex,
        );
        let issuer_signatures = if issuer.threshold_n <= 1 {
            Vec::new()
        } else {
            signatures
        };
        let presentation = crate::presentation::Presentation {
            signature_hex,
            issuer_signatures,
            ..unsigned
        };
        crate::presentation::require_presentation_fields(&presentation)?;
        Ok(presentation)
    }

    /// Verify a signed presentation document against this store accept list.
    /// Reconstruct the documented concatenation. Check the issuer signature.
    /// The issuer public key in the file must be on this store accept list.
    /// Refuse if now is at or after expires_at. Refuse tamper, an unknown key,
    /// and a missing signature.
    ///
    /// Verify-only. Do not mint. Do not write instance records.
    /// A sealed local issuer does not block historical presentation verify.
    /// After the signature verifies, refuse if an accepted kill identifier equals
    /// instance_id, capability_id, or a signed ancestor identifier.
    /// After that, refuse if this store's own records say the instance is revoked
    /// or the capability or chain is killed. Local kill_instance, kill_capability,
    /// revoke_from_here, and issuance-log kill lines are enough. Do not require a
    /// kill-accept bundle for this store's own death. Missing local records mean
    /// this store is not the issuer of that instance.
    /// Soft-fail is forbidden. If ancestor fields are present, they must be in the signature.
    /// This is a signed presentation document, not a name.
    /// Historical receipt verify stays as audit.
    pub fn verify_presentation(
        &self,
        presentation: &crate::presentation::Presentation,
    ) -> Result<()> {
        crate::presentation::verify_presentation_signature(presentation)?;
        let issuer = self.store.load_issuer()?;
        self.require_accepted_artifact_signatures(
            &issuer,
            &presentation.issuer_signatures,
            &presentation.issuer_public_key_hex,
            &presentation.signature_hex,
            &presentation.canonical_message(),
            "presentation",
        )?;
        self.refuse_if_accepted_seal_for_presentation(presentation)?;
        let key = presentation.issuer_public_key_hex.trim();
        if issuer.is_previous_issuer_key_past_kill_date(key, self.now()) {
            return Err(Error::denied(
                "The previous issuer key is past its kill date. A present signed only by that previous key is refused. The check fails closed.",
            ));
        }
        let accepted = issuer.accepted_issuer_public_keys_for_verify_at(self.now());
        if !accepted.iter().any(|existing| existing.trim() == key) {
            return Err(Error::denied(
                "The presentation issuer public key is not on this store accept list. An unknown issuer key is refused. The check fails closed.",
            ));
        }
        if self.now() >= presentation.expires_at {
            return Err(Error::denied(
                "The presentation has expired. The check fails closed.",
            ));
        }
        self.refuse_if_accepted_kill_for_presentation(presentation)?;
        self.refuse_if_local_death_for_presentation(presentation)?;
        Ok(())
    }

    /// Laboratory operator view of this store. Refuse if the issuer is missing.
    /// This is a derived view. This is not a sixth identity record.
    /// Secrets are not included.
    pub fn store_status(&self) -> Result<StoreStatus> {
        let issuer = self.store.load_issuer()?;
        let now = self.now();
        let agent_types = self.store.list_agent_types()?;
        let instances = self.store.list_instances()?;
        let capabilities = self.store.list_capabilities()?;
        let chains = self.store.list_chains()?;
        let merkle = self.store.issuance_log_merkle_root()?;
        let current = issuer.current_public_key_hex();
        let live = instances
            .iter()
            .filter(|instance| instance.status == InstanceStatus::Live)
            .count();
        let revoked = instances
            .iter()
            .filter(|instance| instance.status == InstanceStatus::Revoked)
            .count();
        Ok(StoreStatus {
            crypto_profile: issuer.crypto_profile.clone(),
            current_issuer_public_key_hex: current.clone(),
            current_issuer_public_key_hexadecimal_length: current.len(),
            honest_line: StoreStatus::HONEST_LINE.to_string(),
            threshold_n: issuer.threshold_n,
            member_count: issuer.signing_member_count(),
            sealed: issuer.is_sealed_at(now),
            kill_date: issuer.kill_date,
            agent_type_count: agent_types.len(),
            instance_live_count: live,
            instance_revoked_count: revoked,
            capability_count: capabilities.len(),
            chain_count: chains.len(),
            issuance_log_leaf_count: merkle.leaf_count,
            issuance_log_merkle_root: merkle.root,
            verify_threshold_n: issuer.verify_threshold_n.max(1),
            check_host_bind: "127.0.0.1 only".to_string(),
        })
    }

    /// Write a laboratory X.509-SVID wrap after a successful present.
    /// Reuse challenge and holder proof. Refuse if present would refuse.
    /// This wrap is an artifact. This is not a sixth identity record.
    pub fn present_x509_svid(
        &self,
        instance_id: &str,
        capability_id: &str,
        holder_proof: Option<&HolderProof>,
        challenge_nonce: Option<&str>,
    ) -> Result<crate::svid::X509SvidArtifact> {
        let presentation =
            self.present_capability(instance_id, capability_id, holder_proof, challenge_nonce)?;
        let pretty = serde_json::to_string_pretty(&presentation).map_err(|error| {
            Error::denied(format!(
                "The presentation JSON could not be written: {error}. The check fails closed."
            ))
        })?;
        let presentation_json = format!("{pretty}\n");
        let envelope_secret = self.store.load_biscuit_secret()?;
        let certificate_pem = crate::svid::emit_laboratory_x509_svid(
            presentation_json.as_bytes(),
            &envelope_secret,
            presentation.presented_at,
            presentation.expires_at,
        )?;
        let spiffe_uri = crate::svid::bound_spiffe_uri(presentation_json.as_bytes());
        Ok(crate::svid::X509SvidArtifact {
            presentation,
            presentation_json,
            certificate_pem,
            spiffe_uri,
        })
    }

    /// Parse the wrap, refuse a forbidden distinguished name or Uniform Resource Identifier,
    /// check NotAfter and the envelope signature, then call existing present-verify.
    /// The certificate subject public key must equal the laboratory Ed25519 envelope
    /// public key carried in the signed present. A missing bind fails closed.
    /// The issuing store also requires that signed key to equal biscuit_public_key_hex.
    /// Soft-fail is forbidden. Short life is not kill.
    pub fn verify_x509_svid(
        &self,
        certificate_pem: &str,
        presentation_json_bytes: &[u8],
    ) -> Result<()> {
        let text = std::str::from_utf8(presentation_json_bytes).map_err(|_| {
            Error::denied("The presentation document is not valid UTF-8. The check fails closed.")
        })?;
        let presentation = crate::presentation::parse_presentation_json(text)?;
        let signed_envelope = presentation.laboratory_envelope_public_key_hex.trim();
        if signed_envelope.is_empty() {
            return Err(Error::denied(
                "The signed present does not carry the laboratory Ed25519 envelope public key. X.509-SVID verify fails closed.",
            ));
        }
        let issuer = self.store.load_issuer()?;
        let this_store_issued_the_present = issuer
            .trusted_issuer_keys_for_issuance_log()
            .iter()
            .any(|key| key.trim() == presentation.issuer_public_key_hex.trim());
        if this_store_issued_the_present {
            let biscuit = issuer.biscuit_public_key_hex.trim();
            if biscuit.is_empty() {
                return Err(Error::denied(
                    "The laboratory Ed25519 envelope public key is empty. The check fails closed.",
                ));
            }
            if !signed_envelope.eq_ignore_ascii_case(biscuit) {
                return Err(Error::denied(
                    "The laboratory Ed25519 envelope public key in the signed present does not match this store envelope public key. A resigned wrap fails closed. The check fails closed.",
                ));
            }
        }
        crate::svid::require_laboratory_x509_svid(
            certificate_pem,
            presentation_json_bytes,
            &presentation,
            self.now(),
            signed_envelope,
        )?;
        self.verify_presentation(&presentation)
    }

    /// Write a laboratory Workload Identity Token after a successful present.
    /// Reuse challenge and holder proof. Refuse if present would refuse.
    /// The token subject is the present-hash Uniform Resource Identifier.
    /// Content-Digest binds the same present bytes. This wrap is an artifact.
    /// This is not a sixth identity record. This does not replace x509-svid.
    pub fn present_wimse(
        &self,
        instance_id: &str,
        capability_id: &str,
        holder_proof: Option<&HolderProof>,
        challenge_nonce: Option<&str>,
    ) -> Result<crate::wimse::WimseArtifact> {
        let presentation =
            self.present_capability(instance_id, capability_id, holder_proof, challenge_nonce)?;
        let pretty = serde_json::to_string_pretty(&presentation).map_err(|error| {
            Error::denied(format!(
                "The presentation JSON could not be written: {error}. The check fails closed."
            ))
        })?;
        let presentation_json = format!("{pretty}\n");
        let envelope_secret = self.store.load_biscuit_secret()?;
        let signed_envelope = presentation.laboratory_envelope_public_key_hex.trim();
        if signed_envelope.is_empty() {
            return Err(Error::denied(
                "The signed present does not carry the laboratory Ed25519 envelope public key. WIMSE emit fails closed.",
            ));
        }
        let (workload_identity_token, content_digest, wimse_uri) =
            crate::wimse::emit_laboratory_wit(
                presentation_json.as_bytes(),
                &envelope_secret,
                signed_envelope,
                presentation.presented_at,
                presentation.expires_at,
            )?;
        Ok(crate::wimse::WimseArtifact {
            presentation,
            presentation_json,
            workload_identity_token,
            content_digest,
            wimse_uri,
        })
    }

    /// Parse the Workload Identity Token, refuse a forbidden subject,
    /// check Content-Digest, check the envelope signature and confirmation
    /// key, then call existing present-verify. Local kill and kill accept
    /// still refuse. A swapped body fails closed. Short token life is not
    /// kill. The loopback host adds HTTP Message Signatures over @method,
    /// @request-target, and content-digest.
    pub fn verify_wimse(
        &self,
        workload_identity_token: &str,
        content_digest: &str,
        presentation_json_bytes: &[u8],
    ) -> Result<()> {
        let text = std::str::from_utf8(presentation_json_bytes).map_err(|_| {
            Error::denied("The presentation document is not valid UTF-8. The check fails closed.")
        })?;
        let presentation = crate::presentation::parse_presentation_json(text)?;
        let signed_envelope = presentation.laboratory_envelope_public_key_hex.trim();
        if signed_envelope.is_empty() {
            return Err(Error::denied(
                "The signed present does not carry the laboratory Ed25519 envelope public key. WIMSE verify fails closed.",
            ));
        }
        let issuer = self.store.load_issuer()?;
        let this_store_issued_the_present = issuer
            .trusted_issuer_keys_for_issuance_log()
            .iter()
            .any(|key| key.trim() == presentation.issuer_public_key_hex.trim());
        if this_store_issued_the_present {
            let biscuit = issuer.biscuit_public_key_hex.trim();
            if biscuit.is_empty() {
                return Err(Error::denied(
                    "The laboratory Ed25519 envelope public key is empty. The check fails closed.",
                ));
            }
            if !signed_envelope.eq_ignore_ascii_case(biscuit) {
                return Err(Error::denied(
                    "The laboratory Ed25519 envelope public key in the signed present does not match this store envelope public key. A resigned token fails closed. The check fails closed.",
                ));
            }
        }
        crate::wimse::require_laboratory_wimse(
            workload_identity_token,
            content_digest,
            presentation_json_bytes,
            &presentation,
            self.now(),
            signed_envelope,
        )?;
        self.verify_presentation(&presentation)
    }

    /// Decide a tool action after present-verify already succeeded.
    /// The issuing store still requires holder proof through check_tool_action.
    /// A verifier store has no instance record. Allow from the signed present.
    /// Holder proof is a signature over a verifier nonce against the present
    /// holder public key. The holder secret does not live on the verifier.
    /// Do not copy the inode. Do not append a check receipt line. Intent and
    /// audience must match the signed present. Death still wins: present-verify
    /// already refused an accepted kill.
    pub fn decide_tool_action_after_verified_wimse(
        &self,
        presentation: &crate::presentation::Presentation,
        intent: &str,
        audience: &str,
        holder_proof: Option<&HolderProof>,
        challenge_nonce: Option<&str>,
        on_behalf_of: Option<&str>,
    ) -> Result<CheckDecision> {
        if self
            .try_load_local_instance(&presentation.instance_id)?
            .is_none()
        {
            let refuse = |reason: String| CheckDecision {
                result: "refused".to_string(),
                instance_id: presentation.instance_id.clone(),
                capability_id: Some(presentation.capability_id.clone()),
                intent: intent.to_string(),
                audience: audience.to_string(),
                reason: Some(reason),
                challenge_nonce: challenge_nonce.map(|value| value.to_string()),
                on_behalf_of: Some(presentation.on_behalf_of.clone()),
                receipt: None,
            };
            if let Err(error) =
                self.require_holder_proof_from_present(presentation, holder_proof, challenge_nonce)
            {
                return Ok(refuse(error.to_string()));
            }
            if intent != presentation.intent || audience != presentation.audience {
                return Ok(refuse(
                    "The requested intent and audience must match the present. The check fails closed."
                        .to_string(),
                ));
            }
            if let Some(requested) = on_behalf_of {
                let requested = requested.trim();
                if !requested.is_empty() && requested != presentation.on_behalf_of {
                    return Ok(refuse(
                        "The requested act authority must match the present. The check fails closed."
                            .to_string(),
                    ));
                }
            }
            return Ok(CheckDecision {
                result: "allowed".to_string(),
                instance_id: presentation.instance_id.clone(),
                capability_id: Some(presentation.capability_id.clone()),
                intent: intent.to_string(),
                audience: audience.to_string(),
                reason: None,
                challenge_nonce: challenge_nonce.map(|value| value.to_string()),
                on_behalf_of: Some(presentation.on_behalf_of.clone()),
                receipt: None,
            });
        }
        self.check_tool_action(
            &presentation.instance_id,
            Some(presentation.capability_id.as_str()),
            intent,
            audience,
            holder_proof,
            challenge_nonce,
            on_behalf_of,
        )
    }

    /// Prove holder on a verifier from the signed present. Do not look up an
    /// inode. Do not read a holder secret file. Require a holder signature over
    /// a verifier nonce issued by this host process. Verify that signature
    /// against holder_public_key on the already-verified present.
    fn require_holder_proof_from_present(
        &self,
        presentation: &crate::presentation::Presentation,
        holder_proof: Option<&HolderProof>,
        challenge_nonce: Option<&str>,
    ) -> Result<()> {
        let Some(holder_proof) = holder_proof else {
            return Err(Error::denied(
                "A holder proof is required. Pass a holder signature over the verifier challenge nonce. A capability token is not accepted as a bearer token.",
            ));
        };
        let holder_public_key = presentation.holder_public_key.trim();
        if holder_public_key.is_empty() {
            return Err(Error::denied(
                "The signed present has an empty holder public key. The check fails closed.",
            ));
        }
        match holder_proof {
            HolderProof::SecretPath(_) => Err(Error::denied(
                "This store has no instance record. A holder secret file is not accepted on the verifier. Pass a holder signature over the verifier challenge nonce. The holder secret does not live on the verifier. The check fails closed.",
            )),
            HolderProof::SignatureHexadecimal(signature) => {
                if signature.trim().is_empty() {
                    return Err(Error::denied(
                        "A holder proof is required. Pass a holder signature over the verifier challenge nonce. A capability token is not accepted as a bearer token.",
                    ));
                }
                let Some(nonce) = challenge_nonce.map(str::trim).filter(|value| !value.is_empty())
                else {
                    return Err(Error::denied(
                        "A verifier challenge nonce is required. This store has no instance record. The check fails closed.",
                    ));
                };
                let now = self.now();
                let mut slots = self
                    .verifier_challenges
                    .lock()
                    .expect("verifier challenge lock");
                let slot = slots.get_mut(nonce).ok_or_else(|| {
                    Error::denied(
                        "The verifier challenge nonce is not present. Request a verifier challenge on this host. The check fails closed.",
                    )
                })?;
                if slot.spent {
                    return Err(Error::denied(
                        "This verifier challenge nonce was already spent. The check fails closed.",
                    ));
                }
                if now > slot.expires {
                    return Err(Error::denied(
                        "This verifier challenge is past its time window. The check fails closed.",
                    ));
                }
                if now < slot.issued {
                    return Err(Error::denied(
                        "The clock is before the verifier challenge issued time. The check fails closed.",
                    ));
                }
                let message = tokens::verifier_challenge_message(nonce);
                tokens::verify_holder_signature(holder_public_key, &message, signature).map_err(
                    |_| {
                        Error::denied(
                            "The holder proof is not valid. The holder signature does not match the present holder public key.",
                        )
                    },
                )?;
                slot.spent = true;
                Ok(())
            }
        }
    }

    fn require_accepted_artifact_signatures(
        &self,
        issuer: &Issuer,
        issuer_signatures: &[crate::records::IssuerMemberSignature],
        fallback_public_key_hex: &str,
        fallback_signature_hex: &str,
        message: &str,
        artifact_name: &str,
    ) -> Result<()> {
        let required = issuer.verify_threshold_n.max(1);
        let accepted = issuer.accepted_issuer_public_keys_for_verify_at(self.now());
        if !issuer_signatures.is_empty() {
            return crate::threshold::require_threshold_signatures(
                issuer_signatures,
                fallback_public_key_hex,
                fallback_signature_hex,
                message,
                &accepted,
                &issuer.biscuit_public_key_hex,
                required,
                artifact_name,
            );
        }
        if required > 1 {
            return Err(Error::denied(format!(
                "The {artifact_name} has an empty issuer_signatures list. This store verify_threshold_n is {required}. A second accepted issuer signature is missing. A stolen single member secret is not enough. The check fails closed."
            )));
        }
        Ok(())
    }

    /// Copy issuer.secret plus the issuance ledger to a path outside this store.
    /// Do not copy issuer-member-*.secret. This is operator disk copy, not mint.
    /// Do not append issuance.log. This is not a sixth identity record.
    /// Do not require issuer seal. A dead computer may be unsealed.
    pub fn export_issuer_backup(&self, dest: &Path) -> Result<()> {
        self.store.export_issuer_backup(dest)
    }

    /// Open the same issuer from a laboratory backup onto an empty issuing store.
    /// The old mint must already be dead. The kernel cannot see a second machine.
    /// Member two is not installed from the backup. This is not a sixth identity record.
    pub fn restore_from_backup(
        backup: impl AsRef<Path>,
        dest_root: impl AsRef<Path>,
    ) -> Result<Self> {
        let backup = backup.as_ref();
        let dest_root = dest_root.as_ref();
        Store::restore_issuer_backup(backup, dest_root)?;
        let kernel = Self::open(dest_root);
        let diagnostics = kernel.restore_diagnostics(backup)?;
        if !diagnostics.restore_succeeded || !diagnostics.operation_normal {
            let check = diagnostics
                .first_failed_check()
                .unwrap_or("operation_normal");
            return Err(Error::denied(format!(
                "The restore diagnostics did not report restore_succeeded and operation_normal. {check} failed. The check fails closed."
            )));
        }
        Ok(kernel)
    }

    /// Internal diagnostics that run after restore.
    /// They indicate whether restore succeeded and operation returned to normal.
    /// They do not invent issuer.secret. They do not start mint.
    /// They do not start a second Create Agent Principal. This is not a sixth identity record.
    pub fn restore_diagnostics(&self, backup: &Path) -> Result<RestoreDiagnostics> {
        if !backup.exists() || !backup.is_dir() {
            return Err(Error::denied(
                "The backup path must be a directory that holds issuer.secret and issuer.json. The check fails closed.",
            ));
        }
        let backup_issuer_path = backup.join("issuer.json");
        if !backup_issuer_path.exists() {
            return Err(Error::denied(
                "The backup is missing issuer.json. Restore diagnostics cannot compare the issuer public key. The check fails closed.",
            ));
        }
        let backup_issuer: Issuer = {
            let data = std::fs::read(&backup_issuer_path)?;
            serde_json::from_slice(&data)?
        };
        let dest_has_issuer = self.store.issuer_path().exists();
        let dest_has_secret = self.store.secret_path().exists();
        let dest_issuer = self.store.load_issuer().ok();
        let restore_succeeded = dest_has_issuer && dest_has_secret && dest_issuer.is_some();
        let dest_current = dest_issuer
            .as_ref()
            .map(|issuer| issuer.current_public_key_hex())
            .unwrap_or_default();
        let backup_current = backup_issuer.current_public_key_hex();
        let same_issuer_public_key = dest_issuer.is_some() && dest_current == backup_current;
        let issuer_secret_matches_current = match self.store.load_secret() {
            Ok(secret) if dest_issuer.is_some() => {
                crate::issuer_crypto::public_key_matches_secret(&dest_current, &secret)
                    .unwrap_or(false)
            }
            _ => false,
        };
        let issuance_log_chain_ok = self.verify_log_chain().is_ok();
        let member_two_absent_from_store = !Self::store_has_issuer_member_secret(self.store.root());
        let mut ledger_present = dest_has_issuer
            && self.store.log_path().exists()
            && self.store.root().join("agent_types").is_dir()
            && self.store.root().join("instances").is_dir()
            && self.store.root().join("capabilities").is_dir()
            && self.store.root().join("chains").is_dir();
        if backup.join("holders").exists() {
            ledger_present = ledger_present && self.store.root().join("holders").exists();
        }
        let (instance_live_count, issuance_log_leaf_count) = match self.store_status() {
            Ok(status) => (status.instance_live_count, status.issuance_log_leaf_count),
            Err(_) => (0, 0),
        };
        let operation_normal = restore_succeeded
            && same_issuer_public_key
            && issuer_secret_matches_current
            && issuance_log_chain_ok
            && member_two_absent_from_store
            && ledger_present;
        Ok(RestoreDiagnostics {
            restore_succeeded,
            operation_normal,
            same_issuer_public_key,
            issuer_secret_matches_current,
            issuance_log_chain_ok,
            member_two_absent_from_store,
            ledger_present,
            instance_live_count,
            issuance_log_leaf_count,
        })
    }

    fn store_has_issuer_member_secret(root: &Path) -> bool {
        let Ok(entries) = std::fs::read_dir(root) else {
            return false;
        };
        entries.filter_map(|entry| entry.ok()).any(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with("issuer-member-") && name.ends_with(".secret")
        })
    }

    /// Same as restore_from_backup. Laboratory cold restore onto an empty issuing store.
    pub fn restore_issuer_backup(
        backup: impl AsRef<Path>,
        dest_root: impl AsRef<Path>,
    ) -> Result<Self> {
        Self::restore_from_backup(backup, dest_root)
    }
}

/// A child act authority cannot widen the parent. Fail closed.
/// An autonomous parent may birth an autonomous child or a child on behalf of a named user.
/// A parent on behalf of a named user may birth only a child of that same user.
fn require_child_act_authority_compatible(
    parent_on_behalf_of: &str,
    child_on_behalf_of: &str,
) -> Result<()> {
    if parent_on_behalf_of == "autonomous" {
        if child_on_behalf_of.is_empty() {
            return Err(Error::kernel(
                "The child on_behalf_of value must not be empty. Empty is not autonomous. The exact word autonomous is required.",
            ));
        }
        return Ok(());
    }
    if child_on_behalf_of == "autonomous" {
        return Err(Error::kernel(format!(
            "The child act authority 'autonomous' widens the parent act authority '{parent_on_behalf_of}'. A parent on behalf of a named user cannot birth an autonomous child. Widening to autonomous is refused."
        )));
    }
    if child_on_behalf_of != parent_on_behalf_of {
        return Err(Error::kernel(format!(
            "The child act authority '{child_on_behalf_of}' does not match the parent act authority '{parent_on_behalf_of}'. A child of a named user must keep that same user. A mismatch fails closed."
        )));
    }
    Ok(())
}

/// Act authority is required on check and verify.
/// Empty is not autonomous. The exact word autonomous is required.
fn require_named_act_authority(on_behalf_of: Option<&str>) -> Result<&str> {
    match on_behalf_of {
        None => Err(Error::denied(
            "The request must name on_behalf_of. The kernel does not guess the act authority. Empty is not autonomous.",
        )),
        Some(value) if value.is_empty() => Err(Error::denied(
            "The on_behalf_of value must not be empty. Empty is not autonomous. The exact word autonomous is required.",
        )),
        Some(value) => Ok(value),
    }
}

/// Attenuation creates a new capability identifier. The first persist of that identifier may set a shorter expiry.
/// The child expiry must not exceed the parent expiry. The capability must not outlive the mint.
fn require_child_capability_expiry_not_after_parent(
    child_expires: DateTime<Utc>,
    parent_expires: DateTime<Utc>,
) -> Result<()> {
    if child_expires > parent_expires {
        return Err(Error::denied(
            "The child capability must not expire after the parent capability. Attenuation creates a new capability identifier. The first persist of that identifier may set a shorter expiry. The child expiry must not exceed the parent expiry. The capability must not outlive the mint. This is not a sixth identity record.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::{allowed_intents_within_stored, is_narrower_or_equal};
    use crate::tokens;
    use tempfile::tempdir;

    fn laboratory_kernel() -> (tempfile::TempDir, Kernel) {
        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        (directory, kernel)
    }

    fn add_outside_member_two(kernel: &Kernel) -> (tempfile::TempDir, PathBuf) {
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        kernel
            .add_issuer_member_with_secret_path(Some(&outside))
            .expect("add a second member outside the data directory");
        kernel
            .store()
            .register_extra_member_secret_path(outside.clone())
            .expect("register the outside member secret path");
        (custody_directory, outside)
    }

    fn add_outside_member_three(kernel: &Kernel) -> (tempfile::TempDir, PathBuf) {
        let custody_directory = tempdir().expect("create a member-three custody directory");
        let outside = custody_directory.path().join("member-three.secret");
        kernel
            .add_issuer_member_with_secret_path(Some(&outside))
            .expect("add a third member outside the data directory");
        kernel
            .store()
            .register_extra_member_secret_path(outside.clone())
            .expect("register the outside member-three secret path");
        (custody_directory, outside)
    }

    fn laboratory_agent_type(kernel: &Kernel, authorization_limit: &str, depth: u32) -> AgentType {
        kernel
            .add_agent_type(
                "laboratory".to_string(),
                vec!["read".to_string(), "read/limited".to_string()],
                authorization_limit.to_string(),
                depth,
                crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE.to_string(),
                3600,
            )
            .expect("add an agent type")
    }

    fn holder_proof(kernel: &Kernel, instance: &Instance) -> HolderProof {
        HolderProof::SecretPath(kernel.store().holder_secret_path(&instance.id))
    }

    fn fresh_challenge(kernel: &Kernel, instance: &Instance) -> String {
        kernel
            .issue_holder_challenge(&instance.id)
            .expect("issue a holder challenge")
            .nonce
    }

    fn verifier_holder_signature(
        issuing: &Kernel,
        instance: &Instance,
        verifier: &Kernel,
    ) -> (HolderProof, String) {
        let challenge = verifier
            .issue_verifier_challenge()
            .expect("issue a verifier challenge");
        let signature = issuing
            .sign_holder_nonce(
                &challenge.challenge_message,
                issuing.store().holder_secret_path(&instance.id),
            )
            .expect("sign the verifier nonce on the issuing store");
        (
            HolderProof::SignatureHexadecimal(signature),
            challenge.nonce,
        )
    }

    fn laboratory_capability(kernel: &Kernel) -> (Instance, Capability) {
        let agent_type = laboratory_agent_type(kernel, "payments", 3);
        let instance = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth an instance");
        let capability = kernel
            .mint_capability(&instance.id, "read", "payments", None)
            .expect("mint a capability");
        (instance, capability)
    }

    #[test]
    fn a_child_path_is_narrower() {
        assert!(is_narrower_or_equal("payments/prod", "payments"));
        assert!(is_narrower_or_equal("payments", "payments"));
        assert!(!is_narrower_or_equal("payments", "payments/prod"));
        assert!(!is_narrower_or_equal("other", "payments"));
        assert!(audience_within_authorization_limit(
            "payments/prod",
            "payments"
        ));
        assert!(!audience_within_authorization_limit("public", "payments"));
    }

    #[test]
    fn the_instance_identifier_is_not_the_holder_key() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 2);
        let instance = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .unwrap();
        assert_ne!(instance.id, instance.holder_public_key);
        assert!(instance
            .id
            .chars()
            .all(|character| character.is_ascii_alphanumeric()));
        assert!(instance.holder_public_key.len() > instance.id.len());
    }

    #[test]
    fn mint_rejects_audience_above_the_authorization_limit() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, _capability) = laboratory_capability(&kernel);
        let error = kernel
            .mint_capability(&instance.id, "read", "public", None)
            .expect_err("an audience above the authorization limit must fail");
        assert!(error.to_string().contains("authorization limit"));
    }

    #[test]
    fn mint_accepts_audience_inside_the_authorization_limit() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 2);
        let instance = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .unwrap();
        kernel
            .mint_capability(&instance.id, "read", "payments/prod", None)
            .expect("a child destination of the authorization limit must succeed");
    }

    #[test]
    fn verify_rejects_a_missing_holder_proof() {
        let (_directory, kernel) = laboratory_kernel();
        let (_instance, capability) = laboratory_capability(&kernel);
        let error = kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                None,
                None,
                Some("autonomous"),
            )
            .expect_err("a missing holder proof must fail");
        assert!(error.to_string().contains("holder proof is required"));
    }

    #[test]
    fn verify_rejects_a_missing_challenge_nonce() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let error = kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                None,
                Some("autonomous"),
            )
            .expect_err("a missing challenge nonce must fail");
        assert!(error.to_string().contains("challenge nonce is required"));
    }

    #[test]
    fn verify_rejects_a_wrong_holder_secret() {
        let (directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let other = laboratory_agent_type(&kernel, "payments", 2);
        let stranger = kernel
            .birth_instance(&other.id, "laboratory".to_string(), BTreeMap::new(), None)
            .unwrap();
        let nonce = fresh_challenge(&kernel, &instance);
        let error = kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &stranger)),
                Some(&nonce),
                Some("autonomous"),
            )
            .expect_err("a stolen capability token without the holder key must fail");
        assert!(error.to_string().contains("holder proof is not valid"));
        let _ = directory;
    }

    #[test]
    fn a_spent_challenge_nonce_cannot_be_reused() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let proof = holder_proof(&kernel, &instance);
        let nonce = fresh_challenge(&kernel, &instance);
        kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&proof),
                Some(&nonce),
                Some("autonomous"),
            )
            .expect("the first use of the challenge must succeed");
        let error = kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&proof),
                Some(&nonce),
                Some("autonomous"),
            )
            .expect_err("re-use of a spent nonce must fail");
        assert!(error.to_string().contains("already spent"));
    }

    #[test]
    fn a_challenge_past_its_window_fails_without_a_long_sleep() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let challenge = kernel
            .issue_holder_challenge(&instance.id)
            .expect("issue a holder challenge");
        kernel.set_now_for_test(challenge.expires + Duration::seconds(1));
        let error = kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&challenge.nonce),
                Some("autonomous"),
            )
            .expect_err("a challenge past its window must fail");
        assert!(error.to_string().contains("time window"));
    }

    #[test]
    fn attenuation_rejects_a_wider_audience() {
        let (_directory, kernel) = laboratory_kernel();
        let (_instance, capability) = laboratory_capability(&kernel);
        let error = kernel
            .attenuate_capability(&capability.id, "pay", None)
            .expect_err("a wider audience must fail");
        assert!(error.to_string().contains("Attenuation can only reduce"));
    }

    #[test]
    fn attenuation_rejects_a_wider_intent() {
        let (_directory, kernel) = laboratory_kernel();
        let (_instance, capability) = laboratory_capability(&kernel);
        let limited = kernel
            .attenuate_capability(&capability.id, "payments", Some("read/limited"))
            .expect("a child intent must succeed");
        let error = kernel
            .attenuate_capability(&limited.id, "payments", Some("read"))
            .expect_err("a wider intent must fail");
        assert!(error
            .to_string()
            .contains("Attenuation can only reduce the intent"));
    }

    #[test]
    fn verification_fails_when_the_identifier_is_absent_from_the_log() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let log_path = kernel.store().log_path();
        std::fs::write(&log_path, b"").unwrap();
        let nonce = fresh_challenge(&kernel, &instance);
        let error = kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&nonce),
                Some("autonomous"),
            )
            .expect_err("an empty issuance log must fail verification");
        assert!(error
            .to_string()
            .contains("not present in the issuance log"));
    }

    #[test]
    fn birth_write_is_one_issuance_event() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 2);
        let birth = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "payments",
                None,
            )
            .expect("birth write must succeed");
        assert_ne!(birth.instance.id, birth.instance.holder_public_key);
        let events = kernel.store().read_log().unwrap();
        let birth_events: Vec<_> = events
            .iter()
            .filter(|event| event.operation == "birth_write")
            .collect();
        assert_eq!(birth_events.len(), 1);
        assert_eq!(
            birth_events[0].instance_id.as_deref(),
            Some(birth.instance.id.as_str())
        );
        assert_eq!(
            birth_events[0].capability_id.as_deref(),
            Some(birth.capability.id.as_str())
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.operation == "mint")
                .count(),
            0
        );
        let nonce = fresh_challenge(&kernel, &birth.instance);
        kernel
            .verify_capability(
                &birth.capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &birth.instance)),
                Some(&nonce),
                Some("autonomous"),
            )
            .expect("the birth capability must verify with a holder proof");
    }

    #[test]
    fn a_fourth_hop_fails_when_the_limit_is_three() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let hop1 = kernel
            .attenuate_capability(&capability.id, "payments/a", None)
            .unwrap();
        let hop2 = kernel
            .attenuate_capability(&hop1.id, "payments/a/b", None)
            .unwrap();
        let hop3 = kernel
            .attenuate_capability(&hop2.id, "payments/a/b/c", None)
            .unwrap();
        assert_eq!(kernel.store().load_chain(&hop3.id).unwrap().hop_index, 3);
        let error = kernel
            .attenuate_capability(&hop3.id, "payments/a/b/c/d", None)
            .expect_err("the fourth hop must fail");
        assert!(error.to_string().contains("max_delegation_depth"));
        let _ = instance;
    }

    #[test]
    fn spawn_allows_a_narrower_child_and_refuses_a_wider_child() {
        let (_directory, kernel) = laboratory_kernel();
        let (parent, capability) = laboratory_capability(&kernel);
        let parent_nonce = fresh_challenge(&kernel, &parent);
        let child = kernel
            .spawn_child(
                &parent.id,
                &capability.id,
                "child".to_string(),
                BTreeMap::new(),
                "read",
                "payments/prod",
                None,
                Some(&holder_proof(&kernel, &parent)),
                Some(&parent_nonce),
            )
            .expect("a narrower child must succeed");
        assert_eq!(
            child.instance.parent_instance_id.as_deref(),
            Some(parent.id.as_str())
        );
        assert_eq!(child.parent_capability_id, capability.id);
        let events = kernel.store().read_log().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.operation == "spawn")
                .count(),
            1
        );
        let child_nonce = fresh_challenge(&kernel, &child.instance);
        kernel
            .spawn_child(
                &child.instance.id,
                &child.capability.id,
                "wider".to_string(),
                BTreeMap::new(),
                "read",
                "payments",
                None,
                Some(&holder_proof(&kernel, &child.instance)),
                Some(&child_nonce),
            )
            .expect_err("a wider grandchild must fail");
        let verify_nonce = fresh_challenge(&kernel, &child.instance);
        kernel
            .verify_capability(
                &child.capability.id,
                "payments/prod",
                "read",
                Some(&holder_proof(&kernel, &child.instance)),
                Some(&verify_nonce),
                Some("autonomous"),
            )
            .expect("the child capability must verify");
    }

    #[test]
    fn spawn_constrains_the_child_act_authority_to_the_parent() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 3);
        let parent_user = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "payments",
                Some("jordan".to_string()),
            )
            .expect("birth a parent on behalf of jordan");
        assert_eq!(parent_user.capability.on_behalf_of, "jordan");
        let parent_proof = holder_proof(&kernel, &parent_user.instance);

        let widen_error = kernel
            .spawn_child(
                &parent_user.instance.id,
                &parent_user.capability.id,
                "child-autonomous".to_string(),
                BTreeMap::new(),
                "read",
                "payments/prod",
                Some("autonomous".to_string()),
                Some(&parent_proof),
                Some(&fresh_challenge(&kernel, &parent_user.instance)),
            )
            .expect_err("a named-user parent must refuse an autonomous child");
        let widen_text = widen_error.to_string();
        assert!(
            widen_text.contains("widens") || widen_text.contains("autonomous child"),
            "unexpected widen error: {widen_text}"
        );

        let same_user = kernel
            .spawn_child(
                &parent_user.instance.id,
                &parent_user.capability.id,
                "child-jordan".to_string(),
                BTreeMap::new(),
                "read",
                "payments/prod",
                Some("jordan".to_string()),
                Some(&parent_proof),
                Some(&fresh_challenge(&kernel, &parent_user.instance)),
            )
            .expect("a named-user parent must accept a child of that same user");
        assert_eq!(same_user.capability.on_behalf_of, "jordan");
        kernel
            .verify_capability(
                &same_user.capability.id,
                "payments/prod",
                "read",
                Some(&holder_proof(&kernel, &same_user.instance)),
                Some(&fresh_challenge(&kernel, &same_user.instance)),
                Some("jordan"),
            )
            .expect("the child token must hold the child act authority");

        let parent_autonomous = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "payments",
                Some("autonomous".to_string()),
            )
            .expect("birth an autonomous parent");
        assert_eq!(parent_autonomous.capability.on_behalf_of, "autonomous");
        let autonomous_child = kernel
            .spawn_child(
                &parent_autonomous.instance.id,
                &parent_autonomous.capability.id,
                "child-autonomous".to_string(),
                BTreeMap::new(),
                "read",
                "payments/prod",
                Some("autonomous".to_string()),
                Some(&holder_proof(&kernel, &parent_autonomous.instance)),
                Some(&fresh_challenge(&kernel, &parent_autonomous.instance)),
            )
            .expect("an autonomous parent must accept an autonomous child");
        assert_eq!(autonomous_child.capability.on_behalf_of, "autonomous");
        kernel
            .verify_capability(
                &autonomous_child.capability.id,
                "payments/prod",
                "read",
                Some(&holder_proof(&kernel, &autonomous_child.instance)),
                Some(&fresh_challenge(&kernel, &autonomous_child.instance)),
                Some("autonomous"),
            )
            .expect("the autonomous child token must hold the autonomous act authority");
    }

    #[test]
    fn spawn_without_parent_holder_proof_is_refused() {
        let (_directory, kernel) = laboratory_kernel();
        let (parent, capability) = laboratory_capability(&kernel);
        let error = kernel
            .spawn_child(
                &parent.id,
                &capability.id,
                "child".to_string(),
                BTreeMap::new(),
                "read",
                "payments/prod",
                None,
                None,
                None,
            )
            .expect_err("spawn without a holder proof must fail");
        assert!(error.to_string().contains("holder proof is required"));
    }

    #[test]
    fn check_allows_internal_and_refuses_public() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "internal", 2);
        let birth = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "internal",
                None,
            )
            .unwrap();
        let proof = holder_proof(&kernel, &birth.instance);
        let allowed_nonce = fresh_challenge(&kernel, &birth.instance);
        let allowed = kernel
            .check_tool_action(
                &birth.instance.id,
                Some(&birth.capability.id),
                "read",
                "internal",
                Some(&proof),
                Some(&allowed_nonce),
                Some("autonomous"),
            )
            .unwrap();
        assert_eq!(allowed.result, "allowed");
        let refused_nonce = fresh_challenge(&kernel, &birth.instance);
        let refused = kernel
            .check_tool_action(
                &birth.instance.id,
                Some(&birth.capability.id),
                "read",
                "public",
                Some(&proof),
                Some(&refused_nonce),
                Some("autonomous"),
            )
            .unwrap();
        assert_eq!(refused.result, "refused");
        assert!(refused.reason.unwrap().contains("authorization limit"));
        let events = kernel.store().read_log().unwrap();
        let checks: Vec<_> = events
            .iter()
            .filter(|event| event.operation == "check")
            .collect();
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0].result.as_deref(), Some("allowed"));
        assert_eq!(checks[1].result.as_deref(), Some("refused"));
    }

    #[test]
    fn check_refuses_a_missing_holder_proof() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let decision = kernel
            .check_tool_action(
                &instance.id,
                Some(&capability.id),
                "read",
                "payments",
                None,
                None,
                Some("autonomous"),
            )
            .unwrap();
        assert_eq!(decision.result, "refused");
        assert!(decision
            .reason
            .unwrap()
            .contains("holder proof is required"));
    }

    #[test]
    fn check_refuses_a_missing_capability_identifier() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, _capability) = laboratory_capability(&kernel);
        let proof = holder_proof(&kernel, &instance);
        let nonce = fresh_challenge(&kernel, &instance);
        let decision = kernel
            .check_tool_action(
                &instance.id,
                None,
                "read",
                "payments",
                Some(&proof),
                Some(&nonce),
                None,
            )
            .unwrap();
        assert_eq!(decision.result, "refused");
        assert!(decision
            .reason
            .unwrap()
            .contains("must name the capability identifier"));
    }

    #[test]
    fn parent_kill_revokes_child_instances_and_capabilities() {
        let (_directory, kernel) = laboratory_kernel();
        let (parent, capability) = laboratory_capability(&kernel);
        let parent_nonce = fresh_challenge(&kernel, &parent);
        let child = kernel
            .spawn_child(
                &parent.id,
                &capability.id,
                "child".to_string(),
                BTreeMap::new(),
                "read",
                "payments/prod",
                None,
                Some(&holder_proof(&kernel, &parent)),
                Some(&parent_nonce),
            )
            .expect("a narrower child must succeed");
        let child_nonce = fresh_challenge(&kernel, &child.instance);
        let check_nonce = fresh_challenge(&kernel, &child.instance);
        kernel
            .kill_instance(&parent.id)
            .expect("parent kill must succeed");
        assert_eq!(
            kernel.store().load_instance(&parent.id).unwrap().status,
            InstanceStatus::Revoked
        );
        assert_eq!(
            kernel
                .store()
                .load_instance(&child.instance.id)
                .unwrap()
                .status,
            InstanceStatus::Revoked
        );
        assert!(
            kernel
                .store()
                .load_chain(&child.capability.id)
                .unwrap()
                .revoke_from_here
        );
        let error = kernel
            .verify_capability(
                &child.capability.id,
                "payments/prod",
                "read",
                Some(&holder_proof(&kernel, &child.instance)),
                Some(&child_nonce),
                Some("autonomous"),
            )
            .expect_err("verify on a child capability after parent kill must fail");
        assert!(
            error.to_string().contains("revoked") || error.to_string().contains("revoke_from_here"),
            "unexpected error: {error}"
        );
        let decision = kernel
            .check_tool_action(
                &child.instance.id,
                Some(&child.capability.id),
                "read",
                "payments/prod",
                Some(&holder_proof(&kernel, &child.instance)),
                Some(&check_nonce),
                Some("autonomous"),
            )
            .unwrap();
        assert_eq!(decision.result, "refused");
    }

    #[test]
    fn expired_capability_fails_without_a_long_sleep() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = kernel
            .add_agent_type(
                "laboratory".to_string(),
                vec!["read".to_string()],
                "payments".to_string(),
                2,
                crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE.to_string(),
                60,
            )
            .unwrap();
        let birth = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "payments",
                None,
            )
            .unwrap();
        kernel.set_now_for_test(birth.capability.expires + Duration::seconds(1));
        let nonce = fresh_challenge(&kernel, &birth.instance);
        let error = kernel
            .verify_capability(
                &birth.capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &birth.instance)),
                Some(&nonce),
                Some("autonomous"),
            )
            .expect_err("an expired capability must fail");
        assert!(error.to_string().contains("expired"));
        let check_nonce = fresh_challenge(&kernel, &birth.instance);
        let decision = kernel
            .check_tool_action(
                &birth.instance.id,
                Some(&birth.capability.id),
                "read",
                "payments",
                Some(&holder_proof(&kernel, &birth.instance)),
                Some(&check_nonce),
                Some("autonomous"),
            )
            .unwrap();
        assert_eq!(decision.result, "refused");
        assert!(decision.reason.unwrap().contains("expired"));
    }

    #[test]
    fn check_requires_on_behalf_of_to_match_the_capability() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "internal", 2);
        let birth = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "internal",
                None,
            )
            .unwrap();
        assert_eq!(birth.capability.on_behalf_of, "autonomous");
        let delegated = kernel
            .mint_capability(
                &birth.instance.id,
                "read",
                "internal",
                Some("jordan".to_string()),
            )
            .unwrap();
        assert_eq!(delegated.on_behalf_of, "jordan");
        let proof = holder_proof(&kernel, &birth.instance);

        let allowed_autonomous = kernel
            .check_tool_action(
                &birth.instance.id,
                Some(&birth.capability.id),
                "read",
                "internal",
                Some(&proof),
                Some(&fresh_challenge(&kernel, &birth.instance)),
                Some("autonomous"),
            )
            .unwrap();
        assert_eq!(allowed_autonomous.result, "allowed");
        assert_eq!(
            allowed_autonomous.on_behalf_of.as_deref(),
            Some("autonomous")
        );

        let allowed_delegated = kernel
            .check_tool_action(
                &birth.instance.id,
                Some(&delegated.id),
                "read",
                "internal",
                Some(&proof),
                Some(&fresh_challenge(&kernel, &birth.instance)),
                Some("jordan"),
            )
            .unwrap();
        assert_eq!(allowed_delegated.result, "allowed");
        assert_eq!(allowed_delegated.on_behalf_of.as_deref(), Some("jordan"));

        let mismatch = kernel
            .check_tool_action(
                &birth.instance.id,
                Some(&birth.capability.id),
                "read",
                "internal",
                Some(&proof),
                Some(&fresh_challenge(&kernel, &birth.instance)),
                Some("jordan"),
            )
            .unwrap();
        assert_eq!(mismatch.result, "refused");
        assert!(mismatch.reason.unwrap().contains("act authority"));
        assert_eq!(mismatch.on_behalf_of.as_deref(), Some("autonomous"));

        let reverse = kernel
            .check_tool_action(
                &birth.instance.id,
                Some(&delegated.id),
                "read",
                "internal",
                Some(&proof),
                Some(&fresh_challenge(&kernel, &birth.instance)),
                Some("autonomous"),
            )
            .unwrap();
        assert_eq!(reverse.result, "refused");
        assert!(reverse.reason.unwrap().contains("act authority"));
        assert_eq!(reverse.on_behalf_of.as_deref(), Some("jordan"));

        let missing = kernel
            .check_tool_action(
                &birth.instance.id,
                Some(&birth.capability.id),
                "read",
                "internal",
                Some(&proof),
                Some(&fresh_challenge(&kernel, &birth.instance)),
                None,
            )
            .unwrap();
        assert_eq!(missing.result, "refused");
        assert!(missing.reason.unwrap().contains("must name on_behalf_of"));

        let empty = kernel
            .check_tool_action(
                &birth.instance.id,
                Some(&birth.capability.id),
                "read",
                "internal",
                Some(&proof),
                Some(&fresh_challenge(&kernel, &birth.instance)),
                Some(""),
            )
            .unwrap();
        assert_eq!(empty.result, "refused");
        assert!(empty.reason.unwrap().contains("Empty is not autonomous"));
    }

    #[test]
    fn verify_rejects_a_missing_on_behalf_of() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let error = kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                None,
            )
            .expect_err("a missing on_behalf_of must fail");
        assert!(error.to_string().contains("must name on_behalf_of"));
    }

    #[test]
    fn verify_rejects_an_empty_on_behalf_of() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let error = kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some(""),
            )
            .expect_err("an empty on_behalf_of must fail");
        assert!(error.to_string().contains("Empty is not autonomous"));
    }

    #[test]
    fn check_refuses_when_the_token_act_authority_does_not_match_the_record() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        assert_eq!(capability.on_behalf_of, "autonomous");
        let mut tampered = kernel
            .store()
            .load_capability(&capability.id)
            .expect("load the capability record");
        tampered.on_behalf_of = "jordan".to_string();
        write_capability_record_bypassing_save(&kernel, &tampered);
        let decision = kernel
            .check_tool_action(
                &instance.id,
                Some(&capability.id),
                "read",
                "payments",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("jordan"),
            )
            .unwrap();
        assert_eq!(decision.result, "refused");
        let reason = decision.reason.expect("a refused check must name a reason");
        assert!(
            !reason.contains("must name on_behalf_of"),
            "the request named jordan; the token must refuse it: {reason}"
        );
        assert!(
            reason.contains("verification failed")
                || reason.contains("Denied")
                || reason.contains("check")
                || reason.contains("act authority"),
            "unexpected token mismatch reason: {reason}"
        );
    }

    #[test]
    fn demonstration_sequence() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let proof = holder_proof(&kernel, &instance);
        let first_nonce = fresh_challenge(&kernel, &instance);
        kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&proof),
                Some(&first_nonce),
                Some("autonomous"),
            )
            .expect("the first verification must succeed");
        kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                None,
                None,
                Some("autonomous"),
            )
            .expect_err("verification without a holder proof must fail");
        let narrower = kernel
            .attenuate_capability(&capability.id, "payments/prod", Some("read/limited"))
            .expect("attenuation to a child path must succeed");
        let narrow_nonce = fresh_challenge(&kernel, &instance);
        kernel
            .verify_capability(
                &narrower.id,
                "payments/prod",
                "read/limited",
                Some(&proof),
                Some(&narrow_nonce),
                Some("autonomous"),
            )
            .expect("verification of the narrower audience must succeed");
        let wide_nonce = fresh_challenge(&kernel, &instance);
        kernel
            .verify_capability(
                &narrower.id,
                "payments",
                "read",
                Some(&proof),
                Some(&wide_nonce),
                Some("autonomous"),
            )
            .expect_err("verification of the wider audience must fail");
        kernel
            .kill_capability(&narrower.id)
            .expect("kill must succeed");
        let killed_nonce = fresh_challenge(&kernel, &instance);
        let error = kernel
            .verify_capability(
                &narrower.id,
                "payments/prod",
                "read/limited",
                Some(&proof),
                Some(&killed_nonce),
                Some("autonomous"),
            )
            .expect_err("verification after kill must fail");
        assert!(
            error.to_string().contains("revoked"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn an_allowed_decision_receipt_verifies() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "internal", 2);
        let birth = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "internal",
                None,
            )
            .unwrap();
        let allowed = kernel
            .check_tool_action(
                &birth.instance.id,
                Some(&birth.capability.id),
                "read",
                "internal",
                Some(&holder_proof(&kernel, &birth.instance)),
                Some(&fresh_challenge(&kernel, &birth.instance)),
                Some("autonomous"),
            )
            .unwrap();
        assert_eq!(allowed.result, "allowed");
        let receipt = allowed
            .receipt
            .expect("an allowed check must return a signed receipt");
        assert_eq!(receipt.result, "allowed");
        assert_eq!(receipt.instance_id, birth.instance.id);
        assert_eq!(receipt.capability_id, birth.capability.id);
        assert_eq!(receipt.intent, "read");
        assert_eq!(receipt.audience, "internal");
        assert_eq!(receipt.on_behalf_of, "autonomous");
        assert!(
            !receipt.issuance_log_line.is_empty(),
            "the receipt must include the issuance-log line"
        );
        assert!(
            kernel
                .store()
                .issuance_log_contains_line(&receipt.issuance_log_line)
                .expect("read the issuance log"),
            "the receipt issuance-log line must be present in issuance.log"
        );
        kernel
            .verify_decision_receipt(&receipt)
            .expect("an allowed receipt must verify against the issuer public key");
        let serialized = serde_json::to_string(&receipt).expect("serialize the receipt");
        assert!(
            !serialized.contains("secret"),
            "the receipt must not contain holder secrets"
        );
        assert!(
            !serialized.contains(&birth.capability.biscuit),
            "the receipt must not contain the capability token"
        );
        let holder_secret = kernel
            .store()
            .load_holder_secret(&birth.instance.id)
            .expect("load the holder secret");
        assert!(
            !serialized.contains(&holder_secret),
            "the receipt must not contain the holder secret"
        );
    }

    #[test]
    fn a_refused_decision_receipt_verifies() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "internal", 2);
        let birth = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "internal",
                None,
            )
            .unwrap();
        let refused = kernel
            .check_tool_action(
                &birth.instance.id,
                Some(&birth.capability.id),
                "read",
                "public",
                Some(&holder_proof(&kernel, &birth.instance)),
                Some(&fresh_challenge(&kernel, &birth.instance)),
                Some("autonomous"),
            )
            .unwrap();
        assert_eq!(refused.result, "refused");
        let receipt = refused
            .receipt
            .expect("a refused check must return a signed receipt");
        assert_eq!(receipt.result, "refused");
        assert!(
            receipt
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("authorization limit"),
            "the refused receipt must name the reason"
        );
        kernel
            .verify_decision_receipt(&receipt)
            .expect("a refused receipt must verify against the issuer public key");
    }

    #[test]
    fn a_tampered_decision_receipt_result_fails() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "internal", 2);
        let birth = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "internal",
                None,
            )
            .unwrap();
        let allowed = kernel
            .check_tool_action(
                &birth.instance.id,
                Some(&birth.capability.id),
                "read",
                "internal",
                Some(&holder_proof(&kernel, &birth.instance)),
                Some(&fresh_challenge(&kernel, &birth.instance)),
                Some("autonomous"),
            )
            .unwrap();
        let mut receipt = allowed
            .receipt
            .expect("an allowed check must return a signed receipt");
        receipt.result = "refused".to_string();
        let error = kernel
            .verify_decision_receipt(&receipt)
            .expect_err("a tampered result must fail");
        assert!(
            error.to_string().contains("signature") || error.to_string().contains("not valid"),
            "unexpected tamper error: {error}"
        );
        receipt.signature.clear();
        let missing = kernel
            .verify_decision_receipt(&receipt)
            .expect_err("a missing signature must fail");
        assert!(
            missing.to_string().contains("missing a signature"),
            "unexpected missing-signature error: {missing}"
        );
    }

    #[test]
    fn a_decision_receipt_from_a_foreign_key_fails() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "internal", 2);
        let birth = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "internal",
                None,
            )
            .unwrap();
        let allowed = kernel
            .check_tool_action(
                &birth.instance.id,
                Some(&birth.capability.id),
                "read",
                "internal",
                Some(&holder_proof(&kernel, &birth.instance)),
                Some(&fresh_challenge(&kernel, &birth.instance)),
                Some("autonomous"),
            )
            .unwrap();
        let mut receipt = allowed
            .receipt
            .expect("an allowed check must return a signed receipt");
        let foreign = crate::issuer_crypto::generate_module_lattice_key_pair()
            .expect("generate a foreign module lattice key");
        receipt.signature = tokens::sign_decision_receipt(
            &foreign.secret_key_hexadecimal,
            &receipt.canonical_message(),
        )
        .expect("sign with a foreign key");
        let error = kernel
            .verify_decision_receipt(&receipt)
            .expect_err("a receipt from a foreign key must fail");
        assert!(
            error
                .to_string()
                .contains("not valid for any accepted issuer public key")
                || error.to_string().contains("unknown issuer key")
                || error.to_string().contains("not valid for this issuer")
                || error.to_string().contains("signature"),
            "unexpected foreign-key error: {error}"
        );
    }

    #[test]
    fn a_decision_receipt_fails_when_the_issuance_log_line_is_missing_or_altered() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "internal", 2);
        let birth = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "internal",
                None,
            )
            .unwrap();
        let allowed = kernel
            .check_tool_action(
                &birth.instance.id,
                Some(&birth.capability.id),
                "read",
                "internal",
                Some(&holder_proof(&kernel, &birth.instance)),
                Some(&fresh_challenge(&kernel, &birth.instance)),
                Some("autonomous"),
            )
            .unwrap();
        let receipt = allowed
            .receipt
            .expect("an allowed check must return a signed receipt");
        kernel
            .verify_decision_receipt(&receipt)
            .expect("a valid receipt with the log line present must verify");

        let log_path = kernel.store().log_path();
        let original = std::fs::read_to_string(&log_path).expect("read issuance.log");

        let without: String = original
            .lines()
            .filter(|line| *line != receipt.issuance_log_line)
            .map(|line| format!("{line}\n"))
            .collect();
        std::fs::write(&log_path, &without).expect("write issuance.log without the bound line");
        let missing = kernel
            .verify_decision_receipt(&receipt)
            .expect_err("deleting the bound issuance-log line must fail");
        let missing_text = missing.to_string();
        assert!(
            missing_text.contains("issuance-log line is not present")
                || missing_text.contains("issuance log"),
            "unexpected missing-log error: {missing}"
        );
        assert!(
            !missing_text.contains("signature is not valid"),
            "the signature must still be valid when only the log line is missing: {missing}"
        );

        let altered: String = original
            .lines()
            .map(|line| {
                if line == receipt.issuance_log_line {
                    line.replace("\"allowed\"", "\"altered\"")
                } else {
                    line.to_string()
                }
            })
            .map(|line| format!("{line}\n"))
            .collect();
        std::fs::write(&log_path, &altered).expect("write an altered issuance.log");
        let altered_error = kernel
            .verify_decision_receipt(&receipt)
            .expect_err("altering the bound issuance-log line must fail");
        let altered_text = altered_error.to_string();
        assert!(
            altered_text.contains("issuance-log line is not present")
                || altered_text.contains("issuance log"),
            "unexpected altered-log error: {altered_error}"
        );
        assert!(
            !altered_text.contains("signature is not valid"),
            "the signature must still be valid when only the log line is altered: {altered_error}"
        );

        std::fs::write(&log_path, &original).expect("restore issuance.log");
        let mut stripped = receipt.clone();
        stripped.issuance_log_line.clear();
        let stripped_error = kernel
            .verify_decision_receipt(&stripped)
            .expect_err("a receipt that keeps its signature but omits the log line must fail");
        assert!(
            stripped_error
                .to_string()
                .contains("missing an issuance-log line"),
            "unexpected stripped-log error: {stripped_error}"
        );
    }

    fn laboratory_check_receipt(kernel: &Kernel) -> DecisionReceipt {
        let agent_type = laboratory_agent_type(kernel, "internal", 2);
        let birth = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "internal",
                None,
            )
            .unwrap();
        let allowed = kernel
            .check_tool_action(
                &birth.instance.id,
                Some(&birth.capability.id),
                "read",
                "internal",
                Some(&holder_proof(kernel, &birth.instance)),
                Some(&fresh_challenge(kernel, &birth.instance)),
                Some("autonomous"),
            )
            .unwrap();
        assert_eq!(allowed.result, "allowed");
        allowed
            .receipt
            .expect("an allowed check must return a signed receipt")
    }

    #[test]
    fn an_intact_issuance_log_hash_chain_verifies() {
        let (_directory, kernel) = laboratory_kernel();
        let receipt = laboratory_check_receipt(&kernel);
        kernel
            .verify_log_chain()
            .expect("an intact issuance log hash chain must verify");
        kernel
            .verify_decision_receipt(&receipt)
            .expect("a receipt bound to an intact hash chain must verify");
        let text = kernel.store().log_text().expect("read issuance.log");
        let lines: Vec<&str> = text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        assert!(
            lines.len() >= 3,
            "the laboratory check must write several chained events"
        );
        for line in &lines {
            let event: serde_json::Value = serde_json::from_str(line).expect("parse a log line");
            assert!(
                event
                    .get("previous_line_hash")
                    .and_then(|value| value.as_str())
                    .is_some(),
                "each line must include previous_line_hash"
            );
            assert!(
                event
                    .get("line_hash")
                    .and_then(|value| value.as_str())
                    .is_some(),
                "each line must include line_hash"
            );
            assert!(
                event
                    .get("issuer_public_key_hex")
                    .and_then(|value| value.as_str())
                    .map(|value| !value.is_empty())
                    .unwrap_or(false),
                "each line must include issuer_public_key_hex"
            );
            assert!(
                event
                    .get("issuer_signature_hex")
                    .and_then(|value| value.as_str())
                    .map(|value| !value.is_empty())
                    .unwrap_or(false),
                "each line must include issuer_signature_hex"
            );
        }
    }

    #[test]
    fn deleting_a_middle_issuance_log_line_breaks_the_hash_chain() {
        let (_directory, kernel) = laboratory_kernel();
        let receipt = laboratory_check_receipt(&kernel);
        kernel
            .verify_log_chain()
            .expect("the intact log must verify before the deletion");
        let log_path = kernel.store().log_path();
        let original = std::fs::read_to_string(&log_path).expect("read issuance.log");
        let lines: Vec<&str> = original
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        assert!(lines.len() >= 3, "need a middle line to delete");
        let middle = lines.len() / 2;
        let without: String = lines
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != middle)
            .map(|(_, line)| format!("{line}\n"))
            .collect();
        std::fs::write(&log_path, &without).expect("delete a middle issuance-log line");
        let error = kernel
            .verify_log_chain()
            .expect_err("deleting a middle issuance-log line must fail closed");
        let text = error.to_string();
        assert!(
            text.contains("hash chain is broken") || text.contains("previous_line_hash"),
            "unexpected middle-delete error: {error}"
        );
        let receipt_error = kernel
            .verify_decision_receipt(&receipt)
            .expect_err("receipt verify must fail closed when the hash chain is broken");
        let receipt_text = receipt_error.to_string();
        assert!(
            receipt_text.contains("hash chain is broken") || receipt_text.contains("issuance log"),
            "unexpected receipt error after a middle delete: {receipt_error}"
        );
        assert!(
            !receipt_text.contains("signature is not valid"),
            "the signature must still be valid when only the hash chain is broken: {receipt_error}"
        );
    }

    #[test]
    fn altering_an_issuance_log_field_breaks_the_hash_chain() {
        let (_directory, kernel) = laboratory_kernel();
        let _receipt = laboratory_check_receipt(&kernel);
        kernel
            .verify_log_chain()
            .expect("the intact log must verify before the alteration");
        let log_path = kernel.store().log_path();
        let original = std::fs::read_to_string(&log_path).expect("read issuance.log");
        let lines: Vec<&str> = original
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        assert!(lines.len() >= 2, "need a line to alter");
        let target = lines.len() / 2;
        let altered: String = lines
            .iter()
            .enumerate()
            .map(|(index, line)| {
                if index == target {
                    if line.contains("\"birth_write\"") {
                        line.replace("\"birth_write\"", "\"altered\"")
                    } else if line.contains("\"challenge\"") {
                        line.replace("\"challenge\"", "\"altered\"")
                    } else if line.contains("\"check\"") {
                        line.replace("\"check\"", "\"altered\"")
                    } else if line.contains("\"allowed\"") {
                        line.replace("\"allowed\"", "\"altered\"")
                    } else {
                        format!("{{\"operation\":\"altered\",\"tampered\":true}}")
                    }
                } else {
                    (*line).to_string()
                }
            })
            .map(|line| format!("{line}\n"))
            .collect();
        std::fs::write(&log_path, &altered).expect("alter an issuance-log field");
        let error = kernel
            .verify_log_chain()
            .expect_err("altering an issuance-log field must fail closed");
        let text = error.to_string();
        assert!(
            text.contains("hash chain is broken")
                || text.contains("line_hash")
                || text.contains("previous_line_hash")
                || text.contains("JSON")
                || text.contains("missing field"),
            "unexpected alter-field error: {error}"
        );
    }

    #[test]
    fn the_issuer_accept_list_includes_the_own_public_key() {
        let (_directory, kernel) = laboratory_kernel();
        let issuer = kernel.store().load_issuer().expect("load the issuer");
        assert!(
            !issuer.public_keys.is_empty(),
            "init must write this store's public key"
        );
        let own = issuer.public_keys[0].clone();
        assert!(
            issuer.accepted_issuer_public_keys.contains(&own),
            "accepted_issuer_public_keys must always include this store's own key"
        );
        let receipt = laboratory_check_receipt(&kernel);
        kernel
            .verify_decision_receipt(&receipt)
            .expect("a receipt signed by this store's own key must verify");
    }

    #[test]
    fn issuer_accept_refuses_an_empty_public_key() {
        let (_directory, kernel) = laboratory_kernel();
        let error = kernel
            .accept_issuer_public_key("")
            .expect_err("an empty public key must be refused");
        assert!(
            error.to_string().contains("empty"),
            "unexpected empty-accept error: {error}"
        );
        let whitespace = kernel
            .accept_issuer_public_key("   ")
            .expect_err("a whitespace public key must be refused");
        assert!(
            whitespace.to_string().contains("empty"),
            "unexpected whitespace-accept error: {whitespace}"
        );
        let issuer = kernel.store().load_issuer().expect("load the issuer");
        assert_eq!(
            issuer.accepted_issuer_public_keys.len(),
            1,
            "a refused accept must not change the accept list"
        );
    }

    #[test]
    fn store_b_refuses_a_present_signed_only_by_a_previous_key_past_kill_date() {
        let (_first_directory, first) = laboratory_kernel();
        let start = Utc::now();
        first.set_now_for_test(start);
        let (instance, capability) = laboratory_capability(&first);
        let honest = laboratory_signed_presentation(&first, &instance, &capability);
        let old_secret = first
            .store()
            .load_secret()
            .expect("load store A issuer secret");
        let old_public_key = first_issuer_public_key(&first);
        let (_second_directory, second) = laboratory_kernel();
        second.set_now_for_test(start);
        second
            .accept_issuer_public_key(&old_public_key)
            .expect("store B pins store A current key");
        second
            .verify_presentation(&honest)
            .expect("the honest present must verify on store B before rotate");
        first
            .rotate_issuer_key(60)
            .expect("store A rotate must succeed");
        let new_public_key = first_issuer_public_key(&first);
        let rotated = first
            .store()
            .load_issuer()
            .expect("load store A after rotate");
        assert_eq!(rotated.previous_issuer_keys.len(), 1);
        let previous_kill = rotated.previous_issuer_keys[0].kill_date;
        second
            .accept_issuer_public_key(&new_public_key)
            .expect("store B may also pin the new current key");
        second
            .accept_previous_issuer_key(&old_public_key, previous_kill)
            .expect("store B accepts the previous key with its kill date");
        let accepted = second.store().load_issuer().expect("load store B issuer");
        assert_eq!(accepted.accepted_previous_issuer_keys.len(), 1);
        assert_eq!(
            accepted.accepted_previous_issuer_keys[0].public_key_hex,
            old_public_key
        );
        assert_eq!(
            accepted.accepted_previous_issuer_keys[0].kill_date,
            previous_kill
        );
        let after_kill = start + Duration::seconds(61);
        first.set_now_for_test(after_kill);
        second.set_now_for_test(after_kill);
        let mut stolen = honest.clone();
        stolen.presented_at = DateTime::<Utc>::from_timestamp(after_kill.timestamp(), 0)
            .expect("truncate the stolen present time");
        stolen.expires_at = stolen.presented_at + Duration::seconds(30);
        stolen.issuer_public_key_hex = old_public_key.clone();
        stolen.signature_hex =
            tokens::sign_decision_receipt(&old_secret, &stolen.canonical_message())
                .expect("sign with the stolen previous issuer secret");
        let error = second.verify_presentation(&stolen).expect_err(
            "store B must refuse a present signed only by a previous key past kill date",
        );
        let text = error.to_string();
        assert!(
            text.contains("past its kill date") || text.contains("previous issuer key"),
            "store B must name the previous-key kill date: {error}"
        );
        assert!(
            second.store().load_instance(&instance.id).is_err(),
            "store B must still write no instance record"
        );
        assert_ne!(
            first
                .store()
                .load_secret()
                .expect("load store A current secret"),
            old_secret,
            "issuer.secret must stay on store A and must not be copied to store B"
        );
    }

    #[test]
    fn store_b_persist_refuses_to_postpone_an_accepted_previous_key_kill_date() {
        let (_first_directory, first) = laboratory_kernel();
        let start = Utc::now();
        first.set_now_for_test(start);
        first
            .rotate_issuer_key(60)
            .expect("store A rotate must succeed");
        let rotated = first
            .store()
            .load_issuer()
            .expect("load store A after rotate");
        let old_public_key = rotated.previous_issuer_keys[0].public_key_hex.clone();
        let previous_kill = rotated.previous_issuer_keys[0].kill_date;
        let (_second_directory, second) = laboratory_kernel();
        second.set_now_for_test(start);
        second
            .accept_previous_issuer_key(&old_public_key, previous_kill)
            .expect("store B accepts the previous key with its kill date");
        let postponed = second
            .accept_previous_issuer_key(&old_public_key, previous_kill + Duration::seconds(3600))
            .expect_err("store B must refuse to postpone an accepted previous-key kill date");
        assert!(
            postponed.to_string().contains("kill_date")
                || postponed.to_string().contains("postpone"),
            "store B must name the frozen accepted previous-key kill date: {postponed}"
        );
        let mut issuer = second.store().load_issuer().expect("load store B issuer");
        issuer.accepted_previous_issuer_keys.clear();
        let removed = second
            .store()
            .save_issuer(&issuer)
            .expect_err("store B must refuse to drop an accepted previous key");
        assert!(
            removed.to_string().contains("accepted previous")
                || removed.to_string().contains("removed"),
            "store B must name the refused accepted previous-key remove: {removed}"
        );
        let after = second.store().load_issuer().expect("reload store B issuer");
        assert_eq!(after.accepted_previous_issuer_keys.len(), 1);
        assert_eq!(
            after.accepted_previous_issuer_keys[0].kill_date,
            previous_kill
        );
    }

    #[test]
    fn verify_refuses_a_planted_later_accepted_previous_key_kill_date() {
        let (_first_directory, first) = laboratory_kernel();
        let start = Utc::now();
        first.set_now_for_test(start);
        let (instance, capability) = laboratory_capability(&first);
        let honest = laboratory_signed_presentation(&first, &instance, &capability);
        let old_secret = first
            .store()
            .load_secret()
            .expect("load store A issuer secret");
        let old_public_key = first_issuer_public_key(&first);
        first
            .rotate_issuer_key(60)
            .expect("store A rotate must succeed");
        let new_public_key = first_issuer_public_key(&first);
        let rotated = first
            .store()
            .load_issuer()
            .expect("load store A after rotate");
        let previous_kill = rotated.previous_issuer_keys[0].kill_date;
        let honest_kill = start + Duration::seconds(60);
        assert_eq!(previous_kill, honest_kill);
        let (_second_directory, second) = laboratory_kernel();
        second.set_now_for_test(start);
        second
            .accept_issuer_public_key(&old_public_key)
            .expect("store B pins store A old key");
        second
            .accept_issuer_public_key(&new_public_key)
            .expect("store B pins store A new key");
        second
            .accept_previous_issuer_key(&old_public_key, previous_kill)
            .expect("store B accepts the previous key with its kill date");
        let log = second
            .store()
            .read_log()
            .expect("read store B issuance log");
        assert!(
            log.iter()
                .any(|event| event.operation == "previous_key_accept"),
            "store B must append a signed previous_key_accept line"
        );
        let planted_kill = start + Duration::seconds(3600);
        let issuer_path = second.store().issuer_path();
        let raw = std::fs::read_to_string(&issuer_path).expect("read store B issuer.json");
        let mut planted: serde_json::Value =
            serde_json::from_str(&raw).expect("parse store B issuer.json");
        planted["accepted_previous_issuer_keys"][0]["kill_date"] =
            serde_json::Value::String(planted_kill.to_rfc3339());
        std::fs::write(
            &issuer_path,
            serde_json::to_string_pretty(&planted).expect("serialize planted issuer.json"),
        )
        .expect("plant a later accepted previous-key kill_date without save_issuer");
        let loaded = second
            .store()
            .load_issuer()
            .expect("load store B after the plant");
        assert_eq!(
            loaded.accepted_previous_issuer_keys[0].kill_date,
            honest_kill,
            "load_issuer must overlay the signed accepted previous-key kill_date"
        );
        let still_planted: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&issuer_path).expect("re-read store B issuer.json"),
        )
        .expect("parse planted issuer.json");
        let on_disk_planted = still_planted
            .get("accepted_previous_issuer_keys")
            .and_then(|value| value.get(0))
            .and_then(|value| value.get("kill_date"))
            .and_then(|value| value.as_str())
            .expect("planted later accepted previous-key kill_date must remain on disk");
        let parsed_planted = DateTime::parse_from_rfc3339(on_disk_planted)
            .expect("planted accepted previous-key kill_date is RFC3339")
            .with_timezone(&Utc);
        assert_eq!(
            parsed_planted, planted_kill,
            "load_issuer must not write the file back"
        );
        let after_kill = start + Duration::seconds(61);
        first.set_now_for_test(after_kill);
        second.set_now_for_test(after_kill);
        let mut stolen = honest.clone();
        stolen.presented_at = DateTime::<Utc>::from_timestamp(after_kill.timestamp(), 0)
            .expect("truncate the stolen present time");
        stolen.expires_at = stolen.presented_at + Duration::seconds(30);
        stolen.issuer_public_key_hex = old_public_key.clone();
        stolen.signature_hex =
            tokens::sign_decision_receipt(&old_secret, &stolen.canonical_message())
                .expect("sign with the stolen previous issuer secret");
        let error = second.verify_presentation(&stolen).expect_err(
            "store B must refuse a present signed only by a previous key past the signed kill date",
        );
        let text = error.to_string();
        assert!(
            text.contains("past its kill date") || text.contains("previous issuer key"),
            "store B must name the previous-key kill date: {error}"
        );
        assert_ne!(
            first
                .store()
                .load_secret()
                .expect("load store A current secret"),
            old_secret,
            "issuer.secret must stay on store A and must not be copied to store B"
        );
    }

    #[test]
    fn verify_refuses_a_planted_drop_of_accepted_previous_issuer_keys() {
        let (_first_directory, first) = laboratory_kernel();
        let start = Utc::now();
        first.set_now_for_test(start);
        let (instance, capability) = laboratory_capability(&first);
        let honest = laboratory_signed_presentation(&first, &instance, &capability);
        let old_secret = first
            .store()
            .load_secret()
            .expect("load store A issuer secret");
        let old_public_key = first_issuer_public_key(&first);
        first
            .rotate_issuer_key(60)
            .expect("store A rotate must succeed");
        let new_public_key = first_issuer_public_key(&first);
        let rotated = first
            .store()
            .load_issuer()
            .expect("load store A after rotate");
        let previous_kill = rotated.previous_issuer_keys[0].kill_date;
        let honest_kill = start + Duration::seconds(60);
        assert_eq!(previous_kill, honest_kill);
        let (_second_directory, second) = laboratory_kernel();
        second.set_now_for_test(start);
        second
            .accept_issuer_public_key(&old_public_key)
            .expect("store B pins store A old key");
        second
            .accept_issuer_public_key(&new_public_key)
            .expect("store B pins store A new key");
        second
            .accept_previous_issuer_key(&old_public_key, previous_kill)
            .expect("store B accepts the previous key with its kill date");
        let log = second
            .store()
            .read_log()
            .expect("read store B issuance log");
        assert!(
            log.iter()
                .any(|event| event.operation == "previous_key_accept"),
            "store B must append a signed previous_key_accept line"
        );
        let issuer_path = second.store().issuer_path();
        let raw = std::fs::read_to_string(&issuer_path).expect("read store B issuer.json");
        let mut planted: serde_json::Value =
            serde_json::from_str(&raw).expect("parse store B issuer.json");
        planted["accepted_previous_issuer_keys"] = serde_json::Value::Array(Vec::new());
        std::fs::write(
            &issuer_path,
            serde_json::to_string_pretty(&planted).expect("serialize planted issuer.json"),
        )
        .expect("plant an empty accepted_previous_issuer_keys list without save_issuer");
        let loaded = second
            .store()
            .load_issuer()
            .expect("load store B after the plant");
        let restored = loaded
            .accepted_previous_issuer_keys
            .iter()
            .find(|previous| previous.public_key_hex.trim() == old_public_key.trim())
            .expect("load_issuer must restore the signed accepted previous issuer key");
        assert_eq!(
            restored.kill_date, honest_kill,
            "load_issuer must restore the signed accepted previous-key kill_date"
        );
        let still_planted: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&issuer_path).expect("re-read store B issuer.json"),
        )
        .expect("parse planted issuer.json");
        let on_disk_after = still_planted
            .get("accepted_previous_issuer_keys")
            .and_then(|value| value.as_array())
            .expect("planted accepted_previous_issuer_keys must remain on disk");
        assert!(
            on_disk_after.is_empty(),
            "load_issuer must not write the file back"
        );
        let after_kill = start + Duration::seconds(61);
        first.set_now_for_test(after_kill);
        second.set_now_for_test(after_kill);
        let mut stolen = honest.clone();
        stolen.presented_at = DateTime::<Utc>::from_timestamp(after_kill.timestamp(), 0)
            .expect("truncate the stolen present time");
        stolen.expires_at = stolen.presented_at + Duration::seconds(30);
        stolen.issuer_public_key_hex = old_public_key.clone();
        stolen.signature_hex =
            tokens::sign_decision_receipt(&old_secret, &stolen.canonical_message())
                .expect("sign with the stolen previous issuer secret");
        let error = second.verify_presentation(&stolen).expect_err(
            "store B must refuse a present signed only by a previous key past the signed kill date after a planted drop",
        );
        let text = error.to_string();
        assert!(
            text.contains("past its kill date") || text.contains("previous issuer key"),
            "store B must name the previous-key kill date after a planted drop: {error}"
        );
        assert_ne!(
            first
                .store()
                .load_secret()
                .expect("load store A current secret"),
            old_secret,
            "issuer.secret must stay on store A and must not be copied to store B"
        );
    }

    #[test]
    fn seal_export_is_refused_before_seal() {
        let (_directory, kernel) = laboratory_kernel();
        let error = kernel
            .build_seal_bundle()
            .expect_err("seal export must refuse a live unsealed issuer");
        let text = error.to_string();
        assert!(
            text.contains("still live")
                || text.contains("after local seal")
                || text.contains("kill_date"),
            "seal export before seal must name the live issuer: {error}"
        );
        kernel.seal_issuer(60).expect("local seal must succeed");
        let bundle = kernel
            .build_seal_bundle()
            .expect("seal export must return the public artifacts after local seal");
        assert_eq!(bundle.document.event, "issuer_seal");
        assert!(
            !bundle.document.issuer_public_key_hex.trim().is_empty(),
            "seal export must name the issuer public key"
        );
        assert!(
            !bundle.document.issuance_log_line.contains("secret"),
            "seal export must not carry secret bytes"
        );
    }

    #[test]
    fn seal_export_after_remaining_life_returns_artifacts_a_verifier_can_accept() {
        let (first_directory, first) = laboratory_kernel();
        let start = Utc::now();
        first.set_now_for_test(start);
        first.seal_issuer(1).expect("seal the issuer");
        first.set_now_for_test(start + Duration::seconds(2));
        let issuer = first.store().load_issuer().expect("load the sealed issuer");
        assert!(
            issuer.is_sealed_at(first.now()),
            "remaining life must have elapsed"
        );
        let mint_error = first
            .add_agent_type(
                "laboratory".to_string(),
                vec!["read".to_string()],
                "internal".to_string(),
                2,
                crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE.to_string(),
                3600,
            )
            .expect_err("agent-type add after remaining life must stay refused");
        assert_issuer_seal_refused(&mint_error);
        let seal_directory = first_directory.path().join("seal-bundle-after-life");
        let bundle = first
            .export_seal_bundle(&seal_directory)
            .expect("seal export after remaining life must return the public artifacts");
        assert_eq!(bundle.document.event, "issuer_seal");
        let (_second_directory, second) = laboratory_kernel();
        second
            .accept_issuer_public_key(&first_issuer_public_key(&first))
            .expect("store B pins store A current key");
        second
            .accept_seal_bundle(&seal_directory)
            .expect("store B must accept the seal bundle exported after remaining life");
        let accepted = second.store().load_issuer().expect("load store B issuer");
        assert_eq!(accepted.accepted_sealed_issuer_keys.len(), 1);
        assert_eq!(
            accepted.accepted_sealed_issuer_keys[0].public_key_hex,
            first_issuer_public_key(&first)
        );
    }

    #[test]
    fn kill_export_after_remaining_life_returns_artifacts_a_verifier_can_accept() {
        let (first_directory, first) = laboratory_kernel();
        let (instance, _capability) = laboratory_capability(&first);
        let start = Utc::now();
        first.set_now_for_test(start);
        first.seal_issuer(1).expect("seal the issuer");
        first.set_now_for_test(start + Duration::seconds(2));
        let issuer = first.store().load_issuer().expect("load the sealed issuer");
        assert!(
            issuer.is_sealed_at(first.now()),
            "remaining life must have elapsed"
        );
        first
            .kill_instance(&instance.id)
            .expect("kill after remaining life must stay allowed");
        let kill_directory = first_directory.path().join("kill-bundle-after-life");
        first
            .export_kill_bundle(Some(&instance.id), None, &kill_directory)
            .expect("kill export after remaining life must return the public artifacts");
        let (_second_directory, second) = laboratory_kernel();
        second
            .accept_issuer_public_key(&first_issuer_public_key(&first))
            .expect("store B pins store A current key");
        second
            .accept_kill_bundle(&kill_directory)
            .expect("store B must accept the kill bundle exported after remaining life");
        let accepted = second.store().load_issuer().expect("load store B issuer");
        assert!(
            accepted.has_accepted_killed_instance(&instance.id),
            "store B must persist accepted death from the export after remaining life"
        );
    }

    #[test]
    fn act_export_after_remaining_life_returns_artifacts_a_verifier_can_accept() {
        let (first_directory, first) = laboratory_kernel();
        let receipt = laboratory_check_receipt(&first);
        let start = Utc::now();
        first.set_now_for_test(start);
        first.seal_issuer(1).expect("seal the issuer");
        first.set_now_for_test(start + Duration::seconds(2));
        let issuer = first.store().load_issuer().expect("load the sealed issuer");
        assert!(
            issuer.is_sealed_at(first.now()),
            "remaining life must have elapsed"
        );
        let mint_error = first
            .add_agent_type(
                "laboratory".to_string(),
                vec!["read".to_string()],
                "internal".to_string(),
                2,
                crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE.to_string(),
                3600,
            )
            .expect_err("agent-type add after remaining life must stay refused");
        assert_issuer_seal_refused(&mint_error);
        let act_directory = first_directory.path().join("act-bundle-after-life");
        first
            .export_act_bundle(&receipt, &act_directory)
            .expect("act export after remaining life must return the public artifacts");
        let (_second_directory, second) = laboratory_kernel();
        second
            .accept_issuer_public_key(&first_issuer_public_key(&first))
            .expect("store B pins store A current key");
        second
            .accept_act_bundle(&act_directory)
            .expect("store B must accept the act bundle exported after remaining life");
    }

    #[test]
    fn previous_key_after_remaining_life_still_pins_on_store_b() {
        let (_first_directory, first) = laboratory_kernel();
        let start = Utc::now();
        first.set_now_for_test(start);
        first
            .rotate_issuer_key(60)
            .expect("rotate must write a previous key with a kill date");
        first.seal_issuer(1).expect("seal the issuer");
        first.set_now_for_test(start + Duration::seconds(2));
        let issuer = first.store().load_issuer().expect("load the sealed issuer");
        assert!(
            issuer.is_sealed_at(first.now()),
            "remaining life must have elapsed"
        );
        let previous = issuer
            .previous_issuer_keys
            .last()
            .expect("rotate must keep the previous key");
        let public_key_hex = previous.public_key_hex.clone();
        let kill_date = previous.kill_date;
        let (_second_directory, second) = laboratory_kernel();
        second
            .accept_previous_issuer_key(&public_key_hex, kill_date)
            .expect("store B must pin the previous key exported after remaining life");
        let accepted = second.store().load_issuer().expect("load store B issuer");
        assert!(
            accepted
                .accepted_previous_issuer_keys
                .iter()
                .any(|key| key.public_key_hex == public_key_hex && key.kill_date == kill_date),
            "store B must persist the previous-key pin from the export after remaining life"
        );
    }

    #[test]
    fn issuer_public_listing_after_remaining_life_still_returns_the_current_key() {
        let (_directory, kernel) = laboratory_kernel();
        let expected = first_issuer_public_key(&kernel);
        let start = Utc::now();
        kernel.set_now_for_test(start);
        kernel.seal_issuer(1).expect("seal the issuer");
        kernel.set_now_for_test(start + Duration::seconds(2));
        let issuer = kernel
            .store()
            .load_issuer()
            .expect("load the sealed issuer");
        assert!(
            issuer.is_sealed_at(kernel.now()),
            "remaining life must have elapsed"
        );
        let status = kernel
            .store_status()
            .expect("store status after remaining life must still list the current public key");
        assert_eq!(
            status.current_issuer_public_key_hex, expected,
            "issuer public listing after remaining life must return the current key"
        );
        assert!(
            !status.current_issuer_public_key_hex.is_empty(),
            "issuer public listing after remaining life must not be empty"
        );
        assert!(
            status.sealed,
            "store status after remaining life must name sealed"
        );
    }

    #[test]
    fn store_b_refuses_a_present_signed_after_accepted_seal_even_if_backdated() {
        let (first_directory, first) = laboratory_kernel();
        let start = Utc::now();
        first.set_now_for_test(start);
        let (instance, capability) = laboratory_capability(&first);
        let honest = laboratory_signed_presentation(&first, &instance, &capability);
        let stolen_secret = first
            .store()
            .load_secret()
            .expect("load store A issuer secret");
        let issuer_public_key = first_issuer_public_key(&first);
        let (_second_directory, second) = laboratory_kernel();
        second.set_now_for_test(start);
        second
            .accept_issuer_public_key(&issuer_public_key)
            .expect("store B pins store A current key");
        second
            .verify_presentation(&honest)
            .expect("the honest present must verify on store B before seal accept");
        first.seal_issuer(60).expect("store A seal must succeed");
        let seal_directory = first_directory.path().join("seal-bundle");
        first
            .export_seal_bundle(&seal_directory)
            .expect("store A must export the public seal artifacts");
        second
            .accept_seal_bundle(&seal_directory)
            .expect("store B must accept the seal bundle");
        let accepted = second.store().load_issuer().expect("load store B issuer");
        assert_eq!(accepted.accepted_sealed_issuer_keys.len(), 1);
        assert_eq!(
            accepted.accepted_sealed_issuer_keys[0].public_key_hex,
            issuer_public_key
        );
        let historical = second
            .verify_presentation(&honest)
            .expect_err("store B must refuse any present from that pin after seal accept");
        let historical_text = historical.to_string();
        assert!(
            historical_text.contains("seal accept") || historical_text.contains("issuer death"),
            "store B must name seal accept: {historical}"
        );
        let mut backdated = honest.clone();
        backdated.presented_at = start - Duration::seconds(3600);
        backdated.expires_at = start + Duration::seconds(3600);
        backdated.issuer_public_key_hex = issuer_public_key.clone();
        backdated.signature_hex =
            tokens::sign_decision_receipt(&stolen_secret, &backdated.canonical_message())
                .expect("sign a backdated present with the stolen issuer secret");
        let error = second.verify_presentation(&backdated).expect_err(
            "store B must refuse a present from a sealed pin even when presented_at is backdated",
        );
        let text = error.to_string();
        assert!(
            text.contains("seal accept") || text.contains("issuer death"),
            "store B must refuse from accepted seal, not from expiry: {error}"
        );
        assert!(
            !text.contains("expired"),
            "the backdated present must still be unexpired so the lock is issuer death: {error}"
        );
        assert!(
            second.store().load_instance(&instance.id).is_err(),
            "store B must still write no instance record"
        );
        assert_ne!(
            second
                .store()
                .load_secret()
                .expect("load store B issuer secret"),
            stolen_secret,
            "issuer.secret must stay on store A and must not be copied to store B"
        );
        let mut cleared = second.store().load_issuer().expect("load store B issuer");
        cleared.accepted_sealed_issuer_keys.clear();
        let removed = second
            .store()
            .save_issuer(&cleared)
            .expect_err("store B must refuse to clear an accepted seal");
        assert!(
            removed.to_string().contains("accepted seal")
                || removed.to_string().contains("cleared"),
            "store B must name the refused accepted-seal clear: {removed}"
        );
    }

    #[test]
    fn store_b_act_accept_refuses_after_seal_accept() {
        let (first_directory, first) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&first);
        let allowed = first
            .check_tool_action(
                &instance.id,
                Some(&capability.id),
                "read",
                "payments",
                Some(&holder_proof(&first, &instance)),
                Some(&fresh_challenge(&first, &instance)),
                Some("autonomous"),
            )
            .expect("an allowed check must return a decision");
        assert_eq!(allowed.result, "allowed");
        let receipt = allowed
            .receipt
            .expect("an allowed check must return a signed receipt");
        let act_directory = first_directory.path().join("act-bundle");
        first
            .export_act_bundle(&receipt, &act_directory)
            .expect("export an act bundle before seal");
        first.seal_issuer(60).expect("store A seal must succeed");
        let seal_directory = first_directory.path().join("seal-bundle");
        first
            .export_seal_bundle(&seal_directory)
            .expect("export the seal bundle");
        let (_second_directory, second) = laboratory_kernel();
        second
            .accept_issuer_public_key(&first_issuer_public_key(&first))
            .expect("store B pins store A current key");
        second
            .accept_act_bundle(&act_directory)
            .expect("store B must accept the act bundle before seal accept");
        second
            .accept_seal_bundle(&seal_directory)
            .expect("store B must accept the seal bundle");
        let error = second
            .accept_act_bundle(&act_directory)
            .expect_err("store B must refuse act accept after seal accept");
        let text = error.to_string();
        assert!(
            text.contains("seal accept") || text.contains("issuer death"),
            "store B must name seal accept on act refuse: {error}"
        );
        assert!(
            second.store().load_instance(&instance.id).is_err(),
            "store B must write no instance record after seal accept"
        );
        first
            .verify_decision_receipt(&receipt)
            .expect("historical receipt verify may stay as audit after seal");
    }

    #[test]
    fn an_unknown_issuer_key_fails_receipt_verify() {
        let (_directory, kernel) = laboratory_kernel();
        let mut receipt = laboratory_check_receipt(&kernel);
        let foreign = crate::issuer_crypto::generate_module_lattice_key_pair()
            .expect("generate a foreign module lattice key");
        receipt.signature = tokens::sign_decision_receipt(
            &foreign.secret_key_hexadecimal,
            &receipt.canonical_message(),
        )
        .expect("sign with an unknown key");
        let error = kernel
            .verify_decision_receipt(&receipt)
            .expect_err("a receipt signed by an unknown key must fail");
        let text = error.to_string();
        assert!(
            text.contains("not valid for any accepted issuer public key")
                || text.contains("unknown issuer key"),
            "unexpected unknown-key error: {error}"
        );
    }

    #[test]
    fn an_accepted_foreign_issuer_receipt_verifies_against_the_foreign_log() {
        let (_first_directory, first) = laboratory_kernel();
        let (_second_directory, second) = laboratory_kernel();
        let receipt = laboratory_check_receipt(&first);
        let first_issuer = first.store().load_issuer().expect("load the first issuer");
        let first_public_key = first_issuer.public_keys[0].clone();
        let accepted = second
            .accept_issuer_public_key(&first_public_key)
            .expect("the second store must accept the first public key");
        assert!(
            accepted
                .accepted_issuer_public_keys
                .contains(&first_public_key),
            "the persisted accept list must include the foreign key"
        );
        assert!(
            accepted
                .accepted_issuer_public_keys
                .contains(&accepted.public_keys[0]),
            "the persisted accept list must still include the second store's own key"
        );
        second
            .verify_decision_receipt_against_issuance_log(&receipt, Some(&first.store().log_path()))
            .expect(
                "an accepted foreign key plus the foreign issuance log must verify the receipt",
            );
    }

    #[test]
    fn an_accepted_foreign_issuer_receipt_fails_without_the_foreign_log_line() {
        let (_first_directory, first) = laboratory_kernel();
        let (_second_directory, second) = laboratory_kernel();
        let receipt = laboratory_check_receipt(&first);
        let first_issuer = first.store().load_issuer().expect("load the first issuer");
        second
            .accept_issuer_public_key(&first_issuer.public_keys[0])
            .expect("the second store must accept the first public key");
        let error = second.verify_decision_receipt(&receipt).expect_err(
            "accepting a foreign key is not enough without the foreign issuance-log line",
        );
        let text = error.to_string();
        assert!(
            text.contains("issuance-log line is not present") || text.contains("issuance log"),
            "unexpected missing-foreign-log error: {error}"
        );
        assert!(
            !text.contains("not valid for any accepted issuer public key"),
            "the signature must match the accepted foreign key when only the log line is missing: {error}"
        );
    }

    #[test]
    fn issuer_rotate_replaces_the_secret_and_keeps_the_old_public_key_until_kill_date() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        let before = kernel.store().load_issuer().expect("load the issuer");
        let old_secret = kernel.store().load_secret().expect("load the old secret");
        let old_public_key = before.current_public_key_hex();
        assert!(!old_public_key.is_empty());
        assert!(before.previous_issuer_keys.is_empty());
        let rotated = kernel.rotate_issuer_key(60).expect("rotate must succeed");
        assert_eq!(rotated.current_public_key_hex(), rotated.public_keys[0]);
        assert_ne!(rotated.current_public_key_hex(), old_public_key);
        assert_eq!(rotated.previous_issuer_keys.len(), 1);
        assert_eq!(
            rotated.previous_issuer_keys[0].public_key_hex,
            old_public_key
        );
        assert_eq!(
            rotated.previous_issuer_keys[0].kill_date,
            start + Duration::seconds(60)
        );
        assert!(
            rotated
                .accepted_issuer_public_keys
                .contains(&old_public_key),
            "the old public key must stay on the accept list until kill_date"
        );
        assert!(
            rotated
                .accepted_issuer_public_keys
                .contains(&rotated.current_public_key),
            "the new public key must be on the accept list"
        );
        let new_secret = kernel.store().load_secret().expect("load the new secret");
        assert_ne!(
            new_secret, old_secret,
            "issuer.secret must be the new key only"
        );
        assert_eq!(
            crate::issuer_crypto::public_key_hexadecimal_from_secret(&new_secret)
                .expect("parse new module lattice secret"),
            rotated.current_public_key_hex()
        );
        let events = kernel.store().read_log().expect("read the log");
        assert!(
            events
                .iter()
                .any(|event| event.operation == "issuer_rotate"),
            "rotate must append an issuer_rotate log line"
        );
    }

    #[test]
    fn issuer_rotate_old_receipt_verifies_before_and_after_kill_date() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        let receipt = laboratory_check_receipt(&kernel);
        let old_secret = kernel.store().load_secret().expect("load the old secret");
        kernel.rotate_issuer_key(60).expect("rotate must succeed");
        kernel
            .verify_decision_receipt(&receipt)
            .expect("a receipt from before rotate must verify before kill_date");
        kernel.set_now_for_test(start + Duration::seconds(61));
        kernel.verify_decision_receipt(&receipt).expect(
            "after kill_date the old receipt still verifies because rotate only kills new minting",
        );

        let mut forged = receipt.clone();
        forged.issuance_log_line =
            r#"{"operation":"forged","note":"not in the issuance log"}"#.to_string();
        forged.signature = tokens::sign_decision_receipt(&old_secret, &forged.canonical_message())
            .expect("sign a forged receipt with the stolen old secret");
        let error = kernel.verify_decision_receipt(&forged).expect_err(
            "a forged-not-in-log receipt signed with a previous key past kill_date must fail",
        );
        let text = error.to_string();
        assert!(
            text.contains("past its kill date") || text.contains("stolen old secret"),
            "unexpected forged-old-key error: {error}"
        );
    }

    #[test]
    fn verify_refuses_a_planted_later_previous_key_kill_date_in_issuer_json() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        let receipt = laboratory_check_receipt(&kernel);
        let old_secret = kernel.store().load_secret().expect("load the old secret");
        let old_public_key = kernel
            .store()
            .load_issuer()
            .expect("load the issuer before rotate")
            .current_public_key_hex();
        kernel.rotate_issuer_key(60).expect("rotate must succeed");
        let honest_kill = start + Duration::seconds(60);
        let planted_kill = start + Duration::seconds(3600);
        let issuer_path = kernel.store().issuer_path();
        let raw = std::fs::read_to_string(&issuer_path).expect("read issuer.json");
        let mut planted: serde_json::Value =
            serde_json::from_str(&raw).expect("parse issuer.json");
        let on_disk_honest = planted
            .get("previous_issuer_keys")
            .and_then(|value| value.get(0))
            .and_then(|value| value.get("kill_date"))
            .and_then(|value| value.as_str())
            .expect("honest rotate must write previous_issuer_keys kill_date");
        let parsed_honest = DateTime::parse_from_rfc3339(on_disk_honest)
            .expect("honest previous-key kill_date is RFC3339")
            .with_timezone(&Utc);
        assert_eq!(
            parsed_honest, honest_kill,
            "on-disk previous-key kill_date after rotate is start plus 60 seconds"
        );
        planted["previous_issuer_keys"][0]["kill_date"] =
            serde_json::Value::String(planted_kill.to_rfc3339());
        std::fs::write(
            &issuer_path,
            serde_json::to_string_pretty(&planted).expect("serialize planted issuer.json"),
        )
        .expect("plant a later previous-key kill_date without save_issuer");
        let loaded = kernel
            .store()
            .load_issuer()
            .expect("load the issuer after the plant");
        assert_eq!(
            loaded.previous_issuer_keys[0].kill_date,
            honest_kill,
            "load_issuer must overlay the signed previous-key kill_date"
        );
        let still_planted: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&issuer_path).expect("re-read issuer.json"),
        )
        .expect("parse planted issuer.json");
        let on_disk_planted = still_planted
            .get("previous_issuer_keys")
            .and_then(|value| value.get(0))
            .and_then(|value| value.get("kill_date"))
            .and_then(|value| value.as_str())
            .expect("planted later previous-key kill_date must remain on disk");
        let parsed_planted = DateTime::parse_from_rfc3339(on_disk_planted)
            .expect("planted previous-key kill_date is RFC3339")
            .with_timezone(&Utc);
        assert_eq!(
            parsed_planted, planted_kill,
            "load_issuer must not write the file back"
        );
        assert!(
            !loaded.is_previous_issuer_key_past_kill_date(
                &old_public_key,
                start + Duration::seconds(30)
            ),
            "honest remaining life before the signed previous-key kill_date must stay live"
        );
        kernel.set_now_for_test(start + Duration::seconds(61));
        let after = kernel
            .store()
            .load_issuer()
            .expect("load the issuer after the signed previous-key kill_date");
        assert!(
            after.is_previous_issuer_key_past_kill_date(
                &old_public_key,
                start + Duration::seconds(61)
            ),
            "the signed previous-key kill_date must be live after T1"
        );
        let mut forged = receipt.clone();
        forged.issuance_log_line =
            r#"{"operation":"forged","note":"not in the issuance log"}"#.to_string();
        forged.signature = tokens::sign_decision_receipt(&old_secret, &forged.canonical_message())
            .expect("sign a forged receipt with the stolen old secret");
        let error = kernel.verify_decision_receipt(&forged).expect_err(
            "a forged-not-in-log receipt signed with a previous key past kill_date must fail",
        );
        let text = error.to_string();
        assert!(
            text.contains("past its kill date")
                || text.contains("stolen old secret")
                || text.contains("previous"),
            "unexpected forged-old-key error: {error}"
        );
        let mut postponed = kernel
            .store()
            .load_issuer()
            .expect("load the overlaid issuer for save refuse");
        postponed.previous_issuer_keys[0].kill_date = planted_kill;
        let save_error = kernel.store().save_issuer(&postponed).expect_err(
            "save_issuer must refuse a persist that postpones past the signed previous-key kill_date",
        );
        assert_issuer_previous_key_raise_refused(&save_error);
    }

    #[test]
    fn verify_refuses_a_planted_drop_of_previous_issuer_keys_in_issuer_json() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        let receipt = laboratory_check_receipt(&kernel);
        let old_secret = kernel.store().load_secret().expect("load the old secret");
        let old_public_key = kernel
            .store()
            .load_issuer()
            .expect("load the issuer before rotate")
            .current_public_key_hex();
        kernel.rotate_issuer_key(60).expect("rotate must succeed");
        let honest_kill = start + Duration::seconds(60);
        let issuer_path = kernel.store().issuer_path();
        let raw = std::fs::read_to_string(&issuer_path).expect("read issuer.json");
        let mut planted: serde_json::Value =
            serde_json::from_str(&raw).expect("parse issuer.json");
        let on_disk_list = planted
            .get("previous_issuer_keys")
            .and_then(|value| value.as_array())
            .expect("honest rotate must write previous_issuer_keys");
        assert_eq!(
            on_disk_list.len(),
            1,
            "honest rotate must persist one previous issuer key"
        );
        let on_disk_hex = on_disk_list[0]
            .get("public_key_hex")
            .and_then(|value| value.as_str())
            .expect("honest rotate must write previous_issuer_keys public_key_hex");
        assert_eq!(
            on_disk_hex.trim(),
            old_public_key.trim(),
            "on-disk previous issuer key after rotate is the old current public key"
        );
        planted["previous_issuer_keys"] = serde_json::Value::Array(Vec::new());
        std::fs::write(
            &issuer_path,
            serde_json::to_string_pretty(&planted).expect("serialize planted issuer.json"),
        )
        .expect("plant an empty previous_issuer_keys list without save_issuer");
        let loaded = kernel
            .store()
            .load_issuer()
            .expect("load the issuer after the plant");
        let restored = loaded
            .previous_issuer_keys
            .iter()
            .find(|previous| previous.public_key_hex.trim() == old_public_key.trim())
            .expect("load_issuer must restore the signed previous issuer key");
        assert_eq!(
            restored.kill_date, honest_kill,
            "load_issuer must restore the signed previous-key kill_date"
        );
        let still_planted: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&issuer_path).expect("re-read issuer.json"),
        )
        .expect("parse planted issuer.json");
        let on_disk_after = still_planted
            .get("previous_issuer_keys")
            .and_then(|value| value.as_array())
            .expect("planted previous_issuer_keys must remain on disk");
        assert!(
            on_disk_after.is_empty(),
            "load_issuer must not write the file back"
        );
        assert!(
            !loaded.is_previous_issuer_key_past_kill_date(
                &old_public_key,
                start + Duration::seconds(30)
            ),
            "honest remaining life before the signed previous-key kill_date must stay live"
        );
        kernel.set_now_for_test(start + Duration::seconds(61));
        let after = kernel
            .store()
            .load_issuer()
            .expect("load the issuer after the signed previous-key kill_date");
        assert!(
            after.is_previous_issuer_key_past_kill_date(
                &old_public_key,
                start + Duration::seconds(61)
            ),
            "the signed previous-key kill_date must be live after T1"
        );
        let mut forged = receipt.clone();
        forged.issuance_log_line =
            r#"{"operation":"forged","note":"not in the issuance log"}"#.to_string();
        forged.signature = tokens::sign_decision_receipt(&old_secret, &forged.canonical_message())
            .expect("sign a forged receipt with the stolen old secret");
        let error = kernel.verify_decision_receipt(&forged).expect_err(
            "a forged-not-in-log receipt signed with a previous key past kill_date must fail",
        );
        let text = error.to_string();
        assert!(
            text.contains("past its kill date")
                || text.contains("stolen old secret")
                || text.contains("previous"),
            "unexpected forged-old-key error: {error}"
        );
        let mut dropped = kernel
            .store()
            .load_issuer()
            .expect("load the overlaid issuer for save refuse");
        dropped.previous_issuer_keys.clear();
        let save_error = kernel.store().save_issuer(&dropped).expect_err(
            "save_issuer must refuse a persist that omits a signed previous issuer key",
        );
        assert_issuer_previous_key_raise_refused(&save_error);
    }

    #[test]
    fn issuer_rotate_old_capability_verifies_until_capability_expiry() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        let (instance, capability) = laboratory_capability(&kernel);
        kernel.rotate_issuer_key(60).expect("rotate must succeed");
        let nonce = fresh_challenge(&kernel, &instance);
        kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&nonce),
                Some("autonomous"),
            )
            .expect("an old capability must verify before kill_date");
        kernel.set_now_for_test(start + Duration::seconds(61));
        let later_nonce = fresh_challenge(&kernel, &instance);
        kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&later_nonce),
                Some("autonomous"),
            )
            .expect("an old capability must still verify after kill_date until capability expiry");
        kernel.set_now_for_test(capability.expires + Duration::seconds(1));
        let expired_nonce = fresh_challenge(&kernel, &instance);
        let error = kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&expired_nonce),
                Some("autonomous"),
            )
            .expect_err("an expired capability must fail after rotate");
        assert!(
            error.to_string().contains("expired"),
            "unexpected expiry error: {error}"
        );
    }

    #[test]
    fn issuer_rotate_new_birth_signs_with_the_current_key_only() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        kernel.rotate_issuer_key(60).expect("rotate must succeed");
        let issuer = kernel.store().load_issuer().expect("load the issuer");
        let agent_type = laboratory_agent_type(&kernel, "payments", 2);
        let birth = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "payments",
                None,
            )
            .expect("a new birth after rotate must succeed");
        let token_bytes = hex::decode(&birth.capability.biscuit).expect("decode the new token");
        let biscuit = tokens::public_key_from_hexadecimal(&issuer.biscuit_public_key_hex)
            .expect("parse the Biscuit envelope public key");
        tokens::authorize_token(biscuit, &token_bytes, "read", "payments", "autonomous")
            .expect("the new birth token must verify with the Biscuit envelope key");
        crate::issuer_crypto::require_module_lattice_public_key(&issuer.current_public_key_hex())
            .expect("the current identity root after rotate must stay Module-Lattice");
        assert_eq!(
            birth.capability.issuer_public_key_hex,
            issuer.current_public_key_hex(),
            "the new birth record must be signed with the current Module-Lattice key only"
        );
        assert_ne!(
            issuer.current_public_key_hex(),
            issuer.previous_issuer_keys[0].public_key_hex,
            "rotate must change the Module-Lattice current key"
        );
        let nonce = fresh_challenge(&kernel, &birth.instance);
        kernel
            .verify_capability(
                &birth.capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &birth.instance)),
                Some(&nonce),
                Some("autonomous"),
            )
            .expect("a new birth after rotate must verify");
        let allowed = kernel
            .check_tool_action(
                &birth.instance.id,
                Some(&birth.capability.id),
                "read",
                "payments",
                Some(&holder_proof(&kernel, &birth.instance)),
                Some(&fresh_challenge(&kernel, &birth.instance)),
                Some("autonomous"),
            )
            .expect("a new check after rotate must run");
        assert_eq!(allowed.result, "allowed");
        let receipt = allowed
            .receipt
            .expect("the new check must return a receipt");
        kernel
            .verify_decision_receipt(&receipt)
            .expect("a receipt signed with the current key must verify");
        tokens::verify_decision_receipt_signature(
            &issuer.current_public_key_hex(),
            &receipt.canonical_message(),
            &receipt.signature,
        )
        .expect("the new receipt must match the current key");
        let previous_receipt = tokens::verify_decision_receipt_signature(
            &issuer.previous_issuer_keys[0].public_key_hex,
            &receipt.canonical_message(),
            &receipt.signature,
        );
        assert!(
            previous_receipt.is_err(),
            "the new receipt must not match the previous key"
        );
    }

    #[test]
    fn issuer_rotate_forged_old_key_token_after_kill_date_fails() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        let (instance, capability) = laboratory_capability(&kernel);
        let _old_secret = kernel.store().load_secret().expect("load the old secret");
        kernel.rotate_issuer_key(60).expect("rotate must succeed");
        kernel.set_now_for_test(start + Duration::seconds(61));
        let biscuit_secret = kernel
            .store()
            .load_biscuit_secret()
            .expect("load the biscuit envelope secret");
        let biscuit_pair = tokens::keypair_from_private_hexadecimal(&biscuit_secret)
            .expect("parse the biscuit envelope secret");
        let forged_id = "01FORGEDCAPABILITYTOKEN0000000000";
        let expires: std::time::SystemTime = (start + Duration::seconds(3600)).into();
        let (token_bytes, revoke_identifier) = tokens::mint_token(
            &biscuit_pair,
            forged_id,
            &instance.id,
            "read",
            "payments",
            "autonomous",
            expires,
        )
        .expect("mint an offline token with the stolen old secret");
        let mut forged = capability.clone();
        forged.id = forged_id.to_string();
        forged.biscuit = hex::encode(&token_bytes);
        forged.revoke_identifier = revoke_identifier;
        kernel
            .store()
            .save_capability(&forged)
            .expect("write the forged capability record");
        kernel
            .store()
            .save_chain(&crate::records::Chain {
                capability_id: forged.id.clone(),
                parent_capability_id: None,
                hop_index: 0,
                attenuated_by: "forged".to_string(),
                revoke_from_here: false,
                issuer_public_key_hex: String::new(),
                issuer_signature_hex: String::new(),
                issuer_signatures: Vec::new(),
            })
            .expect("write the forged chain record");
        let nonce = fresh_challenge(&kernel, &instance);
        let error = kernel
            .verify_capability(
                &forged.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&nonce),
                Some("autonomous"),
            )
            .expect_err("an offline mint with a stolen old secret after kill_date must fail");
        let text = error.to_string();
        assert!(
            text.contains("past its kill date")
                || text.contains("stolen old secret")
                || text.contains("not present in the issuance log"),
            "unexpected forged-token error: {error}"
        );
    }

    fn birth_write_line_hash(kernel: &Kernel) -> String {
        let events = kernel.store().read_log().expect("read the issuance log");
        events
            .iter()
            .find(|event| event.operation == "birth_write")
            .expect("the birth_write line must exist")
            .line_hash
            .clone()
    }

    fn laboratory_birth(kernel: &Kernel) -> BirthWrite {
        let agent_type = laboratory_agent_type(kernel, "internal", 2);
        kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "internal",
                None,
            )
            .expect("birth an instance and the first capability")
    }

    #[test]
    fn proving_a_real_issuance_log_line_checks_against_the_current_root() {
        let (_directory, kernel) = laboratory_kernel();
        let _birth = laboratory_birth(&kernel);
        let line_hash = birth_write_line_hash(&kernel);
        let proof = kernel
            .prove_issuance_log_inclusion(&line_hash)
            .expect("prove a real birth line");
        assert_eq!(proof.line_hash, line_hash);
        kernel
            .check_issuance_log_inclusion_proof(&proof, None)
            .expect("check-proof must accept a real proof against this store root");
        let root = kernel
            .issuance_log_merkle_root()
            .expect("compute the current Merkle root");
        assert_eq!(proof.root, root.root);
        assert!(
            root.leaf_count >= 1,
            "birth must append at least one issuance-log line"
        );
    }

    #[test]
    fn altering_one_inclusion_proof_sibling_fails_closed() {
        let (_directory, kernel) = laboratory_kernel();
        let first = laboratory_birth(&kernel);
        kernel
            .birth_write(
                &first.instance.agent_type_id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "internal",
                None,
            )
            .expect("append a second birth so the Merkle path has a sibling");
        let line_hash = birth_write_line_hash(&kernel);
        let mut proof = kernel
            .prove_issuance_log_inclusion(&line_hash)
            .expect("prove a real birth line");
        assert!(
            !proof.sibling_hashes.is_empty(),
            "two issuance-log lines must produce a sibling"
        );
        proof.sibling_hashes[0] = crate::log_chain::sha256_hexadecimal(b"tampered-sibling");
        let error = kernel
            .check_issuance_log_inclusion_proof(&proof, None)
            .expect_err("a tampered sibling must fail closed");
        let text = error.to_string();
        assert!(
            text.contains("does not match") || text.contains("fails closed"),
            "unexpected tampered-sibling error: {error}"
        );
    }

    #[test]
    fn proving_a_missing_issuance_log_line_fails_closed() {
        let (_directory, kernel) = laboratory_kernel();
        let _birth = laboratory_birth(&kernel);
        let missing = crate::log_chain::sha256_hexadecimal(b"missing-line-hash");
        let error = kernel
            .prove_issuance_log_inclusion(&missing)
            .expect_err("a missing line_hash must fail closed");
        assert!(
            error
                .to_string()
                .contains("not present in this issuance log"),
            "unexpected missing-line error: {error}"
        );
    }

    #[test]
    fn an_old_inclusion_proof_checks_against_the_old_root_and_fails_against_the_new_root() {
        let (_directory, kernel) = laboratory_kernel();
        let first = laboratory_birth(&kernel);
        let line_hash = birth_write_line_hash(&kernel);
        let old_root = kernel
            .issuance_log_merkle_root()
            .expect("compute the old Merkle root");
        let old_proof = kernel
            .prove_issuance_log_inclusion(&line_hash)
            .expect("prove the first birth line");
        kernel
            .check_issuance_log_inclusion_proof(&old_proof, Some(&old_root.root))
            .expect("the old proof must check against the old root");
        kernel
            .birth_write(
                &first.instance.agent_type_id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "internal",
                None,
            )
            .expect("append a second birth");
        let new_root = kernel
            .issuance_log_merkle_root()
            .expect("compute the new Merkle root");
        assert_ne!(
            old_root.root, new_root.root,
            "a new append must change the Merkle root"
        );
        kernel
            .check_issuance_log_inclusion_proof(&old_proof, Some(&old_root.root))
            .expect("an old proof must still check against the old root after a new append");
        let error = kernel
            .check_issuance_log_inclusion_proof(&old_proof, None)
            .expect_err("an old proof must fail against the new store root");
        assert!(
            error.to_string().contains("does not match"),
            "unexpected old-proof-against-new-root error: {error}"
        );
        let supplied_new = kernel
            .check_issuance_log_inclusion_proof(&old_proof, Some(&new_root.root))
            .expect_err("an old proof must fail against a supplied new root");
        assert!(
            supplied_new.to_string().contains("does not match"),
            "unexpected old-proof-against-supplied-new-root error: {supplied_new}"
        );
    }

    #[test]
    fn a_signed_tree_head_checks_against_the_issuer_key() {
        let (_directory, kernel) = laboratory_kernel();
        let _birth = laboratory_birth(&kernel);
        let tree_head = kernel
            .sign_issuance_log_tree_head()
            .expect("sign the current Merkle root");
        let issuer = kernel.store().load_issuer().expect("load the issuer");
        assert_eq!(
            tree_head.issuer_public_key_hex,
            issuer.current_public_key_hex()
        );
        assert!(
            tree_head.leaf_count >= 1,
            "birth must append at least one issuance-log line"
        );
        assert!(!tree_head.signature_hex.is_empty());
        kernel
            .check_issuance_log_tree_head(&tree_head, false)
            .expect("check-root must accept a real signed tree head");
        kernel
            .check_issuance_log_tree_head(&tree_head, true)
            .expect("require-current-root must accept a matching signed tree head");
    }

    #[test]
    fn a_tampered_signed_tree_head_root_fails_closed() {
        let (_directory, kernel) = laboratory_kernel();
        let _birth = laboratory_birth(&kernel);
        let mut tree_head = kernel
            .sign_issuance_log_tree_head()
            .expect("sign the current Merkle root");
        tree_head.merkle_root = crate::log_chain::sha256_hexadecimal(b"tampered-root");
        let error = kernel
            .check_issuance_log_tree_head(&tree_head, false)
            .expect_err("a tampered Merkle root must fail closed");
        let text = error.to_string();
        assert!(
            text.contains("not valid")
                || text.contains("tampered")
                || text.contains("fails closed"),
            "unexpected tampered-root error: {error}"
        );
    }

    #[test]
    fn a_signed_tree_head_with_an_unknown_issuer_key_fails_closed() {
        let (_directory, first) = laboratory_kernel();
        let _birth = laboratory_birth(&first);
        let tree_head = first
            .sign_issuance_log_tree_head()
            .expect("sign the first store Merkle root");
        let (_directory_two, second) = laboratory_kernel();
        let error = second
            .check_issuance_log_tree_head(&tree_head, false)
            .expect_err("an unknown issuer key must fail closed");
        assert!(
            error.to_string().contains("unknown issuer key"),
            "unexpected unknown-key error: {error}"
        );
        second
            .accept_issuer_public_key(&tree_head.issuer_public_key_hex)
            .expect("accept the first issuer public key");
        second
            .check_issuance_log_tree_head(&tree_head, false)
            .expect("a second store can pin a foreign signed tree head after accepting the key");
        let require_current = second
            .check_issuance_log_tree_head(&tree_head, true)
            .expect_err("require-current-root must refuse a foreign tree head");
        assert!(
            require_current.to_string().contains("current Merkle root")
                || require_current.to_string().contains("leaf_count"),
            "unexpected require-current-root error: {require_current}"
        );
    }

    #[test]
    fn rotate_then_a_new_signed_tree_head_uses_the_new_key_and_the_old_tree_head_remains_a_historical_pin(
    ) {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        let _birth = laboratory_birth(&kernel);
        let old_tree_head = kernel
            .sign_issuance_log_tree_head()
            .expect("sign with the first issuer key");
        let old_key = old_tree_head.issuer_public_key_hex.clone();
        kernel.rotate_issuer_key(60).expect("rotate must succeed");
        let issuer = kernel.store().load_issuer().expect("load the issuer");
        let new_tree_head = kernel
            .sign_issuance_log_tree_head()
            .expect("sign with the current issuer key after rotate");
        assert_eq!(
            new_tree_head.issuer_public_key_hex,
            issuer.current_public_key_hex()
        );
        assert_ne!(
            new_tree_head.issuer_public_key_hex, old_key,
            "a new signed tree head must use the new key"
        );
        kernel
            .check_issuance_log_tree_head(&old_tree_head, false)
            .expect(
                "an old signed tree head must still check as a historical pin before kill_date",
            );
        kernel.set_now_for_test(start + Duration::seconds(61));
        kernel
            .check_issuance_log_tree_head(&old_tree_head, false)
            .expect("an old signed tree head must still check as a historical pin after kill_date");
        kernel
            .check_issuance_log_tree_head(&new_tree_head, false)
            .expect("the new signed tree head must still check after kill_date");
    }

    #[test]
    fn a_previous_key_used_to_sign_a_tree_head_after_kill_date_fails_closed() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        let _birth = laboratory_birth(&kernel);
        let old_secret = kernel.store().load_secret().expect("load the old secret");
        kernel.rotate_issuer_key(60).expect("rotate must succeed");
        let after_kill = start + Duration::seconds(61);
        kernel.set_now_for_test(after_kill);
        let root = kernel
            .issuance_log_merkle_root()
            .expect("compute the current Merkle root");
        let old_public_key = crate::issuer_crypto::public_key_hexadecimal_from_secret(&old_secret)
            .expect("parse the stolen old module lattice secret");
        let signed_at = DateTime::<Utc>::from_timestamp(after_kill.timestamp(), 0)
            .expect("truncate the injected clock");
        let message = crate::log_tree_head::signed_tree_head_message(
            &root.root,
            root.leaf_count,
            signed_at,
            &old_public_key,
        );
        let signature_hex = tokens::sign_decision_receipt(&old_secret, &message)
            .expect("sign with the stolen old secret after kill_date");
        let forged = crate::log_tree_head::SignedTreeHead {
            merkle_root: root.root,
            leaf_count: root.leaf_count,
            signed_at,
            issuer_public_key_hex: old_public_key,
            signature_hex,
            issuer_signatures: Vec::new(),
        };
        let error = kernel
            .check_issuance_log_tree_head(&forged, false)
            .expect_err("a previous key used after kill_date must fail closed");
        assert!(
            error.to_string().contains("after its kill date"),
            "unexpected previous-key-after-kill-date error: {error}"
        );
    }

    #[test]
    fn require_current_root_fails_after_a_new_append() {
        let (_directory, kernel) = laboratory_kernel();
        let first = laboratory_birth(&kernel);
        let old_tree_head = kernel
            .sign_issuance_log_tree_head()
            .expect("sign the first Merkle root");
        kernel
            .check_issuance_log_tree_head(&old_tree_head, true)
            .expect("require-current-root must accept the matching root");
        kernel
            .birth_write(
                &first.instance.agent_type_id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "internal",
                None,
            )
            .expect("append a second birth");
        let error = kernel
            .check_issuance_log_tree_head(&old_tree_head, true)
            .expect_err("require-current-root must refuse an old tree head after a new append");
        assert!(
            error.to_string().contains("current Merkle root")
                || error.to_string().contains("leaf_count"),
            "unexpected require-current-root-after-append error: {error}"
        );
        kernel
            .check_issuance_log_tree_head(&old_tree_head, false)
            .expect("default check-root must still accept the old signed tree head as a pin");
    }

    #[test]
    fn a_signed_tree_head_with_an_empty_signature_fails_closed() {
        let (_directory, kernel) = laboratory_kernel();
        let _birth = laboratory_birth(&kernel);
        let mut tree_head = kernel
            .sign_issuance_log_tree_head()
            .expect("sign the current Merkle root");
        tree_head.signature_hex.clear();
        let error = kernel
            .check_issuance_log_tree_head(&tree_head, false)
            .expect_err("a missing signature must fail closed");
        assert!(
            error.to_string().contains("missing a signature"),
            "unexpected empty-signature error: {error}"
        );
    }

    fn other_holder_public_key() -> String {
        tokens::public_key_hexadecimal(&tokens::generate_keypair())
    }

    #[test]
    fn first_binder_refuses_a_mutated_holder_public_key_on_save() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 2);
        let mut instance = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth must set the first binder");
        let original = instance.holder_public_key.clone();
        instance.holder_public_key = other_holder_public_key();
        let error = kernel
            .store()
            .save_instance(&instance)
            .expect_err("a mutated holder public key must be refused");
        assert!(
            error.to_string().contains("first binder"),
            "unexpected first-binder error: {error}"
        );
        let stored = kernel
            .store()
            .load_instance(&instance.id)
            .expect("load the instance");
        assert_eq!(stored.holder_public_key, original);
    }

    #[test]
    fn first_binder_refuses_a_mutated_child_holder_public_key() {
        let (_directory, kernel) = laboratory_kernel();
        let (parent, capability) = laboratory_capability(&kernel);
        let parent_nonce = fresh_challenge(&kernel, &parent);
        let child = kernel
            .spawn_child(
                &parent.id,
                &capability.id,
                "child".to_string(),
                BTreeMap::new(),
                "read",
                "payments/prod",
                None,
                Some(&holder_proof(&kernel, &parent)),
                Some(&parent_nonce),
            )
            .expect("a narrower child must succeed");
        assert_ne!(
            child.instance.holder_public_key, parent.holder_public_key,
            "the child must have its own holder public key"
        );
        let original = child.instance.holder_public_key.clone();
        let mut mutated = child.instance.clone();
        mutated.holder_public_key = other_holder_public_key();
        let error = kernel
            .store()
            .save_instance(&mutated)
            .expect_err("changing the child holder public key must be refused");
        assert!(
            error.to_string().contains("first binder"),
            "unexpected child first-binder error: {error}"
        );
        let stored = kernel
            .store()
            .load_instance(&child.instance.id)
            .expect("load the child");
        assert_eq!(stored.holder_public_key, original);
    }

    #[test]
    fn first_binder_refuses_a_mutated_parent_holder_public_key() {
        let (_directory, kernel) = laboratory_kernel();
        let (parent, capability) = laboratory_capability(&kernel);
        let parent_nonce = fresh_challenge(&kernel, &parent);
        let _child = kernel
            .spawn_child(
                &parent.id,
                &capability.id,
                "child".to_string(),
                BTreeMap::new(),
                "read",
                "payments/prod",
                None,
                Some(&holder_proof(&kernel, &parent)),
                Some(&parent_nonce),
            )
            .expect("a narrower child must succeed");
        let original = parent.holder_public_key.clone();
        let mut mutated = parent.clone();
        mutated.holder_public_key = other_holder_public_key();
        let error = kernel
            .store()
            .save_instance(&mutated)
            .expect_err("changing the parent holder public key must be refused");
        assert!(
            error.to_string().contains("first binder"),
            "unexpected parent first-binder error: {error}"
        );
        let stored = kernel
            .store()
            .load_instance(&parent.id)
            .expect("load the parent");
        assert_eq!(stored.holder_public_key, original);
    }

    #[test]
    fn kill_and_revoke_leave_holder_public_key_unchanged() {
        let (_directory, kernel) = laboratory_kernel();
        let (parent, capability) = laboratory_capability(&kernel);
        let parent_key = parent.holder_public_key.clone();
        let parent_nonce = fresh_challenge(&kernel, &parent);
        let child = kernel
            .spawn_child(
                &parent.id,
                &capability.id,
                "child".to_string(),
                BTreeMap::new(),
                "read",
                "payments/prod",
                None,
                Some(&holder_proof(&kernel, &parent)),
                Some(&parent_nonce),
            )
            .expect("a narrower child must succeed");
        let child_key = child.instance.holder_public_key.clone();
        kernel
            .kill_capability(&capability.id)
            .expect("capability revoke must succeed");
        let after_capability_kill = kernel
            .store()
            .load_instance(&parent.id)
            .expect("load the parent after capability kill");
        assert_eq!(after_capability_kill.holder_public_key, parent_key);
        kernel
            .kill_instance(&parent.id)
            .expect("parent kill must succeed");
        let killed_parent = kernel
            .store()
            .load_instance(&parent.id)
            .expect("load the killed parent");
        let killed_child = kernel
            .store()
            .load_instance(&child.instance.id)
            .expect("load the killed child");
        assert_eq!(killed_parent.status, InstanceStatus::Revoked);
        assert_eq!(killed_child.status, InstanceStatus::Revoked);
        assert_eq!(killed_parent.holder_public_key, parent_key);
        assert_eq!(killed_child.holder_public_key, child_key);
    }

    #[test]
    fn a_new_instance_with_a_holder_key_still_succeeds() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 2);
        let instance = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("a new instance must set the first binder");
        assert!(!instance.holder_public_key.trim().is_empty());
        assert_ne!(instance.id, instance.holder_public_key);
        let shown = kernel
            .show_instance(&instance.id)
            .expect("show must return the born instance");
        assert_eq!(shown.holder_public_key, instance.holder_public_key);
        let again = kernel
            .birth_instance(&agent_type.id, "second".to_string(), BTreeMap::new(), None)
            .expect("a second new instance must set its own first binder");
        assert_ne!(again.holder_public_key, instance.holder_public_key);
        let error = kernel
            .rebind_holder_public_key(&instance.id, &other_holder_public_key())
            .expect_err("rebind must always refuse");
        assert!(
            error.to_string().contains("first binder"),
            "unexpected rebind error: {error}"
        );
        let stored = kernel
            .store()
            .load_instance(&instance.id)
            .expect("load after refused rebind");
        assert_eq!(stored.holder_public_key, instance.holder_public_key);
    }

    #[test]
    fn first_binder_refuses_an_empty_holder_public_key() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 2);
        let mut instance = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth must set the first binder");
        let original = instance.holder_public_key.clone();
        instance.holder_public_key.clear();
        let error = kernel
            .store()
            .save_instance(&instance)
            .expect_err("an empty holder public key must be refused");
        assert!(
            error.to_string().contains("must not be empty")
                || error.to_string().contains("first binder"),
            "unexpected empty-binder error: {error}"
        );
        let stored = kernel
            .store()
            .load_instance(&instance.id)
            .expect("load the instance");
        assert_eq!(stored.holder_public_key, original);
    }

    fn assert_authorization_limit_raise_refused(error: &Error) {
        let text = error.to_string();
        assert!(
            text.contains("authorization limit") && text.contains("raise"),
            "unexpected authorization-limit freeze error: {error}"
        );
    }

    #[test]
    fn authorization_limit_freeze_refuses_a_raised_limit_on_save() {
        let (_directory, kernel) = laboratory_kernel();
        let mut agent_type = laboratory_agent_type(&kernel, "payments", 2);
        let original = agent_type.authorization_limit.clone();
        agent_type.authorization_limit = "public".to_string();
        let error = kernel
            .store()
            .save_agent_type(&agent_type)
            .expect_err("a raised authorization limit must be refused");
        assert_authorization_limit_raise_refused(&error);
        let stored = kernel
            .store()
            .load_agent_type(&agent_type.id)
            .expect("load the agent type");
        assert_eq!(stored.authorization_limit, original);
    }

    #[test]
    fn authorization_limit_freeze_refuses_a_raised_limit_after_an_instance_exists() {
        let (_directory, kernel) = laboratory_kernel();
        let mut agent_type = laboratory_agent_type(&kernel, "payments", 2);
        let original = agent_type.authorization_limit.clone();
        kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth an instance of the type");
        agent_type.authorization_limit = "public".to_string();
        let error = kernel
            .store()
            .save_agent_type(&agent_type)
            .expect_err("a raised authorization limit after an instance exists must be refused");
        assert_authorization_limit_raise_refused(&error);
        let stored = kernel
            .store()
            .load_agent_type(&agent_type.id)
            .expect("load the agent type");
        assert_eq!(stored.authorization_limit, original);
    }

    #[test]
    fn authorization_limit_freeze_refuses_a_shorter_prefix() {
        let (_directory, kernel) = laboratory_kernel();
        let mut agent_type = laboratory_agent_type(&kernel, "payments/prod", 2);
        let original = agent_type.authorization_limit.clone();
        agent_type.authorization_limit = "payments".to_string();
        let error = kernel
            .store()
            .save_agent_type(&agent_type)
            .expect_err("a shorter prefix is a raise and must be refused");
        assert_authorization_limit_raise_refused(&error);
        let stored = kernel
            .store()
            .load_agent_type(&agent_type.id)
            .expect("load the agent type");
        assert_eq!(stored.authorization_limit, original);
    }

    #[test]
    fn authorization_limit_freeze_allows_a_narrower_limit() {
        let (_directory, kernel) = laboratory_kernel();
        let mut agent_type = laboratory_agent_type(&kernel, "payments", 2);
        agent_type.authorization_limit = "payments/prod".to_string();
        kernel
            .store()
            .save_agent_type(&agent_type)
            .expect("a child of the stored limit is a narrowing and may persist");
        let stored = kernel
            .store()
            .load_agent_type(&agent_type.id)
            .expect("load the narrowed agent type");
        assert_eq!(stored.authorization_limit, "payments/prod");
    }

    #[test]
    fn authorization_limit_freeze_allows_the_same_limit() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 2);
        kernel
            .store()
            .save_agent_type(&agent_type)
            .expect("persisting the same authorization limit must succeed");
        let stored = kernel
            .store()
            .load_agent_type(&agent_type.id)
            .expect("load the agent type");
        assert_eq!(stored.authorization_limit, "payments");
    }

    #[test]
    fn instance_still_cannot_exceed_the_type_after_a_refused_raise() {
        let (_directory, kernel) = laboratory_kernel();
        let mut agent_type = laboratory_agent_type(&kernel, "payments", 2);
        let instance = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth an instance");
        agent_type.authorization_limit = "public".to_string();
        kernel
            .store()
            .save_agent_type(&agent_type)
            .expect_err("the raise must be refused");
        let error = kernel
            .mint_capability(&instance.id, "read", "public", None)
            .expect_err("an instance still cannot mint above the stored type limit");
        assert!(
            error.to_string().contains("authorization limit"),
            "unexpected mint error after refused raise: {error}"
        );
        kernel
            .mint_capability(&instance.id, "read", "payments/prod", None)
            .expect("a child destination of the stored type limit must still succeed");
    }

    #[test]
    fn authorization_limit_raise_command_always_refuses() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 2);
        let error = kernel
            .raise_authorization_limit(&agent_type.id, "public")
            .expect_err("raise must refuse when no instance exists");
        assert_authorization_limit_raise_refused(&error);
        let stored = kernel
            .store()
            .load_agent_type(&agent_type.id)
            .expect("load after refused raise");
        assert_eq!(stored.authorization_limit, "payments");
        kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth an instance");
        let error = kernel
            .raise_authorization_limit(&agent_type.id, "public")
            .expect_err("raise must refuse after an instance exists");
        assert_authorization_limit_raise_refused(&error);
        let stored = kernel
            .store()
            .load_agent_type(&agent_type.id)
            .expect("load after the second refused raise");
        assert_eq!(stored.authorization_limit, "payments");
    }

    fn assert_allowed_intents_raise_refused(error: &Error) {
        let text = error.to_string();
        assert!(
            text.contains("allowed intents")
                && (text.contains("adds an intent") || text.contains("raise")),
            "unexpected allowed-intents freeze error: {error}"
        );
    }

    fn assert_delegation_depth_raise_refused(error: &Error) {
        let text = error.to_string();
        assert!(
            text.contains("delegation depth")
                && (text.contains("raises") || text.contains("raise")),
            "unexpected maximum-delegation-depth freeze error: {error}"
        );
    }

    #[test]
    fn allowed_intents_freeze_refuses_an_added_intent_on_save() {
        let (_directory, kernel) = laboratory_kernel();
        let mut agent_type = laboratory_agent_type(&kernel, "payments", 2);
        assert_eq!(
            agent_type.allowed_intents,
            vec!["read".to_string(), "read/limited".to_string()]
        );
        let original = agent_type.allowed_intents.clone();
        agent_type.allowed_intents.push("write".to_string());
        let error = kernel
            .store()
            .save_agent_type(&agent_type)
            .expect_err("adding a third intent must be refused");
        assert_allowed_intents_raise_refused(&error);
        let stored = kernel
            .store()
            .load_agent_type(&agent_type.id)
            .expect("load the agent type");
        assert_eq!(stored.allowed_intents, original);
    }

    #[test]
    fn allowed_intents_freeze_allows_a_narrower_set() {
        let (_directory, kernel) = laboratory_kernel();
        let mut agent_type = laboratory_agent_type(&kernel, "payments", 2);
        agent_type.allowed_intents = vec!["read".to_string()];
        kernel
            .store()
            .save_agent_type(&agent_type)
            .expect("removing an intent is a narrowing and may persist");
        let stored = kernel
            .store()
            .load_agent_type(&agent_type.id)
            .expect("load the narrowed agent type");
        assert_eq!(stored.allowed_intents, vec!["read".to_string()]);
        assert!(allowed_intents_within_stored(
            &stored.allowed_intents,
            &vec!["read".to_string(), "read/limited".to_string()]
        ));
    }

    #[test]
    fn allowed_intents_freeze_allows_the_same_set() {
        let (_directory, kernel) = laboratory_kernel();
        let mut agent_type = laboratory_agent_type(&kernel, "payments", 2);
        kernel
            .store()
            .save_agent_type(&agent_type)
            .expect("persisting the same allowed intents must succeed");
        agent_type.allowed_intents = vec!["read/limited".to_string(), "read".to_string()];
        kernel
            .store()
            .save_agent_type(&agent_type)
            .expect("the same intent set in a different order may persist");
        let stored = kernel
            .store()
            .load_agent_type(&agent_type.id)
            .expect("load the agent type");
        assert_eq!(
            stored.allowed_intents,
            vec!["read/limited".to_string(), "read".to_string()]
        );
    }

    #[test]
    fn mint_of_a_removed_intent_fails_after_narrow() {
        let (_directory, kernel) = laboratory_kernel();
        let mut agent_type = laboratory_agent_type(&kernel, "payments", 2);
        agent_type.allowed_intents = vec!["read".to_string()];
        kernel
            .store()
            .save_agent_type(&agent_type)
            .expect("narrowing to one of the two intents may persist");
        let instance = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth an instance of the narrowed type");
        let error = kernel
            .mint_capability(&instance.id, "read/limited", "payments", None)
            .expect_err("mint of a removed intent must fail");
        assert!(
            error.to_string().contains("allowed intents"),
            "unexpected mint error after intent narrow: {error}"
        );
        kernel
            .mint_capability(&instance.id, "read", "payments", None)
            .expect("mint of a remaining intent must still succeed");
    }

    #[test]
    fn allowed_intents_add_intent_command_always_refuses() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 2);
        let original = agent_type.allowed_intents.clone();
        let error = kernel
            .add_allowed_intent(&agent_type.id, "write")
            .expect_err("add-intent must refuse when no instance exists");
        assert_allowed_intents_raise_refused(&error);
        let stored = kernel
            .store()
            .load_agent_type(&agent_type.id)
            .expect("load after refused add-intent");
        assert_eq!(stored.allowed_intents, original);
        kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth an instance");
        let error = kernel
            .add_allowed_intent(&agent_type.id, "write")
            .expect_err("add-intent must refuse after an instance exists");
        assert_allowed_intents_raise_refused(&error);
        let stored = kernel
            .store()
            .load_agent_type(&agent_type.id)
            .expect("load after the second refused add-intent");
        assert_eq!(stored.allowed_intents, original);
    }

    #[test]
    fn max_delegation_depth_freeze_refuses_a_raised_depth() {
        let (_directory, kernel) = laboratory_kernel();
        let mut agent_type = laboratory_agent_type(&kernel, "payments", 2);
        let original = agent_type.max_delegation_depth;
        agent_type.max_delegation_depth = 4;
        let error = kernel
            .store()
            .save_agent_type(&agent_type)
            .expect_err("a raised maximum delegation depth must be refused");
        assert_delegation_depth_raise_refused(&error);
        let stored = kernel
            .store()
            .load_agent_type(&agent_type.id)
            .expect("load the agent type");
        assert_eq!(stored.max_delegation_depth, original);
    }

    #[test]
    fn max_delegation_depth_freeze_allows_a_narrower_depth() {
        let (_directory, kernel) = laboratory_kernel();
        let mut agent_type = laboratory_agent_type(&kernel, "payments", 2);
        agent_type.max_delegation_depth = 1;
        kernel
            .store()
            .save_agent_type(&agent_type)
            .expect("a lower maximum delegation depth is a narrowing and may persist");
        let stored = kernel
            .store()
            .load_agent_type(&agent_type.id)
            .expect("load the narrowed agent type");
        assert_eq!(stored.max_delegation_depth, 1);
    }

    #[test]
    fn max_delegation_depth_freeze_allows_the_same_depth() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 2);
        kernel
            .store()
            .save_agent_type(&agent_type)
            .expect("persisting the same maximum delegation depth must succeed");
        let stored = kernel
            .store()
            .load_agent_type(&agent_type.id)
            .expect("load the agent type");
        assert_eq!(stored.max_delegation_depth, 2);
    }

    fn assert_capability_expiry_extension_refused(error: &Error) {
        let text = error.to_string();
        assert!(
            text.contains("expires") && (text.contains("extension") || text.contains("frozen")),
            "unexpected capability-expiry freeze error: {error}"
        );
    }

    #[test]
    fn expiry_freeze_first_persist_sets_expires() {
        let (_directory, kernel) = laboratory_kernel();
        let (_instance, capability) = laboratory_capability(&kernel);
        assert!(capability.expires > capability.issued);
        let stored = kernel
            .store()
            .load_capability(&capability.id)
            .expect("load the minted capability");
        assert_eq!(stored.expires, capability.expires);
    }

    #[test]
    fn expiry_freeze_refuses_a_later_expires_on_save() {
        let (_directory, kernel) = laboratory_kernel();
        let (_instance, mut capability) = laboratory_capability(&kernel);
        let original = capability.expires;
        capability.expires = original + Duration::seconds(3600);
        let error = kernel
            .store()
            .save_capability(&capability)
            .expect_err("a later expires must be refused");
        assert_capability_expiry_extension_refused(&error);
        let stored = kernel
            .store()
            .load_capability(&capability.id)
            .expect("load the capability");
        assert_eq!(stored.expires, original);
    }

    #[test]
    fn expiry_freeze_allows_a_shorter_expires() {
        let (_directory, kernel) = laboratory_kernel();
        let (_instance, mut capability) = laboratory_capability(&kernel);
        let shorter = capability.expires - Duration::seconds(60);
        capability.expires = shorter;
        kernel
            .store()
            .save_capability(&capability)
            .expect("a shorter expiry may persist");
        let stored = kernel
            .store()
            .load_capability(&capability.id)
            .expect("load the shortened capability");
        assert_eq!(stored.expires, shorter);
    }

    #[test]
    fn expiry_freeze_allows_the_same_expires() {
        let (_directory, kernel) = laboratory_kernel();
        let (_instance, capability) = laboratory_capability(&kernel);
        let original = capability.expires;
        kernel
            .store()
            .save_capability(&capability)
            .expect("persisting the same expires must succeed");
        let stored = kernel
            .store()
            .load_capability(&capability.id)
            .expect("load the capability");
        assert_eq!(stored.expires, original);
    }

    #[test]
    fn capability_extend_command_always_refuses() {
        let (_directory, kernel) = laboratory_kernel();
        let (_instance, capability) = laboratory_capability(&kernel);
        let later = (capability.expires + Duration::seconds(3600))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let error = kernel
            .extend_capability_expiry(&capability.id, &later)
            .expect_err("extend must always refuse");
        assert_capability_expiry_extension_refused(&error);
        let stored = kernel
            .store()
            .load_capability(&capability.id)
            .expect("load after refused extend");
        assert_eq!(stored.expires, capability.expires);
    }

    #[test]
    fn attenuate_child_cannot_expire_after_parent() {
        let (_directory, kernel) = laboratory_kernel();
        let (_instance, parent) = laboratory_capability(&kernel);
        let child = kernel
            .attenuate_capability(&parent.id, "payments/prod", None)
            .expect("attenuation must create a new capability identifier");
        assert_ne!(child.id, parent.id);
        assert!(
            child.expires <= parent.expires,
            "the child expiry must not exceed the parent expiry"
        );
        let error = require_child_capability_expiry_not_after_parent(
            parent.expires + Duration::seconds(1),
            parent.expires,
        )
        .expect_err("a child expiry after the parent must be refused");
        assert!(
            error
                .to_string()
                .contains("must not expire after the parent"),
            "unexpected child-expiry error: {error}"
        );
        require_child_capability_expiry_not_after_parent(parent.expires, parent.expires)
            .expect("an equal child expiry must be allowed");
        require_child_capability_expiry_not_after_parent(
            parent.expires - Duration::seconds(1),
            parent.expires,
        )
        .expect("a shorter child expiry must be allowed");
    }

    fn assert_issuer_seal_refused(error: &Error) {
        let text = error.to_string();
        assert!(
            text.contains("issuer seal") || text.contains("kill_date has been reached"),
            "unexpected issuer-seal error: {error}"
        );
    }

    fn assert_issuer_seal_persist_postpone_refused(error: &Error) {
        let text = error.to_string();
        assert!(
            text.contains("cannot postpone")
                || text.contains("clears kill_date")
                || text.contains("kill_date is frozen"),
            "unexpected issuer-seal persist postpone error: {error}"
        );
    }

    #[test]
    fn issuer_seal_refuses_zero_after_seconds() {
        let (_directory, kernel) = laboratory_kernel();
        let error = kernel
            .seal_issuer(0)
            .expect_err("after_seconds of zero must be refused");
        assert!(
            error.to_string().contains("greater than zero"),
            "unexpected zero-seal error: {error}"
        );
        let issuer = kernel.store().load_issuer().expect("load the issuer");
        assert!(
            issuer.kill_date.is_none(),
            "a refused seal must not write kill_date"
        );
    }

    #[test]
    fn issuer_seal_cannot_postpone_death_and_may_shorten() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        let first = kernel.seal_issuer(60).expect("the first seal must succeed");
        let first_kill = first
            .kill_date
            .expect("the first seal must set issuer.kill_date");
        assert_eq!(first_kill, start + Duration::seconds(60));
        let postpone = kernel
            .seal_issuer(90)
            .expect_err("a later or equal death time must be refused");
        assert!(
            postpone.to_string().contains("cannot postpone"),
            "unexpected postpone error: {postpone}"
        );
        let equal = kernel
            .seal_issuer(60)
            .expect_err("an equal death time must be refused");
        assert!(
            equal.to_string().contains("cannot postpone"),
            "unexpected equal-seal error: {equal}"
        );
        let shortened = kernel
            .seal_issuer(30)
            .expect("a later seal that only shortens remaining life must succeed");
        let shorter_kill = shortened
            .kill_date
            .expect("the shortened seal must set issuer.kill_date");
        assert_eq!(shorter_kill, start + Duration::seconds(30));
        assert!(shorter_kill < first_kill);
        let previous = kernel.store().load_issuer().expect("load the issuer");
        assert!(
            previous.previous_issuer_keys.is_empty(),
            "realm seal must not write previous_issuer_keys"
        );
    }

    #[test]
    fn issuer_seal_mint_works_before_kill_date_and_refuses_act_after() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        let (instance, capability) = laboratory_capability(&kernel);
        let pre_seal_receipt = kernel
            .check_tool_action(
                &instance.id,
                Some(&capability.id),
                "read",
                "payments",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect("a check before seal must return a decision")
            .receipt
            .expect("a check before seal must return a signed receipt");
        kernel
            .verify_decision_receipt(&pre_seal_receipt)
            .expect("the pre-seal receipt must verify before seal");

        let sealed = kernel
            .seal_issuer(60)
            .expect("seal 60 seconds must succeed");
        assert_eq!(
            sealed.kill_date,
            Some(start + Duration::seconds(60)),
            "issuer.kill_date is the store-wide death"
        );
        assert!(
            sealed.previous_issuer_keys.is_empty(),
            "realm kill_date must not be confused with previous-key kill_date"
        );

        kernel.set_now_for_test(start + Duration::seconds(30));
        kernel
            .mint_capability(&instance.id, "read", "payments", None)
            .expect("mint must work before the issuer seal kill_date");
        let nonce_before = fresh_challenge(&kernel, &instance);
        kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&nonce_before),
                Some("autonomous"),
            )
            .expect("verify must work before the issuer seal kill_date");

        let nonce_spawn = fresh_challenge(&kernel, &instance);
        let nonce_after = fresh_challenge(&kernel, &instance);
        let nonce_verify_decision = fresh_challenge(&kernel, &instance);
        let nonce_check = fresh_challenge(&kernel, &instance);

        kernel.set_now_for_test(start + Duration::seconds(60));
        let mint_error = kernel
            .mint_capability(&instance.id, "read", "payments", None)
            .expect_err("mint must refuse at kill_date");
        assert_issuer_seal_refused(&mint_error);

        let birth_error = kernel
            .birth_write(
                &instance.agent_type_id,
                "after-death".to_string(),
                BTreeMap::new(),
                "read",
                "payments",
                None,
            )
            .expect_err("birth must refuse after kill_date");
        assert_issuer_seal_refused(&birth_error);

        let spawn_error = kernel
            .spawn_child(
                &instance.id,
                &capability.id,
                "child".to_string(),
                BTreeMap::new(),
                "read",
                "payments/prod",
                None,
                Some(&holder_proof(&kernel, &instance)),
                Some(&nonce_spawn),
            )
            .expect_err("spawn must refuse after kill_date");
        assert_issuer_seal_refused(&spawn_error);

        let rotate_error = kernel
            .rotate_issuer_key(30)
            .expect_err("issuer rotate must refuse after kill_date");
        assert_issuer_seal_refused(&rotate_error);

        let accept_error = kernel
            .accept_issuer_public_key(&("ab".repeat(32)))
            .expect_err("issuer accept must refuse after kill_date");
        assert_issuer_seal_refused(&accept_error);

        let tree_head = kernel
            .sign_issuance_log_tree_head()
            .expect("log sign-root after remaining life must stay allowed so seal-export and kill-export can produce a verifier document");
        assert!(
            !tree_head.signature_hex.is_empty(),
            "a tree head after remaining life must still carry a signature"
        );

        let verify_error = kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&nonce_after),
                Some("autonomous"),
            )
            .expect_err("verify must refuse after kill_date even if the capability is unexpired");
        assert_issuer_seal_refused(&verify_error);

        let decision = kernel
            .verify_capability_decision(
                &capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&nonce_verify_decision),
                Some("autonomous"),
            )
            .expect("verify after seal must return a refused decision");
        assert_eq!(decision.result, "refused");
        assert!(
            decision
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("issuer seal"),
            "the refused verify must name the issuer seal: {:?}",
            decision.reason
        );
        assert!(
            decision.receipt.is_none(),
            "after seal the store must not sign a new decision receipt"
        );

        let check = kernel
            .check_tool_action(
                &instance.id,
                Some(&capability.id),
                "read",
                "payments",
                Some(&holder_proof(&kernel, &instance)),
                Some(&nonce_check),
                Some("autonomous"),
            )
            .expect("check after seal must return a refused decision");
        assert_eq!(check.result, "refused");
        assert!(
            check
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("issuer seal"),
            "the refused check must name the issuer seal: {:?}",
            check.reason
        );
        assert!(
            check.receipt.is_none(),
            "after seal the store must not sign a new decision receipt"
        );

        kernel.verify_decision_receipt(&pre_seal_receipt).expect(
            "historical receipt verify of a pre-seal receipt must still succeed after kill_date",
        );
    }

    #[test]
    fn mint_and_birth_refuse_a_planted_cleared_kill_date_in_issuer_json() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        let (instance, _capability) = laboratory_capability(&kernel);
        kernel
            .seal_issuer(60)
            .expect("seal 60 seconds must succeed");
        let issuer_path = kernel.store().issuer_path();
        let raw = std::fs::read_to_string(&issuer_path).expect("read issuer.json");
        let mut planted: serde_json::Value =
            serde_json::from_str(&raw).expect("parse issuer.json");
        assert!(
            planted
                .get("kill_date")
                .and_then(|value| value.as_str())
                .is_some(),
            "honest persist must write kill_date"
        );
        planted["kill_date"] = serde_json::Value::Null;
        std::fs::write(
            &issuer_path,
            serde_json::to_string_pretty(&planted).expect("serialize planted issuer.json"),
        )
        .expect("plant a cleared kill_date without save_issuer");
        let loaded = kernel
            .store()
            .load_issuer()
            .expect("load the issuer after the plant");
        assert!(
            loaded.kill_date.is_some(),
            "load_issuer must overlay the signed issuer_seal timestamp"
        );
        let still_planted: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&issuer_path).expect("re-read issuer.json"),
        )
        .expect("parse planted issuer.json");
        let on_disk_kill = still_planted.get("kill_date");
        assert!(
            on_disk_kill.is_none() || on_disk_kill == Some(&serde_json::Value::Null),
            "load_issuer must not write the file back"
        );
        kernel.set_now_for_test(start + Duration::seconds(30));
        let mint_error = kernel
            .mint_capability(&instance.id, "read", "payments", None)
            .expect_err(
                "mint must refuse a planted cleared kill_date inside honest remaining life",
            );
        assert_issuer_seal_refused(&mint_error);
        let birth_error = kernel
            .birth_write(
                &instance.agent_type_id,
                "planted-clear".to_string(),
                BTreeMap::new(),
                "read",
                "payments",
                None,
            )
            .expect_err(
                "birth must refuse a planted cleared kill_date inside honest remaining life",
            );
        assert_issuer_seal_refused(&birth_error);
        let mut cleared = kernel
            .store()
            .load_issuer()
            .expect("load the overlaid issuer for save refuse");
        cleared.kill_date = None;
        let save_error = kernel
            .store()
            .save_issuer(&cleared)
            .expect_err("save_issuer must refuse a persist that clears kill_date after issuer_seal");
        assert_issuer_seal_persist_postpone_refused(&save_error);
    }

    #[test]
    fn mint_and_birth_refuse_a_planted_later_kill_date_in_issuer_json() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        let (instance, _capability) = laboratory_capability(&kernel);
        kernel
            .seal_issuer(60)
            .expect("seal 60 seconds must succeed");
        let honest_kill = start + Duration::seconds(60);
        let planted_kill = start + Duration::seconds(3600);
        let issuer_path = kernel.store().issuer_path();
        let raw = std::fs::read_to_string(&issuer_path).expect("read issuer.json");
        let mut planted: serde_json::Value =
            serde_json::from_str(&raw).expect("parse issuer.json");
        let on_disk_honest = planted
            .get("kill_date")
            .and_then(|value| value.as_str())
            .expect("honest persist must write kill_date");
        let parsed_honest = DateTime::parse_from_rfc3339(on_disk_honest)
            .expect("honest kill_date is RFC3339")
            .with_timezone(&Utc);
        assert_eq!(
            parsed_honest, honest_kill,
            "on-disk kill_date after seal is start plus 60 seconds"
        );
        planted["kill_date"] = serde_json::Value::String(planted_kill.to_rfc3339());
        std::fs::write(
            &issuer_path,
            serde_json::to_string_pretty(&planted).expect("serialize planted issuer.json"),
        )
        .expect("plant a later kill_date without save_issuer");
        let loaded = kernel
            .store()
            .load_issuer()
            .expect("load the issuer after the plant");
        assert_eq!(
            loaded.kill_date,
            Some(honest_kill),
            "load_issuer must overlay the signed issuer.kill_date"
        );
        let still_planted: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&issuer_path).expect("re-read issuer.json"),
        )
        .expect("parse planted issuer.json");
        let on_disk_planted = still_planted
            .get("kill_date")
            .and_then(|value| value.as_str())
            .expect("planted later kill_date must remain on disk");
        let parsed_planted = DateTime::parse_from_rfc3339(on_disk_planted)
            .expect("planted kill_date is RFC3339")
            .with_timezone(&Utc);
        assert_eq!(
            parsed_planted, planted_kill,
            "load_issuer must not write the file back"
        );
        kernel.set_now_for_test(start + Duration::seconds(30));
        kernel
            .mint_capability(&instance.id, "read", "payments", None)
            .expect("mint must work before the signed issuer seal kill_date");
        kernel.set_now_for_test(start + Duration::seconds(60));
        let mint_error = kernel
            .mint_capability(&instance.id, "read", "payments", None)
            .expect_err("mint must refuse at the signed kill_date");
        assert_issuer_seal_refused(&mint_error);
        let birth_error = kernel
            .birth_write(
                &instance.agent_type_id,
                "planted-later".to_string(),
                BTreeMap::new(),
                "read",
                "payments",
                None,
            )
            .expect_err("birth must refuse at the signed kill_date");
        assert_issuer_seal_refused(&birth_error);
        let mut postponed = kernel
            .store()
            .load_issuer()
            .expect("load the overlaid issuer for save refuse");
        postponed.kill_date = Some(planted_kill);
        let save_error = kernel
            .store()
            .save_issuer(&postponed)
            .expect_err(
                "save_issuer must refuse a persist that postpones past the signed kill_date",
            );
        assert_issuer_seal_persist_postpone_refused(&save_error);
    }

    fn laboratory_allowed_check_receipt(kernel: &Kernel) -> DecisionReceipt {
        let birth = laboratory_birth(kernel);
        let allowed = kernel
            .check_tool_action(
                &birth.instance.id,
                Some(&birth.capability.id),
                "read",
                "internal",
                Some(&holder_proof(kernel, &birth.instance)),
                Some(&fresh_challenge(kernel, &birth.instance)),
                Some("autonomous"),
            )
            .expect("an allowed check must return a decision");
        assert_eq!(allowed.result, "allowed");
        allowed
            .receipt
            .expect("an allowed check must return a signed receipt")
    }

    fn first_issuer_public_key(kernel: &Kernel) -> String {
        kernel
            .store()
            .load_issuer()
            .expect("load the issuer")
            .current_public_key_hex()
    }

    #[test]
    fn init_writes_verify_threshold_n_one() {
        let (_directory, kernel) = laboratory_kernel();
        let issuer = kernel.store().load_issuer().expect("load the issuer");
        assert_eq!(issuer.verify_threshold_n, 1);
    }

    #[test]
    fn verify_threshold_n_cannot_be_lowered() {
        let (_directory, kernel) = laboratory_kernel();
        kernel
            .set_verify_threshold(2)
            .expect("raising verify_threshold_n must succeed");
        let error = kernel
            .set_verify_threshold(1)
            .expect_err("lowering verify_threshold_n must refuse");
        assert!(
            error.to_string().contains("cannot be lowered"),
            "unexpected lower-verify-threshold error: {error}"
        );
        let mut issuer = kernel.store().load_issuer().expect("load the issuer");
        issuer.verify_threshold_n = 1;
        let persist_error = kernel
            .store()
            .save_issuer(&issuer)
            .expect_err("persist must refuse lowering verify_threshold_n");
        assert!(
            persist_error.to_string().contains("cannot be lowered"),
            "unexpected persist-lower-verify error: {persist_error}"
        );
    }

    #[test]
    fn historical_log_lines_keep_their_threshold_after_issuance_raise() {
        let (_first_directory, _custody, first, _member_two) = n2_signing_kernel();
        first
            .verify_log_chain()
            .expect("old one-signature lines must still verify after issuance threshold_n 2");
        let receipt = laboratory_allowed_check_receipt(&first);
        assert!(
            receipt.issuer_signatures.len() >= 2,
            "new lines after issuance threshold_n 2 must carry two member signatures",
        );
        let events = first.store().read_log().expect("read the issuance log");
        let mut saw_one = false;
        let mut saw_two = false;
        for event in &events {
            let line_threshold = event.threshold_n.max(1);
            if line_threshold == 1 {
                saw_one = true;
            }
            if line_threshold >= 2 {
                saw_two = true;
                assert!(
                    event.issuer_signatures.len() >= 2
                        || (!event.issuer_signature_hex.is_empty()
                            && event.issuer_signatures.len() >= 1),
                    "a threshold_n 2 line must carry two member signatures: {:?}",
                    event.operation,
                );
            }
        }
        assert!(
            saw_one,
            "the log must still contain historical threshold_n 1 lines"
        );
        assert!(saw_two, "the log must contain new threshold_n 2 lines");
    }

    fn n2_signing_kernel() -> (tempfile::TempDir, tempfile::TempDir, Kernel, String) {
        let store_directory = tempdir().expect("create a store directory");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        kernel
            .add_issuer_member_with_secret_path(Some(&outside))
            .expect("add member two outside the data directory");
        let issuer = kernel.store().load_issuer().expect("load the issuer");
        let current = issuer.current_public_key_hex();
        let member_two = issuer
            .trusted_signing_member_public_keys()
            .into_iter()
            .find(|key| key != &current)
            .expect("member two public key");
        let signing =
            Kernel::open_with_member_secrets(store_directory.path(), vec![outside.clone()])
                .expect("an outside member secret path must open");
        signing
            .set_issuer_threshold(2)
            .expect("set issuance threshold_n 2");
        (store_directory, custody_directory, signing, member_two)
    }

    #[test]
    fn foreign_act_accept_uses_verify_threshold_not_issuance_threshold() {
        let (first_directory, _custody, first, member_two) = n2_signing_kernel();
        let receipt = laboratory_allowed_check_receipt(&first);
        assert!(
            receipt.issuer_signatures.len() >= 2,
            "n=2 check must sign the receipt with two members"
        );
        let bundle_directory = first_directory.path().join("act-bundle");
        first
            .export_act_bundle(&receipt, &bundle_directory)
            .expect("export a two-member act bundle");
        let first_key = first_issuer_public_key(&first);

        let (_second_directory, second) = laboratory_kernel();
        second
            .accept_issuer_public_key(&first_key)
            .expect("accept member one");
        second
            .accept_act_bundle(&bundle_directory)
            .expect("verify_threshold_n 1 may still accept one trusted signature");

        second
            .set_verify_threshold(2)
            .expect("raise verify_threshold_n to 2");
        let error = second
            .accept_act_bundle(&bundle_directory)
            .expect_err("verify_threshold_n 2 must refuse when member two is not accepted");
        let text = error.to_string();
        assert!(
            text.contains("needs 2")
                || text.contains("verify_threshold")
                || text.contains("member signatures")
                || text.contains("accepted"),
            "unexpected missing-member-two-accept error: {error}"
        );

        second
            .accept_issuer_public_key(&member_two)
            .expect("accept member two");
        second
            .accept_act_bundle(&bundle_directory)
            .expect("two accepted member signatures must meet verify_threshold_n 2");

        let receipt_path = bundle_directory.join("receipt.json");
        let mut stripped: DecisionReceipt =
            serde_json::from_str(&std::fs::read_to_string(&receipt_path).expect("read receipt"))
                .expect("parse receipt");
        assert!(stripped.issuer_signatures.len() >= 2);
        stripped.issuer_signatures.pop();
        std::fs::write(
            &receipt_path,
            serde_json::to_string_pretty(&stripped).expect("write stripped receipt"),
        )
        .expect("overwrite receipt");
        let stripped_error = second
            .accept_act_bundle(&bundle_directory)
            .expect_err("a stripped one-of-two receipt must refuse");
        let stripped_text = stripped_error.to_string();
        assert!(
            stripped_text.contains("needs 2")
                || stripped_text.contains("one signature")
                || stripped_text.contains("member signatures")
                || stripped_text.contains("verify_threshold"),
            "unexpected stripped-receipt error: {stripped_error}"
        );
    }

    #[test]
    fn a_single_signature_receipt_refuses_when_verify_threshold_is_two() {
        let (first_directory, first) = laboratory_kernel();
        let receipt = laboratory_allowed_check_receipt(&first);
        let bundle_directory = first_directory.path().join("act-bundle");
        first
            .export_act_bundle(&receipt, &bundle_directory)
            .expect("export a one-member act bundle");
        let (_second_directory, second) = laboratory_kernel();
        second
            .accept_issuer_public_key(&first_issuer_public_key(&first))
            .expect("accept the first public key");
        second
            .set_verify_threshold(2)
            .expect("raise verify_threshold_n to 2");
        let error = second
            .accept_act_bundle(&bundle_directory)
            .expect_err("a one-signature bundle must refuse when verify_threshold_n is 2");
        let text = error.to_string();
        assert!(
            text.contains("one signature") || text.contains("verify_threshold_n"),
            "unexpected single-signature verify-threshold error: {error}"
        );
    }

    #[test]
    fn foreign_act_refuses_a_planted_lower_verify_threshold_n_in_issuer_json() {
        let (first_directory, first) = laboratory_kernel();
        let receipt = laboratory_allowed_check_receipt(&first);
        let bundle_directory = first_directory.path().join("act-bundle");
        first
            .export_act_bundle(&receipt, &bundle_directory)
            .expect("export a one-member act bundle");
        let (_second_directory, second) = laboratory_kernel();
        second
            .accept_issuer_public_key(&first_issuer_public_key(&first))
            .expect("accept the first public key");
        second
            .set_verify_threshold(2)
            .expect("raise verify_threshold_n to 2");
        let issuer_path = second.store().issuer_path();
        let raw = std::fs::read_to_string(&issuer_path).expect("read issuer.json");
        let mut planted: serde_json::Value =
            serde_json::from_str(&raw).expect("parse issuer.json");
        assert_eq!(
            planted
                .get("verify_threshold_n")
                .and_then(|value| value.as_u64()),
            Some(2),
            "honest persist must write verify_threshold_n 2"
        );
        planted["verify_threshold_n"] = serde_json::json!(1);
        std::fs::write(
            &issuer_path,
            serde_json::to_string_pretty(&planted).expect("serialize planted issuer.json"),
        )
        .expect("plant a lower verify_threshold_n without save_issuer");
        let loaded = second
            .store()
            .load_issuer()
            .expect("load the issuer after the plant");
        assert_eq!(
            loaded.verify_threshold_n, 2,
            "load_issuer must overlay the signed log n"
        );
        let still_planted: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&issuer_path).expect("re-read issuer.json"),
        )
        .expect("parse planted issuer.json");
        assert_eq!(
            still_planted
                .get("verify_threshold_n")
                .and_then(|value| value.as_u64()),
            Some(1),
            "load_issuer must not write the file back"
        );
        let error = second
            .accept_act_bundle(&bundle_directory)
            .expect_err(
                "a one-signature bundle must refuse when the signed verify_threshold_n is 2",
            );
        let text = error.to_string();
        assert!(
            text.contains("one signature") || text.contains("verify_threshold_n"),
            "unexpected planted-verify-threshold error: {error}"
        );
        let mut lowered = second
            .store()
            .load_issuer()
            .expect("load the overlaid issuer for save refuse");
        lowered.verify_threshold_n = 1;
        let save_error = second
            .store()
            .save_issuer(&lowered)
            .expect_err("save_issuer must refuse persist below the signed log n");
        let save_text = save_error.to_string();
        assert!(
            save_text.contains("lowered") || save_text.contains("cannot be lowered"),
            "unexpected planted-n save_issuer error: {save_error}"
        );
        let set_error = second
            .set_verify_threshold(1)
            .expect_err("set_verify_threshold must refuse lowering after a plant");
        let set_text = set_error.to_string();
        assert!(
            set_text.contains("lowered") || set_text.contains("cannot be lowered"),
            "unexpected planted-n set_verify_threshold error: {set_error}"
        );
    }

    #[test]
    fn export_after_a_real_check_receipt_accepts_on_a_second_store() {
        let (first_directory, first) = laboratory_kernel();
        let receipt = laboratory_allowed_check_receipt(&first);
        let bundle_directory = first_directory.path().join("act-bundle");
        first
            .export_act_bundle(&receipt, &bundle_directory)
            .expect("export a real check receipt");
        assert!(bundle_directory.join("receipt.json").exists());
        assert!(bundle_directory.join("proof.json").exists());
        assert!(bundle_directory.join("tree-head.json").exists());

        let (_second_directory, second) = laboratory_kernel();
        let first_key = first_issuer_public_key(&first);
        second
            .accept_issuer_public_key(&first_key)
            .expect("the second store must accept the first public key");
        let log_before = second
            .store()
            .log_text()
            .expect("read the second issuance log");
        let instances_before = second
            .store()
            .list_instances()
            .expect("list second-store instances");
        second
            .accept_act_bundle(&bundle_directory)
            .expect("a second store that accepted the first public key must accept the act bundle");
        let log_after = second
            .store()
            .log_text()
            .expect("read the second issuance log after accept");
        let instances_after = second
            .store()
            .list_instances()
            .expect("list second-store instances after accept");
        assert_eq!(
            log_before, log_after,
            "act accept must not write a second issuance.log line"
        );
        assert_eq!(
            instances_before.len(),
            instances_after.len(),
            "act accept must not create instance records"
        );
    }

    #[test]
    fn foreign_store_refuses_present_and_act_after_kill_accept() {
        let (first_directory, first) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&first);
        let presentation = laboratory_signed_presentation(&first, &instance, &capability);
        let allowed = first
            .check_tool_action(
                &instance.id,
                Some(&capability.id),
                "read",
                "payments",
                Some(&holder_proof(&first, &instance)),
                Some(&fresh_challenge(&first, &instance)),
                Some("autonomous"),
            )
            .expect("an allowed check must return a decision");
        assert_eq!(allowed.result, "allowed");
        let receipt = allowed
            .receipt
            .expect("an allowed check must return a signed receipt");
        let act_directory = first_directory.path().join("act-bundle");
        first
            .export_act_bundle(&receipt, &act_directory)
            .expect("export an act bundle before kill");
        first
            .kill_instance(&instance.id)
            .expect("store A must persist kill");
        let kill_directory = first_directory.path().join("kill-bundle");
        first
            .export_kill_bundle(Some(&instance.id), None, &kill_directory)
            .expect("export a kill bundle after kill");
        assert!(kill_directory.join("event.json").exists());
        assert!(kill_directory.join("proof.json").exists());
        assert!(kill_directory.join("tree-head.json").exists());

        let (_second_directory, second) = laboratory_kernel();
        second
            .accept_issuer_public_key(&first_issuer_public_key(&first))
            .expect("the second store must accept the first public key");
        let log_before = second
            .store()
            .log_text()
            .expect("read the second issuance log");
        let instances_before = second
            .store()
            .list_instances()
            .expect("list second-store instances");
        second
            .accept_kill_bundle(&kill_directory)
            .expect("store B must accept the kill bundle");
        let log_after = second
            .store()
            .log_text()
            .expect("read the second issuance log after kill accept");
        let instances_after = second
            .store()
            .list_instances()
            .expect("list second-store instances after kill accept");
        assert_eq!(
            log_before, log_after,
            "kill accept must not write a second issuance.log line"
        );
        assert_eq!(
            instances_before.len(),
            instances_after.len(),
            "kill accept must not create instance records"
        );
        let issuer = second.store().load_issuer().expect("load store B issuer");
        assert!(
            issuer.has_accepted_killed_instance(&instance.id),
            "kill accept must persist accepted death on the issuer"
        );

        let present_error = second
            .verify_presentation(&presentation)
            .expect_err("present verify must refuse after kill accept");
        let present_text = present_error.to_string();
        assert!(
            present_text.contains("kill accept"),
            "unexpected present-after-kill-accept error: {present_error}"
        );

        let act_error = second
            .accept_act_bundle(&act_directory)
            .expect_err("act accept must refuse after kill accept");
        let act_text = act_error.to_string();
        assert!(
            act_text.contains("kill accept"),
            "unexpected act-after-kill-accept error: {act_error}"
        );

        first
            .verify_decision_receipt(&receipt)
            .expect("historical receipt verify on store A must still succeed");
        let first_log = first.store().log_path();
        second
            .verify_decision_receipt_against_issuance_log(&receipt, Some(&first_log))
            .expect("historical receipt verify on store B must still succeed after kill accept");

        let mut cleared = second
            .store()
            .load_issuer()
            .expect("load issuer to attempt un-kill");
        cleared.accepted_killed_instance_ids.clear();
        let clear_error = second
            .store()
            .save_issuer(&cleared)
            .expect_err("clearing an accepted kill must refuse");
        let clear_text = clear_error.to_string();
        assert!(
            clear_text.contains("cannot be cleared")
                || clear_text.contains("Un-kill")
                || clear_text.contains("golden-ticket"),
            "unexpected un-kill error: {clear_error}"
        );
        let still = second
            .store()
            .load_issuer()
            .expect("reload issuer after refused un-kill");
        assert!(
            still.has_accepted_killed_instance(&instance.id),
            "a refused un-kill must leave accepted death on disk"
        );
    }

    #[test]
    fn parent_kill_accept_refuses_child_present_and_act() {
        let (first_directory, first) = laboratory_kernel();
        let (parent, parent_capability) = laboratory_capability(&first);
        let parent_nonce = fresh_challenge(&first, &parent);
        let child = first
            .spawn_child(
                &parent.id,
                &parent_capability.id,
                "child".to_string(),
                BTreeMap::new(),
                "read",
                "payments/prod",
                None,
                Some(&holder_proof(&first, &parent)),
                Some(&parent_nonce),
            )
            .expect("a narrower child must succeed");
        let parent_presentation =
            laboratory_signed_presentation(&first, &parent, &parent_capability);
        let child_presentation =
            laboratory_signed_presentation(&first, &child.instance, &child.capability);
        let child_allowed = first
            .check_tool_action(
                &child.instance.id,
                Some(&child.capability.id),
                "read",
                "payments/prod",
                Some(&holder_proof(&first, &child.instance)),
                Some(&fresh_challenge(&first, &child.instance)),
                Some("autonomous"),
            )
            .expect("a child check before parent kill must return a decision");
        assert_eq!(child_allowed.result, "allowed");
        let child_receipt = child_allowed
            .receipt
            .expect("an allowed child check must return a signed receipt");
        let child_act_directory = first_directory.path().join("child-act-bundle");
        first
            .export_act_bundle(&child_receipt, &child_act_directory)
            .expect("export a child act bundle before parent kill");
        let parent_allowed = first
            .check_tool_action(
                &parent.id,
                Some(&parent_capability.id),
                "read",
                "payments",
                Some(&holder_proof(&first, &parent)),
                Some(&fresh_challenge(&first, &parent)),
                Some("autonomous"),
            )
            .expect("a parent check before parent kill must return a decision");
        assert_eq!(parent_allowed.result, "allowed");
        let parent_receipt = parent_allowed
            .receipt
            .expect("an allowed parent check must return a signed receipt");
        let parent_act_directory = first_directory.path().join("parent-act-bundle");
        first
            .export_act_bundle(&parent_receipt, &parent_act_directory)
            .expect("export a parent act bundle before parent kill");

        first
            .kill_instance(&parent.id)
            .expect("store A must persist parent kill");
        let events = first.store().read_log().expect("read the issuance log");
        let parent_kill = events
            .iter()
            .find(|event| {
                event.operation == "kill_instance"
                    && event.instance_id.as_deref() == Some(parent.id.as_str())
            })
            .expect("the parent kill_instance line must exist");
        assert!(
            parent_kill
                .killed_instance_ids
                .iter()
                .any(|id| id == &parent.id),
            "the parent kill line must carry the parent identifier"
        );
        assert!(
            parent_kill
                .killed_instance_ids
                .iter()
                .any(|id| id == &child.instance.id),
            "the parent kill line must carry the child identifier"
        );
        assert!(
            parent_kill
                .killed_capability_ids
                .iter()
                .any(|id| id == &parent_capability.id),
            "the parent kill line must carry the parent capability identifier"
        );
        assert!(
            parent_kill
                .killed_capability_ids
                .iter()
                .any(|id| id == &child.capability.id),
            "the parent kill line must carry the child capability identifier"
        );
        let child_kill = events
            .iter()
            .find(|event| {
                event.operation == "kill_instance"
                    && event.instance_id.as_deref() == Some(child.instance.id.as_str())
            })
            .expect("the child kill_instance line must exist");
        assert!(
            !child_kill
                .killed_instance_ids
                .iter()
                .any(|id| id == &parent.id),
            "a child cascade line must not add the parent"
        );

        let kill_directory = first_directory.path().join("parent-kill-bundle");
        let exported = first
            .export_kill_bundle(Some(&parent.id), None, &kill_directory)
            .expect("export the parent kill bundle once");
        assert_eq!(
            exported.document.instance_id.as_deref(),
            Some(parent.id.as_str()),
            "parent export must bind the parent kill_instance line"
        );
        assert!(
            exported
                .document
                .killed_instance_ids
                .iter()
                .any(|id| id == &child.instance.id),
            "parent export must carry the child identifier from the signed line"
        );

        let (_second_directory, second) = laboratory_kernel();
        second
            .accept_issuer_public_key(&first_issuer_public_key(&first))
            .expect("the second store must accept the first public key");
        second
            .accept_kill_bundle(&kill_directory)
            .expect("store B must accept the parent kill bundle");
        let issuer = second.store().load_issuer().expect("load store B issuer");
        assert!(
            issuer.has_accepted_killed_instance(&parent.id),
            "parent kill accept must persist parent death"
        );
        assert!(
            issuer.has_accepted_killed_instance(&child.instance.id),
            "parent kill accept must persist child death from the signed cascade"
        );
        assert!(
            issuer.has_accepted_killed_capability(&parent_capability.id),
            "parent kill accept must persist parent capability death"
        );
        assert!(
            issuer.has_accepted_killed_capability(&child.capability.id),
            "parent kill accept must persist child capability death"
        );

        let child_present_error = second
            .verify_presentation(&child_presentation)
            .expect_err("child present verify must refuse after parent kill accept");
        assert!(
            child_present_error.to_string().contains("kill accept"),
            "unexpected child present-after-parent-kill error: {child_present_error}"
        );
        let child_act_error = second
            .accept_act_bundle(&child_act_directory)
            .expect_err("child act accept must refuse after parent kill accept");
        assert!(
            child_act_error.to_string().contains("kill accept"),
            "unexpected child act-after-parent-kill error: {child_act_error}"
        );
        let parent_present_error = second
            .verify_presentation(&parent_presentation)
            .expect_err("parent present verify must refuse after parent kill accept");
        assert!(
            parent_present_error.to_string().contains("kill accept"),
            "unexpected parent present-after-parent-kill error: {parent_present_error}"
        );
        let parent_act_error = second
            .accept_act_bundle(&parent_act_directory)
            .expect_err("parent act accept must refuse after parent kill accept");
        assert!(
            parent_act_error.to_string().contains("kill accept"),
            "unexpected parent act-after-parent-kill error: {parent_act_error}"
        );
    }

    #[test]
    fn child_present_refuses_when_signed_ancestor_is_accepted_kill() {
        let (_first_directory, first) = laboratory_kernel();
        let (parent, parent_capability) = laboratory_capability(&first);
        let parent_nonce = fresh_challenge(&first, &parent);
        let child = first
            .spawn_child(
                &parent.id,
                &parent_capability.id,
                "child".to_string(),
                BTreeMap::new(),
                "read",
                "payments/prod",
                None,
                Some(&holder_proof(&first, &parent)),
                Some(&parent_nonce),
            )
            .expect("a narrower child must succeed");
        let child_presentation =
            laboratory_signed_presentation(&first, &child.instance, &child.capability);
        assert_eq!(
            child_presentation.ancestor_instance_ids,
            vec![parent.id.clone()],
            "present must walk parent_instance_id into the signed ancestor set"
        );
        assert_eq!(
            child_presentation.ancestor_capability_ids,
            vec![parent_capability.id.clone()],
            "present must walk parent_capability_id into the signed ancestor set"
        );
        assert!(
            !child_presentation
                .ancestor_instance_ids
                .iter()
                .any(|identifier| identifier == &child.instance.id),
            "the presented instance must stay out of ancestor_instance_ids"
        );
        assert!(
            !child_presentation
                .ancestor_capability_ids
                .iter()
                .any(|identifier| identifier == &child.capability.id),
            "the presented capability must stay out of ancestor_capability_ids"
        );

        let (unrelated, unrelated_capability) = laboratory_capability(&first);
        let unrelated_presentation =
            laboratory_signed_presentation(&first, &unrelated, &unrelated_capability);
        assert!(
            unrelated_presentation.ancestor_instance_ids.is_empty(),
            "an unrelated root present must keep empty ancestor lists"
        );
        assert!(
            !unrelated_presentation
                .ancestor_instance_ids
                .iter()
                .any(|identifier| identifier == &parent.id),
            "an unrelated present must not name the killed parent"
        );

        let (_second_directory, second) = laboratory_kernel();
        second
            .accept_issuer_public_key(&first_issuer_public_key(&first))
            .expect("the second store must accept the first public key");
        let mut issuer = second
            .store()
            .load_issuer()
            .expect("load store B issuer before parent-only accept");
        assert!(
            issuer.accepted_killed_instance_ids.is_empty(),
            "store B must start with an empty accepted-kill list"
        );
        Issuer::push_unique_public_key(&mut issuer.accepted_killed_instance_ids, &parent.id);
        second
            .store()
            .save_issuer(&issuer)
            .expect("growing accepted_killed_instance_ids from empty to parent only must succeed");
        let stored = second
            .store()
            .load_issuer()
            .expect("reload store B issuer after parent-only accept");
        assert!(
            stored.has_accepted_killed_instance(&parent.id),
            "store B must accept parent death only"
        );
        assert!(
            !stored.has_accepted_killed_instance(&child.instance.id),
            "store B must not have the child on the accepted-kill list"
        );

        let child_error = second.verify_presentation(&child_presentation).expect_err(
            "child present verify must refuse when a signed ancestor is an accepted kill",
        );
        let child_text = child_error.to_string();
        assert!(
            child_text.contains("kill accept"),
            "unexpected child ancestor-kill error: {child_error}"
        );
        assert!(
            child_text.contains("ancestor"),
            "the refuse reason must name the ancestor rule: {child_error}"
        );

        second
            .verify_presentation(&unrelated_presentation)
            .expect(
                "an unrelated present whose ancestor set does not contain the accepted kill must still succeed",
            );

        let mut stripped = child_presentation.clone();
        stripped.ancestor_instance_ids.clear();
        stripped.ancestor_capability_ids.clear();
        let strip_error = second
            .verify_presentation(&stripped)
            .expect_err("stripping signed ancestor fields must fail the signature, not soft-fail");
        let strip_text = strip_error.to_string();
        assert!(
            strip_text.contains("signature") || strip_text.contains("tampered"),
            "omitted ancestor fields after sign must fail closed: {strip_error}"
        );
    }

    #[test]
    fn child_act_refuses_when_signed_ancestor_is_accepted_kill() {
        let (first_directory, first) = laboratory_kernel();
        let (parent, parent_capability) = laboratory_capability(&first);
        let parent_nonce = fresh_challenge(&first, &parent);
        let child = first
            .spawn_child(
                &parent.id,
                &parent_capability.id,
                "child".to_string(),
                BTreeMap::new(),
                "read",
                "payments/prod",
                None,
                Some(&holder_proof(&first, &parent)),
                Some(&parent_nonce),
            )
            .expect("a narrower child must succeed");
        let child_allowed = first
            .check_tool_action(
                &child.instance.id,
                Some(&child.capability.id),
                "read",
                "payments/prod",
                Some(&holder_proof(&first, &child.instance)),
                Some(&fresh_challenge(&first, &child.instance)),
                Some("autonomous"),
            )
            .expect("a child check must return a decision");
        assert_eq!(child_allowed.result, "allowed");
        let child_receipt = child_allowed
            .receipt
            .expect("an allowed child check must return a signed receipt");
        assert_eq!(
            child_receipt.ancestor_instance_ids,
            vec![parent.id.clone()],
            "check must walk parent_instance_id into the signed ancestor set"
        );
        assert_eq!(
            child_receipt.ancestor_capability_ids,
            vec![parent_capability.id.clone()],
            "check must walk parent_capability_id into the signed ancestor set"
        );
        assert!(
            !child_receipt
                .ancestor_instance_ids
                .iter()
                .any(|identifier| identifier == &child.instance.id),
            "the receipt instance must stay out of ancestor_instance_ids"
        );
        assert!(
            !child_receipt
                .ancestor_capability_ids
                .iter()
                .any(|identifier| identifier == &child.capability.id),
            "the receipt capability must stay out of ancestor_capability_ids"
        );
        let child_act_directory = first_directory.path().join("child-act-bundle");
        first
            .export_act_bundle(&child_receipt, &child_act_directory)
            .expect("export a child act bundle");

        let (unrelated, unrelated_capability) = laboratory_capability(&first);
        let unrelated_allowed = first
            .check_tool_action(
                &unrelated.id,
                Some(&unrelated_capability.id),
                "read",
                "payments",
                Some(&holder_proof(&first, &unrelated)),
                Some(&fresh_challenge(&first, &unrelated)),
                Some("autonomous"),
            )
            .expect("an unrelated root check must return a decision");
        assert_eq!(unrelated_allowed.result, "allowed");
        let unrelated_receipt = unrelated_allowed
            .receipt
            .expect("an allowed unrelated check must return a signed receipt");
        assert!(
            unrelated_receipt.ancestor_instance_ids.is_empty(),
            "an unrelated root act must keep empty ancestor lists"
        );
        assert!(
            unrelated_receipt.ancestor_capability_ids.is_empty(),
            "an unrelated root act must keep empty ancestor capability lists"
        );
        assert!(
            !unrelated_receipt
                .ancestor_instance_ids
                .iter()
                .any(|identifier| identifier == &parent.id),
            "an unrelated receipt must not name the killed parent"
        );
        let unrelated_act_directory = first_directory.path().join("unrelated-act-bundle");
        first
            .export_act_bundle(&unrelated_receipt, &unrelated_act_directory)
            .expect("export an unrelated root act bundle");

        let (_second_directory, second) = laboratory_kernel();
        second
            .accept_issuer_public_key(&first_issuer_public_key(&first))
            .expect("the second store must accept the first public key");
        let mut issuer = second
            .store()
            .load_issuer()
            .expect("load store B issuer before parent-only accept");
        assert!(
            issuer.accepted_killed_instance_ids.is_empty(),
            "store B must start with an empty accepted-kill list"
        );
        Issuer::push_unique_public_key(&mut issuer.accepted_killed_instance_ids, &parent.id);
        second
            .store()
            .save_issuer(&issuer)
            .expect("growing accepted_killed_instance_ids from empty to parent only must succeed");
        let stored = second
            .store()
            .load_issuer()
            .expect("reload store B issuer after parent-only accept");
        assert!(
            stored.has_accepted_killed_instance(&parent.id),
            "store B must accept parent death only"
        );
        assert!(
            !stored.has_accepted_killed_instance(&child.instance.id),
            "store B must not have the child on the accepted-kill list"
        );

        let child_error = second
            .accept_act_bundle(&child_act_directory)
            .expect_err("child act accept must refuse when a signed ancestor is an accepted kill");
        let child_text = child_error.to_string();
        assert!(
            child_text.contains("kill accept"),
            "unexpected child ancestor-kill error: {child_error}"
        );
        assert!(
            child_text.contains("ancestor"),
            "the refuse reason must name the ancestor rule: {child_error}"
        );

        second
            .accept_act_bundle(&unrelated_act_directory)
            .expect(
                "an unrelated root receipt whose ancestor set does not contain the accepted kill must still accept",
            );

        let receipt_path = child_act_directory.join("receipt.json");
        let mut stripped: DecisionReceipt = serde_json::from_str(
            &std::fs::read_to_string(&receipt_path).expect("read the child receipt"),
        )
        .expect("parse the child receipt");
        stripped.ancestor_instance_ids.clear();
        stripped.ancestor_capability_ids.clear();
        std::fs::write(
            &receipt_path,
            serde_json::to_string_pretty(&stripped).expect("write a stripped child receipt"),
        )
        .expect("overwrite the child receipt");
        let strip_error = second
            .accept_act_bundle(&child_act_directory)
            .expect_err("stripping signed ancestor fields must fail the signature, not soft-fail");
        let strip_text = strip_error.to_string();
        assert!(
            strip_text.contains("signature") || strip_text.contains("tampered"),
            "omitted ancestor fields after sign must fail closed: {strip_error}"
        );
    }

    #[test]
    fn capability_kill_accept_refuses_descendant_present_and_act() {
        let (first_directory, first) = laboratory_kernel();
        let (parent, parent_capability) = laboratory_capability(&first);
        let parent_nonce = fresh_challenge(&first, &parent);
        let child = first
            .spawn_child(
                &parent.id,
                &parent_capability.id,
                "child".to_string(),
                BTreeMap::new(),
                "read",
                "payments/prod",
                None,
                Some(&holder_proof(&first, &parent)),
                Some(&parent_nonce),
            )
            .expect("a narrower child must succeed");
        let parent_presentation =
            laboratory_signed_presentation(&first, &parent, &parent_capability);
        let child_presentation =
            laboratory_signed_presentation(&first, &child.instance, &child.capability);
        let child_allowed = first
            .check_tool_action(
                &child.instance.id,
                Some(&child.capability.id),
                "read",
                "payments/prod",
                Some(&holder_proof(&first, &child.instance)),
                Some(&fresh_challenge(&first, &child.instance)),
                Some("autonomous"),
            )
            .expect("a child check before parent capability kill must return a decision");
        assert_eq!(child_allowed.result, "allowed");
        let child_receipt = child_allowed
            .receipt
            .expect("an allowed child check must return a signed receipt");
        let child_act_directory = first_directory.path().join("child-act-bundle");
        first
            .export_act_bundle(&child_receipt, &child_act_directory)
            .expect("export a child act bundle before parent capability kill");
        let parent_allowed = first
            .check_tool_action(
                &parent.id,
                Some(&parent_capability.id),
                "read",
                "payments",
                Some(&holder_proof(&first, &parent)),
                Some(&fresh_challenge(&first, &parent)),
                Some("autonomous"),
            )
            .expect("a parent check before parent capability kill must return a decision");
        assert_eq!(parent_allowed.result, "allowed");
        let parent_receipt = parent_allowed
            .receipt
            .expect("an allowed parent check must return a signed receipt");
        let parent_act_directory = first_directory.path().join("parent-act-bundle");
        first
            .export_act_bundle(&parent_receipt, &parent_act_directory)
            .expect("export a parent act bundle before parent capability kill");

        first
            .kill_capability(&parent_capability.id)
            .expect("store A must persist parent capability kill");
        let live_parent = first
            .store()
            .load_instance(&parent.id)
            .expect("load the parent instance after capability kill");
        assert_eq!(
            live_parent.status,
            InstanceStatus::Live,
            "a capability kill must not require the parent instance to die"
        );
        let events = first.store().read_log().expect("read the issuance log");
        let parent_kill = events
            .iter()
            .find(|event| {
                event.operation == "kill_capability"
                    && event.capability_id.as_deref() == Some(parent_capability.id.as_str())
            })
            .expect("the parent kill_capability line must exist");
        assert!(
            parent_kill
                .killed_capability_ids
                .iter()
                .any(|id| id == &parent_capability.id),
            "the capability kill line must carry the killed capability identifier"
        );
        assert!(
            parent_kill
                .killed_capability_ids
                .iter()
                .any(|id| id == &child.capability.id),
            "the capability kill line must carry the descendant capability identifier"
        );
        if let Some(parent_of_killed) = parent_kill.parent_capability_id.as_deref() {
            assert!(
                !parent_kill
                    .killed_capability_ids
                    .iter()
                    .any(|id| id == parent_of_killed),
                "a capability kill must not add the parent of the killed capability"
            );
        }
        assert!(
            parent_kill.killed_instance_ids.is_empty(),
            "a capability kill must not add unrelated instance identifiers"
        );

        let kill_directory = first_directory.path().join("capability-kill-bundle");
        let exported = first
            .export_kill_bundle(None, Some(&parent_capability.id), &kill_directory)
            .expect("export the parent capability kill bundle once");
        assert_eq!(
            exported.document.capability_id.as_deref(),
            Some(parent_capability.id.as_str()),
            "capability export must bind the kill_capability line"
        );
        assert!(
            exported
                .document
                .killed_capability_ids
                .iter()
                .any(|id| id == &child.capability.id),
            "capability export must carry the descendant identifier from the signed line"
        );

        let (_second_directory, second) = laboratory_kernel();
        second
            .accept_issuer_public_key(&first_issuer_public_key(&first))
            .expect("the second store must accept the first public key");
        second
            .accept_kill_bundle(&kill_directory)
            .expect("store B must accept the parent capability kill bundle");
        let issuer = second.store().load_issuer().expect("load store B issuer");
        assert!(
            issuer.has_accepted_killed_capability(&parent_capability.id),
            "capability kill accept must persist the killed capability"
        );
        assert!(
            issuer.has_accepted_killed_capability(&child.capability.id),
            "capability kill accept must persist descendant death from the signed cascade"
        );
        assert!(
            !issuer.has_accepted_killed_instance(&parent.id),
            "capability kill accept must not require the parent instance to die"
        );

        let child_present_error = second
            .verify_presentation(&child_presentation)
            .expect_err("child present verify must refuse after parent capability kill accept");
        assert!(
            child_present_error.to_string().contains("kill accept"),
            "unexpected child present-after-capability-kill error: {child_present_error}"
        );
        let child_act_error = second
            .accept_act_bundle(&child_act_directory)
            .expect_err("child act accept must refuse after parent capability kill accept");
        assert!(
            child_act_error.to_string().contains("kill accept"),
            "unexpected child act-after-capability-kill error: {child_act_error}"
        );
        let parent_present_error = second.verify_presentation(&parent_presentation).expect_err(
            "killed capability present verify must refuse after capability kill accept",
        );
        assert!(
            parent_present_error.to_string().contains("kill accept"),
            "unexpected parent present-after-capability-kill error: {parent_present_error}"
        );
        let parent_act_error = second
            .accept_act_bundle(&parent_act_directory)
            .expect_err("killed capability act accept must refuse after capability kill accept");
        assert!(
            parent_act_error.to_string().contains("kill accept"),
            "unexpected parent act-after-capability-kill error: {parent_act_error}"
        );
    }

    #[test]
    fn child_kill_export_does_not_add_parent_and_refuses_extra_document_ids() {
        let (first_directory, first) = laboratory_kernel();
        let (parent, parent_capability) = laboratory_capability(&first);
        let parent_nonce = fresh_challenge(&first, &parent);
        let child = first
            .spawn_child(
                &parent.id,
                &parent_capability.id,
                "child".to_string(),
                BTreeMap::new(),
                "read",
                "payments/prod",
                None,
                Some(&holder_proof(&first, &parent)),
                Some(&parent_nonce),
            )
            .expect("a narrower child must succeed");
        let parent_presentation =
            laboratory_signed_presentation(&first, &parent, &parent_capability);
        let child_presentation =
            laboratory_signed_presentation(&first, &child.instance, &child.capability);
        first
            .kill_instance(&child.instance.id)
            .expect("store A must persist child kill");
        let events = first.store().read_log().expect("read the issuance log");
        let child_kill = events
            .iter()
            .find(|event| {
                event.operation == "kill_instance"
                    && event.instance_id.as_deref() == Some(child.instance.id.as_str())
            })
            .expect("the child kill_instance line must exist");
        assert!(
            !child_kill
                .killed_instance_ids
                .iter()
                .any(|id| id == &parent.id),
            "a child kill must not add the parent to the signed cascade"
        );

        let kill_directory = first_directory.path().join("child-kill-bundle");
        first
            .export_kill_bundle(Some(&child.instance.id), None, &kill_directory)
            .expect("export the child kill bundle");
        let event_path = kill_directory.join("event.json");
        let original = std::fs::read_to_string(&event_path).expect("read child kill event.json");
        let mut tampered: crate::kill_bundle::KillDocument =
            serde_json::from_str(&original).expect("parse child kill event.json");
        tampered.killed_instance_ids.push(parent.id.clone());
        std::fs::write(
            &event_path,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&tampered).expect("serialize tampered event")
            ),
        )
        .expect("write tampered event.json");
        let (_second_directory, second) = laboratory_kernel();
        second
            .accept_issuer_public_key(&first_issuer_public_key(&first))
            .expect("the second store must accept the first public key");
        let tamper_error = second
            .accept_kill_bundle(&kill_directory)
            .expect_err("extra parent identifier on event.json must refuse");
        assert!(
            tamper_error.to_string().contains("killed_instance_ids")
                || tamper_error.to_string().contains("does not match"),
            "unexpected extra-document-id error: {tamper_error}"
        );
        std::fs::write(&event_path, original).expect("restore the bound child kill document");
        second
            .accept_kill_bundle(&kill_directory)
            .expect("store B must accept the child-only kill bundle");
        let issuer = second.store().load_issuer().expect("load store B issuer");
        assert!(
            issuer.has_accepted_killed_instance(&child.instance.id),
            "child kill accept must persist child death"
        );
        assert!(
            !issuer.has_accepted_killed_instance(&parent.id),
            "child kill accept must not persist parent death"
        );
        second
            .verify_presentation(&parent_presentation)
            .expect("parent present verify must still succeed after child-only kill accept");
        let child_error = second
            .verify_presentation(&child_presentation)
            .expect_err("child present verify must refuse after child kill accept");
        assert!(
            child_error.to_string().contains("kill accept"),
            "unexpected child present-after-child-kill error: {child_error}"
        );
    }

    #[test]
    fn historical_log_lines_without_cascade_fields_still_verify() {
        let (_directory, kernel) = laboratory_kernel();
        let (_instance, _capability) = laboratory_capability(&kernel);
        let text = kernel.store().log_text().expect("read the issuance log");
        assert!(
            !text.contains("killed_instance_ids"),
            "mint and birth lines must omit empty killed_instance_ids so old logs still hash"
        );
        assert!(
            !text.contains("killed_capability_ids"),
            "mint and birth lines must omit empty killed_capability_ids so old logs still hash"
        );
        kernel
            .verify_log_chain()
            .expect("historical lines without cascade fields must still verify");
    }

    #[test]
    fn a_second_store_without_the_accept_list_key_refuses_the_act_bundle() {
        let (first_directory, first) = laboratory_kernel();
        let receipt = laboratory_allowed_check_receipt(&first);
        let bundle_directory = first_directory.path().join("act-bundle");
        first
            .export_act_bundle(&receipt, &bundle_directory)
            .expect("export a real check receipt");
        let (_second_directory, second) = laboratory_kernel();
        let error = second
            .accept_act_bundle(&bundle_directory)
            .expect_err("a second store without the first public key must refuse");
        let text = error.to_string();
        assert!(
            text.contains("unknown issuer key")
                || text.contains("accept list")
                || text.contains("not valid for any accepted"),
            "unexpected missing-accept-key error: {error}"
        );
    }

    #[test]
    fn a_tampered_receipt_in_the_act_bundle_refuses() {
        let (first_directory, first) = laboratory_kernel();
        let receipt = laboratory_allowed_check_receipt(&first);
        let bundle_directory = first_directory.path().join("act-bundle");
        first
            .export_act_bundle(&receipt, &bundle_directory)
            .expect("export a real check receipt");
        let receipt_path = bundle_directory.join("receipt.json");
        let mut tampered: DecisionReceipt =
            serde_json::from_str(&std::fs::read_to_string(&receipt_path).expect("read receipt"))
                .expect("parse receipt");
        tampered.result = "refused".to_string();
        std::fs::write(
            &receipt_path,
            format!(
                "{}
",
                serde_json::to_string_pretty(&tampered).expect("serialize")
            ),
        )
        .expect("write tampered receipt");
        let (_second_directory, second) = laboratory_kernel();
        second
            .accept_issuer_public_key(&first_issuer_public_key(&first))
            .expect("accept the first public key");
        let error = second
            .accept_act_bundle(&bundle_directory)
            .expect_err("a tampered receipt must fail closed");
        let text = error.to_string();
        assert!(
            text.contains("signature")
                || text.contains("not valid")
                || text.contains("fails closed"),
            "unexpected tampered-receipt error: {error}"
        );
    }

    #[test]
    fn an_act_bundle_proof_sibling_tamper_refuses() {
        let (first_directory, first) = laboratory_kernel();
        let receipt = laboratory_allowed_check_receipt(&first);
        let bundle_directory = first_directory.path().join("act-bundle");
        first
            .export_act_bundle(&receipt, &bundle_directory)
            .expect("export a real check receipt");
        let proof_path = bundle_directory.join("proof.json");
        let mut proof: crate::log_proof::IssuanceLogInclusionProof =
            serde_json::from_str(&std::fs::read_to_string(&proof_path).expect("read proof"))
                .expect("parse proof");
        assert!(
            !proof.sibling_hashes.is_empty(),
            "a check after birth must produce at least one Merkle sibling"
        );
        proof.sibling_hashes[0] = crate::log_chain::sha256_hexadecimal(b"tampered-act-sibling");
        std::fs::write(
            &proof_path,
            format!(
                "{}
",
                serde_json::to_string_pretty(&proof).expect("serialize")
            ),
        )
        .expect("write tampered proof");
        let (_second_directory, second) = laboratory_kernel();
        second
            .accept_issuer_public_key(&first_issuer_public_key(&first))
            .expect("accept the first public key");
        let error = second
            .accept_act_bundle(&bundle_directory)
            .expect_err("a tampered proof sibling must fail closed");
        let text = error.to_string();
        assert!(
            text.contains("does not match") || text.contains("fails closed"),
            "unexpected tampered-sibling error: {error}"
        );
    }

    #[test]
    fn an_act_bundle_tree_head_root_tamper_refuses() {
        let (first_directory, first) = laboratory_kernel();
        let receipt = laboratory_allowed_check_receipt(&first);
        let bundle_directory = first_directory.path().join("act-bundle");
        first
            .export_act_bundle(&receipt, &bundle_directory)
            .expect("export a real check receipt");
        let tree_head_path = bundle_directory.join("tree-head.json");
        let mut tree_head: crate::log_tree_head::SignedTreeHead = serde_json::from_str(
            &std::fs::read_to_string(&tree_head_path).expect("read tree head"),
        )
        .expect("parse tree head");
        tree_head.merkle_root = crate::log_chain::sha256_hexadecimal(b"tampered-act-root");
        std::fs::write(
            &tree_head_path,
            format!(
                "{}
",
                serde_json::to_string_pretty(&tree_head).expect("serialize")
            ),
        )
        .expect("write tampered tree head");
        let (_second_directory, second) = laboratory_kernel();
        second
            .accept_issuer_public_key(&first_issuer_public_key(&first))
            .expect("accept the first public key");
        let error = second
            .accept_act_bundle(&bundle_directory)
            .expect_err("a tampered tree-head root must fail closed");
        let text = error.to_string();
        assert!(
            text.contains("not valid")
                || text.contains("tampered")
                || text.contains("does not match")
                || text.contains("fails closed"),
            "unexpected tampered-tree-head error: {error}"
        );
    }

    #[test]
    fn a_missing_act_bundle_proof_file_refuses() {
        let (first_directory, first) = laboratory_kernel();
        let receipt = laboratory_allowed_check_receipt(&first);
        let bundle_directory = first_directory.path().join("act-bundle");
        first
            .export_act_bundle(&receipt, &bundle_directory)
            .expect("export a real check receipt");
        std::fs::remove_file(bundle_directory.join("proof.json")).expect("remove proof.json");
        let (_second_directory, second) = laboratory_kernel();
        second
            .accept_issuer_public_key(&first_issuer_public_key(&first))
            .expect("accept the first public key");
        let error = second
            .accept_act_bundle(&bundle_directory)
            .expect_err("a missing proof file must fail closed");
        assert!(
            error.to_string().contains("missing proof.json"),
            "unexpected missing-proof error: {error}"
        );
    }

    #[test]
    fn an_act_bundle_line_hash_mismatch_between_receipt_and_proof_refuses() {
        let (first_directory, first) = laboratory_kernel();
        let receipt = laboratory_allowed_check_receipt(&first);
        let bundle_directory = first_directory.path().join("act-bundle");
        first
            .export_act_bundle(&receipt, &bundle_directory)
            .expect("export a real check receipt");
        let birth_line_hash = birth_write_line_hash(&first);
        let other_proof = first
            .prove_issuance_log_inclusion(&birth_line_hash)
            .expect("prove the birth line, which is not the receipt bound line");
        let receipt_line_hash = crate::act_bundle::line_hash_from_bound_issuance_log_line(
            receipt.issuance_log_line.trim(),
        )
        .expect("read the receipt bound line_hash");
        assert_ne!(
            other_proof.line_hash, receipt_line_hash,
            "the substituted proof must name a different line_hash"
        );
        std::fs::write(
            bundle_directory.join("proof.json"),
            format!(
                "{}
",
                serde_json::to_string_pretty(&other_proof).expect("serialize")
            ),
        )
        .expect("write a proof for a different line");
        let (_second_directory, second) = laboratory_kernel();
        second
            .accept_issuer_public_key(&first_issuer_public_key(&first))
            .expect("accept the first public key");
        let error = second
            .accept_act_bundle(&bundle_directory)
            .expect_err("a line_hash mismatch must fail closed");
        assert!(
            error
                .to_string()
                .contains("does not match the receipt bound line"),
            "unexpected line_hash-mismatch error: {error}"
        );
    }

    fn laboratory_signed_presentation(
        kernel: &Kernel,
        instance: &Instance,
        capability: &Capability,
    ) -> crate::presentation::Presentation {
        let nonce = fresh_challenge(kernel, instance);
        kernel
            .present_capability(
                &instance.id,
                &capability.id,
                Some(&holder_proof(kernel, instance)),
                Some(&nonce),
            )
            .expect("write a signed presentation")
    }

    #[test]
    fn present_then_verify_succeeds() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let presentation = laboratory_signed_presentation(&kernel, &instance, &capability);
        assert_eq!(presentation.instance_id, instance.id);
        assert_eq!(presentation.capability_id, capability.id);
        assert_eq!(presentation.agent_type_id, instance.agent_type_id);
        assert_eq!(presentation.on_behalf_of, capability.on_behalf_of);
        assert_eq!(presentation.intent, capability.intent);
        assert_eq!(presentation.audience, capability.audience);
        assert_eq!(presentation.holder_public_key, instance.holder_public_key);
        assert_eq!(
            presentation.issuer_public_key_hex,
            first_issuer_public_key(&kernel)
        );
        assert!(!presentation.signature_hex.is_empty());
        assert!(presentation.expires_at > presentation.presented_at);
        assert!(
            presentation.ancestor_instance_ids.is_empty(),
            "a root present must keep empty ancestor instance lists"
        );
        assert!(
            presentation.ancestor_capability_ids.is_empty(),
            "a root present must keep empty ancestor capability lists"
        );
        kernel
            .verify_presentation(&presentation)
            .expect("a fresh presentation must verify");
    }

    fn store_b_with_verified_present() -> (
        tempfile::TempDir,
        Kernel,
        tempfile::TempDir,
        Kernel,
        Instance,
        crate::presentation::Presentation,
    ) {
        let (first_directory, first) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&first);
        let presentation = laboratory_signed_presentation(&first, &instance, &capability);
        let (second_directory, second) = laboratory_kernel();
        second
            .accept_issuer_public_key(&first_issuer_public_key(&first))
            .expect("store B must accept store A issuer public key");
        second
            .verify_presentation(&presentation)
            .expect("the honest present must verify on store B");
        assert!(
            second.store().load_instance(&instance.id).is_err(),
            "store B must have no instance record"
        );
        (
            first_directory,
            first,
            second_directory,
            second,
            instance,
            presentation,
        )
    }

    #[test]
    fn store_b_allow_from_present_refuses_missing_empty_or_wrong_holder_proof() {
        let (_first_directory, first, _second_directory, second, instance, presentation) =
            store_b_with_verified_present();
        let missing = second
            .decide_tool_action_after_verified_wimse(
                &presentation,
                &presentation.intent,
                &presentation.audience,
                None,
                None,
                Some("autonomous"),
            )
            .expect("a missing holder proof must return a decision");
        assert_eq!(
            missing.result, "refused",
            "store B must not allow without holder proof: {:?}",
            missing.reason
        );
        assert!(
            missing
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("holder proof is required"),
            "store B must name the missing holder proof refuse: {:?}",
            missing.reason
        );

        let secret_path = first.store().holder_secret_path(&instance.id);
        let secret_only = second
            .decide_tool_action_after_verified_wimse(
                &presentation,
                &presentation.intent,
                &presentation.audience,
                Some(&HolderProof::SecretPath(secret_path)),
                None,
                Some("autonomous"),
            )
            .expect("a holder secret path on store B must return a decision");
        assert_eq!(
            secret_only.result, "refused",
            "store B must not allow a holder secret path: {:?}",
            secret_only.reason
        );
        assert!(
            secret_only
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("holder secret file is not accepted"),
            "store B must name the holder secret path refuse: {:?}",
            secret_only.reason
        );

        let challenge = second
            .issue_verifier_challenge()
            .expect("issue a verifier challenge");
        let missing_signature = second
            .decide_tool_action_after_verified_wimse(
                &presentation,
                &presentation.intent,
                &presentation.audience,
                None,
                Some(&challenge.nonce),
                Some("autonomous"),
            )
            .expect("a missing holder signature must return a decision");
        assert_eq!(
            missing_signature.result, "refused",
            "store B must not allow a nonce without a holder signature: {:?}",
            missing_signature.reason
        );

        let stranger = tokens::generate_keypair();
        let wrong_signature = tokens::sign_holder_challenge(
            &tokens::private_key_hexadecimal(&stranger),
            &challenge.challenge_message,
        )
        .expect("sign with a stranger holder key");
        let wrong = second
            .decide_tool_action_after_verified_wimse(
                &presentation,
                &presentation.intent,
                &presentation.audience,
                Some(&HolderProof::SignatureHexadecimal(wrong_signature)),
                Some(&challenge.nonce),
                Some("autonomous"),
            )
            .expect("a wrong holder signature must return a decision");
        assert_eq!(
            wrong.result, "refused",
            "store B must not allow a wrong holder signature: {:?}",
            wrong.reason
        );
        assert!(
            wrong
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("holder proof is not valid"),
            "store B must name the wrong holder refuse: {:?}",
            wrong.reason
        );

        let (proof, nonce) = verifier_holder_signature(&first, &instance, &second);
        let honest = second
            .decide_tool_action_after_verified_wimse(
                &presentation,
                &presentation.intent,
                &presentation.audience,
                Some(&proof),
                Some(&nonce),
                Some("autonomous"),
            )
            .expect("an honest holder signature must return a decision");
        assert_eq!(
            honest.result, "allowed",
            "store B must allow from the present when the holder signature matches: {:?}",
            honest.reason
        );
        assert!(
            honest.receipt.is_none(),
            "a verifier allow must not mint a check receipt"
        );
        assert!(
            second.store().load_instance(&instance.id).is_err(),
            "store B must not copy the issuing inode"
        );

        let replay = second
            .decide_tool_action_after_verified_wimse(
                &presentation,
                &presentation.intent,
                &presentation.audience,
                Some(&proof),
                Some(&nonce),
                Some("autonomous"),
            )
            .expect("a spent verifier nonce must return a decision");
        assert_eq!(
            replay.result, "refused",
            "store B must refuse a spent verifier nonce: {:?}",
            replay.reason
        );
        assert!(
            replay
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("already spent"),
            "store B must name the spent nonce refuse: {:?}",
            replay.reason
        );
    }

    #[test]
    fn sign_holder_nonce_on_a_verifier_store_with_no_instance_is_refused() {
        let (_first_directory, first, _second_directory, second, instance, _presentation) =
            store_b_with_verified_present();
        assert!(
            second
                .store()
                .list_instances()
                .expect("list store B instances")
                .is_empty(),
            "store B must start with no instance"
        );
        let challenge = second
            .issue_verifier_challenge()
            .expect("issue a verifier challenge");
        let secret_path = first.store().holder_secret_path(&instance.id);
        let error = second
            .sign_holder_nonce(&challenge.challenge_message, &secret_path)
            .expect_err("a verifier store with no instance must not sign a holder nonce");
        assert!(
            error.to_string().contains("no matching local instance"),
            "the refuse must name the missing local instance: {error}"
        );
        assert!(
            second.store().load_instance(&instance.id).is_err(),
            "store B must not copy the issuing inode"
        );
        assert!(
            second
                .store()
                .list_instances()
                .expect("list store B instances after refuse")
                .is_empty(),
            "store B must still write no instance"
        );
    }

    #[test]
    fn sign_holder_nonce_for_a_revoked_local_instance_is_refused() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, _capability) = laboratory_capability(&kernel);
        let secret_path = kernel.store().holder_secret_path(&instance.id);
        kernel
            .kill_instance(&instance.id)
            .expect("kill the local instance");
        let challenge = kernel
            .issue_verifier_challenge()
            .expect("issue a verifier challenge");
        let error = kernel
            .sign_holder_nonce(&challenge.challenge_message, &secret_path)
            .expect_err("signing for a revoked local instance must be refused");
        assert!(
            error.to_string().contains("revoked"),
            "the refuse must name the revoked instance: {error}"
        );
    }

    #[test]
    fn sign_holder_nonce_after_issuer_seal_is_refused() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, _capability) = laboratory_capability(&kernel);
        let secret_path = kernel.store().holder_secret_path(&instance.id);
        let start = Utc::now();
        kernel.set_now_for_test(start);
        kernel.seal_issuer(1).expect("seal the issuer");
        kernel.set_now_for_test(start + Duration::seconds(2));
        let challenge = kernel
            .issue_verifier_challenge()
            .expect("issue a verifier challenge after seal");
        let error = kernel
            .sign_holder_nonce(&challenge.challenge_message, &secret_path)
            .expect_err("signing after issuer seal must be refused");
        assert_issuer_seal_refused(&error);
    }

    #[test]
    fn issue_holder_challenge_refuses_after_instance_kill() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, _capability) = laboratory_capability(&kernel);
        kernel
            .kill_instance(&instance.id)
            .expect("kill the local instance");
        let log_before = kernel
            .store()
            .read_log()
            .expect("read the issuance log before the refused challenge");
        let challenge_lines_before = log_before
            .iter()
            .filter(|event| event.operation == "challenge")
            .count();
        let error = kernel
            .issue_holder_challenge(&instance.id)
            .expect_err("a holder challenge after instance kill must be refused");
        let error_text = error.to_string();
        assert!(
            error_text.contains("revoked")
                || error_text.contains("kill")
                || error_text.contains("death")
                || error_text.contains("live"),
            "the refuse must name revoked, kill, death, or live: {error}"
        );
        let lifetime_error = kernel
            .issue_holder_challenge_with_lifetime(&instance.id, CHALLENGE_WINDOW_SECONDS)
            .expect_err("a holder challenge with lifetime after instance kill must be refused");
        let lifetime_text = lifetime_error.to_string();
        assert!(
            lifetime_text.contains("revoked")
                || lifetime_text.contains("kill")
                || lifetime_text.contains("death")
                || lifetime_text.contains("live"),
            "the lifetime refuse must name revoked, kill, death, or live: {lifetime_error}"
        );
        let log_after = kernel
            .store()
            .read_log()
            .expect("read the issuance log after the refused challenge");
        let challenge_lines_after = log_after
            .iter()
            .filter(|event| event.operation == "challenge")
            .count();
        assert_eq!(
            challenge_lines_after, challenge_lines_before,
            "a refused holder challenge must not append a challenge issuance.log line"
        );
    }

    #[test]
    fn issue_holder_challenge_after_issuer_seal_is_refused() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, _capability) = laboratory_capability(&kernel);
        let start = Utc::now();
        kernel.set_now_for_test(start);
        kernel.seal_issuer(1).expect("seal the issuer");
        kernel.set_now_for_test(start + Duration::seconds(2));
        let log_before = kernel
            .store()
            .read_log()
            .expect("read the issuance log before the refused challenge");
        let challenge_lines_before = log_before
            .iter()
            .filter(|event| event.operation == "challenge")
            .count();
        let error = kernel
            .issue_holder_challenge(&instance.id)
            .expect_err("a holder challenge after remaining life must be refused");
        assert_issuer_seal_refused(&error);
        let verifier = kernel
            .issue_verifier_challenge()
            .expect("a verifier challenge after remaining life stays allowed");
        assert!(
            !verifier.nonce.is_empty(),
            "a verifier challenge after remaining life must still return a nonce"
        );
        let log_after = kernel
            .store()
            .read_log()
            .expect("read the issuance log after the refused challenge");
        let challenge_lines_after = log_after
            .iter()
            .filter(|event| event.operation == "challenge")
            .count();
        assert_eq!(
            challenge_lines_after, challenge_lines_before,
            "a refused holder challenge must not append a challenge issuance.log line"
        );
        assert_eq!(
            log_after.len(),
            log_before.len(),
            "a verifier challenge after remaining life must not append an issuance.log line"
        );
    }

    #[test]
    fn add_issuer_member_after_issuer_seal_is_refused() {
        let (_directory, kernel) = laboratory_kernel();
        kernel
            .seal_issuer(60)
            .expect("seal the issuer with remaining life");
        let issuer = kernel
            .store()
            .load_issuer()
            .expect("load the sealed issuer");
        assert!(issuer.kill_date.is_some(), "seal must write kill_date");
        assert!(
            !issuer.is_sealed_at(kernel.now()),
            "remaining life must still be open"
        );
        let member_count_before = issuer.signing_member_count();
        let log_before = kernel
            .store()
            .read_log()
            .expect("read the issuance log before the refused member add");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let error = kernel
            .add_issuer_member_with_secret_path(Some(&outside))
            .expect_err("adding a member after issuer seal must be refused");
        assert_issuer_seal_refused(&error);
        let after = kernel
            .store()
            .load_issuer()
            .expect("load the issuer after the refused member add");
        assert_eq!(
            after.signing_member_count(),
            member_count_before,
            "a refused member add must not grow the member list"
        );
        assert!(after.kill_date.is_some(), "seal must still hold");
        let log_after = kernel
            .store()
            .read_log()
            .expect("read the issuance log after the refused member add");
        assert_eq!(
            log_after.len(),
            log_before.len(),
            "a refused member add must not append an issuance.log line"
        );
    }

    #[test]
    fn set_issuer_threshold_after_issuer_seal_is_refused() {
        let store_directory = tempfile::tempdir().expect("create a store directory");
        let custody_directory = tempfile::tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        kernel
            .add_issuer_member_with_secret_path(Some(&outside))
            .expect("add member two before seal");
        kernel
            .seal_issuer(60)
            .expect("seal the issuer with remaining life");
        let before = kernel
            .store()
            .load_issuer()
            .expect("load the issuer before the refused threshold");
        assert_eq!(before.threshold_n.max(1), 1);
        let log_before = kernel
            .store()
            .read_log()
            .expect("read the issuance log before the refused threshold");
        let error = kernel
            .set_issuer_threshold(2)
            .expect_err("raising issuance threshold after issuer seal must be refused");
        assert_issuer_seal_refused(&error);
        let after = kernel
            .store()
            .load_issuer()
            .expect("load the issuer after the refused threshold");
        assert_eq!(
            after.threshold_n.max(1),
            1,
            "a refused issuer-threshold must not raise threshold_n"
        );
        assert!(after.kill_date.is_some(), "seal must still hold");
        let log_after = kernel
            .store()
            .read_log()
            .expect("read the issuance log after the refused threshold");
        assert_eq!(
            log_after.len(),
            log_before.len(),
            "a refused issuer-threshold must not append an issuance.log line"
        );
    }

    #[test]
    fn set_verify_threshold_after_issuer_seal_is_refused() {
        let store_directory = tempfile::tempdir().expect("create a store directory");
        let custody_directory = tempfile::tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        kernel
            .add_issuer_member_with_secret_path(Some(&outside))
            .expect("add member two before seal");
        kernel
            .seal_issuer(60)
            .expect("seal the issuer with remaining life");
        let before = kernel
            .store()
            .load_issuer()
            .expect("load the issuer before the refused verify threshold");
        assert_eq!(before.verify_threshold_n.max(1), 1);
        let log_before = kernel
            .store()
            .read_log()
            .expect("read the issuance log before the refused verify threshold");
        let error = kernel
            .set_verify_threshold(2)
            .expect_err("raising verify threshold after issuer seal must be refused");
        assert_issuer_seal_refused(&error);
        let after = kernel
            .store()
            .load_issuer()
            .expect("load the issuer after the refused verify threshold");
        assert_eq!(
            after.verify_threshold_n.max(1),
            1,
            "a refused verify-threshold must not raise verify_threshold_n"
        );
        assert!(after.kill_date.is_some(), "seal must still hold");
        let log_after = kernel
            .store()
            .read_log()
            .expect("read the issuance log after the refused verify threshold");
        assert_eq!(
            log_after.len(),
            log_before.len(),
            "a refused verify-threshold must not append an issuance.log line"
        );
    }

    #[test]
    fn store_b_allow_from_present_refuses_a_wider_intent_or_audience() {
        let (_first_directory, first, _second_directory, second, instance, presentation) =
            store_b_with_verified_present();
        let (proof, nonce) = verifier_holder_signature(&first, &instance, &second);
        let wider_intent = second
            .decide_tool_action_after_verified_wimse(
                &presentation,
                "write",
                &presentation.audience,
                Some(&proof),
                Some(&nonce),
                Some("autonomous"),
            )
            .expect("a wider intent must return a decision");
        assert_eq!(
            wider_intent.result, "refused",
            "store B must not allow a wider intent than the present: {:?}",
            wider_intent.reason
        );
        assert!(
            wider_intent
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("intent and audience must match the present"),
            "store B must name the present limit refuse: {:?}",
            wider_intent.reason
        );
        let (audience_proof, audience_nonce) =
            verifier_holder_signature(&first, &instance, &second);
        let wider_audience = second
            .decide_tool_action_after_verified_wimse(
                &presentation,
                &presentation.intent,
                "public",
                Some(&audience_proof),
                Some(&audience_nonce),
                Some("autonomous"),
            )
            .expect("a wider audience must return a decision");
        assert_eq!(
            wider_audience.result, "refused",
            "store B must not allow a wider audience than the present: {:?}",
            wider_audience.reason
        );
        assert!(
            wider_audience
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("intent and audience must match the present"),
            "store B must name the present limit refuse: {:?}",
            wider_audience.reason
        );
    }

    #[test]
    fn historical_present_without_ancestor_fields_still_verifies() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let presentation = laboratory_signed_presentation(&kernel, &instance, &capability);
        assert!(presentation.ancestor_instance_ids.is_empty());
        assert!(presentation.ancestor_capability_ids.is_empty());
        let json = serde_json::to_string(&presentation).expect("serialize a root present");
        assert!(
            !json.contains("ancestor_instance_ids"),
            "empty ancestor lists must skip-if-empty so historical JSON stays the same"
        );
        assert!(
            !json.contains("ancestor_capability_ids"),
            "empty ancestor lists must skip-if-empty so historical JSON stays the same"
        );
        let parsed = crate::presentation::parse_presentation_json(&json)
            .expect("historical JSON without ancestor fields must parse");
        assert!(parsed.ancestor_instance_ids.is_empty());
        assert!(parsed.ancestor_capability_ids.is_empty());
        assert_eq!(parsed.canonical_message(), presentation.canonical_message());
        kernel
            .verify_presentation(&parsed)
            .expect("a historical present without ancestor fields must still verify");
    }

    #[test]
    fn historical_receipt_without_ancestor_fields_still_verifies() {
        let (_directory, kernel) = laboratory_kernel();
        let receipt = laboratory_allowed_check_receipt(&kernel);
        assert!(
            receipt.ancestor_instance_ids.is_empty(),
            "a root receipt must keep empty ancestor instance lists"
        );
        assert!(
            receipt.ancestor_capability_ids.is_empty(),
            "a root receipt must keep empty ancestor capability lists"
        );
        let json = serde_json::to_string(&receipt).expect("serialize a root receipt");
        assert!(
            !json.contains("ancestor_instance_ids"),
            "empty ancestor lists must skip-if-empty so historical JSON stays the same"
        );
        assert!(
            !json.contains("ancestor_capability_ids"),
            "empty ancestor lists must skip-if-empty so historical JSON stays the same"
        );
        let parsed: DecisionReceipt = serde_json::from_str(&json)
            .expect("historical JSON without ancestor fields must parse");
        assert!(parsed.ancestor_instance_ids.is_empty());
        assert!(parsed.ancestor_capability_ids.is_empty());
        assert_eq!(parsed.canonical_message(), receipt.canonical_message());
        kernel
            .verify_decision_receipt(&parsed)
            .expect("a historical receipt without ancestor fields must still verify");
    }

    #[test]
    fn present_refuses_a_capability_that_does_not_belong_to_the_instance() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance_one, _capability_one) = laboratory_capability(&kernel);
        let (_instance_two, capability_two) = laboratory_capability(&kernel);
        let nonce = fresh_challenge(&kernel, &instance_one);
        let error = kernel
            .present_capability(
                &instance_one.id,
                &capability_two.id,
                Some(&holder_proof(&kernel, &instance_one)),
                Some(&nonce),
            )
            .expect_err("a wrong instance and capability pair must fail closed");
        assert!(
            error
                .to_string()
                .contains("does not belong to this instance"),
            "unexpected wrong-pair error: {error}"
        );
    }

    #[test]
    fn present_refuses_a_spent_challenge_nonce() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let nonce = fresh_challenge(&kernel, &instance);
        kernel
            .present_capability(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&nonce),
            )
            .expect("the first present must succeed");
        let error = kernel
            .present_capability(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&nonce),
            )
            .expect_err("a spent challenge nonce must fail closed");
        assert!(
            error.to_string().contains("already spent"),
            "unexpected spent-nonce error: {error}"
        );
    }

    #[test]
    fn an_expired_presentation_refuses() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        let (instance, capability) = laboratory_capability(&kernel);
        let presentation = laboratory_signed_presentation(&kernel, &instance, &capability);
        kernel
            .verify_presentation(&presentation)
            .expect("a presentation inside its window must verify");
        kernel.set_now_for_test(presentation.expires_at);
        let error = kernel
            .verify_presentation(&presentation)
            .expect_err("an expired presentation must fail closed");
        assert!(
            error.to_string().contains("expired"),
            "unexpected expired-presentation error: {error}"
        );
    }

    #[test]
    fn a_tampered_presentation_refuses() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let mut presentation = laboratory_signed_presentation(&kernel, &instance, &capability);
        presentation.intent = "write".to_string();
        let error = kernel
            .verify_presentation(&presentation)
            .expect_err("a tampered presentation must fail closed");
        let text = error.to_string();
        assert!(
            text.contains("not valid")
                || text.contains("tampered")
                || text.contains("fails closed"),
            "unexpected tampered-presentation error: {error}"
        );
    }

    #[test]
    fn a_second_store_with_the_accept_list_key_verifies_a_presentation() {
        let (_first_directory, first) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&first);
        let presentation = laboratory_signed_presentation(&first, &instance, &capability);
        let (_second_directory, second) = laboratory_kernel();
        second
            .accept_issuer_public_key(&first_issuer_public_key(&first))
            .expect("the second store must accept the first public key");
        let log_before = second
            .store()
            .log_text()
            .expect("read the second issuance log");
        let instances_before = second
            .store()
            .list_instances()
            .expect("list second-store instances");
        second.verify_presentation(&presentation).expect(
            "a second store that accepted the first public key must verify the presentation",
        );
        let log_after = second
            .store()
            .log_text()
            .expect("read the second issuance log after verify");
        let instances_after = second
            .store()
            .list_instances()
            .expect("list second-store instances after verify");
        assert_eq!(
            log_before, log_after,
            "presentation verify must not write a second issuance.log line"
        );
        assert_eq!(
            instances_before.len(),
            instances_after.len(),
            "presentation verify must not create instance records"
        );
    }

    #[test]
    fn a_second_store_without_the_accept_list_key_refuses_a_presentation() {
        let (_first_directory, first) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&first);
        let presentation = laboratory_signed_presentation(&first, &instance, &capability);
        let (_second_directory, second) = laboratory_kernel();
        let error = second
            .verify_presentation(&presentation)
            .expect_err("a second store without the first public key must refuse");
        let text = error.to_string();
        assert!(
            text.contains("unknown issuer key") || text.contains("accept list"),
            "unexpected missing-accept-key error: {error}"
        );
    }

    #[test]
    fn present_refuses_a_revoked_instance() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let nonce = fresh_challenge(&kernel, &instance);
        kernel
            .kill_instance(&instance.id)
            .expect("revoke the instance");
        let error = kernel
            .present_capability(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&nonce),
            )
            .expect_err("a revoked instance must fail closed");
        assert!(
            error.to_string().contains("revoked"),
            "unexpected revoked-instance error: {error}"
        );
    }

    #[test]
    fn present_refuses_a_sealed_issuer() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        let (instance, capability) = laboratory_capability(&kernel);
        let nonce = fresh_challenge(&kernel, &instance);
        kernel.seal_issuer(60).expect("seal the issuer");
        kernel.set_now_for_test(start + Duration::seconds(60));
        let error = kernel
            .present_capability(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&nonce),
            )
            .expect_err("a sealed issuer must fail closed");
        assert!(
            error.to_string().contains("seal") || error.to_string().contains("kill_date"),
            "unexpected sealed-issuer error: {error}"
        );
    }

    #[test]
    fn present_refuses_a_missing_challenge_nonce() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let error = kernel
            .present_capability(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                None,
            )
            .expect_err("a missing challenge nonce must fail closed");
        assert!(
            error.to_string().contains("challenge nonce"),
            "unexpected missing-challenge error: {error}"
        );
    }

    fn write_capability_record_bypassing_save(kernel: &Kernel, capability: &Capability) {
        let path = kernel
            .store()
            .root()
            .join("capabilities")
            .join(format!("{}.json", capability.id));
        let data = serde_json::to_vec_pretty(capability).expect("serialize the capability");
        std::fs::write(path, data).expect("write the capability json without save_capability");
    }

    fn swap_capability_token(kernel: &Kernel, target: &Capability, source: &Capability) {
        let mut tampered = kernel
            .store()
            .load_capability(&target.id)
            .expect("load the target capability record");
        tampered.biscuit = source.biscuit.clone();
        write_capability_record_bypassing_save(kernel, &tampered);
    }

    fn refuse_reason_is_token_record_lie(reason: &str) {
        assert!(
            reason.contains("golden-ticket-class lie")
                || reason.contains("wider than the capability record")
                || reason.contains("does not match the capability record"),
            "unexpected token-record consistency reason: {reason}"
        );
    }

    #[test]
    fn verify_refuses_a_token_with_a_wider_audience_than_the_record() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 3);
        let instance = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth an instance");
        let narrow = kernel
            .mint_capability(&instance.id, "read", "payments/prod", None)
            .expect("mint a narrow capability");
        let wide = kernel
            .mint_capability(&instance.id, "read", "payments", None)
            .expect("mint a wider capability");
        swap_capability_token(&kernel, &narrow, &wide);
        let error = kernel
            .verify_capability(
                &narrow.id,
                "payments/prod",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect_err("a wider token audience must fail closed");
        refuse_reason_is_token_record_lie(&error.to_string());
    }

    #[test]
    fn check_refuses_a_token_with_a_wider_intent_than_the_record() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 3);
        let instance = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth an instance");
        let narrow = kernel
            .mint_capability(&instance.id, "read/limited", "payments", None)
            .expect("mint a narrow capability");
        let wide = kernel
            .mint_capability(&instance.id, "read", "payments", None)
            .expect("mint a wider capability");
        swap_capability_token(&kernel, &narrow, &wide);
        let decision = kernel
            .check_tool_action(
                &instance.id,
                Some(&narrow.id),
                "read/limited",
                "payments",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect("check returns a decision");
        assert_eq!(decision.result, "refused");
        let reason = decision.reason.expect("a refused check must name a reason");
        refuse_reason_is_token_record_lie(&reason);
    }

    #[test]
    fn verify_refuses_a_token_with_a_different_act_authority_than_the_record() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 3);
        let instance = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth an instance");
        let autonomous = kernel
            .mint_capability(&instance.id, "read", "payments", None)
            .expect("mint an autonomous capability");
        let named = kernel
            .mint_capability(&instance.id, "read", "payments", Some("jordan".to_string()))
            .expect("mint a named-user capability");
        swap_capability_token(&kernel, &autonomous, &named);
        let error = kernel
            .verify_capability(
                &autonomous.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect_err("a different token act authority must fail closed");
        refuse_reason_is_token_record_lie(&error.to_string());
    }

    #[test]
    fn verify_refuses_a_token_with_a_different_instance_identifier_than_the_record() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 3);
        let first = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth the first instance");
        let second = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth the second instance");
        let first_capability = kernel
            .mint_capability(&first.id, "read", "payments", None)
            .expect("mint the first capability");
        let second_capability = kernel
            .mint_capability(&second.id, "read", "payments", None)
            .expect("mint the second capability");
        swap_capability_token(&kernel, &first_capability, &second_capability);
        let error = kernel
            .verify_capability(
                &first_capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &first)),
                Some(&fresh_challenge(&kernel, &first)),
                Some("autonomous"),
            )
            .expect_err("a different token instance identifier must fail closed");
        refuse_reason_is_token_record_lie(&error.to_string());
    }

    #[test]
    fn present_refuses_a_token_with_a_wider_audience_than_the_record() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 3);
        let instance = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth an instance");
        let narrow = kernel
            .mint_capability(&instance.id, "read", "payments/prod", None)
            .expect("mint a narrow capability");
        let wide = kernel
            .mint_capability(&instance.id, "read", "payments", None)
            .expect("mint a wider capability");
        swap_capability_token(&kernel, &narrow, &wide);
        let error = kernel
            .present_capability(
                &instance.id,
                &narrow.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
            )
            .expect_err("present must refuse a wider token");
        refuse_reason_is_token_record_lie(&error.to_string());
    }

    #[test]
    fn check_refuses_a_sibling_prefix_audience_that_is_not_a_child_path() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = kernel
            .add_agent_type(
                "laboratory".to_string(),
                vec!["read".to_string()],
                "internal".to_string(),
                3,
                crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE.to_string(),
                3600,
            )
            .expect("add an agent type");
        let instance = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth an instance");
        let capability = kernel
            .mint_capability(&instance.id, "read", "internal/pay", None)
            .expect("mint a capability for internal/pay");
        let decision = kernel
            .check_tool_action(
                &instance.id,
                Some(&capability.id),
                "read",
                "internal/payroll",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect("check returns a decision");
        assert_eq!(decision.result, "refused");
        let reason = decision.reason.expect("a refused check must name a reason");
        assert!(
            reason.contains("exceeds the capability")
                || reason.contains("child path")
                || reason.contains("string prefix"),
            "unexpected sibling-prefix audience reason: {reason}"
        );
    }

    #[test]
    fn verify_refuses_a_sibling_prefix_intent_that_is_not_a_child_path() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = kernel
            .add_agent_type(
                "laboratory".to_string(),
                vec!["read".to_string(), "readwrite".to_string()],
                "internal".to_string(),
                3,
                crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE.to_string(),
                3600,
            )
            .expect("add an agent type");
        let instance = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth an instance");
        let capability = kernel
            .mint_capability(&instance.id, "read", "internal", None)
            .expect("mint a capability for read");
        let error = kernel
            .verify_capability(
                &capability.id,
                "internal",
                "readwrite",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect_err("a sibling-prefix intent must fail closed");
        let reason = error.to_string();
        assert!(
            reason.contains("exceeds the capability")
                || reason.contains("child path")
                || reason.contains("string prefix"),
            "unexpected sibling-prefix intent reason: {reason}"
        );
    }

    #[test]
    fn check_allows_a_true_child_path_after_the_sibling_prefix_lock() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = kernel
            .add_agent_type(
                "laboratory".to_string(),
                vec!["read".to_string()],
                "internal".to_string(),
                3,
                crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE.to_string(),
                3600,
            )
            .expect("add an agent type");
        let instance = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth an instance");
        let capability = kernel
            .mint_capability(&instance.id, "read", "internal/pay", None)
            .expect("mint a capability for internal/pay");
        let decision = kernel
            .check_tool_action(
                &instance.id,
                Some(&capability.id),
                "read",
                "internal/pay/refunds",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect("check returns a decision");
        assert_eq!(decision.result, "allowed");
    }

    #[test]
    fn an_attenuated_capability_still_verifies_against_its_narrower_record() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let narrower = kernel
            .attenuate_capability(&capability.id, "payments/prod", Some("read/limited"))
            .expect("attenuate to a child path");
        kernel
            .verify_capability(
                &narrower.id,
                "payments/prod",
                "read/limited",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect("an honest attenuated child must still verify");
        let decision = kernel
            .check_tool_action(
                &instance.id,
                Some(&narrower.id),
                "read/limited",
                "payments/prod",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect("check returns a decision");
        assert_eq!(decision.result, "allowed");
    }

    fn assert_instance_expiry_extension_refused(error: &Error) {
        let text = error.to_string();
        assert!(
            text.contains("instance expiry")
                && (text.contains("extension") || text.contains("frozen")),
            "unexpected instance-expiry freeze error: {error}"
        );
    }

    fn assert_agent_type_id_swap_refused(error: &Error) {
        let text = error.to_string();
        assert!(
            text.contains("agent type identifier")
                && (text.contains("replaces") || text.contains("raise")),
            "unexpected agent-type-identifier freeze error: {error}"
        );
    }

    fn assert_parent_instance_change_refused(error: &Error) {
        let text = error.to_string();
        assert!(
            text.contains("parent instance identifier")
                && (text.contains("clears") || text.contains("raise")),
            "unexpected parent-instance freeze error: {error}"
        );
    }

    fn assert_instance_unrevoke_refused(error: &Error) {
        let text = error.to_string();
        assert!(
            text.contains("cannot return to live") || text.contains("Un-revoking"),
            "unexpected instance un-revoke freeze error: {error}"
        );
    }

    fn assert_lifetime_raise_refused(error: &Error) {
        let text = error.to_string();
        assert!(
            text.contains("lifetime") && (text.contains("raises") || text.contains("raise")),
            "unexpected lifetime-seconds freeze error: {error}"
        );
    }

    fn assert_hop_index_decrease_refused(error: &Error) {
        let text = error.to_string();
        assert!(
            text.contains("hop index") && (text.contains("decreases") || text.contains("raise")),
            "unexpected hop-index freeze error: {error}"
        );
    }

    fn assert_revoke_from_here_clear_refused(error: &Error) {
        let text = error.to_string();
        assert!(
            text.contains("revoke-from-here")
                && (text.contains("clears") || text.contains("raise")),
            "unexpected revoke-from-here freeze error: {error}"
        );
    }

    fn assert_parent_capability_change_refused(error: &Error) {
        let text = error.to_string();
        assert!(
            text.contains("parent capability identifier")
                && (text.contains("clears") || text.contains("raise")),
            "unexpected parent-capability freeze error: {error}"
        );
    }

    #[test]
    fn instance_expiry_freeze_refuses_a_later_expires_on_save() {
        let (_directory, kernel) = laboratory_kernel();
        let (mut instance, _capability) = laboratory_capability(&kernel);
        let original = instance.expires;
        instance.expires = original + Duration::seconds(3600);
        let error = kernel
            .store()
            .save_instance(&instance)
            .expect_err("a later instance expires must be refused");
        assert_instance_expiry_extension_refused(&error);
        let stored = kernel
            .store()
            .load_instance(&instance.id)
            .expect("load the instance");
        assert_eq!(stored.expires, original);
    }

    #[test]
    fn instance_expiry_freeze_allows_a_shorter_expires() {
        let (_directory, kernel) = laboratory_kernel();
        let (mut instance, _capability) = laboratory_capability(&kernel);
        let shorter = instance.expires - Duration::seconds(60);
        instance.expires = shorter;
        kernel
            .store()
            .save_instance(&instance)
            .expect("a shorter instance expiry may persist");
        let stored = kernel
            .store()
            .load_instance(&instance.id)
            .expect("load the shortened instance");
        assert_eq!(stored.expires, shorter);
    }

    #[test]
    fn instance_expiry_freeze_allows_the_same_expires() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, _capability) = laboratory_capability(&kernel);
        let original = instance.expires;
        kernel
            .store()
            .save_instance(&instance)
            .expect("persisting the same instance expires must succeed");
        let stored = kernel
            .store()
            .load_instance(&instance.id)
            .expect("load the instance");
        assert_eq!(stored.expires, original);
    }

    #[test]
    fn instance_expiry_freeze_keeps_mint_refused_after_the_original_expiry() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        let (mut instance, _capability) = laboratory_capability(&kernel);
        let original = instance.expires;
        instance.expires = original + Duration::seconds(3600);
        kernel
            .store()
            .save_instance(&instance)
            .expect_err("the extension must be refused");
        kernel.set_now_for_test(original + Duration::seconds(1));
        let error = kernel
            .mint_capability(&instance.id, "read", "payments", None)
            .expect_err("mint must still fail after the original instance expiry");
        assert!(
            error.to_string().contains("expired"),
            "unexpected mint error after refused instance expiry extension: {error}"
        );
    }

    #[test]
    fn instance_agent_type_id_freeze_refuses_a_swap_to_a_more_powerful_type() {
        let (_directory, kernel) = laboratory_kernel();
        let (mut instance, _capability) = laboratory_capability(&kernel);
        let original = instance.agent_type_id.clone();
        let powerful = kernel
            .add_agent_type(
                "laboratory".to_string(),
                vec![
                    "read".to_string(),
                    "read/limited".to_string(),
                    "write".to_string(),
                ],
                "public".to_string(),
                8,
                crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE.to_string(),
                7200,
            )
            .expect("add a more powerful agent type");
        instance.agent_type_id = powerful.id.clone();
        let error = kernel
            .store()
            .save_instance(&instance)
            .expect_err("swapping agent_type_id must be refused");
        assert_agent_type_id_swap_refused(&error);
        let stored = kernel
            .store()
            .load_instance(&instance.id)
            .expect("load the instance");
        assert_eq!(stored.agent_type_id, original);
        let mint_error = kernel
            .mint_capability(&instance.id, "write", "public", None)
            .expect_err("mint must still use the original type after a refused swap");
        assert!(
            mint_error.to_string().contains("allowed intents")
                || mint_error.to_string().contains("authorization limit"),
            "unexpected mint error after refused type swap: {mint_error}"
        );
    }

    #[test]
    fn instance_agent_type_id_freeze_allows_the_same_type() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, _capability) = laboratory_capability(&kernel);
        let original = instance.agent_type_id.clone();
        kernel
            .store()
            .save_instance(&instance)
            .expect("persisting the same agent_type_id must succeed");
        let stored = kernel
            .store()
            .load_instance(&instance.id)
            .expect("load the instance");
        assert_eq!(stored.agent_type_id, original);
    }

    #[test]
    fn instance_parent_instance_id_freeze_refuses_a_clear() {
        let (_directory, kernel) = laboratory_kernel();
        let (parent, capability) = laboratory_capability(&kernel);
        let parent_nonce = fresh_challenge(&kernel, &parent);
        let child = kernel
            .spawn_child(
                &parent.id,
                &capability.id,
                "child".to_string(),
                BTreeMap::new(),
                "read",
                "payments/prod",
                None,
                Some(&holder_proof(&kernel, &parent)),
                Some(&parent_nonce),
            )
            .expect("a narrower child must succeed");
        let original = child.instance.parent_instance_id.clone();
        assert_eq!(original.as_deref(), Some(parent.id.as_str()));
        let mut mutated = child.instance.clone();
        mutated.parent_instance_id = None;
        let error = kernel
            .store()
            .save_instance(&mutated)
            .expect_err("clearing parent_instance_id must be refused");
        assert_parent_instance_change_refused(&error);
        let stored = kernel
            .store()
            .load_instance(&child.instance.id)
            .expect("load the child");
        assert_eq!(stored.parent_instance_id, original);
    }

    #[test]
    fn instance_status_freeze_refuses_unrevoke() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, _capability) = laboratory_capability(&kernel);
        kernel
            .kill_instance(&instance.id)
            .expect("instance kill must succeed");
        let mut killed = kernel
            .store()
            .load_instance(&instance.id)
            .expect("load the killed instance");
        assert_eq!(killed.status, InstanceStatus::Revoked);
        killed.status = InstanceStatus::Live;
        let error = kernel
            .store()
            .save_instance(&killed)
            .expect_err("un-revoking an instance must be refused");
        assert_instance_unrevoke_refused(&error);
        let stored = kernel
            .store()
            .load_instance(&instance.id)
            .expect("load after refused un-revoke");
        assert_eq!(stored.status, InstanceStatus::Revoked);
        let mint_error = kernel
            .mint_capability(&instance.id, "read", "payments", None)
            .expect_err("mint must still fail after a refused un-revoke");
        assert!(
            mint_error.to_string().contains("revoked"),
            "unexpected mint error after refused un-revoke: {mint_error}"
        );
    }

    #[test]
    fn lifetime_seconds_freeze_refuses_a_raised_lifetime() {
        let (_directory, kernel) = laboratory_kernel();
        let mut agent_type = laboratory_agent_type(&kernel, "payments", 2);
        let original = agent_type.lifetime_seconds;
        agent_type.lifetime_seconds = original + 3600;
        let error = kernel
            .store()
            .save_agent_type(&agent_type)
            .expect_err("a raised lifetime_seconds must be refused");
        assert_lifetime_raise_refused(&error);
        let stored = kernel
            .store()
            .load_agent_type(&agent_type.id)
            .expect("load the agent type");
        assert_eq!(stored.lifetime_seconds, original);
    }

    #[test]
    fn lifetime_seconds_freeze_allows_a_narrower_lifetime() {
        let (_directory, kernel) = laboratory_kernel();
        let mut agent_type = laboratory_agent_type(&kernel, "payments", 2);
        agent_type.lifetime_seconds = 60;
        kernel
            .store()
            .save_agent_type(&agent_type)
            .expect("a lower lifetime_seconds is a narrowing and may persist");
        let stored = kernel
            .store()
            .load_agent_type(&agent_type.id)
            .expect("load the narrowed agent type");
        assert_eq!(stored.lifetime_seconds, 60);
    }

    #[test]
    fn lifetime_seconds_freeze_allows_the_same_lifetime() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 2);
        kernel
            .store()
            .save_agent_type(&agent_type)
            .expect("persisting the same lifetime_seconds must succeed");
        let stored = kernel
            .store()
            .load_agent_type(&agent_type.id)
            .expect("load the agent type");
        assert_eq!(stored.lifetime_seconds, 3600);
    }

    #[test]
    fn chain_hop_index_freeze_refuses_a_decreased_hop() {
        let (_directory, kernel) = laboratory_kernel();
        let (_instance, parent) = laboratory_capability(&kernel);
        let child = kernel
            .attenuate_capability(&parent.id, "payments/prod", None)
            .expect("attenuation must create a child hop");
        let mut chain = kernel
            .store()
            .load_chain(&child.id)
            .expect("load the child chain");
        assert!(chain.hop_index > 0);
        let original = chain.hop_index;
        chain.hop_index = original - 1;
        let error = kernel
            .store()
            .save_chain(&chain)
            .expect_err("a decreased hop_index must be refused");
        assert_hop_index_decrease_refused(&error);
        let stored = kernel
            .store()
            .load_chain(&child.id)
            .expect("load the child chain");
        assert_eq!(stored.hop_index, original);
    }

    #[test]
    fn chain_hop_index_freeze_allows_the_same_hop() {
        let (_directory, kernel) = laboratory_kernel();
        let (_instance, capability) = laboratory_capability(&kernel);
        let chain = kernel
            .store()
            .load_chain(&capability.id)
            .expect("load the chain");
        let original = chain.hop_index;
        kernel
            .store()
            .save_chain(&chain)
            .expect("persisting the same hop_index must succeed");
        let stored = kernel
            .store()
            .load_chain(&capability.id)
            .expect("load the chain");
        assert_eq!(stored.hop_index, original);
    }

    #[test]
    fn chain_revoke_from_here_freeze_refuses_a_clear_after_kill() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, parent) = laboratory_capability(&kernel);
        let child = kernel
            .attenuate_capability(&parent.id, "payments/prod", None)
            .expect("attenuation must create a child hop");
        kernel
            .kill_capability(&parent.id)
            .expect("parent capability kill must succeed");
        let mut chain = kernel
            .store()
            .load_chain(&parent.id)
            .expect("load the killed parent chain");
        assert!(chain.revoke_from_here);
        chain.revoke_from_here = false;
        let error = kernel
            .store()
            .save_chain(&chain)
            .expect_err("clearing revoke_from_here after kill must be refused");
        assert_revoke_from_here_clear_refused(&error);
        let stored = kernel
            .store()
            .load_chain(&parent.id)
            .expect("load the parent chain");
        assert!(stored.revoke_from_here);
        let child_error = kernel
            .verify_capability(
                &child.id,
                "payments/prod",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect_err("the child must still refuse after a refused revoke-from-here clear");
        assert!(
            child_error.to_string().contains("revoke_from_here")
                || child_error.to_string().contains("revoked"),
            "unexpected child verify error after refused flag clear: {child_error}"
        );
    }

    #[test]
    fn chain_parent_capability_id_freeze_refuses_a_clear() {
        let (_directory, kernel) = laboratory_kernel();
        let (_instance, parent) = laboratory_capability(&kernel);
        let child = kernel
            .attenuate_capability(&parent.id, "payments/prod", None)
            .expect("attenuation must create a child hop");
        let mut chain = kernel
            .store()
            .load_chain(&child.id)
            .expect("load the child chain");
        let original = chain.parent_capability_id.clone();
        assert_eq!(original.as_deref(), Some(parent.id.as_str()));
        chain.parent_capability_id = None;
        let error = kernel
            .store()
            .save_chain(&chain)
            .expect_err("clearing parent_capability_id must be refused");
        assert_parent_capability_change_refused(&error);
        let stored = kernel
            .store()
            .load_chain(&child.id)
            .expect("load the child chain");
        assert_eq!(stored.parent_capability_id, original);
    }

    #[test]
    fn issuer_seal_persist_refuses_a_later_kill_date() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        kernel.seal_issuer(60).expect("the first seal must succeed");
        let mut issuer = kernel
            .store()
            .load_issuer()
            .expect("load the sealed issuer");
        let original = issuer
            .kill_date
            .expect("the first seal must set issuer.kill_date");
        issuer.kill_date = Some(original + Duration::seconds(3600));
        let error = kernel
            .store()
            .save_issuer(&issuer)
            .expect_err("persisting a later issuer.kill_date must be refused");
        assert_issuer_seal_persist_postpone_refused(&error);
        let stored = kernel
            .store()
            .load_issuer()
            .expect("load after refused postpone");
        assert_eq!(stored.kill_date, Some(original));
    }

    #[test]
    fn issuer_seal_persist_refuses_a_cleared_kill_date() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        kernel.seal_issuer(60).expect("the first seal must succeed");
        let mut issuer = kernel
            .store()
            .load_issuer()
            .expect("load the sealed issuer");
        let original = issuer
            .kill_date
            .expect("the first seal must set issuer.kill_date");
        issuer.kill_date = None;
        let error = kernel
            .store()
            .save_issuer(&issuer)
            .expect_err("clearing issuer.kill_date must be refused");
        assert_issuer_seal_persist_postpone_refused(&error);
        let stored = kernel
            .store()
            .load_issuer()
            .expect("load after refused clear");
        assert_eq!(stored.kill_date, Some(original));
    }

    #[test]
    fn issuer_seal_persist_allows_a_shorter_kill_date() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        kernel.seal_issuer(60).expect("the first seal must succeed");
        let mut issuer = kernel
            .store()
            .load_issuer()
            .expect("load the sealed issuer");
        let original = issuer
            .kill_date
            .expect("the first seal must set issuer.kill_date");
        let shorter = original - Duration::seconds(30);
        issuer.kill_date = Some(shorter);
        kernel
            .store()
            .save_issuer(&issuer)
            .expect("a shorter issuer.kill_date may persist");
        let stored = kernel
            .store()
            .load_issuer()
            .expect("load the shortened issuer");
        assert_eq!(stored.kill_date, Some(shorter));
    }

    #[test]
    fn issuer_seal_persist_keeps_mint_refused_after_the_original_kill_date() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        let (instance, _capability) = laboratory_capability(&kernel);
        kernel.seal_issuer(60).expect("the first seal must succeed");
        let mut issuer = kernel
            .store()
            .load_issuer()
            .expect("load the sealed issuer");
        let original = issuer
            .kill_date
            .expect("the first seal must set issuer.kill_date");
        issuer.kill_date = Some(original + Duration::seconds(3600));
        kernel
            .store()
            .save_issuer(&issuer)
            .expect_err("the postpone must be refused");
        kernel.set_now_for_test(original);
        let error = kernel
            .mint_capability(&instance.id, "read", "payments", None)
            .expect_err("mint must still fail at the original issuer seal kill_date");
        assert_issuer_seal_refused(&error);
    }

    fn attacker_public_key_hex() -> String {
        tokens::public_key_hexadecimal(&tokens::generate_keypair())
    }

    fn assert_issuer_current_swap_refused(error: &Error) {
        let text = error.to_string();
        assert!(
            text.contains("forged current")
                || text.contains("swaps current_public_key")
                || text.contains("clears current_public_key")
                || text.contains("without recording the old key"),
            "unexpected current-swap persist error: {error}"
        );
    }

    fn assert_issuer_public_keys_grow_refused(error: &Error) {
        let text = error.to_string();
        assert!(
            text.contains("public_keys") && (text.contains("foreign") || text.contains("grow")),
            "unexpected public_keys grow persist error: {error}"
        );
    }

    fn assert_issuer_previous_key_raise_refused(error: &Error) {
        let text = error.to_string();
        assert!(
            text.contains("previous")
                && (text.contains("removed")
                    || text.contains("drops a previous")
                    || text.contains("kill_date")
                    || text.contains("foreign previous")
                    || text.contains("never-previous")
                    || text.contains("never this store current")),
            "unexpected previous-key persist error: {error}"
        );
    }

    fn forged_tree_head_with_secret(
        kernel: &Kernel,
        secret: &str,
        signed_at: DateTime<Utc>,
    ) -> crate::log_tree_head::SignedTreeHead {
        let root = kernel
            .issuance_log_merkle_root()
            .expect("compute the current Merkle root");
        let public_key = crate::issuer_crypto::public_key_hexadecimal_from_secret(secret)
            .expect("parse the module lattice secret");
        let truncated = DateTime::<Utc>::from_timestamp(signed_at.timestamp(), 0)
            .expect("truncate the injected clock");
        let message = crate::log_tree_head::signed_tree_head_message(
            &root.root,
            root.leaf_count,
            truncated,
            &public_key,
        );
        let signature_hex =
            tokens::sign_decision_receipt(secret, &message).expect("sign the forged tree head");
        crate::log_tree_head::SignedTreeHead {
            merkle_root: root.root,
            leaf_count: root.leaf_count,
            signed_at: truncated,
            issuer_public_key_hex: public_key,
            signature_hex,
            issuer_signatures: Vec::new(),
        }
    }

    #[test]
    fn issuer_persist_refuses_a_swapped_current_public_key() {
        let (_directory, kernel) = laboratory_kernel();
        let receipt = laboratory_check_receipt(&kernel);
        let stored = kernel.store().load_issuer().expect("load the issuer");
        let original = stored.current_public_key_hex();
        let mut issuer = stored;
        issuer.current_public_key = attacker_public_key_hex();
        let error = kernel
            .store()
            .save_issuer(&issuer)
            .expect_err("swapping current_public_key without rotate must be refused");
        assert_issuer_current_swap_refused(&error);
        let after = kernel
            .store()
            .load_issuer()
            .expect("load after refused swap");
        assert_eq!(after.current_public_key_hex(), original);
        let mut foreign = receipt.clone();
        let attacker = crate::issuer_crypto::generate_module_lattice_key_pair()
            .expect("generate an attacker module lattice key");
        foreign.signature = tokens::sign_decision_receipt(
            &attacker.secret_key_hexadecimal,
            &foreign.canonical_message(),
        )
        .expect("sign with a foreign key");
        let foreign_error = kernel
            .verify_decision_receipt(&foreign)
            .expect_err("a foreign receipt must still fail after the refused current swap");
        let text = foreign_error.to_string();
        assert!(
            text.contains("not valid for any accepted issuer public key")
                || text.contains("unknown issuer key"),
            "unexpected foreign-receipt error: {foreign_error}"
        );
        kernel
            .verify_decision_receipt(&receipt)
            .expect("an honest receipt must still verify after the refused current swap");
    }

    #[test]
    fn issuer_persist_refuses_public_keys_grown_with_an_attacker_key() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let stored = kernel.store().load_issuer().expect("load the issuer");
        let original = stored.public_keys.clone();
        let attacker = tokens::generate_keypair();
        let attacker_public = tokens::public_key_hexadecimal(&attacker);
        let mut issuer = stored;
        issuer.public_keys.push(attacker_public.clone());
        let error = kernel
            .store()
            .save_issuer(&issuer)
            .expect_err("growing public_keys with a foreign key must be refused");
        assert_issuer_public_keys_grow_refused(&error);
        let after = kernel
            .store()
            .load_issuer()
            .expect("load after refused grow");
        assert_eq!(after.public_keys, original);
        let expires: std::time::SystemTime = (Utc::now() + Duration::seconds(3600)).into();
        let (token_bytes, revoke_identifier) = tokens::mint_token(
            &attacker,
            &capability.id,
            &instance.id,
            "read",
            "payments",
            "autonomous",
            expires,
        )
        .expect("mint a token with the attacker key");
        let mut swapped = capability.clone();
        swapped.biscuit = hex::encode(&token_bytes);
        swapped.revoke_identifier = revoke_identifier;
        write_capability_record_bypassing_save(&kernel, &swapped);
        let nonce = fresh_challenge(&kernel, &instance);
        let verify_error = kernel
            .verify_capability(
                &swapped.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&nonce),
                Some("autonomous"),
            )
            .expect_err("verify must not accept a token signed by the refused attacker key");
        let text = verify_error.to_string();
        assert!(
            text.contains("not valid")
                || text.contains("public key")
                || text.contains("fails closed")
                || text.contains("capability token"),
            "unexpected attacker-token verify error: {verify_error}"
        );
    }

    #[test]
    fn issuer_persist_refuses_a_later_previous_key_kill_date() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        let _birth = laboratory_birth(&kernel);
        let old_secret = kernel.store().load_secret().expect("load the old secret");
        kernel.rotate_issuer_key(60).expect("rotate must succeed");
        let mut issuer = kernel.store().load_issuer().expect("load after rotate");
        assert_eq!(issuer.previous_issuer_keys.len(), 1);
        let original = issuer.previous_issuer_keys[0].kill_date;
        issuer.previous_issuer_keys[0].kill_date = original + Duration::seconds(3600);
        let error = kernel
            .store()
            .save_issuer(&issuer)
            .expect_err("postponing a previous-key kill_date must be refused");
        assert_issuer_previous_key_raise_refused(&error);
        let after = kernel
            .store()
            .load_issuer()
            .expect("load after refused postpone");
        assert_eq!(after.previous_issuer_keys[0].kill_date, original);
        let after_kill = start + Duration::seconds(61);
        kernel.set_now_for_test(after_kill);
        let forged = forged_tree_head_with_secret(&kernel, &old_secret, after_kill);
        let tree_error = kernel
            .check_issuance_log_tree_head(&forged, false)
            .expect_err(
                "a stolen old key must still fail after the original previous-key kill_date",
            );
        assert!(
            tree_error.to_string().contains("after its kill date"),
            "unexpected stolen-old-key tree-head error: {tree_error}"
        );
    }

    #[test]
    fn issuer_persist_refuses_a_removed_previous_issuer_key() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        let _birth = laboratory_birth(&kernel);
        let old_secret = kernel.store().load_secret().expect("load the old secret");
        kernel.rotate_issuer_key(60).expect("rotate must succeed");
        let mut issuer = kernel.store().load_issuer().expect("load after rotate");
        let original = issuer.previous_issuer_keys.clone();
        issuer.previous_issuer_keys.clear();
        let error = kernel
            .store()
            .save_issuer(&issuer)
            .expect_err("removing a previous issuer key must be refused");
        assert_issuer_previous_key_raise_refused(&error);
        let after = kernel
            .store()
            .load_issuer()
            .expect("load after refused remove");
        assert_eq!(after.previous_issuer_keys.len(), original.len());
        assert_eq!(
            after.previous_issuer_keys[0].public_key_hex,
            original[0].public_key_hex
        );
        let after_kill = start + Duration::seconds(61);
        kernel.set_now_for_test(after_kill);
        let forged = forged_tree_head_with_secret(&kernel, &old_secret, after_kill);
        let tree_error = kernel
            .check_issuance_log_tree_head(&forged, false)
            .expect_err("a stolen old key must still be previous after the refused remove");
        assert!(
            tree_error.to_string().contains("after its kill date"),
            "unexpected stolen-old-key tree-head error: {tree_error}"
        );
    }

    #[test]
    fn issuer_persist_refuses_a_foreign_previous_issuer_key() {
        let (_directory, kernel) = laboratory_kernel();
        let mut issuer = kernel.store().load_issuer().expect("load the issuer");
        issuer.previous_issuer_keys.push(PreviousIssuerKey {
            public_key_hex: attacker_public_key_hex(),
            kill_date: Utc::now() + Duration::seconds(3600),
        });
        let error = kernel
            .store()
            .save_issuer(&issuer)
            .expect_err("adding a foreign previous issuer key must be refused");
        assert_issuer_previous_key_raise_refused(&error);
        let after = kernel
            .store()
            .load_issuer()
            .expect("load after refused add");
        assert!(after.previous_issuer_keys.is_empty());
    }

    #[test]
    fn issuer_persist_allows_a_shorter_previous_key_kill_date() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        kernel.rotate_issuer_key(60).expect("rotate must succeed");
        let mut issuer = kernel.store().load_issuer().expect("load after rotate");
        let original = issuer.previous_issuer_keys[0].kill_date;
        let shorter = original - Duration::seconds(30);
        issuer.previous_issuer_keys[0].kill_date = shorter;
        kernel
            .store()
            .save_issuer(&issuer)
            .expect("a shorter previous-key kill_date may persist");
        let stored = kernel
            .store()
            .load_issuer()
            .expect("load the shortened previous key");
        assert_eq!(stored.previous_issuer_keys[0].kill_date, shorter);
    }

    #[test]
    fn emptying_accepted_issuer_public_keys_is_not_allow_all() {
        let (_directory, kernel) = laboratory_kernel();
        let receipt = laboratory_check_receipt(&kernel);
        let mut issuer = kernel.store().load_issuer().expect("load the issuer");
        let own = issuer.current_public_key_hex();
        issuer.accepted_issuer_public_keys.clear();
        kernel
            .store()
            .save_issuer(&issuer)
            .expect("emptying the accept-list field is not a raise when current remains");
        let stored = kernel
            .store()
            .load_issuer()
            .expect("load after empty accept list");
        assert!(
            stored.accepted_issuer_public_keys.is_empty(),
            "the emptied accept-list field may persist"
        );
        assert_eq!(stored.current_public_key_hex(), own);
        kernel
            .verify_decision_receipt(&receipt)
            .expect("own current key must still verify after the accept list field is emptied");
        let mut foreign = receipt.clone();
        let attacker = crate::issuer_crypto::generate_module_lattice_key_pair()
            .expect("generate an attacker module lattice key");
        foreign.signature = tokens::sign_decision_receipt(
            &attacker.secret_key_hexadecimal,
            &foreign.canonical_message(),
        )
        .expect("sign with a foreign key");
        let error = kernel
            .verify_decision_receipt(&foreign)
            .expect_err("emptying accepted_issuer_public_keys must not become allow-all");
        let text = error.to_string();
        assert!(
            text.contains("not valid for any accepted issuer public key")
                || text.contains("unknown issuer key")
                || text.contains("accept list is empty"),
            "unexpected empty-accept-list foreign error: {error}"
        );
    }

    #[test]
    fn issuer_unused_fields_do_not_skip_verify() {
        let (_directory, kernel) = laboratory_kernel();
        let receipt = laboratory_check_receipt(&kernel);
        let mut issuer = kernel.store().load_issuer().expect("load the issuer");
        issuer.crypto_profile = "skip-verify".to_string();
        issuer.issuance_log = "/dev/null".to_string();
        kernel
            .store()
            .save_issuer(&issuer)
            .expect("crypto_profile and issuance_log may persist because they do not skip verify");
        kernel
            .verify_decision_receipt(&receipt)
            .expect("an honest receipt must still verify after unused-field persist");
        let mut foreign = receipt.clone();
        let attacker = crate::issuer_crypto::generate_module_lattice_key_pair()
            .expect("generate an attacker module lattice key");
        foreign.signature = tokens::sign_decision_receipt(
            &attacker.secret_key_hexadecimal,
            &foreign.canonical_message(),
        )
        .expect("sign with a foreign key");
        let error = kernel
            .verify_decision_receipt(&foreign)
            .expect_err("crypto_profile and issuance_log must not skip verify");
        let text = error.to_string();
        assert!(
            text.contains("not valid for any accepted issuer public key")
                || text.contains("unknown issuer key"),
            "unexpected unused-field foreign error: {error}"
        );
        let stored = kernel
            .store()
            .load_issuer()
            .expect("load after unused-field persist");
        assert_eq!(stored.threshold_n, 1);
        assert_eq!(stored.crypto_profile, "skip-verify");
        assert_eq!(stored.issuance_log, "/dev/null");
    }

    fn assert_capability_intent_raise_refused(error: &Error) {
        let text = error.to_string();
        assert!(
            text.contains("intent") && (text.contains("widens") || text.contains("frozen")),
            "unexpected capability-intent persist raise error: {error}"
        );
    }

    fn assert_capability_audience_raise_refused(error: &Error) {
        let text = error.to_string();
        assert!(
            text.contains("audience") && (text.contains("widens") || text.contains("frozen")),
            "unexpected capability-audience persist raise error: {error}"
        );
    }

    fn assert_capability_on_behalf_of_raise_refused(error: &Error) {
        let text = error.to_string();
        assert!(
            text.contains("on_behalf_of") || text.contains("act authority"),
            "unexpected capability-on_behalf_of persist raise error: {error}"
        );
    }

    fn assert_capability_instance_id_raise_refused(error: &Error) {
        let text = error.to_string();
        assert!(
            text.contains("instance") && (text.contains("replaces") || text.contains("Swapping")),
            "unexpected capability-instance_id persist raise error: {error}"
        );
    }

    fn assert_capability_biscuit_raise_refused(error: &Error) {
        let text = error.to_string();
        assert!(
            text.contains("biscuit")
                || text.contains("token bytes")
                || text.contains("Swapping the token"),
            "unexpected capability-biscuit persist raise error: {error}"
        );
    }

    #[test]
    fn capability_persist_refuses_a_widened_intent_and_present_stays_narrow() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 3);
        let instance = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth an instance");
        let capability = kernel
            .mint_capability(&instance.id, "read/limited", "payments", None)
            .expect("mint a narrow intent");
        let original = capability.intent.clone();
        let mut widened = capability.clone();
        widened.intent = "read".to_string();
        let error = kernel
            .store()
            .save_capability(&widened)
            .expect_err("a widened intent must be refused");
        assert_capability_intent_raise_refused(&error);
        let stored = kernel
            .store()
            .load_capability(&capability.id)
            .expect("load after refused intent widen");
        assert_eq!(stored.intent, original);
        let presentation = laboratory_signed_presentation(&kernel, &instance, &capability);
        assert_eq!(
            presentation.intent, original,
            "present must not copy a widened intent after the refused persist"
        );
    }

    #[test]
    fn capability_persist_allows_a_narrower_intent() {
        let (_directory, kernel) = laboratory_kernel();
        let (_instance, mut capability) = laboratory_capability(&kernel);
        capability.intent = "read/limited".to_string();
        kernel
            .store()
            .save_capability(&capability)
            .expect("a narrower intent may persist");
        let stored = kernel
            .store()
            .load_capability(&capability.id)
            .expect("load the narrowed capability");
        assert_eq!(stored.intent, "read/limited");
    }

    #[test]
    fn capability_persist_allows_the_same_intent() {
        let (_directory, kernel) = laboratory_kernel();
        let (_instance, capability) = laboratory_capability(&kernel);
        let original = capability.intent.clone();
        kernel
            .store()
            .save_capability(&capability)
            .expect("persisting the same intent must succeed");
        let stored = kernel
            .store()
            .load_capability(&capability.id)
            .expect("load the capability");
        assert_eq!(stored.intent, original);
    }

    #[test]
    fn capability_persist_refuses_a_widened_audience_and_present_stays_narrow() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 3);
        let instance = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth an instance");
        let capability = kernel
            .mint_capability(&instance.id, "read", "payments/prod", None)
            .expect("mint a narrow audience");
        let original = capability.audience.clone();
        let mut widened = capability.clone();
        widened.audience = "payments".to_string();
        let error = kernel
            .store()
            .save_capability(&widened)
            .expect_err("a widened audience must be refused");
        assert_capability_audience_raise_refused(&error);
        let stored = kernel
            .store()
            .load_capability(&capability.id)
            .expect("load after refused audience widen");
        assert_eq!(stored.audience, original);
        let presentation = laboratory_signed_presentation(&kernel, &instance, &capability);
        assert_eq!(
            presentation.audience, original,
            "present must not copy a widened audience after the refused persist"
        );
    }

    #[test]
    fn capability_persist_allows_a_narrower_audience() {
        let (_directory, kernel) = laboratory_kernel();
        let (_instance, mut capability) = laboratory_capability(&kernel);
        capability.audience = "payments/prod".to_string();
        kernel
            .store()
            .save_capability(&capability)
            .expect("a narrower audience may persist");
        let stored = kernel
            .store()
            .load_capability(&capability.id)
            .expect("load the narrowed capability");
        assert_eq!(stored.audience, "payments/prod");
    }

    #[test]
    fn capability_persist_allows_the_same_audience() {
        let (_directory, kernel) = laboratory_kernel();
        let (_instance, capability) = laboratory_capability(&kernel);
        let original = capability.audience.clone();
        kernel
            .store()
            .save_capability(&capability)
            .expect("persisting the same audience must succeed");
        let stored = kernel
            .store()
            .load_capability(&capability.id)
            .expect("load the capability");
        assert_eq!(stored.audience, original);
    }

    #[test]
    fn capability_persist_refuses_an_on_behalf_of_change() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 3);
        let instance = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth an instance");
        let named = kernel
            .mint_capability(&instance.id, "read", "payments", Some("jordan".to_string()))
            .expect("mint a named-user capability");
        let mut to_autonomous = named.clone();
        to_autonomous.on_behalf_of = "autonomous".to_string();
        let error = kernel
            .store()
            .save_capability(&to_autonomous)
            .expect_err("named user to autonomous must be refused");
        assert_capability_on_behalf_of_raise_refused(&error);
        let mut to_other = named.clone();
        to_other.on_behalf_of = "alex".to_string();
        let error = kernel
            .store()
            .save_capability(&to_other)
            .expect_err("user A to user B must be refused");
        assert_capability_on_behalf_of_raise_refused(&error);
        let stored = kernel
            .store()
            .load_capability(&named.id)
            .expect("load after refused on_behalf_of changes");
        assert_eq!(stored.on_behalf_of, "jordan");
        kernel
            .store()
            .save_capability(&named)
            .expect("persisting the same on_behalf_of must succeed");
    }

    #[test]
    fn capability_persist_refuses_an_instance_id_swap() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 3);
        let first = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth the first instance");
        let second = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth the second instance");
        let capability = kernel
            .mint_capability(&first.id, "read", "payments", None)
            .expect("mint the first capability");
        let original = capability.instance_id.clone();
        let mut swapped = capability.clone();
        swapped.instance_id = second.id.clone();
        let error = kernel
            .store()
            .save_capability(&swapped)
            .expect_err("swapping instance_id must be refused");
        assert_capability_instance_id_raise_refused(&error);
        let stored = kernel
            .store()
            .load_capability(&capability.id)
            .expect("load after refused instance_id swap");
        assert_eq!(stored.instance_id, original);
        kernel
            .store()
            .save_capability(&capability)
            .expect("persisting the same instance_id must succeed");
    }

    #[test]
    fn capability_persist_refuses_a_biscuit_swap() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 3);
        let instance = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth an instance");
        let narrow = kernel
            .mint_capability(&instance.id, "read", "payments/prod", None)
            .expect("mint a narrow capability");
        let wide = kernel
            .mint_capability(&instance.id, "read", "payments", None)
            .expect("mint a wider capability");
        let original = narrow.biscuit.clone();
        let mut swapped = narrow.clone();
        swapped.biscuit = wide.biscuit.clone();
        swapped.revoke_identifier = wide.revoke_identifier.clone();
        let error = kernel
            .store()
            .save_capability(&swapped)
            .expect_err("swapping biscuit must be refused");
        assert_capability_biscuit_raise_refused(&error);
        let stored = kernel
            .store()
            .load_capability(&narrow.id)
            .expect("load after refused biscuit swap");
        assert_eq!(stored.biscuit, original);
        assert_eq!(stored.audience, "payments/prod");
    }

    #[test]
    fn capability_persist_refuses_a_wider_token_and_matching_record() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 3);
        let instance = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth an instance");
        let narrow = kernel
            .mint_capability(&instance.id, "read", "payments/prod", None)
            .expect("mint a narrow capability");
        let wide = kernel
            .mint_capability(&instance.id, "read", "payments", None)
            .expect("mint a wider capability");
        let mut swapped = narrow.clone();
        swapped.biscuit = wide.biscuit.clone();
        swapped.revoke_identifier = wide.revoke_identifier.clone();
        swapped.audience = wide.audience.clone();
        swapped.intent = wide.intent.clone();
        let error = kernel
            .store()
            .save_capability(&swapped)
            .expect_err("a wider token plus a matching widened record must be refused");
        assert!(
            error.to_string().contains("widens")
                || error.to_string().contains("biscuit")
                || error.to_string().contains("token bytes"),
            "unexpected wider-token-and-record error: {error}"
        );
        let stored = kernel
            .store()
            .load_capability(&narrow.id)
            .expect("load after refused widen");
        assert_eq!(stored.audience, "payments/prod");
        assert_eq!(stored.biscuit, narrow.biscuit);
        let verify_error = kernel
            .verify_capability(
                &narrow.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect_err("a wide request must still fail after the refused persist");
        let text = verify_error.to_string();
        assert!(
            text.contains("exceeds the capability")
                || text.contains("child path")
                || text.contains("authorization failed"),
            "unexpected wide-request error after refused persist: {verify_error}"
        );
        let presentation = laboratory_signed_presentation(&kernel, &instance, &narrow);
        assert_eq!(presentation.audience, "payments/prod");
    }

    #[test]
    fn capability_persist_refuses_named_to_autonomous_with_a_token_swap() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 3);
        let instance = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth an instance");
        let named = kernel
            .mint_capability(&instance.id, "read", "payments", Some("jordan".to_string()))
            .expect("mint a named-user capability");
        let autonomous = kernel
            .mint_capability(&instance.id, "read", "payments", None)
            .expect("mint an autonomous capability");
        let mut swapped = named.clone();
        swapped.biscuit = autonomous.biscuit.clone();
        swapped.revoke_identifier = autonomous.revoke_identifier.clone();
        swapped.on_behalf_of = "autonomous".to_string();
        let error = kernel
            .store()
            .save_capability(&swapped)
            .expect_err("named user to autonomous with a token swap must be refused");
        assert!(
            error.to_string().contains("on_behalf_of")
                || error.to_string().contains("act authority")
                || error.to_string().contains("biscuit")
                || error.to_string().contains("token bytes"),
            "unexpected named-to-autonomous persist error: {error}"
        );
        let stored = kernel
            .store()
            .load_capability(&named.id)
            .expect("load after refused named-to-autonomous persist");
        assert_eq!(stored.on_behalf_of, "jordan");
        assert_eq!(stored.biscuit, named.biscuit);
        let decision = kernel
            .check_tool_action(
                &instance.id,
                Some(&named.id),
                "read",
                "payments",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect("check returns a decision");
        assert_eq!(decision.result, "refused");
        let reason = decision.reason.expect("a refused check must name a reason");
        assert!(
            reason.contains("does not match the capability on_behalf_of")
                || reason.contains("act authority"),
            "unexpected autonomous check reason after refused persist: {reason}"
        );
    }

    fn write_instance_record_bypassing_save(kernel: &Kernel, instance: &Instance) {
        let path = kernel
            .store()
            .root()
            .join("instances")
            .join(format!("{}.json", instance.id));
        let data = serde_json::to_vec_pretty(instance).expect("serialize the instance");
        std::fs::write(path, data).expect("write the instance json without save_instance");
    }

    fn assert_record_signature_refused(reason: &str) {
        assert!(
            reason.contains("issuer signature")
                || reason.contains("planted record")
                || reason.contains("trusted issuer key")
                || reason.contains("signed identity fields"),
            "unexpected issuer-signature refuse reason: {reason}"
        );
    }

    fn flip_signature_nibble(signature_hex: &str) -> String {
        let mut characters: Vec<char> = signature_hex.chars().collect();
        assert!(
            !characters.is_empty(),
            "the stored signature must not be empty before a nibble flip"
        );
        characters[0] = if characters[0] == '0' { '1' } else { '0' };
        characters.into_iter().collect()
    }

    #[test]
    fn birth_and_mint_produce_records_with_valid_issuer_signatures() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let issuer = kernel.store().load_issuer().expect("load the issuer");
        let now = Utc::now();
        assert!(
            !instance.issuer_signature_hex.trim().is_empty(),
            "birth must persist an instance issuer signature"
        );
        assert!(
            !capability.issuer_signature_hex.trim().is_empty(),
            "mint must persist a capability issuer signature"
        );
        tokens::require_trusted_instance_issuer_signature(&instance, &issuer, now)
            .expect("birth must produce a valid instance issuer signature");
        tokens::require_trusted_capability_issuer_signature(&capability, &issuer, now)
            .expect("mint must produce a valid capability issuer signature");
        let stored_instance = kernel
            .store()
            .load_instance(&instance.id)
            .expect("load the born instance");
        let stored_capability = kernel
            .store()
            .load_capability(&capability.id)
            .expect("load the minted capability");
        tokens::require_trusted_instance_issuer_signature(&stored_instance, &issuer, now)
            .expect("the stored instance signature must verify");
        tokens::require_trusted_capability_issuer_signature(&stored_capability, &issuer, now)
            .expect("the stored capability signature must verify");
    }

    #[test]
    fn verify_check_and_present_refuse_a_stripped_issuer_signature() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let mut stripped = kernel
            .store()
            .load_capability(&capability.id)
            .expect("load the capability");
        stripped.issuer_signature_hex.clear();
        write_capability_record_bypassing_save(&kernel, &stripped);
        let error = kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect_err("verify must refuse a missing capability issuer signature");
        assert_record_signature_refused(&error.to_string());
        let decision = kernel
            .check_tool_action(
                &instance.id,
                Some(&capability.id),
                "read",
                "payments",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect("check returns a decision");
        assert_eq!(decision.result, "refused");
        let reason = decision.reason.expect("a refused check must name a reason");
        assert_record_signature_refused(&reason);
        let present_error = kernel
            .present_capability(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
            )
            .expect_err("present must refuse a missing capability issuer signature");
        assert_record_signature_refused(&present_error.to_string());
    }

    #[test]
    fn verify_refuses_a_flipped_issuer_signature_nibble() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let mut flipped = kernel
            .store()
            .load_capability(&capability.id)
            .expect("load the capability");
        flipped.issuer_signature_hex = flip_signature_nibble(&flipped.issuer_signature_hex);
        write_capability_record_bypassing_save(&kernel, &flipped);
        let error = kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect_err("verify must refuse a flipped capability issuer signature nibble");
        assert_record_signature_refused(&error.to_string());
        let mut flipped_instance = kernel
            .store()
            .load_instance(&instance.id)
            .expect("load the instance");
        flipped_instance.issuer_signature_hex =
            flip_signature_nibble(&flipped_instance.issuer_signature_hex);
        write_instance_record_bypassing_save(&kernel, &flipped_instance);
        let instance_error = kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect_err("verify must refuse a flipped instance issuer signature nibble");
        assert_record_signature_refused(&instance_error.to_string());
    }

    #[test]
    fn check_refuses_a_planted_capability_json_with_no_signature() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let planted_id = "01PLANTEDCAPABILITY000000000000";
        let mut planted = capability.clone();
        planted.id = planted_id.to_string();
        planted.issuer_signature_hex.clear();
        planted.issuer_public_key_hex.clear();
        write_capability_record_bypassing_save(&kernel, &planted);
        let decision = kernel
            .check_tool_action(
                &instance.id,
                Some(planted_id),
                "read",
                "payments",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect("check returns a decision");
        assert_eq!(decision.result, "refused");
        let reason = decision.reason.expect("a refused check must name a reason");
        assert_record_signature_refused(&reason);
    }

    #[test]
    fn a_tampered_identity_field_in_memory_fails_signature_recompute() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let issuer = kernel.store().load_issuer().expect("load the issuer");
        let now = Utc::now();
        let mut tampered_instance = instance.clone();
        tampered_instance.id = "01TAMPEREDINSTANCE0000000000000".to_string();
        let instance_error =
            tokens::require_trusted_instance_issuer_signature(&tampered_instance, &issuer, now)
                .expect_err(
                    "changing the instance identifier in memory must fail the recomputed signature",
                );
        assert_record_signature_refused(&instance_error.to_string());
        let mut tampered_capability = capability.clone();
        tampered_capability.id = "01TAMPEREDCAPABILITY00000000000".to_string();
        let capability_error = tokens::require_trusted_capability_issuer_signature(
            &tampered_capability,
            &issuer,
            now,
        )
        .expect_err(
            "changing the capability identifier in memory must fail the recomputed signature",
        );
        assert_record_signature_refused(&capability_error.to_string());
    }

    fn write_agent_type_record_bypassing_save(kernel: &Kernel, agent_type: &AgentType) {
        let path = kernel
            .store()
            .root()
            .join("agent_types")
            .join(format!("{}.json", agent_type.id));
        if let Some(parent_directory) = path.parent() {
            std::fs::create_dir_all(parent_directory).expect("create the agent_types directory");
        }
        let data = serde_json::to_vec_pretty(agent_type).expect("serialize the agent type");
        std::fs::write(path, data).expect("write the agent type json without save_agent_type");
    }

    #[test]
    fn add_agent_type_produces_a_record_with_a_valid_issuer_signature() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 3);
        let issuer = kernel.store().load_issuer().expect("load the issuer");
        let now = Utc::now();
        assert!(
            !agent_type.issuer_signature_hex.trim().is_empty(),
            "add must persist an agent type issuer signature"
        );
        assert!(
            !agent_type.issuer_public_key_hex.trim().is_empty(),
            "add must persist an agent type issuer public key"
        );
        tokens::require_trusted_agent_type_issuer_signature(&agent_type, &issuer, now)
            .expect("add must produce a valid agent type issuer signature");
        let stored = kernel
            .store()
            .load_agent_type(&agent_type.id)
            .expect("load the stored agent type");
        tokens::require_trusted_agent_type_issuer_signature(&stored, &issuer, now)
            .expect("the stored agent type signature must verify");
        assert_eq!(
            stored.issuer_public_key_hex,
            issuer.current_public_key_hex()
        );
    }

    #[test]
    fn mint_refuses_a_stripped_agent_type_issuer_signature() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let mut stripped = kernel
            .store()
            .load_agent_type(&instance.agent_type_id)
            .expect("load the agent type");
        stripped.issuer_signature_hex.clear();
        write_agent_type_record_bypassing_save(&kernel, &stripped);
        let mint_error = kernel
            .mint_capability(&instance.id, "read", "payments", None)
            .expect_err("mint must refuse a missing agent type issuer signature");
        assert_record_signature_refused(&mint_error.to_string());
        let verify_error = kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect_err("evaluate must refuse a missing agent type issuer signature");
        assert_record_signature_refused(&verify_error.to_string());
        let decision = kernel
            .check_tool_action(
                &instance.id,
                Some(&capability.id),
                "read",
                "payments",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect("check returns a decision");
        assert_eq!(decision.result, "refused");
        let reason = decision.reason.expect("a refused check must name a reason");
        assert_record_signature_refused(&reason);
    }

    #[test]
    fn birth_and_mint_refuse_a_planted_agent_type_with_a_wider_limit() {
        let (_directory, kernel) = laboratory_kernel();
        let planted_id = "01PLANTEDAGENTTYPE0000000000000";
        let planted = AgentType {
            id: planted_id.to_string(),
            owner: "attacker".to_string(),
            allowed_intents: vec!["read".to_string(), "write".to_string()],
            authorization_limit: "public".to_string(),
            max_delegation_depth: 9,
            crypto_profile: crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE.to_string(),
            lifetime_seconds: 3600,
            issuer_public_key_hex: String::new(),
            issuer_signature_hex: String::new(),
            issuer_signatures: Vec::new(),
        };
        write_agent_type_record_bypassing_save(&kernel, &planted);
        let birth_error = kernel
            .birth_instance(planted_id, "laboratory".to_string(), BTreeMap::new(), None)
            .expect_err("birth must refuse a planted agent type with no issuer signature");
        assert_record_signature_refused(&birth_error.to_string());
        let birth_write_error = kernel
            .birth_write(
                planted_id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "write",
                "public",
                None,
            )
            .expect_err("birth write must refuse a planted agent type with a wider limit");
        assert_record_signature_refused(&birth_write_error.to_string());

        let (instance, _capability) = laboratory_capability(&kernel);
        let mut widened = kernel
            .store()
            .load_agent_type(&instance.agent_type_id)
            .expect("load the honest agent type");
        widened.authorization_limit = "public".to_string();
        widened.allowed_intents.push("write".to_string());
        widened.issuer_signature_hex.clear();
        widened.issuer_public_key_hex.clear();
        write_agent_type_record_bypassing_save(&kernel, &widened);
        let mint_error = kernel
            .mint_capability(&instance.id, "write", "public", None)
            .expect_err("mint must refuse a planted wider agent type with no issuer signature");
        assert_record_signature_refused(&mint_error.to_string());

        let mut forged = widened.clone();
        forged.issuer_public_key_hex = kernel
            .store()
            .load_issuer()
            .expect("load the issuer")
            .current_public_key_hex();
        forged.issuer_signature_hex = "00".repeat(64);
        write_agent_type_record_bypassing_save(&kernel, &forged);
        let forged_error = kernel
            .mint_capability(&instance.id, "write", "public", None)
            .expect_err(
                "mint must refuse a planted wider agent type with a forged issuer signature",
            );
        assert_record_signature_refused(&forged_error.to_string());
    }

    #[test]
    fn mint_refuses_a_flipped_agent_type_issuer_signature_nibble() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let mut flipped = kernel
            .store()
            .load_agent_type(&instance.agent_type_id)
            .expect("load the agent type");
        flipped.issuer_signature_hex = flip_signature_nibble(&flipped.issuer_signature_hex);
        write_agent_type_record_bypassing_save(&kernel, &flipped);
        let mint_error = kernel
            .mint_capability(&instance.id, "read", "payments", None)
            .expect_err("mint must refuse a flipped agent type issuer signature nibble");
        assert_record_signature_refused(&mint_error.to_string());
        let verify_error = kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect_err("evaluate must refuse a flipped agent type issuer signature nibble");
        assert_record_signature_refused(&verify_error.to_string());
    }

    fn write_chain_record_bypassing_save(kernel: &Kernel, chain: &Chain) {
        let path = kernel
            .store()
            .root()
            .join("chains")
            .join(format!("{}.json", chain.capability_id));
        if let Some(parent_directory) = path.parent() {
            std::fs::create_dir_all(parent_directory).expect("create the chains directory");
        }
        let data = serde_json::to_vec_pretty(chain).expect("serialize the chain");
        std::fs::write(path, data).expect("write the chain json without save_chain");
    }

    #[test]
    fn birth_and_mint_produce_a_chain_with_a_valid_issuer_signature() {
        let (_directory, kernel) = laboratory_kernel();
        let (_instance, capability) = laboratory_capability(&kernel);
        let issuer = kernel.store().load_issuer().expect("load the issuer");
        let now = Utc::now();
        let chain = kernel
            .store()
            .load_chain(&capability.id)
            .expect("load the minted chain");
        assert!(
            !chain.issuer_signature_hex.trim().is_empty(),
            "mint must persist a chain issuer signature"
        );
        assert!(
            !chain.issuer_public_key_hex.trim().is_empty(),
            "mint must persist a chain issuer public key"
        );
        tokens::require_trusted_chain_issuer_signature(&chain, &issuer, now)
            .expect("mint must produce a valid chain issuer signature");
        assert_eq!(chain.issuer_public_key_hex, issuer.current_public_key_hex());
        let child = kernel
            .attenuate_capability(&capability.id, "payments/prod", None)
            .expect("attenuation must create a child chain");
        let child_chain = kernel
            .store()
            .load_chain(&child.id)
            .expect("load the child chain");
        tokens::require_trusted_chain_issuer_signature(&child_chain, &issuer, now)
            .expect("attenuation must persist a valid child chain issuer signature");
        assert!(child_chain.hop_index > chain.hop_index);
    }

    #[test]
    fn verify_check_and_present_refuse_a_stripped_chain_issuer_signature() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let mut stripped = kernel
            .store()
            .load_chain(&capability.id)
            .expect("load the chain");
        stripped.issuer_signature_hex.clear();
        write_chain_record_bypassing_save(&kernel, &stripped);
        let error = kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect_err("verify must refuse a missing chain issuer signature");
        assert_record_signature_refused(&error.to_string());
        let decision = kernel
            .check_tool_action(
                &instance.id,
                Some(&capability.id),
                "read",
                "payments",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect("check returns a decision");
        assert_eq!(decision.result, "refused");
        let reason = decision.reason.expect("a refused check must name a reason");
        assert_record_signature_refused(&reason);
        let present_error = kernel
            .present_capability(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
            )
            .expect_err("present must refuse a missing chain issuer signature");
        assert_record_signature_refused(&present_error.to_string());
    }

    #[test]
    fn verify_refuses_a_flipped_chain_issuer_signature_nibble() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let mut flipped = kernel
            .store()
            .load_chain(&capability.id)
            .expect("load the chain");
        flipped.issuer_signature_hex = flip_signature_nibble(&flipped.issuer_signature_hex);
        write_chain_record_bypassing_save(&kernel, &flipped);
        let error = kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect_err("verify must refuse a flipped chain issuer signature nibble");
        assert_record_signature_refused(&error.to_string());
        let attenuate_error = kernel
            .attenuate_capability(&capability.id, "payments/prod", None)
            .expect_err("attenuate must refuse a flipped chain issuer signature nibble");
        assert_record_signature_refused(&attenuate_error.to_string());
    }

    #[test]
    fn evaluate_refuses_a_planted_chain_that_clears_revoke_from_here() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, parent) = laboratory_capability(&kernel);
        let child = kernel
            .attenuate_capability(&parent.id, "payments/prod", None)
            .expect("attenuation must create a child hop");
        kernel
            .kill_capability(&parent.id)
            .expect("parent capability kill must succeed");
        let mut planted = kernel
            .store()
            .load_chain(&parent.id)
            .expect("load the killed parent chain");
        assert!(planted.revoke_from_here);
        planted.revoke_from_here = false;
        planted.issuer_signature_hex.clear();
        planted.issuer_public_key_hex.clear();
        write_chain_record_bypassing_save(&kernel, &planted);
        let child_error = kernel
            .verify_capability(
                &child.id,
                "payments/prod",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect_err("a planted cleared revoke-from-here must not revive the child");
        assert_record_signature_refused(&child_error.to_string());
        let decision = kernel
            .check_tool_action(
                &instance.id,
                Some(&child.id),
                "read",
                "payments/prod",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect("check returns a decision");
        assert_eq!(decision.result, "refused");
        let reason = decision.reason.expect("a refused check must name a reason");
        assert_record_signature_refused(&reason);
    }

    #[test]
    fn spawn_and_attenuate_refuse_a_planted_chain_with_a_lower_hop_index() {
        let (_directory, kernel) = laboratory_kernel();
        let (parent, capability) = laboratory_capability(&kernel);
        let hop1 = kernel
            .attenuate_capability(&capability.id, "payments/prod", None)
            .expect("first hop must succeed");
        let hop2 = kernel
            .attenuate_capability(&hop1.id, "payments/prod/a", None)
            .expect("second hop must succeed");
        let original = kernel
            .store()
            .load_chain(&hop2.id)
            .expect("load the hop-2 chain");
        assert!(original.hop_index >= 2);
        let mut planted = original.clone();
        planted.hop_index = 0;
        planted.issuer_signature_hex.clear();
        planted.issuer_public_key_hex.clear();
        write_chain_record_bypassing_save(&kernel, &planted);
        let attenuate_error = kernel
            .attenuate_capability(&hop2.id, "payments/prod/a/b", None)
            .expect_err("attenuate must refuse a planted lower hop_index");
        assert_record_signature_refused(&attenuate_error.to_string());
        let spawn_error = kernel
            .spawn_child(
                &parent.id,
                &hop2.id,
                "child".to_string(),
                BTreeMap::new(),
                "read",
                "payments/prod/a",
                None,
                Some(&holder_proof(&kernel, &parent)),
                Some(&fresh_challenge(&kernel, &parent)),
            )
            .expect_err("spawn must refuse a planted lower hop_index");
        assert_record_signature_refused(&spawn_error.to_string());
        let stored = kernel
            .store()
            .load_chain(&hop2.id)
            .expect("load after refused planted hop");
        assert_eq!(stored.hop_index, 0);
        assert!(stored.issuer_signature_hex.trim().is_empty());
    }

    #[test]
    fn rotate_re_signs_chain_records() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let before = kernel
            .store()
            .load_chain(&capability.id)
            .expect("load the chain before rotate");
        let old_signature = before.issuer_signature_hex.clone();
        let old_key = before.issuer_public_key_hex.clone();
        kernel.rotate_issuer_key(60).expect("rotate must succeed");
        let after = kernel
            .store()
            .load_chain(&capability.id)
            .expect("load the chain after rotate");
        let issuer = kernel.store().load_issuer().expect("load the issuer");
        assert_eq!(after.issuer_public_key_hex, issuer.current_public_key_hex());
        assert_ne!(after.issuer_public_key_hex, old_key);
        assert_ne!(after.issuer_signature_hex, old_signature);
        tokens::require_trusted_chain_issuer_signature(&after, &issuer, Utc::now())
            .expect("rotate must re-sign the chain with the current issuer secret");
        kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect("an honest capability must still verify after rotate re-signs the chain");
    }

    #[test]
    fn rotate_does_not_launder_a_planted_wider_agent_type() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let planted_id = "01PLANTEDAGENTTYPE0000000000000";
        let planted = AgentType {
            id: planted_id.to_string(),
            owner: "attacker".to_string(),
            allowed_intents: vec!["read".to_string(), "write".to_string()],
            authorization_limit: "public".to_string(),
            max_delegation_depth: 9,
            crypto_profile: crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE.to_string(),
            lifetime_seconds: 3600,
            issuer_public_key_hex: String::new(),
            issuer_signature_hex: String::new(),
            issuer_signatures: Vec::new(),
        };
        write_agent_type_record_bypassing_save(&kernel, &planted);
        kernel
            .rotate_issuer_key(60)
            .expect("rotate must succeed without laundering a planted type");
        let stored = kernel
            .store()
            .load_agent_type(planted_id)
            .expect("the planted type file must still be on disk");
        assert!(
            stored.issuer_signature_hex.trim().is_empty(),
            "rotate must not write a trusted signature onto a planted agent type"
        );
        assert_eq!(stored.authorization_limit, "public");
        let birth_error = kernel
            .birth_write(
                planted_id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "write",
                "public",
                None,
            )
            .expect_err("birth must still refuse a planted wider type after rotate");
        assert_record_signature_refused(&birth_error.to_string());
        let mint_error = kernel
            .mint_capability(&instance.id, "write", "public", None)
            .expect_err("mint must still use the honest signed type after rotate");
        assert!(
            mint_error.to_string().contains("allowed intents")
                || mint_error.to_string().contains("authorization limit")
                || mint_error.to_string().contains("issuer signature"),
            "unexpected mint error after rotate skipped a planted type: {mint_error}"
        );
        kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect("an honest capability must still verify after rotate skips a planted type");
    }

    #[test]
    fn rotate_does_not_launder_a_planted_chain_that_clears_revoke_from_here() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, parent) = laboratory_capability(&kernel);
        let child = kernel
            .attenuate_capability(&parent.id, "payments/prod", None)
            .expect("attenuation must create a child hop");
        kernel
            .kill_capability(&parent.id)
            .expect("parent capability kill must succeed");
        let mut planted = kernel
            .store()
            .load_chain(&parent.id)
            .expect("load the killed parent chain");
        assert!(planted.revoke_from_here);
        planted.revoke_from_here = false;
        planted.issuer_signature_hex.clear();
        planted.issuer_public_key_hex.clear();
        write_chain_record_bypassing_save(&kernel, &planted);
        kernel
            .rotate_issuer_key(60)
            .expect("rotate must succeed without laundering a planted chain");
        let stored = kernel
            .store()
            .load_chain(&parent.id)
            .expect("load the planted parent chain after rotate");
        assert!(
            stored.issuer_signature_hex.trim().is_empty(),
            "rotate must not write a trusted signature onto a planted cleared revoke-from-here"
        );
        assert!(!stored.revoke_from_here);
        let child_error = kernel
            .verify_capability(
                &child.id,
                "payments/prod",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect_err(
                "a planted cleared revoke-from-here must not revive the child after rotate",
            );
        assert_record_signature_refused(&child_error.to_string());
    }

    #[test]
    fn save_refuses_to_persist_a_planted_unsigned_existing_record() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 3);
        let mut planted_type = kernel
            .store()
            .load_agent_type(&agent_type.id)
            .expect("load the honest agent type");
        planted_type.authorization_limit = "public".to_string();
        planted_type.allowed_intents.push("write".to_string());
        planted_type.issuer_signature_hex.clear();
        planted_type.issuer_public_key_hex.clear();
        write_agent_type_record_bypassing_save(&kernel, &planted_type);
        let type_error = kernel
            .store()
            .save_agent_type(&planted_type)
            .expect_err("save_agent_type must refuse a planted unsigned existing type");
        assert_record_signature_refused(&type_error.to_string());
        let stored_type = kernel
            .store()
            .load_agent_type(&agent_type.id)
            .expect("load after refused planted type persist");
        assert!(stored_type.issuer_signature_hex.trim().is_empty());
        assert_eq!(stored_type.authorization_limit, "public");

        let (_instance, capability) = laboratory_capability(&kernel);
        let mut planted_chain = kernel
            .store()
            .load_chain(&capability.id)
            .expect("load the honest chain");
        planted_chain.hop_index = 0;
        planted_chain.issuer_signature_hex.clear();
        planted_chain.issuer_public_key_hex.clear();
        write_chain_record_bypassing_save(&kernel, &planted_chain);
        let chain_error = kernel
            .store()
            .save_chain(&planted_chain)
            .expect_err("save_chain must refuse a planted unsigned existing chain");
        assert_record_signature_refused(&chain_error.to_string());
        let stored_chain = kernel
            .store()
            .load_chain(&capability.id)
            .expect("load after refused planted chain persist");
        assert!(stored_chain.issuer_signature_hex.trim().is_empty());
        assert_eq!(stored_chain.hop_index, 0);
    }

    fn last_nonempty_issuance_log_line(kernel: &Kernel) -> String {
        kernel
            .store()
            .last_nonempty_log_line()
            .expect("read the last issuance-log line")
            .expect("the issuance log must have a line")
    }

    fn rewrite_last_issuance_log_line(kernel: &Kernel, new_last_line: &str) {
        let log_path = kernel.store().log_path();
        let original = std::fs::read_to_string(&log_path).expect("read issuance.log");
        let mut lines: Vec<String> = original
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| line.to_string())
            .collect();
        assert!(
            !lines.is_empty(),
            "the issuance log must have a line to rewrite"
        );
        let last = lines.len() - 1;
        lines[last] = new_last_line.to_string();
        let rewritten = lines
            .into_iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        std::fs::write(&log_path, rewritten).expect("rewrite the last issuance-log line");
    }

    fn assert_log_line_signature_refused(reason: &str) {
        assert!(
            reason.contains("issuer signature")
                || reason.contains("issuer public key")
                || reason.contains("hash-chain-only")
                || reason.contains("trusted issuer key")
                || reason.contains("without issuer.secret"),
            "unexpected issuance-log line signature refuse reason: {reason}"
        );
    }

    #[test]
    fn honest_issuance_log_append_verifies_hash_chain_and_line_signatures() {
        let (_directory, kernel) = laboratory_kernel();
        let receipt = laboratory_check_receipt(&kernel);
        kernel
            .verify_log_chain()
            .expect("an honest kernel append must verify the hash chain and each line signature");
        kernel
            .verify_decision_receipt(&receipt)
            .expect("a receipt bound to an honest signed line must verify");
        let last = last_nonempty_issuance_log_line(&kernel);
        let event: crate::records::LogEvent =
            serde_json::from_str(&last).expect("parse the last log line");
        assert!(
            !event.issuer_signature_hex.trim().is_empty(),
            "kernel append must write issuer_signature_hex"
        );
        assert!(
            !event.issuer_public_key_hex.trim().is_empty(),
            "kernel append must write issuer_public_key_hex"
        );
        let issuer = kernel.store().load_issuer().expect("load the issuer");
        crate::log_chain::require_issuance_log_line_issuer_signature(
            &event,
            &issuer.trusted_issuer_keys_for_issuance_log(),
        )
        .expect("the last honest line signature must verify");
    }

    #[test]
    fn log_verify_refuses_a_stripped_issuance_log_line_signature() {
        let (_directory, kernel) = laboratory_kernel();
        let _receipt = laboratory_check_receipt(&kernel);
        kernel
            .verify_log_chain()
            .expect("the intact log must verify before the strip");
        let last = last_nonempty_issuance_log_line(&kernel);
        let event: crate::records::LogEvent =
            serde_json::from_str(&last).expect("parse the last log line");
        assert!(
            !event.issuer_signature_hex.trim().is_empty(),
            "the last line must carry a signature before the strip"
        );
        let stripped = last.replace(
            &format!(
                r#","issuer_signature_hex":"{}""#,
                event.issuer_signature_hex
            ),
            "",
        );
        assert_ne!(stripped, last, "the signature field must be removed");
        rewrite_last_issuance_log_line(&kernel, &stripped);
        let error = kernel
            .verify_log_chain()
            .expect_err("stripping the last line issuer signature must fail closed");
        assert_log_line_signature_refused(&error.to_string());
    }

    #[test]
    fn log_verify_refuses_a_flipped_issuance_log_line_signature_nibble() {
        let (_directory, kernel) = laboratory_kernel();
        let _receipt = laboratory_check_receipt(&kernel);
        kernel
            .verify_log_chain()
            .expect("the intact log must verify before the nibble flip");
        let last = last_nonempty_issuance_log_line(&kernel);
        let event: crate::records::LogEvent =
            serde_json::from_str(&last).expect("parse the last log line");
        let flipped = flip_signature_nibble(&event.issuer_signature_hex);
        let mutated = last.replace(&event.issuer_signature_hex, &flipped);
        assert_ne!(mutated, last, "one signature nibble must change");
        rewrite_last_issuance_log_line(&kernel, &mutated);
        let error = kernel
            .verify_log_chain()
            .expect_err("a flipped issuance-log line signature nibble must fail closed");
        assert_log_line_signature_refused(&error.to_string());
    }

    #[test]
    fn log_verify_refuses_a_well_hashed_line_without_a_valid_signature() {
        let (_directory, kernel) = laboratory_kernel();
        let _receipt = laboratory_check_receipt(&kernel);
        kernel
            .verify_log_chain()
            .expect("the intact log must verify before the planted line");
        let previous = kernel
            .store()
            .last_nonempty_log_line()
            .expect("read the previous line");
        let mut planted = LogEvent {
            operation: "planted".to_string(),
            timestamp: kernel.now(),
            capability_id: None,
            parent_capability_id: None,
            instance_id: None,
            revoke_identifier: None,
            intent: None,
            audience: None,
            note: Some("hash-chain-only append without issuer.secret".to_string()),
            result: None,
            challenge_nonce: None,
            challenge_expires: None,
            on_behalf_of: None,
            killed_instance_ids: Vec::new(),
            killed_capability_ids: Vec::new(),
            previous_line_hash: String::new(),
            line_hash: String::new(),
            issuer_public_key_hex: String::new(),
            issuer_signature_hex: String::new(),
            threshold_n: 1,
            issuer_signatures: Vec::new(),
        };
        crate::log_chain::seal_log_event(&mut planted, previous.as_deref())
            .expect("seal a well-hashed unsigned line");
        assert!(
            !planted.line_hash.is_empty(),
            "the planted line must carry a line_hash"
        );
        assert!(
            planted.issuer_signature_hex.is_empty(),
            "the planted line must not carry a signature"
        );
        let planted_line = serde_json::to_string(&planted).expect("serialize the planted line");
        kernel
            .store()
            .append_log_line(&planted_line)
            .expect("raw-write the well-hashed unsigned line");
        let error = kernel
            .verify_log_chain()
            .expect_err("a well-hashed line without a valid issuer signature must fail closed");
        assert_log_line_signature_refused(&error.to_string());
    }

    #[test]
    fn receipt_verify_refuses_a_bound_unsigned_issuance_log_line() {
        let (_directory, kernel) = laboratory_kernel();
        let receipt = laboratory_check_receipt(&kernel);
        kernel
            .verify_decision_receipt(&receipt)
            .expect("the honest receipt must verify before the unsigned bind");
        let original_line = receipt.issuance_log_line.clone();
        let mut event: crate::records::LogEvent =
            serde_json::from_str(&original_line).expect("parse the bound line");
        assert!(
            !event.issuer_signature_hex.trim().is_empty(),
            "the honest bound line must carry a signature"
        );
        event.issuer_signature_hex.clear();
        let unsigned = serde_json::to_string(&event).expect("serialize the unsigned bound line");
        let log_path = kernel.store().log_path();
        let original = std::fs::read_to_string(&log_path).expect("read issuance.log");
        let rewritten: String = original
            .lines()
            .map(|line| {
                if line == original_line {
                    unsigned.clone()
                } else {
                    line.to_string()
                }
            })
            .map(|line| format!("{line}\n"))
            .collect();
        std::fs::write(&log_path, rewritten).expect("write the unsigned bound line");
        let mut unsigned_receipt = receipt.clone();
        unsigned_receipt.issuance_log_line = unsigned;
        let secret = kernel
            .store()
            .load_secret()
            .expect("load the issuer secret");
        unsigned_receipt.signature =
            tokens::sign_decision_receipt(&secret, &unsigned_receipt.canonical_message())
                .expect("re-sign the receipt over the unsigned bound line");
        let error = kernel
            .verify_decision_receipt(&unsigned_receipt)
            .expect_err("a receipt bound to an unsigned issuance-log line must fail closed");
        assert_log_line_signature_refused(&error.to_string());
    }

    #[test]
    fn issuer_init_with_a_classical_only_profile_is_refused() {
        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        let error = kernel
            .initialize_with_crypto_profile(
                crate::issuer_crypto::CLASSICAL_ONLY_ISSUER_CRYPTO_PROFILE,
            )
            .expect_err("lab-ed25519 as the only issuer signature algorithm must be refused");
        let text = error.to_string();
        assert!(
            text.contains("classical-only") || text.contains("lab-ed25519"),
            "unexpected classical-init error: {error}"
        );
        assert!(
            !kernel.store().issuer_exists(),
            "a refused classical-only init must not write an issuer"
        );
    }

    #[test]
    fn issuer_init_default_succeeds_with_a_module_lattice_current_key() {
        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        let issuer = kernel
            .initialize()
            .expect("default init must succeed with the hybrid profile");
        assert_eq!(
            issuer.crypto_profile,
            crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE
        );
        crate::issuer_crypto::require_module_lattice_public_key(&issuer.current_public_key_hex())
            .expect("the current issuer key must be Module-Lattice Digital Signature Algorithm");
        tokens::public_key_from_hexadecimal(&issuer.biscuit_public_key_hex)
            .expect("the Biscuit envelope key must stay laboratory Ed25519");
        let issuer_secret = kernel.store().load_secret().expect("load issuer.secret");
        crate::issuer_crypto::public_key_matches_secret(
            &issuer.current_public_key_hex(),
            &issuer_secret,
        )
        .expect("the issuer secret must match the current Module-Lattice public key");
        let biscuit_secret = kernel
            .store()
            .load_biscuit_secret()
            .expect("load biscuit.secret");
        assert!(
            tokens::public_key_matches_secret(&issuer.biscuit_public_key_hex, &biscuit_secret)
                .expect("the Biscuit secret must match the envelope public key"),
            "biscuit.secret must derive biscuit_public_key_hex"
        );
    }

    #[test]
    fn a_biscuit_token_still_verifies_with_the_envelope_ed25519_key() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let issuer = kernel.store().load_issuer().expect("load the issuer");
        let token_bytes = hex::decode(&capability.biscuit).expect("decode the token");
        let root = tokens::first_public_key_that_parses_token(
            &issuer.token_verify_public_key_hex_list(),
            &token_bytes,
        )
        .expect("the Biscuit envelope public key must parse the token");
        tokens::authorize_token(root, &token_bytes, "read", "payments", "autonomous")
            .expect("the capability token must still authorize with the envelope Ed25519 key");
        let _ = instance;
    }

    #[test]
    fn a_forged_classical_only_issuer_used_as_current_root_is_refused() {
        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel
            .initialize()
            .expect("honest init must succeed before the forged plant");
        let classical = tokens::generate_keypair();
        let mut issuer = kernel
            .store()
            .load_issuer()
            .expect("load the honest issuer");
        issuer.crypto_profile =
            crate::issuer_crypto::CLASSICAL_ONLY_ISSUER_CRYPTO_PROFILE.to_string();
        issuer.current_public_key = tokens::public_key_hexadecimal(&classical);
        issuer.public_keys = vec![issuer.current_public_key.clone()];
        issuer.accepted_issuer_public_keys = vec![issuer.current_public_key.clone()];
        std::fs::write(
            kernel.store().issuer_path(),
            serde_json::to_vec_pretty(&issuer).expect("serialize the forged issuer"),
        )
        .expect("plant a classical-only issuer.json");
        std::fs::write(
            kernel.store().secret_path(),
            tokens::private_key_hexadecimal(&classical),
        )
        .expect("plant a classical issuer.secret");
        let error = kernel
            .add_agent_type(
                "laboratory".to_string(),
                vec!["read".to_string()],
                "payments".to_string(),
                2,
                crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE.to_string(),
                3600,
            )
            .expect_err("a forged Ed25519-only current root must refuse birth and type add");
        let text = error.to_string();
        assert!(
            text.contains("classical-only")
                || text.contains("forged Ed25519-only")
                || text.contains("Module-Lattice"),
            "unexpected forged-classical-root error: {error}"
        );
        let birth_error = kernel
            .birth_write(
                "missing-type",
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "payments",
                None,
            )
            .expect_err("birth must refuse a classical-only current root");
        let birth_text = birth_error.to_string();
        assert!(
            birth_text.contains("classical-only")
                || birth_text.contains("forged Ed25519-only")
                || birth_text.contains("Module-Lattice"),
            "unexpected birth classical-root error: {birth_error}"
        );
    }

    #[test]
    fn stripping_or_flipping_a_module_lattice_signature_refuses() {
        let (_directory, kernel) = laboratory_kernel();
        let (_instance, capability) = laboratory_capability(&kernel);
        let mut stripped = capability.clone();
        stripped.issuer_signature_hex.clear();
        let issuer = kernel.store().load_issuer().expect("load the issuer");
        tokens::require_trusted_capability_issuer_signature(&stripped, &issuer, Utc::now())
            .expect_err("a stripped Module-Lattice signature must refuse");
        let mut flipped = capability.clone();
        let mut chars: Vec<char> = flipped.issuer_signature_hex.chars().collect();
        assert!(
            chars.len() > 8,
            "a Module-Lattice signature must be longer than an Ed25519 signature"
        );
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        flipped.issuer_signature_hex = chars.into_iter().collect();
        tokens::require_trusted_capability_issuer_signature(&flipped, &issuer, Utc::now())
            .expect_err("a flipped Module-Lattice signature must refuse");
    }

    #[test]
    fn init_still_writes_threshold_n_one() {
        let (_directory, kernel) = laboratory_kernel();
        let issuer = kernel.store().load_issuer().expect("load the issuer");
        assert_eq!(issuer.threshold_n, 1);
        assert_eq!(issuer.signing_member_count(), 1);
    }

    #[test]
    fn setting_threshold_two_with_only_one_member_is_refused() {
        let (_directory, kernel) = laboratory_kernel();
        let error = kernel
            .set_issuer_threshold(2)
            .expect_err("n=2 with one member must refuse");
        let text = error.to_string();
        assert!(
            text.contains("greater than the number of trusted")
                || text.contains("Need two members"),
            "unexpected one-member n=2 error: {error}"
        );
        let issuer = kernel.store().load_issuer().expect("load the issuer");
        assert_eq!(issuer.threshold_n, 1);
    }


    #[test]
    fn add_issuer_member_without_an_outside_path_is_refused() {
        let (directory, kernel) = laboratory_kernel();
        let error = kernel
            .add_issuer_member()
            .expect_err("a missing member secret path must refuse");
        let text = error.to_string();
        assert!(
            text.contains("required") || text.contains("under the data directory"),
            "unexpected missing-path add-member error: {error}"
        );
        let none_error = kernel
            .add_issuer_member_with_secret_path(None)
            .expect_err("None must refuse the in-directory member write");
        let none_text = none_error.to_string();
        assert!(
            none_text.contains("required") || none_text.contains("under the data directory"),
            "unexpected None add-member error: {none_error}"
        );
        let stray: Vec<_> = std::fs::read_dir(directory.path())
            .expect("read the store")
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("issuer-member-")
            })
            .collect();
        assert!(
            stray.is_empty(),
            "a refused add member must not write a member secret inside the data directory"
        );
        let issuer = kernel.store().load_issuer().expect("load the issuer");
        assert_eq!(
            issuer.signing_member_count(),
            1,
            "a refused add member must not grow the issuer member list"
        );
    }

    #[test]
    fn adding_a_second_member_then_setting_threshold_two_succeeds() {
        let (_directory, kernel) = laboratory_kernel();
        let (_custody, _outside) = add_outside_member_two(&kernel);
        let issuer = kernel.store().load_issuer().expect("load the issuer after member two");
        assert!(issuer.signing_member_count() >= 2);
        let issuer = kernel
            .set_issuer_threshold(2)
            .expect("n=2 after a second member must succeed");
        assert_eq!(issuer.threshold_n, 2);
    }

    #[test]
    fn mint_and_birth_refuse_when_only_one_secret_is_present_and_threshold_is_two() {
        let (directory, kernel) = laboratory_kernel();
        let (_custody, outside) = add_outside_member_two(&kernel);
        let issuer = kernel.store().load_issuer().expect("load the issuer after member two");
        kernel.set_issuer_threshold(2).expect("set n=2");
        let extra = issuer
            .trusted_signing_member_public_keys()
            .into_iter()
            .find(|key| key != &issuer.current_public_key_hex())
            .expect("the additional member public key");
        let agent_type = laboratory_agent_type(&kernel, "payments", 2);
        std::fs::remove_file(&outside)
            .expect("remove the additional member secret");
        let _ = extra;
        let error = kernel.mint_capability(
            &{
                kernel
                    .birth_instance(
                        &agent_type.id,
                        "laboratory".to_string(),
                        BTreeMap::new(),
                        None,
                    )
                    .map(|instance| instance.id)
                    .unwrap_or_else(|_| "missing".to_string())
            },
            "read",
            "payments",
            None,
        );
        // birth itself also signs and must refuse
        let birth_error = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "payments",
                None,
            )
            .expect_err("birth must refuse when only one secret is present and n=2");
        let text = birth_error.to_string();
        assert!(
            text.contains("only") && (text.contains("secret") || text.contains("member")),
            "unexpected one-secret n=2 birth error: {birth_error}"
        );
        let _ = (directory, error);
    }

    #[test]
    fn mint_and_birth_refuse_a_planted_lower_threshold_n_in_issuer_json() {
        let (directory, kernel) = laboratory_kernel();
        let (_custody, outside) = add_outside_member_two(&kernel);
        kernel.set_issuer_threshold(2).expect("set n=2");
        let issuer_path = kernel.store().issuer_path();
        let raw = std::fs::read_to_string(&issuer_path).expect("read issuer.json");
        let mut planted: serde_json::Value =
            serde_json::from_str(&raw).expect("parse issuer.json");
        assert_eq!(
            planted.get("threshold_n").and_then(|value| value.as_u64()),
            Some(2),
            "honest persist must write threshold_n 2"
        );
        let agent_type = laboratory_agent_type(&kernel, "payments", 2);
        planted["threshold_n"] = serde_json::json!(1);
        std::fs::write(
            &issuer_path,
            serde_json::to_string_pretty(&planted).expect("serialize planted issuer.json"),
        )
        .expect("plant a lower threshold_n without save_issuer");
        std::fs::remove_file(&outside).expect("remove the additional member secret");
        let loaded = kernel
            .store()
            .load_issuer()
            .expect("load the issuer after the plant");
        assert_eq!(
            loaded.threshold_n, 2,
            "load_issuer must overlay the signed log n"
        );
        let still_planted: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&issuer_path).expect("re-read issuer.json"),
        )
        .expect("parse planted issuer.json");
        assert_eq!(
            still_planted
                .get("threshold_n")
                .and_then(|value| value.as_u64()),
            Some(1),
            "load_issuer must not write the file back"
        );
        let birth_error = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "payments",
                None,
            )
            .expect_err(
                "birth must refuse a planted lower threshold_n when only one secret is present",
            );
        let text = birth_error.to_string();
        assert!(
            text.contains("only") && (text.contains("secret") || text.contains("member")),
            "unexpected planted-n birth error: {birth_error}"
        );
        let lower_error = kernel
            .set_issuer_threshold(1)
            .expect_err("set_issuer_threshold must refuse lowering after a plant");
        let lower_text = lower_error.to_string();
        assert!(
            lower_text.contains("lowered") || lower_text.contains("cannot be lowered"),
            "unexpected planted-n lower error: {lower_error}"
        );
        let mut lowered = kernel
            .store()
            .load_issuer()
            .expect("load the overlaid issuer for save refuse");
        lowered.threshold_n = 1;
        let save_error = kernel
            .store()
            .save_issuer(&lowered)
            .expect_err("save_issuer must refuse persist below the signed log n");
        let save_text = save_error.to_string();
        assert!(
            save_text.contains("lowered") || save_text.contains("cannot be lowered"),
            "unexpected planted-n save_issuer error: {save_error}"
        );
        let _ = directory;
    }

    #[test]
    fn mint_with_two_member_secrets_when_threshold_is_two_succeeds_and_verifies() {
        let (_directory, kernel) = laboratory_kernel();
        let (_custody, _outside) = add_outside_member_two(&kernel);
        kernel.set_issuer_threshold(2).expect("set n=2");
        let agent_type = laboratory_agent_type(&kernel, "payments", 2);
        let birth = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "payments",
                None,
            )
            .expect("birth with two member secrets must succeed");
        let issuer = kernel.store().load_issuer().expect("load the issuer");
        assert_eq!(issuer.threshold_n, 2);
        assert!(
            birth.instance.issuer_signatures.len() >= 2,
            "n=2 birth must persist two member signatures"
        );
        assert!(
            birth.capability.issuer_signatures.len() >= 2,
            "n=2 mint must persist two member signatures"
        );
        tokens::require_trusted_instance_issuer_signature(&birth.instance, &issuer, Utc::now())
            .expect("the n=2 instance record must verify");
        tokens::require_trusted_capability_issuer_signature(&birth.capability, &issuer, Utc::now())
            .expect("the n=2 capability record must verify");
    }

    #[test]
    fn set_issuer_threshold_three_succeeds_after_a_third_outside_member() {
        let (_directory, kernel) = laboratory_kernel();
        let (_two_custody, two) = add_outside_member_two(&kernel);
        let (_three_custody, three) = add_outside_member_three(&kernel);
        assert_ne!(
            two, three,
            "member three must not use the member-two custody path"
        );
        let issuer = kernel
            .set_issuer_threshold(3)
            .expect("set_issuer_threshold(3) must succeed after a third outside member");
        assert_eq!(issuer.threshold_n, 3);
        assert!(
            issuer.signing_member_count() >= 3,
            "n=3 must keep three trusted members"
        );
        let log = kernel
            .store()
            .read_log()
            .expect("read the issuance log after n=3");
        assert!(
            log.iter()
                .any(|event| event.operation == "issuer_threshold"
                    && event
                        .note
                        .as_deref()
                        .unwrap_or("")
                        .contains("threshold_n to 3")),
            "an honest n=3 raise must append a signed issuer_threshold line"
        );
    }

    #[test]
    fn set_issuer_threshold_three_refuses_with_only_two_members() {
        let (_directory, kernel) = laboratory_kernel();
        let (_custody, _outside) = add_outside_member_two(&kernel);
        let error = kernel
            .set_issuer_threshold(3)
            .expect_err("set_issuer_threshold(3) must refuse when only two members exist");
        let text = error.to_string();
        assert!(
            text.contains("3") && (text.contains("member") || text.contains("greater")),
            "n=3 with two members must name the missing third member: {error}"
        );
        let after = kernel
            .store()
            .load_issuer()
            .expect("load the issuer after a refused n=3");
        assert_eq!(
            after.threshold_n.max(1),
            1,
            "a refused set_issuer_threshold(3) must not persist n=3"
        );
    }

    #[test]
    fn mint_and_birth_refuse_when_only_two_secrets_are_present_and_threshold_is_three() {
        let (_directory, kernel) = laboratory_kernel();
        let (_two_custody, _two) = add_outside_member_two(&kernel);
        let (_three_custody, three) = add_outside_member_three(&kernel);
        kernel
            .set_issuer_threshold(3)
            .expect("set n=3 after three members");
        let agent_type = laboratory_agent_type(&kernel, "payments", 2);
        std::fs::remove_file(&three).expect("remove the third member secret");
        let birth_error = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "payments",
                None,
            )
            .expect_err("birth must refuse when only two secrets are present and n=3");
        let text = birth_error.to_string();
        assert!(
            text.contains("only") && (text.contains("secret") || text.contains("member")),
            "unexpected two-secret n=3 birth error: {birth_error}"
        );
    }

    #[test]
    fn mint_with_three_member_secrets_when_threshold_is_three_succeeds_and_verifies() {
        let (_directory, kernel) = laboratory_kernel();
        let (_two_custody, _two) = add_outside_member_two(&kernel);
        let (_three_custody, _three) = add_outside_member_three(&kernel);
        kernel
            .set_issuer_threshold(3)
            .expect("set n=3 after three members");
        let agent_type = laboratory_agent_type(&kernel, "payments", 2);
        let birth = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "payments",
                None,
            )
            .expect("birth with three member secrets must succeed");
        let issuer = kernel.store().load_issuer().expect("load the issuer");
        assert_eq!(issuer.threshold_n, 3);
        assert!(
            birth.instance.issuer_signatures.len() >= 3,
            "n=3 birth must persist three member signatures"
        );
        assert!(
            birth.capability.issuer_signatures.len() >= 3,
            "n=3 mint must persist three member signatures"
        );
        tokens::require_trusted_instance_issuer_signature(&birth.instance, &issuer, Utc::now())
            .expect("the n=3 instance record must verify");
        tokens::require_trusted_capability_issuer_signature(&birth.capability, &issuer, Utc::now())
            .expect("the n=3 capability record must verify");
    }

    #[test]
    fn stripping_one_of_two_signatures_refuses_evaluate() {
        let (_directory, kernel) = laboratory_kernel();
        let (_custody, _outside) = add_outside_member_two(&kernel);
        kernel.set_issuer_threshold(2).expect("set n=2");
        let (instance, capability) = laboratory_capability(&kernel);
        let mut stripped = kernel
            .store()
            .load_capability(&capability.id)
            .expect("load the capability");
        assert!(
            stripped.issuer_signatures.len() >= 2,
            "n=2 mint must write two signatures"
        );
        stripped.issuer_signatures.pop();
        write_capability_record_bypassing_save(&kernel, &stripped);
        let error = kernel
            .verify_capability(
                &capability.id,
                "payments",
                "read",
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
                Some("autonomous"),
            )
            .expect_err("evaluate must refuse a record with only one of two signatures");
        let text = error.to_string();
        assert!(
            text.contains("needs 2")
                || text.contains("member signatures")
                || text.contains("issuer signature"),
            "unexpected stripped-one-of-two error: {error}"
        );
    }

    #[test]
    fn a_biscuit_envelope_key_used_as_a_member_signature_does_not_count() {
        let (_directory, kernel) = laboratory_kernel();
        let (_custody, _outside) = add_outside_member_two(&kernel);
        kernel.set_issuer_threshold(2).expect("set n=2");
        let (_instance, capability) = laboratory_capability(&kernel);
        let issuer = kernel.store().load_issuer().expect("load the issuer");
        let mut record = kernel
            .store()
            .load_capability(&capability.id)
            .expect("load the capability");
        assert!(record.issuer_signatures.len() >= 2);
        let biscuit_secret = kernel
            .store()
            .load_biscuit_secret()
            .expect("load the biscuit secret");
        let biscuit_public = issuer.biscuit_public_key_hex.clone();
        let message = crate::records::capability_issuer_signature_message(&record);
        // Replace one member signature with a Biscuit-key signature over the same bytes.
        // Ed25519 biscuit secret cannot produce an ML-DSA signature; plant the biscuit
        // public key with the remaining valid ML-DSA signature so the key is untrusted.
        record.issuer_signatures[0].public_key_hex = biscuit_public;
        let error =
            tokens::require_trusted_capability_issuer_signature(&record, &issuer, Utc::now())
                .expect_err("a Biscuit envelope key must not count as a member");
        let text = error.to_string();
        assert!(
            text.contains("Biscuit")
                || text.contains("needs 2")
                || text.contains("member signatures")
                || text.contains("trusted issuer key"),
            "unexpected biscuit-member error: {error}"
        );
        let _ = (biscuit_secret, message);
    }

    #[test]
    fn member_add_refuses_a_secret_path_inside_the_data_directory() {
        let (directory, kernel) = laboratory_kernel();
        let inside = directory.path().join("inside-member.secret");
        let error = kernel
            .add_issuer_member_with_secret_path(Some(&inside))
            .expect_err("a member secret path inside the data directory must refuse");
        let text = error.to_string();
        assert!(
            text.contains("outside the data directory")
                || text.contains("inside the data directory"),
            "unexpected inside-path error: {error}"
        );
        assert!(
            !inside.exists(),
            "a refused inside path must not write the member secret"
        );
    }

    #[test]
    fn member_secret_flag_refuses_a_path_inside_the_data_directory() {
        let store_directory = tempdir().expect("create a store directory");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        kernel
            .add_issuer_member_with_secret_path(Some(&outside))
            .expect("add member two outside the data directory");
        let inside = store_directory.path().join("copied-member-two.secret");
        std::fs::copy(&outside, &inside).expect("copy the member secret into the data directory");
        let error = Kernel::open_with_member_secrets(store_directory.path(), vec![inside.clone()])
            .err()
            .expect("a --member-secret path inside the data directory must refuse");
        let text = error.to_string();
        assert!(
            text.contains("outside the data directory")
                || text.contains("inside the data directory"),
            "unexpected inside --member-secret error: {error}",
        );
        let signing =
            Kernel::open_with_member_secrets(store_directory.path(), vec![outside.clone()])
                .expect("an outside member secret path must still open");
        signing
            .set_issuer_threshold(2)
            .expect("outside custody must still raise issuance threshold_n");
    }

    #[test]
    fn birth_refuses_threshold_two_when_the_outside_member_secret_is_not_presented() {
        let store_directory = tempdir().expect("create a store directory");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        kernel
            .add_issuer_member_with_secret_path(Some(&outside))
            .expect("add member two outside the data directory");
        assert!(
            outside.exists(),
            "member two must be written outside the data directory"
        );
        let stray: Vec<_> = std::fs::read_dir(store_directory.path())
            .expect("read the store")
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("issuer-member-")
            })
            .collect();
        assert!(
            stray.is_empty(),
            "member two must not also live in the data directory"
        );
        let signing =
            Kernel::open_with_member_secrets(store_directory.path(), vec![outside.clone()])
                .expect("an outside member secret path must open");
        signing
            .set_issuer_threshold(2)
            .expect("set n=2 with member two in hand");
        let agent_type = laboratory_agent_type(&signing, "payments", 2);
        let stolen = Kernel::open(store_directory.path());
        let error = stolen
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "payments",
                None,
            )
            .expect_err("birth must refuse when member two is not presented");
        let text = error.to_string();
        assert!(
            text.contains("only") && (text.contains("secret") || text.contains("member")),
            "unexpected missing-custody birth error: {error}"
        );
    }

    #[test]
    fn birth_succeeds_threshold_two_when_the_outside_member_secret_is_presented() {
        let store_directory = tempdir().expect("create a store directory");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        kernel
            .add_issuer_member_with_secret_path(Some(&outside))
            .expect("add member two outside the data directory");
        let signing =
            Kernel::open_with_member_secrets(store_directory.path(), vec![outside.clone()])
                .expect("an outside member secret path must open");
        signing
            .set_issuer_threshold(2)
            .expect("set n=2 with member two in hand");
        let agent_type = laboratory_agent_type(&signing, "payments", 2);
        let birth = signing
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "payments",
                None,
            )
            .expect("birth must succeed when member two is presented");
        assert!(
            birth.instance.issuer_signatures.len() >= 2,
            "n=2 birth must persist two member signatures"
        );
        assert!(
            birth.capability.issuer_signatures.len() >= 2,
            "n=2 mint must persist two member signatures"
        );
    }

    #[test]
    fn rotate_at_issuance_threshold_two_needs_the_outside_member_secret() {
        let store_directory = tempdir().expect("create a store directory");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        kernel
            .add_issuer_member_with_secret_path(Some(&outside))
            .expect("add member two outside the data directory");
        let signing =
            Kernel::open_with_member_secrets(store_directory.path(), vec![outside.clone()])
                .expect("an outside member secret path must open");
        signing
            .set_issuer_threshold(2)
            .expect("set issuance threshold_n 2");
        let original = signing.store().load_issuer().expect("load the issuer");
        let original_current = original.current_public_key_hex();
        let original_secret = signing.store().load_secret().expect("load issuer.secret");

        let stolen = Kernel::open(store_directory.path());
        let error = stolen
            .rotate_issuer_key(60)
            .expect_err("rotate must refuse when member two is not presented");
        let message = error.to_string();
        assert!(
            (message.contains("only")
                && (message.contains("secret") || message.contains("member")))
                || message.contains("threshold"),
            "unexpected missing-custody rotate error: {error}"
        );
        let after_stolen = stolen
            .store()
            .load_issuer()
            .expect("load the issuer after a refused rotate");
        assert_eq!(
            after_stolen.current_public_key_hex(),
            original_current,
            "a refused rotate must not swap the current issuer public key"
        );
        let after_secret = stolen
            .store()
            .load_secret()
            .expect("load issuer.secret after a refused rotate");
        assert_eq!(
            after_secret, original_secret,
            "a refused rotate must not replace issuer.secret"
        );
        assert!(
            after_stolen.previous_issuer_keys.is_empty(),
            "a refused rotate must not record a previous issuer key"
        );

        signing
            .rotate_issuer_key(60)
            .expect("rotate must succeed when member two is presented");
        let rotated = signing
            .store()
            .load_issuer()
            .expect("load the issuer after rotate");
        assert_ne!(
            rotated.current_public_key_hex(),
            original_current,
            "rotate with member two must write a new current issuer public key"
        );
        assert_eq!(rotated.threshold_n, 2);
    }

    #[test]
    fn kill_at_issuance_threshold_two_needs_the_outside_member_secret() {
        let store_directory = tempdir().expect("create a store directory");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        kernel
            .add_issuer_member_with_secret_path(Some(&outside))
            .expect("add member two outside the data directory");
        let signing =
            Kernel::open_with_member_secrets(store_directory.path(), vec![outside.clone()])
                .expect("an outside member secret path must open");
        signing
            .set_issuer_threshold(2)
            .expect("set issuance threshold_n 2");
        let agent_type = laboratory_agent_type(&signing, "payments", 2);
        let birth = signing
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "payments",
                None,
            )
            .expect("birth must succeed when member two is presented");
        let instance_id = birth.instance.id.clone();
        let capability_id = birth.capability.id.clone();
        let live_status = signing
            .store()
            .load_instance(&instance_id)
            .expect("load the live instance")
            .status;
        assert_eq!(live_status, InstanceStatus::Live);
        let chain_before = signing
            .store()
            .load_chain(&capability_id)
            .expect("load the live chain");
        assert!(
            !chain_before.revoke_from_here,
            "revoke_from_here must stay false before kill"
        );

        let stolen = Kernel::open(store_directory.path());
        let error = stolen
            .kill_instance(&instance_id)
            .expect_err("kill must refuse when member two is not presented");
        let message = error.to_string();
        assert!(
            (message.contains("only")
                && (message.contains("secret") || message.contains("member")))
                || message.contains("threshold"),
            "unexpected missing-custody kill error: {error}"
        );
        let after_stolen = stolen
            .store()
            .load_instance(&instance_id)
            .expect("load the instance after a refused kill");
        assert_eq!(
            after_stolen.status,
            InstanceStatus::Live,
            "a refused kill must not change instance status on disk"
        );
        let chain_after = stolen
            .store()
            .load_chain(&capability_id)
            .expect("load the chain after a refused kill");
        assert!(
            !chain_after.revoke_from_here,
            "a refused kill must not set revoke_from_here"
        );

        signing
            .kill_instance(&instance_id)
            .expect("kill must succeed when member two is presented");
        let killed = signing
            .store()
            .load_instance(&instance_id)
            .expect("load the instance after kill");
        assert_eq!(killed.status, InstanceStatus::Revoked);
    }

    #[test]
    fn seal_at_issuance_threshold_two_needs_the_outside_member_secret() {
        let store_directory = tempdir().expect("create a store directory");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        kernel
            .add_issuer_member_with_secret_path(Some(&outside))
            .expect("add member two outside the data directory");
        let signing =
            Kernel::open_with_member_secrets(store_directory.path(), vec![outside.clone()])
                .expect("an outside member secret path must open");
        signing
            .set_issuer_threshold(2)
            .expect("set issuance threshold_n 2");
        let original = signing.store().load_issuer().expect("load the issuer");
        assert!(
            original.kill_date.is_none(),
            "the issuer must not be sealed before the first seal"
        );

        let stolen = Kernel::open(store_directory.path());
        let error = stolen
            .seal_issuer(60)
            .expect_err("seal must refuse when member two is not presented");
        let message = error.to_string();
        assert!(
            (message.contains("only")
                && (message.contains("secret") || message.contains("member")))
                || message.contains("threshold"),
            "unexpected missing-custody seal error: {error}"
        );
        let after_stolen = stolen
            .store()
            .load_issuer()
            .expect("load the issuer after a refused seal");
        assert!(
            after_stolen.kill_date.is_none(),
            "a refused seal must not write issuer.kill_date"
        );

        signing
            .seal_issuer(60)
            .expect("seal must succeed when member two is presented");
        let sealed = signing
            .store()
            .load_issuer()
            .expect("load the issuer after seal");
        let first_kill = sealed
            .kill_date
            .expect("seal with member two must write issuer.kill_date");
        assert_eq!(sealed.threshold_n, 2);

        let stolen_shorten = stolen
            .seal_issuer(30)
            .expect_err("a later shorter seal must refuse when member two is not presented");
        let shorten_message = stolen_shorten.to_string();
        assert!(
            (shorten_message.contains("only")
                && (shorten_message.contains("secret") || shorten_message.contains("member")))
                || shorten_message.contains("threshold"),
            "unexpected missing-custody shorter-seal error: {stolen_shorten}"
        );
        let after_shorten = stolen
            .store()
            .load_issuer()
            .expect("load the issuer after a refused shorter seal");
        assert_eq!(
            after_shorten.kill_date,
            Some(first_kill),
            "a refused shorter seal must not change issuer.kill_date"
        );
    }

    #[test]
    fn add_issuer_member_at_issuance_threshold_two_needs_the_outside_member_secret() {
        let store_directory = tempdir().expect("create a store directory");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        kernel
            .add_issuer_member_with_secret_path(Some(&outside))
            .expect("add member two outside the data directory");
        let signing =
            Kernel::open_with_member_secrets(store_directory.path(), vec![outside.clone()])
                .expect("an outside member secret path must open");
        signing
            .set_issuer_threshold(2)
            .expect("set issuance threshold_n 2");
        let original = signing.store().load_issuer().expect("load the issuer");
        let original_member_count = original.signing_member_count();
        let original_public_keys = original.public_keys.clone();
        let original_accepted = original.accepted_issuer_public_keys.clone();

        let stolen = Kernel::open(store_directory.path());
        let third_stolen = custody_directory.path().join("member-three-stolen.secret");
        let error = stolen
            .add_issuer_member_with_secret_path(Some(&third_stolen))
            .expect_err("add member must refuse when member two is not presented");
        let message = error.to_string();
        assert!(
            (message.contains("only")
                && (message.contains("secret") || message.contains("member")))
                || message.contains("threshold"),
            "unexpected missing-custody add-member error: {error}"
        );
        let after_stolen = stolen
            .store()
            .load_issuer()
            .expect("load the issuer after a refused add member");
        assert_eq!(
            after_stolen.signing_member_count(),
            original_member_count,
            "a refused add member must not grow the issuer member list"
        );
        assert_eq!(
            after_stolen.public_keys, original_public_keys,
            "a refused add member must not grow public_keys"
        );
        assert_eq!(
            after_stolen.accepted_issuer_public_keys, original_accepted,
            "a refused add member must not grow accepted_issuer_public_keys"
        );
        let stray: Vec<_> = std::fs::read_dir(store_directory.path())
            .expect("read the store")
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("issuer-member-")
            })
            .collect();
        assert!(
            stray.is_empty(),
            "a refused add member must not write a member secret inside the data directory"
        );

        let third = custody_directory.path().join("member-three.secret");
        signing
            .add_issuer_member_with_secret_path(Some(&third))
            .expect("add member must succeed when member two is presented");
        let added = signing
            .store()
            .load_issuer()
            .expect("load the issuer after add member");
        assert_eq!(
            added.signing_member_count(),
            original_member_count + 1,
            "add member with member two must grow the issuer member list"
        );
        assert_eq!(added.threshold_n, 2);
    }

    #[test]
    fn set_verify_threshold_at_issuance_threshold_two_needs_the_outside_member_secret() {
        let store_directory = tempdir().expect("create a store directory");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        kernel
            .add_issuer_member_with_secret_path(Some(&outside))
            .expect("add member two outside the data directory");
        let signing =
            Kernel::open_with_member_secrets(store_directory.path(), vec![outside.clone()])
                .expect("an outside member secret path must open");
        signing
            .set_issuer_threshold(2)
            .expect("set issuance threshold_n 2");
        let original = signing.store().load_issuer().expect("load the issuer");
        let original_verify = original.verify_threshold_n;
        assert_eq!(
            original_verify, 1,
            "verify_threshold_n must start at 1 after initialize"
        );

        let stolen = Kernel::open(store_directory.path());
        let error = stolen
            .set_verify_threshold(2)
            .expect_err("set_verify_threshold must refuse when member two is not presented");
        let message = error.to_string();
        assert!(
            (message.contains("only")
                && (message.contains("secret") || message.contains("member")))
                || message.contains("threshold"),
            "unexpected missing-custody set_verify_threshold error: {error}"
        );
        let after_stolen = stolen
            .store()
            .load_issuer()
            .expect("load the issuer after a refused set_verify_threshold");
        assert_eq!(
            after_stolen.verify_threshold_n, original_verify,
            "a refused set_verify_threshold must not change verify_threshold_n on disk"
        );

        signing
            .set_verify_threshold(2)
            .expect("set_verify_threshold must succeed when member two is presented");
        let raised = signing
            .store()
            .load_issuer()
            .expect("load the issuer after set_verify_threshold");
        assert_eq!(
            raised.verify_threshold_n, 2,
            "set_verify_threshold with member two must raise verify_threshold_n"
        );
        assert_eq!(raised.threshold_n, 2);
    }

    #[test]
    fn set_issuer_threshold_needs_the_outside_member_secret() {
        let store_directory = tempdir().expect("create a store directory");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        kernel
            .add_issuer_member_with_secret_path(Some(&outside))
            .expect("add member two outside the data directory");
        let original = kernel.store().load_issuer().expect("load the issuer");
        assert_eq!(original.threshold_n.max(1), 1);
        let log_before = kernel
            .store()
            .read_log()
            .expect("read the issuance log before the refused raise");

        let stolen = Kernel::open(store_directory.path());
        let error = stolen.set_issuer_threshold(2).expect_err(
            "raising issuance threshold_n must refuse when member two is not presented",
        );
        let message = error.to_string();
        assert!(
            (message.contains("only")
                && (message.contains("secret") || message.contains("member")))
                || message.contains("threshold"),
            "unexpected missing-custody set_issuer_threshold error: {error}"
        );
        let after_stolen = stolen
            .store()
            .load_issuer()
            .expect("load the issuer after a refused set_issuer_threshold");
        assert_eq!(
            after_stolen.threshold_n.max(1),
            1,
            "a refused set_issuer_threshold must not persist the new threshold_n"
        );
        let log_after = stolen
            .store()
            .read_log()
            .expect("read the issuance log after the refused raise");
        assert_eq!(
            log_after.len(),
            log_before.len(),
            "a refused set_issuer_threshold must not append an issuance.log line"
        );

        let signing =
            Kernel::open_with_member_secrets(store_directory.path(), vec![outside.clone()])
                .expect("an outside member secret path must open");
        signing
            .set_issuer_threshold(2)
            .expect("set_issuer_threshold must succeed when member two is presented");
        let raised = signing
            .store()
            .load_issuer()
            .expect("load the issuer after set_issuer_threshold");
        assert_eq!(
            raised.threshold_n, 2,
            "set_issuer_threshold with member two must raise threshold_n"
        );
        let log_raised = signing
            .store()
            .read_log()
            .expect("read the issuance log after the honest raise");
        assert!(
            log_raised.len() > log_before.len(),
            "an honest set_issuer_threshold raise must append a signed issuance.log line"
        );
        assert!(
            log_raised
                .iter()
                .any(|event| event.operation == "issuer_threshold"),
            "an honest set_issuer_threshold raise must write an issuer_threshold line"
        );
    }

    #[test]
    fn threshold_n_cannot_be_lowered() {
        let (_directory, kernel) = laboratory_kernel();
        let (_custody, _outside) = add_outside_member_two(&kernel);
        kernel.set_issuer_threshold(2).expect("set n=2");
        let error = kernel
            .set_issuer_threshold(1)
            .expect_err("lowering threshold_n must refuse");
        assert!(
            error.to_string().contains("cannot be lowered"),
            "unexpected lower-threshold error: {error}"
        );
        let mut issuer = kernel.store().load_issuer().expect("load the issuer");
        issuer.threshold_n = 1;
        let persist_error = kernel
            .store()
            .save_issuer(&issuer)
            .expect_err("persist must refuse lowering threshold_n");
        assert!(
            persist_error.to_string().contains("cannot be lowered"),
            "unexpected persist-lower error: {persist_error}"
        );
    }

    #[test]
    fn status_refuses_when_the_issuer_is_missing() {
        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        let error = kernel
            .store_status()
            .expect_err("status must refuse a store that was not initialized");
        assert!(
            error.to_string().contains("issuer record is missing"),
            "unexpected missing-issuer status error: {error}"
        );
    }

    #[test]
    fn status_after_init_shows_an_empty_store() {
        let (_directory, kernel) = laboratory_kernel();
        let status = kernel.store_status().expect("status after init");
        assert_eq!(
            status.crypto_profile,
            crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE
        );
        assert!(status.current_issuer_public_key_hexadecimal_length > 16);
        assert_eq!(
            status.current_issuer_public_key_hexadecimal_length,
            status.current_issuer_public_key_hex.len()
        );
        assert_eq!(status.honest_line, StoreStatus::HONEST_LINE);
        assert_eq!(status.threshold_n, 1);
        assert_eq!(status.member_count, 1);
        assert!(!status.sealed);
        assert!(status.kill_date.is_none());
        assert_eq!(status.agent_type_count, 0);
        assert_eq!(status.instance_live_count, 0);
        assert_eq!(status.instance_revoked_count, 0);
        assert_eq!(status.capability_count, 0);
        assert_eq!(status.chain_count, 0);
        assert_eq!(status.issuance_log_leaf_count, 0);
        assert_eq!(
            status.issuance_log_merkle_root,
            crate::log_chain::EMPTY_PREVIOUS_LINE_HASH
        );
        assert_eq!(status.check_host_bind, "127.0.0.1 only");
        let human = status.format_human();
        assert!(
            human.contains("The identity root is Module-Lattice Digital Signature Algorithm 65")
        );
        assert!(human
            .contains("The Biscuit envelope is laboratory Ed25519 and is not a threshold member"));
        assert!(human.contains("The check host must bind to 127.0.0.1 only"));
        assert!(human.contains("threshold_n: 1"));
        assert!(human.contains("member_count: 1"));
        assert!(human.contains("sealed: no"));
        assert!(human.contains("agent_types: 0"));
        assert!(human.contains("0 live, 0 revoked"));
        assert!(!human.contains("issuer.secret"));
        assert!(!human.contains("biscuit.secret"));
    }

    #[test]
    fn status_after_birth_counts_records() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 2);
        let birth = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "payments",
                None,
            )
            .expect("birth one write");
        let status = kernel.store_status().expect("status after birth");
        assert_eq!(status.agent_type_count, 1);
        assert_eq!(status.instance_live_count, 1);
        assert_eq!(status.instance_revoked_count, 0);
        assert_eq!(status.capability_count, 1);
        assert_eq!(status.chain_count, 1);
        assert!(status.issuance_log_leaf_count >= 1);
        assert_ne!(
            status.issuance_log_merkle_root,
            crate::log_chain::EMPTY_PREVIOUS_LINE_HASH
        );
        assert!(!status.sealed);
        assert_eq!(status.threshold_n, 1);
        let _ = birth;
    }

    #[test]
    fn status_does_not_include_secret_material() {
        let (_directory, kernel) = laboratory_kernel();
        let issuer_secret = kernel.store().load_secret().expect("load issuer secret");
        let biscuit_secret = kernel
            .store()
            .load_biscuit_secret()
            .expect("load biscuit secret");
        let status = kernel.store_status().expect("status");
        let human = status.format_human();
        let json = serde_json::to_string(&status).expect("serialize status");
        assert!(!human.contains(&issuer_secret));
        assert!(!json.contains(&issuer_secret));
        assert!(!human.contains(&biscuit_secret));
        assert!(!json.contains(&biscuit_secret));
        assert!(!human.contains("issuer.secret"));
        assert!(!human.contains("biscuit.secret"));
        assert!(!json.contains("issuer.secret"));
        assert!(!json.contains("biscuit.secret"));
    }

    #[test]
    fn first_binder_refuses_a_later_instance_file_that_rebinds_the_holder_public_key() {
        let (_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 2);
        let mut instance = kernel
            .birth_instance(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                None,
            )
            .expect("birth must set the first binder");
        let path = kernel
            .store()
            .root()
            .join("instances")
            .join(format!("{}.json", instance.id));
        std::fs::remove_file(&path).expect("remove the instance file after birth");
        instance.holder_public_key = other_holder_public_key();
        let error = kernel
            .store()
            .save_instance(&instance)
            .expect_err("a later instance file that rebinds the holder public key must be refused");
        assert!(
            error.to_string().contains("first binder"),
            "unexpected first-binder later-file error: {error}"
        );
        assert!(
            !path.exists(),
            "the refused later file must not persist a new holder"
        );
        assert!(
            kernel.store().holder_secret_path(&instance.id).exists(),
            "birth must keep the original holder secret"
        );
    }

    #[test]
    fn cold_restore_from_backup_returns_the_same_issuer_public_key() {
        let (source_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 2);
        let birth = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "payments",
                None,
            )
            .expect("birth_write on the source issuer");
        let backup_directory = tempdir().expect("create a backup directory");
        let backup = backup_directory.path().join("issuer-backup");
        kernel
            .export_issuer_backup(&backup)
            .expect("export a laboratory backup outside the data directory");
        let dest_directory = tempdir().expect("create a restore destination");
        let dest_root = dest_directory.path().join("restored");
        let restored = Kernel::restore_from_backup(&backup, &dest_root)
            .expect("restore onto an empty issuing store");
        let source_issuer = kernel.store().load_issuer().expect("load the source issuer");
        let restored_issuer = restored
            .store()
            .load_issuer()
            .expect("load the restored issuer");
        assert_eq!(
            restored_issuer.current_public_key_hex(),
            source_issuer.current_public_key_hex()
        );
        restored
            .store()
            .load_instance(&birth.instance.id)
            .expect("the born instance must load after restore");
        assert!(
            source_directory.path().join("issuer.json").exists(),
            "the source kernel still exists"
        );
        kernel
            .store()
            .load_issuer()
            .expect("the source issuer still loads");
    }

    #[test]
    fn issuer_backup_refuses_a_path_inside_the_data_directory() {
        let (_directory, kernel) = laboratory_kernel();
        let inside = kernel.store().root().join("backup");
        let error = kernel
            .export_issuer_backup(&inside)
            .expect_err("a backup path inside the data directory must be refused");
        assert!(
            error.to_string().contains("data directory"),
            "unexpected inside-data-directory backup error: {error}"
        );
    }

    #[test]
    fn issuer_backup_does_not_copy_member_two() {
        let (_source_directory, kernel) = laboratory_kernel();
        let (custody_directory, outside) = add_outside_member_two(&kernel);
        kernel
            .set_issuer_threshold(2)
            .expect("set n=2 with member two in hand");
        let agent_type = laboratory_agent_type(&kernel, "payments", 2);
        let backup_directory = tempdir().expect("create a backup directory");
        let backup = backup_directory.path().join("issuer-backup");
        kernel
            .export_issuer_backup(&backup)
            .expect("export a laboratory backup");
        let stray_backup: Vec<_> = std::fs::read_dir(&backup)
            .expect("read the backup")
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("issuer-member-")
            })
            .collect();
        assert!(
            stray_backup.is_empty(),
            "the backup must not include issuer-member secrets"
        );
        let dest_directory = tempdir().expect("create a restore destination");
        let dest_root = dest_directory.path().join("restored");
        let restored = Kernel::restore_from_backup(&backup, &dest_root)
            .expect("restore onto an empty issuing store");
        let stray_dest: Vec<_> = std::fs::read_dir(&dest_root)
            .expect("read the restored store")
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("issuer-member-")
            })
            .collect();
        assert!(
            stray_dest.is_empty(),
            "restore must not install member two"
        );
        let error = restored
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "payments",
                None,
            )
            .expect_err("birth must refuse on the restored n=2 store without member two");
        let text = error.to_string();
        assert!(
            text.contains("only") && (text.contains("secret") || text.contains("member")),
            "unexpected missing-custody birth error: {error}"
        );
        restored
            .store()
            .register_extra_member_secret_path(outside.clone())
            .expect("register the same outside member-two file");
        restored
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "payments",
                None,
            )
            .expect("birth must succeed after the outside member-two path is registered");
        let _keep_custody = custody_directory;
    }

    #[test]
    fn issuer_restore_refuses_a_destination_that_already_has_an_issuer() {
        let (_source_directory, kernel) = laboratory_kernel();
        let backup_directory = tempdir().expect("create a backup directory");
        let backup = backup_directory.path().join("issuer-backup");
        kernel
            .export_issuer_backup(&backup)
            .expect("export a laboratory backup");
        let (live_directory, _live) = laboratory_kernel();
        let error = match Kernel::restore_from_backup(&backup, live_directory.path()) {
            Ok(_) => panic!("restore onto a store that already has an issuer must be refused"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("already has an issuer")
                || error.to_string().contains("already"),
            "unexpected dest-with-issuer restore error: {error}"
        );
    }

    #[test]
    fn issuer_restore_refuses_a_backup_that_is_missing_issuer_secret() {
        let (_source_directory, kernel) = laboratory_kernel();
        let backup_directory = tempdir().expect("create a backup directory");
        let backup = backup_directory.path().join("issuer-backup");
        kernel
            .export_issuer_backup(&backup)
            .expect("export a laboratory backup");
        std::fs::remove_file(backup.join("issuer.secret"))
            .expect("remove issuer.secret from the backup");
        let dest_directory = tempdir().expect("create a restore destination");
        let dest_root = dest_directory.path().join("restored");
        let error = match Kernel::restore_from_backup(&backup, &dest_root) {
            Ok(_) => panic!("a backup missing issuer.secret must be refused"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("issuer.secret"),
            "unexpected missing-secret restore error: {error}"
        );
    }

    #[test]
    fn restore_diagnostics_report_operation_normal_after_honest_cold_restore() {
        let (_source_directory, kernel) = laboratory_kernel();
        let agent_type = laboratory_agent_type(&kernel, "payments", 2);
        let _birth = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "payments",
                None,
            )
            .expect("birth_write on the source issuer");
        let backup_directory = tempdir().expect("create a backup directory");
        let backup = backup_directory.path().join("issuer-backup");
        kernel
            .export_issuer_backup(&backup)
            .expect("export a laboratory backup outside the data directory");
        let dest_directory = tempdir().expect("create a restore destination");
        let dest_root = dest_directory.path().join("restored");
        let restored = Kernel::restore_from_backup(&backup, &dest_root)
            .expect("restore onto an empty issuing store");
        let diagnostics = restored
            .restore_diagnostics(&backup)
            .expect("restore diagnostics after honest restore");
        assert!(
            diagnostics.restore_succeeded && diagnostics.operation_normal,
            "honest restore must report restore_succeeded and operation_normal"
        );
        assert!(
            diagnostics.same_issuer_public_key,
            "dest current key must equal the backup issuer.json current key"
        );
        assert!(
            diagnostics.issuer_secret_matches_current,
            "dest issuer.secret must match the current public key"
        );
        assert!(
            diagnostics.issuance_log_chain_ok,
            "dest issuance log chain must verify"
        );
        assert!(
            diagnostics.member_two_absent_from_store,
            "dest must not hold issuer-member secrets"
        );
        let stray_dest: Vec<_> = std::fs::read_dir(&dest_root)
            .expect("read the restored store")
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("issuer-member-")
            })
            .collect();
        assert!(
            stray_dest.is_empty(),
            "dest must not include issuer-member-*.secret"
        );
    }

    #[test]
    fn restore_diagnostics_refuse_when_restored_secret_does_not_match() {
        let (_source_directory, kernel) = laboratory_kernel();
        let backup_directory = tempdir().expect("create a backup directory");
        let backup = backup_directory.path().join("issuer-backup");
        kernel
            .export_issuer_backup(&backup)
            .expect("export a laboratory backup");
        let dest_directory = tempdir().expect("create a restore destination");
        let dest_root = dest_directory.path().join("restored");
        let restored = Kernel::restore_from_backup(&backup, &dest_root)
            .expect("restore onto an empty issuing store");
        let stranger = crate::issuer_crypto::generate_module_lattice_key_pair()
            .expect("generate a different module-lattice secret");
        std::fs::write(
            restored.store().secret_path(),
            stranger.secret_key_hexadecimal,
        )
        .expect("overwrite dest issuer.secret");
        match restored.restore_diagnostics(&backup) {
            Ok(diagnostics) => {
                assert!(
                    !diagnostics.restore_succeeded || !diagnostics.operation_normal,
                    "a dest issuer.secret that does not match the current public key must not report operation_normal"
                );
            }
            Err(_) => {}
        }
    }
    #[test]
    fn cold_restore_present_verifies_on_a_store_that_pinned_the_original_issuer() {
        let (_source_directory, first) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&first);
        let _source_present = laboratory_signed_presentation(&first, &instance, &capability);
        let backup_directory = tempdir().expect("create a backup directory");
        let backup = backup_directory.path().join("issuer-backup");
        first
            .export_issuer_backup(&backup)
            .expect("export a laboratory backup outside the data directory");
        let dest_directory = tempdir().expect("create a restore destination");
        let dest_root = dest_directory.path().join("restored");
        let restored = Kernel::restore_from_backup(&backup, &dest_root)
            .expect("restore onto an empty issuing store");
        let diagnostics = restored
            .restore_diagnostics(&backup)
            .expect("restore diagnostics after honest restore");
        assert!(
            diagnostics.restore_succeeded && diagnostics.operation_normal,
            "honest restore must report restore_succeeded and operation_normal"
        );
        let source_key = first_issuer_public_key(&first);
        assert_eq!(
            first_issuer_public_key(&restored),
            source_key,
            "the restored issuer public key must equal the source issuer public key"
        );
        assert!(
            restored.store().holder_secret_path(&instance.id).exists(),
            "the holder secret must restore from holders/"
        );
        let restored_present = laboratory_signed_presentation(&restored, &instance, &capability);
        restored
            .verify_presentation(&restored_present)
            .expect("an honest present from the restored live instance must verify");
        let (_verifier_directory, verifier) = laboratory_kernel();
        verifier
            .accept_issuer_public_key(&source_key)
            .expect("store C pins the original issuer public key");
        verifier
            .verify_presentation(&restored_present)
            .expect("a store that pinned the original public key must allow the restored present");
        restored
            .kill_instance(&instance.id)
            .expect("kill on the restored issuer");
        let kill_directory = dest_directory.path().join("kill-bundle");
        restored
            .export_kill_bundle(Some(&instance.id), None, &kill_directory)
            .expect("export a kill bundle after kill");
        verifier
            .accept_kill_bundle(&kill_directory)
            .expect("store C must accept the kill bundle");
        let refuse = verifier
            .verify_presentation(&restored_present)
            .expect_err("present verify must refuse after kill accept");
        assert!(
            refuse.to_string().contains("kill accept"),
            "unexpected present-after-kill-accept error: {refuse}"
        );
    }
}
