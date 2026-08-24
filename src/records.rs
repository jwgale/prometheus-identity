//! These five records are the only stored objects.
//! A name is not a key. An instance identifier is not a holder key.

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One Module-Lattice Digital Signature Algorithm signature from a trusted issuer member.
/// Multi-signature issuance collects these over the same documented concatenation.
/// This is not a Shamir split of issuer.secret. This is not FROST.
/// This is not Federal Information Processing Standard 204 threshold Module-Lattice Digital Signature Algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerMemberSignature {
    pub public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentType {
    /// A ULID or UUID string. This field is not a cryptographic key.
    pub id: String,
    pub owner: String,
    /// Intent strings this agent type may mint. Frozen after the first write. A later persist must not add an intent. See the README allowed-intents freeze section.
    pub allowed_intents: Vec<String>,
    /// Highest destination prefix this agent type may hold. Frozen after the first write. See the README authorization-limit freeze section.
    pub authorization_limit: String,
    /// Maximum hop index after the first capability. Frozen after the first write. A later persist must not raise this depth.
    pub max_delegation_depth: u32,
    /// Example: "lab-ml-dsa-65-hybrid-biscuit-ed25519".
    pub crypto_profile: String,
    /// Lifetime of a new instance and of the first capability, in seconds. Frozen after the first write. A later persist must not raise this lifetime.
    pub lifetime_seconds: u64,
    /// Laboratory issuer public key that signed this agent type record.
    /// Signed bytes exclude this field's companion signature. Missing is refused on mint.
    #[serde(default)]
    pub issuer_public_key_hex: String,
    /// Laboratory Module-Lattice Digital Signature Algorithm signature over the documented agent type concatenation.
    /// This is not the raw JSON. The signature field itself is excluded.
    #[serde(default)]
    pub issuer_signature_hex: String,
    /// Distinct trusted member signatures over the documented concatenation.
    /// Empty when threshold_n is 1 and the single issuer_signature_hex field is used.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuer_signatures: Vec<IssuerMemberSignature>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InstanceStatus {
    Live,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instance {
    /// A ULID string. This field is not a cryptographic key.
    pub id: String,
    /// Agent type identifier. Written once at birth. A later persist must not replace this value.
    pub agent_type_id: String,
    pub owner: String,
    pub born: DateTime<Utc>,
    /// Expiry of this instance. Frozen after the first write. A later persist must not move this time later.
    pub expires: DateTime<Utc>,
    /// Public key bytes in hexadecimal. This key is for the laboratory holder challenge only.
    pub holder_public_key: String,
    pub status: InstanceStatus,
    /// Parent instance identifier. Written once at birth. A later persist must not clear or replace this value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_instance_id: Option<String>,
    pub attributes: BTreeMap<String, String>,
    /// Laboratory issuer public key that signed this instance record.
    /// Signed bytes exclude this field's companion signature. Missing is refused on act.
    #[serde(default)]
    pub issuer_public_key_hex: String,
    /// Laboratory Module-Lattice Digital Signature Algorithm signature over the documented instance concatenation.
    /// This is not the raw JSON. The signature field itself is excluded.
    #[serde(default)]
    pub issuer_signature_hex: String,
    /// Distinct trusted member signatures over the documented concatenation.
    /// Empty when threshold_n is 1 and the single issuer_signature_hex field is used.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuer_signatures: Vec<IssuerMemberSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub id: String,
    /// Instance identifier. Written once at mint. A later persist must not replace this value.
    pub instance_id: String,
    /// A user identifier, or the word "autonomous". Written once at mint. A later persist must not replace this value.
    pub on_behalf_of: String,
    /// Intent of this capability. Frozen after the first write. A later persist must not widen this value.
    pub intent: String,
    /// Audience of this capability. Frozen after the first write. A later persist must not widen this value.
    pub audience: String,
    pub caveats: BTreeMap<String, serde_json::Value>,
    pub issued: DateTime<Utc>,
    /// Expiry of this capability. Frozen after the first write. A later persist must not move this time later. See the README capability-expiry freeze section.
    pub expires: DateTime<Utc>,
    /// Hexadecimal revocation identifier of the last capability-token block.
    pub revoke_identifier: String,
    /// Capability token bytes in hexadecimal. Written once at mint. A later persist must not replace this value.
    pub biscuit: String,
    /// Laboratory issuer public key that signed this capability record.
    /// Signed bytes exclude this field's companion signature. Missing is refused on act.
    #[serde(default)]
    pub issuer_public_key_hex: String,
    /// Laboratory Module-Lattice Digital Signature Algorithm signature over the documented capability concatenation.
    /// This is not the raw JSON. The signature field itself is excluded.
    #[serde(default)]
    pub issuer_signature_hex: String,
    /// Distinct trusted member signatures over the documented concatenation.
    /// Empty when threshold_n is 1 and the single issuer_signature_hex field is used.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuer_signatures: Vec<IssuerMemberSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chain {
    pub capability_id: String,
    /// Parent capability identifier. Written once at birth. A later persist must not clear or replace this value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_capability_id: Option<String>,
    /// Hop index after the first capability. Frozen after the first write. A later persist must not decrease this index.
    pub hop_index: u32,
    pub attenuated_by: String,
    /// Kill flag. After this flag is true, a later persist must not set it false.
    pub revoke_from_here: bool,
    /// Laboratory issuer public key that signed this chain record.
    /// Signed bytes exclude this field's companion signature. Missing is refused on act.
    #[serde(default)]
    pub issuer_public_key_hex: String,
    /// Laboratory Module-Lattice Digital Signature Algorithm signature over the documented chain concatenation.
    /// This is not the raw JSON. The signature field itself is excluded.
    #[serde(default)]
    pub issuer_signature_hex: String,
    /// Distinct trusted member signatures over the documented concatenation.
    /// Empty when threshold_n is 1 and the single issuer_signature_hex field is used.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuer_signatures: Vec<IssuerMemberSignature>,
}

/// A previous laboratory issuer public key and the time after which it must not mint.
/// After kill_date the old key cannot mint. Old capabilities still verify until capability expiry.
/// This is laboratory single-key rotate of the Module-Lattice identity root. The Biscuit envelope key stays. This is not threshold issuance. This is not a production FIPS module. This is not a post-quantum Biscuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviousIssuerKey {
    pub public_key_hex: String,
    pub kill_date: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issuer {
    /// Own laboratory issuer public keys. After the first write, a later persist must not grow this list with a foreign key.
    pub public_keys: Vec<String>,
    /// Current laboratory issuer public key. New mint, birth, spawn, and receipts sign with this key only.
    /// After the first write, a later persist must not swap this key unless rotate already wrote the matching issuer secret.
    #[serde(default)]
    pub current_public_key: String,
    /// Previous issuer keys with a kill date. After kill_date that key cannot mint.
    /// The old public key stays on the accept list until kill_date.
    /// Old capabilities verify until capability expiry. This is not a sixth identity record.
    /// After rotate, a later persist must not remove a previous key and must not move a previous-key kill_date later.
    #[serde(default)]
    pub previous_issuer_keys: Vec<PreviousIssuerKey>,
    /// Hexadecimal public keys this store trusts for receipt verify.
    /// Always includes this store's own issuer public key.
    /// This is an accept list. This is not a global name system. This is not SPIFFE federation.
    #[serde(default)]
    pub accepted_issuer_public_keys: Vec<String>,
    /// Foreign previous issuer keys with a kill date this store accepted.
    /// After kill_date a wrap or act signed only by that key is refused on this store.
    /// Verifier state on the issuer. This is not a sixth identity record.
    /// This is not a public transparency log. After accept, a later persist must not
    /// remove a key and must not move a kill_date later.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_previous_issuer_keys: Vec<PreviousIssuerKey>,
    /// Foreign issuer public keys this store accepted as sealed, with the store-wide kill date.
    /// After accept, present verify and act accept for that issuer pin are refused.
    /// Verify is issuer death: membership refuses. The date is audit. This is not a present-timestamp check.
    /// Verifier state on the issuer. This is not a sixth identity record.
    /// Growing is allowed. Clearing an accepted seal is refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_sealed_issuer_keys: Vec<PreviousIssuerKey>,
    pub crypto_profile: String,
    /// Store-wide issuer death. After this time the store refuses new mint, birth, and spawn, and refuses act.
    /// Historical receipt signature check may still succeed. This is not a previous-key kill_date.
    /// This is a pre-committed issuer death. This is not a network partition detector. This is not a sixth identity record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kill_date: Option<DateTime<Utc>>,
    /// Laboratory Biscuit capability-envelope public key. This is not the identity root.
    /// The Biscuit key must not sign records, log lines, receipts, or tree heads.
    /// Written once at init. Rotate keeps this key. This is not a sixth identity record.
    #[serde(default)]
    pub biscuit_public_key_hex: String,
    /// Multi-signature issuance threshold. A mint, birth, spawn, save-sign, log-append,
    /// receipt, or tree-head is valid only when at least this many distinct trusted
    /// Module-Lattice Digital Signature Algorithm member signatures verify.
    /// Init default is 1. Lowering is refused. This is not a Shamir split.
    /// This is not FROST. This is not Federal Information Processing Standard 204
    /// threshold Module-Lattice Digital Signature Algorithm.
    pub threshold_n: u32,
    /// How many distinct accepted issuer signatures a foreign act, receipt,
    /// presentation, or tree head needs. This is not issuance threshold_n.
    /// Init default is 1. Lowering is refused. This is not a sixth identity record.
    #[serde(default = "default_threshold_one")]
    pub verify_threshold_n: u32,
    /// Instance identifiers this store accepted as dead from a foreign kill bundle.
    /// Verifier state on the issuer. This is not a sixth identity record.
    /// Growing is allowed. Clearing or removing an accepted kill is refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_killed_instance_ids: Vec<String>,
    /// Capability identifiers this store accepted as dead from a foreign kill bundle.
    /// Verifier state on the issuer. This is not a sixth identity record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_killed_capability_ids: Vec<String>,
    /// Revoke identifiers this store accepted as dead from a foreign kill bundle.
    /// Verifier state on the issuer. This is not a sixth identity record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_revoke_identifiers: Vec<String>,
    pub issuance_log: String,
}

fn default_threshold_one() -> u32 {
    1
}

fn is_threshold_one(value: &u32) -> bool {
    *value <= 1
}

impl Issuer {
    /// Current laboratory issuer public key. Falls back to public_keys when the field is empty.
    /// True when the store-wide issuer.kill_date has been reached.
    /// This is realm death. This is not a previous-key kill_date.
    pub fn is_sealed_at(&self, now: DateTime<Utc>) -> bool {
        match self.kill_date {
            Some(kill_date) => now >= kill_date,
            None => false,
        }
    }

    pub fn current_public_key_hex(&self) -> String {
        let current = self.current_public_key.trim();
        if !current.is_empty() {
            return current.to_string();
        }
        self.public_keys
            .iter()
            .map(|key| key.trim())
            .find(|key| !key.is_empty())
            .unwrap_or("")
            .to_string()
    }

    pub fn push_unique_public_key(keys: &mut Vec<String>, public_key_hex: &str) {
        let trimmed = public_key_hex.trim();
        if trimmed.is_empty() {
            return;
        }
        if !keys.iter().any(|existing| existing == trimmed) {
            keys.push(trimmed.to_string());
        }
    }

    pub fn is_previous_issuer_key_past_kill_date(
        &self,
        public_key_hex: &str,
        now: DateTime<Utc>,
    ) -> bool {
        let trimmed = public_key_hex.trim();
        self.previous_issuer_keys
            .iter()
            .any(|previous| previous.public_key_hex.trim() == trimmed && now >= previous.kill_date)
            || self.accepted_previous_issuer_keys.iter().any(|previous| {
                previous.public_key_hex.trim() == trimmed && now >= previous.kill_date
            })
    }

    /// Previous issuer public keys whose kill_date has been reached.
    /// A new signature from these keys is refused even if the signature is valid.
    pub fn previous_issuer_public_keys_past_kill_date(&self, now: DateTime<Utc>) -> Vec<String> {
        let mut keys = Vec::new();
        for previous in &self.previous_issuer_keys {
            if now >= previous.kill_date {
                Self::push_unique_public_key(&mut keys, &previous.public_key_hex);
            }
        }
        for previous in &self.accepted_previous_issuer_keys {
            if now >= previous.kill_date {
                Self::push_unique_public_key(&mut keys, &previous.public_key_hex);
            }
        }
        keys
    }

    /// Biscuit capability-envelope public keys used to parse capability tokens.
    /// This is the envelope key, not the identity root. Rotate keeps this key.
    /// Old capability tokens still parse after issuer Module-Lattice rotate.
    pub fn token_verify_public_key_hex_list(&self) -> Vec<String> {
        let mut keys = Vec::new();
        Self::push_unique_public_key(&mut keys, &self.biscuit_public_key_hex);
        keys
    }

    /// Keys this store trusts for receipt verify at `now`.
    /// Current key: always, if present.
    /// Previous key: only when now is before kill_date.
    /// This is an accept list. This is not a global name system. This is not SPIFFE federation.
    pub fn accepted_issuer_public_keys_for_verify_at(&self, now: DateTime<Utc>) -> Vec<String> {
        let mut keys = Vec::new();
        Self::push_unique_public_key(&mut keys, &self.current_public_key_hex());
        for key in &self.public_keys {
            Self::push_unique_public_key(&mut keys, key);
        }
        for previous in &self.previous_issuer_keys {
            if now < previous.kill_date {
                Self::push_unique_public_key(&mut keys, &previous.public_key_hex);
            }
        }
        for key in &self.accepted_issuer_public_keys {
            if self.is_previous_issuer_key_past_kill_date(key, now) {
                continue;
            }
            Self::push_unique_public_key(&mut keys, key);
        }
        keys
    }

    /// Keys this store trusts for receipt verify using the wall clock.
    /// Prefer accepted_issuer_public_keys_for_verify_at with the kernel clock in tests.
    pub fn accepted_issuer_public_keys_for_verify(&self) -> Vec<String> {
        self.accepted_issuer_public_keys_for_verify_at(Utc::now())
    }

    /// Keys this store trusts for issuance-log line signatures.
    /// Current Module-Lattice key plus every previous public key. The log is append-only
    /// and is not re-signed on rotate, so a previous key remains valid for already-written
    /// lines after kill_date. A foreign accept-list key cannot sign this store's log.
    /// The Biscuit envelope key must not appear here. This is not allow-all.
    /// This is still a local log. This is not Certificate Transparency.
    pub fn trusted_issuer_keys_for_issuance_log(&self) -> Vec<String> {
        let mut keys = Vec::new();
        Self::push_unique_public_key(&mut keys, &self.current_public_key_hex());
        for key in &self.public_keys {
            Self::push_unique_public_key(&mut keys, key);
        }
        for previous in &self.previous_issuer_keys {
            Self::push_unique_public_key(&mut keys, &previous.public_key_hex);
        }
        keys.retain(|key| !self.is_biscuit_envelope_key(key));
        keys
    }

    /// True when this hexadecimal key is the laboratory Biscuit envelope key.
    /// The Biscuit envelope key is not a threshold member.
    pub fn is_biscuit_envelope_key(&self, public_key_hex: &str) -> bool {
        let biscuit = self.biscuit_public_key_hex.trim();
        !biscuit.is_empty() && biscuit == public_key_hex.trim()
    }

    /// True when this store accepted a kill for the instance identifier.
    /// This is verifier state on the issuer. This is not a sixth identity record.
    pub fn has_accepted_killed_instance(&self, instance_id: &str) -> bool {
        let trimmed = instance_id.trim();
        !trimmed.is_empty()
            && self
                .accepted_killed_instance_ids
                .iter()
                .any(|existing| existing.trim() == trimmed)
    }

    /// True when this store accepted a kill for the capability identifier.
    pub fn has_accepted_killed_capability(&self, capability_id: &str) -> bool {
        let trimmed = capability_id.trim();
        !trimmed.is_empty()
            && self
                .accepted_killed_capability_ids
                .iter()
                .any(|existing| existing.trim() == trimmed)
    }

    /// True when this store accepted a kill for the revoke identifier.
    pub fn has_accepted_revoke_identifier(&self, revoke_identifier: &str) -> bool {
        let trimmed = revoke_identifier.trim();
        !trimmed.is_empty()
            && self
                .accepted_revoke_identifiers
                .iter()
                .any(|existing| existing.trim() == trimmed)
    }

    /// True when this store accepted a seal for the foreign issuer public key.
    /// Seal accept is issuer death for verify. This is not a present-timestamp check.
    /// This is verifier state on the issuer. This is not a sixth identity record.
    pub fn has_accepted_sealed_issuer(&self, public_key_hex: &str) -> bool {
        let trimmed = public_key_hex.trim();
        !trimmed.is_empty()
            && self
                .accepted_sealed_issuer_keys
                .iter()
                .any(|previous| previous.public_key_hex.trim() == trimmed)
    }

    /// Trusted Module-Lattice Digital Signature Algorithm signing members.
    /// Current key plus additional member public keys stored on public_keys.
    /// The Biscuit envelope key is never a member.
    pub fn trusted_signing_member_public_keys(&self) -> Vec<String> {
        let mut keys = Vec::new();
        Self::push_unique_public_key(&mut keys, &self.current_public_key_hex());
        for key in &self.public_keys {
            if self.is_biscuit_envelope_key(key) {
                continue;
            }
            Self::push_unique_public_key(&mut keys, key);
        }
        keys
    }

    /// Number of trusted Module-Lattice Digital Signature Algorithm signing members.
    pub fn signing_member_count(&self) -> u32 {
        self.trusted_signing_member_public_keys().len() as u32
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub operation: String,
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_capability_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoke_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Result of a tool-boundary check: allowed or refused. Empty for issuance events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    /// One-time holder challenge nonce. This is log state, not a sixth identity record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_nonce: Option<String>,
    /// Expiry of a holder challenge. This is log state, not a sixth identity record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_expires: Option<DateTime<Utc>>,
    /// Act authority recorded on a check. This is log state, not a sixth identity record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
    /// Instance identifiers revoked in a parent kill cascade, including the parent.
    /// Empty on historical lines. Signed inside the issuance-log line.
    /// This is not a sixth identity record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub killed_instance_ids: Vec<String>,
    /// Capability identifiers revoked in a parent kill cascade.
    /// Empty on historical lines. Signed inside the issuance-log line.
    /// This is not a sixth identity record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub killed_capability_ids: Vec<String>,
    /// SHA-256 hexadecimal digest of the previous raw issuance-log line, or EMPTY_PREVIOUS_LINE_HASH for the first line.
    /// This is a local hash chain. This is not a public append-only service.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub previous_line_hash: String,
    /// SHA-256 hexadecimal digest of this line's compact JSON with line_hash and
    /// issuer_signature_hex omitted. previous_line_hash and issuer_public_key_hex are included.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub line_hash: String,
    /// Laboratory issuer public key that signed this issuance-log line.
    /// Signed bytes exclude this field's companion signature.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub issuer_public_key_hex: String,
    /// Laboratory Module-Lattice Digital Signature Algorithm signature over line_hash and issuer_public_key_hex.
    /// The signature field itself is excluded from line_hash.
    /// This is still a local log. This is not Certificate Transparency.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub issuer_signature_hex: String,
    /// Distinct trusted member signatures over line_hash and issuer_public_key_hex.
    /// Empty when threshold_n is 1 and the single issuer_signature_hex field is used.
    /// Excluded from line_hash.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuer_signatures: Vec<IssuerMemberSignature>,
    /// Issuance threshold in force when this line was written. Init default 1.
    /// Historical lines keep this value after a later raise. A value of 1 is omitted from JSON so old logs still hash.
    /// This is not a sixth identity record.
    #[serde(
        default = "default_threshold_one",
        skip_serializing_if = "is_threshold_one"
    )]
    pub threshold_n: u32,
}

impl InstanceStatus {
    pub fn as_label(self) -> &'static str {
        match self {
            InstanceStatus::Live => "live",
            InstanceStatus::Revoked => "revoked",
        }
    }
}

/// Documented signed bytes for an agent type record issuer signature.
///
/// The signature is Module-Lattice Digital Signature Algorithm over the UTF-8 bytes of this exact concatenation:
///
/// `prometheus-agent-type|{id}|{owner}|{allowed_intents sorted}|{authorization_limit}|{max_delegation_depth}|{crypto_profile}|{lifetime_seconds}|{issuer_public_key_hex}`
///
/// - `allowed_intents sorted` is the intent strings sorted in lexicographic order
///   and joined with a comma. An empty list is the empty string.
/// - The pipe character is literal ASCII 0x7C
///
/// This is not JSON. The signature field is excluded. Field reorder in the JSON
/// container cannot change the signed bytes. The kernel re-signs on every
/// successful save. This is a laboratory issuer signature on the agent type JSON
/// record. It is not a Merkle tree of the whole store. It is not a database.
/// It is not a transparency log of records. This is not production post-quantum.
pub fn agent_type_issuer_signature_message(agent_type: &AgentType) -> String {
    let mut intents = agent_type.allowed_intents.clone();
    intents.sort();
    format!(
        "prometheus-agent-type|{}|{}|{}|{}|{}|{}|{}|{}",
        agent_type.id,
        agent_type.owner,
        intents.join(","),
        agent_type.authorization_limit,
        agent_type.max_delegation_depth,
        agent_type.crypto_profile,
        agent_type.lifetime_seconds,
        agent_type.issuer_public_key_hex,
    )
}

/// Documented signed bytes for an instance record issuer signature.
///
/// The signature is Module-Lattice Digital Signature Algorithm over the UTF-8 bytes of this exact concatenation:
///
/// `prometheus-instance|{id}|{agent_type_id}|{owner}|{born}|{expires}|{holder_public_key}|{status}|{parent_instance_id}|{issuer_public_key_hex}`
///
/// - `born` and `expires` are RFC3339 UTC with seconds precision and a `Z` suffix
/// - `status` is the exact word `live` or `revoked`
/// - `parent_instance_id` is empty when there is no parent
/// - The pipe character is literal ASCII 0x7C
///
/// This is not JSON. The signature field is excluded. Field reorder in the JSON
/// container cannot change the signed bytes. Status is included so a revoked-to-live
/// write breaks the signature and is already refused at persist.
/// This is a laboratory issuer signature on the instance JSON record. It is not a
/// Merkle tree of the whole store. It is not a database. It is not a transparency
/// log of records. This is not production post-quantum.
pub fn instance_issuer_signature_message(instance: &Instance) -> String {
    format!(
        "prometheus-instance|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        instance.id,
        instance.agent_type_id,
        instance.owner,
        instance.born.to_rfc3339_opts(SecondsFormat::Secs, true),
        instance.expires.to_rfc3339_opts(SecondsFormat::Secs, true),
        instance.holder_public_key,
        instance.status.as_label(),
        instance.parent_instance_id.as_deref().unwrap_or(""),
        instance.issuer_public_key_hex,
    )
}

/// Documented signed bytes for a capability record issuer signature.
///
/// The signature is Module-Lattice Digital Signature Algorithm over the UTF-8 bytes of this exact concatenation:
///
/// `prometheus-capability|{id}|{instance_id}|{on_behalf_of}|{intent}|{audience}|{issued}|{expires}|{issuer_public_key_hex}`
///
/// - `issued` and `expires` are RFC3339 UTC with seconds precision and a `Z` suffix
/// - The pipe character is literal ASCII 0x7C
///
/// This is not JSON. The signature field is excluded. Token bytes are excluded so
/// token-record fact consistency stays the token-versus-record layer. Status is
/// not a capability field. The kernel re-signs on every successful save.
/// This is a laboratory issuer signature on the capability JSON record. It is not a
/// Merkle tree of the whole store. It is not a database. It is not a transparency
/// log of records. This is not production post-quantum.
pub fn capability_issuer_signature_message(capability: &Capability) -> String {
    format!(
        "prometheus-capability|{}|{}|{}|{}|{}|{}|{}|{}",
        capability.id,
        capability.instance_id,
        capability.on_behalf_of,
        capability.intent,
        capability.audience,
        capability.issued.to_rfc3339_opts(SecondsFormat::Secs, true),
        capability
            .expires
            .to_rfc3339_opts(SecondsFormat::Secs, true),
        capability.issuer_public_key_hex,
    )
}

/// Documented signed bytes for a chain record issuer signature.
///
/// The signature is Module-Lattice Digital Signature Algorithm over the UTF-8 bytes of this exact concatenation:
///
/// `prometheus-chain|{capability_id}|{parent_capability_id}|{hop_index}|{attenuated_by}|{revoke_from_here}|{issuer_public_key_hex}`
///
/// - `parent_capability_id` is empty when there is no parent
/// - `hop_index` is a decimal integer with no leading zeros, except the number 0
/// - `revoke_from_here` is the exact word `true` or `false`
/// - The pipe character is literal ASCII 0x7C
///
/// This is not JSON. The signature field is excluded. Field reorder in the JSON
/// container cannot change the signed bytes. Hop index and revoke-from-here are
/// included so a planted lower hop or a cleared kill flag breaks the signature.
/// The kernel re-signs on every successful save.
/// This is a laboratory issuer signature on the chain JSON record. It is not a
/// Merkle tree of the whole store. It is not a database. It is not a transparency
/// log of records. This is not production post-quantum.
pub fn chain_issuer_signature_message(chain: &Chain) -> String {
    format!(
        "prometheus-chain|{}|{}|{}|{}|{}|{}",
        chain.capability_id,
        chain.parent_capability_id.as_deref().unwrap_or(""),
        chain.hop_index,
        chain.attenuated_by,
        if chain.revoke_from_here {
            "true"
        } else {
            "false"
        },
        chain.issuer_public_key_hex,
    )
}

/// Documented signed bytes for an issuance-log line issuer signature.
///
/// The signature is Module-Lattice Digital Signature Algorithm over the UTF-8 bytes of this exact concatenation:
///
/// `prometheus-issuance-log-line|{line_hash}|{issuer_public_key_hex}`
///
/// line_hash is SHA-256 of the compact JSON including previous_line_hash and
/// issuer_public_key_hex, with line_hash and issuer_signature_hex omitted.
/// The kernel then signs those two fields. log verify checks the hash chain
/// and the signature. The signature field itself is excluded from the hash.
/// This is not JSON. Field reorder in the JSON container cannot change the
/// signed bytes. This is still a local log. This is not Certificate Transparency.
pub fn issuance_log_line_issuer_signature_message(event: &LogEvent) -> String {
    format!(
        "prometheus-issuance-log-line|{}|{}",
        event.line_hash, event.issuer_public_key_hex,
    )
}

/// Return true if `new_value` equals `old_value` or is a child path of `old_value`.
/// A child path starts with `old_value` followed by "/" or ".".
pub fn is_narrower_or_equal(new_value: &str, old_value: &str) -> bool {
    new_value == old_value
        || new_value.starts_with(&format!("{old_value}/"))
        || new_value.starts_with(&format!("{old_value}."))
}

pub fn is_strictly_narrower(new_value: &str, old_value: &str) -> bool {
    new_value != old_value && is_narrower_or_equal(new_value, old_value)
}

/// Return true if the audience sits inside the authorization limit destination prefix.
pub fn audience_within_authorization_limit(audience: &str, authorization_limit: &str) -> bool {
    is_narrower_or_equal(audience, authorization_limit)
}

/// Return true if every intent in `new_intents` already sits in `stored_intents`.
/// Adding an intent string that is not in the stored set is a raise.
/// Removing an intent is a narrowing. The same set is allowed.
pub fn allowed_intents_within_stored(new_intents: &[String], stored_intents: &[String]) -> bool {
    new_intents
        .iter()
        .all(|intent| stored_intents.iter().any(|stored| stored == intent))
}

pub fn new_identifier() -> String {
    ulid::Ulid::new().to_string()
}

#[cfg(test)]
mod tests {
    use super::LogEvent;

    #[test]
    fn historical_log_event_without_cascade_fields_still_hashes() {
        let json = r#"{"operation":"mint","timestamp":"2026-08-19T00:00:00Z"}"#;
        let event: LogEvent = serde_json::from_str(json).expect("parse a historical line");
        assert!(
            event.killed_instance_ids.is_empty(),
            "a historical line must default killed_instance_ids to empty"
        );
        assert!(
            event.killed_capability_ids.is_empty(),
            "a historical line must default killed_capability_ids to empty"
        );
        let again = serde_json::to_string(&event).expect("serialize the historical line");
        assert!(
            !again.contains("killed_instance_ids"),
            "empty killed_instance_ids must skip so old logs still hash: {again}"
        );
        assert!(
            !again.contains("killed_capability_ids"),
            "empty killed_capability_ids must skip so old logs still hash: {again}"
        );
    }
}
