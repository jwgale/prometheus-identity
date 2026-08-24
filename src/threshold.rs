//! Multi-signature issuance for the laboratory issuer.
//!
//! A mint, birth, spawn, save-sign, log-append, receipt, or tree-head is valid
//! only when at least `threshold_n` distinct Module-Lattice Digital Signature
//! Algorithm signatures from trusted issuer member keys verify over the same
//! documented concatenation.
//!
//! Honest cryptographic bound:
//! - This is not a Shamir split of `issuer.secret`. A Shamir split reconstitutes
//!   one key on one host. That is not threshold issuance.
//! - This is not FROST or threshold Edwards-curve Digital Signature Algorithm
//!   on Curve 25519 as the identity root. That root would be classical.
//! - This is not Federal Information Processing Standard 204 threshold
//!   Module-Lattice Digital Signature Algorithm. That scheme is not what this
//!   laboratory ships.
//!
//! When `threshold_n` is 1, one current Module-Lattice key signs, the same as
//! before this module existed.

use crate::error::{Error, Result};
use crate::issuer_crypto;
use crate::records::{Issuer, IssuerMemberSignature};
use chrono::{DateTime, Utc};
use std::collections::BTreeSet;

/// Collect member signatures. When the list is empty, fall back to the single
/// legacy signature field paired with the named public key.
pub fn collect_member_signatures(
    issuer_signatures: &[IssuerMemberSignature],
    legacy_public_key_hex: &str,
    legacy_signature_hex: &str,
) -> Vec<IssuerMemberSignature> {
    if !issuer_signatures.is_empty() {
        return issuer_signatures.to_vec();
    }
    if legacy_signature_hex.trim().is_empty() {
        return Vec::new();
    }
    vec![IssuerMemberSignature {
        public_key_hex: legacy_public_key_hex.trim().to_string(),
        signature_hex: legacy_signature_hex.trim().to_string(),
    }]
}

/// Count distinct trusted Module-Lattice keys whose signatures verify.
/// Missing, untrusted, duplicate-key, and Biscuit-envelope signatures do not count.
pub fn count_valid_threshold_signatures(
    signatures: &[IssuerMemberSignature],
    message: &str,
    trusted_keys: &[String],
    biscuit_public_key_hex: &str,
) -> u32 {
    let mut counted = BTreeSet::new();
    let biscuit = biscuit_public_key_hex.trim();
    for signature in signatures {
        let key = signature.public_key_hex.trim();
        if key.is_empty() || signature.signature_hex.trim().is_empty() {
            continue;
        }
        if !biscuit.is_empty() && key == biscuit {
            continue;
        }
        if counted.contains(key) {
            continue;
        }
        if !trusted_keys.iter().any(|trusted| trusted.trim() == key) {
            continue;
        }
        if issuer_crypto::verify_module_lattice_signature(key, message, &signature.signature_hex)
            .is_ok()
        {
            counted.insert(key.to_string());
        }
    }
    counted.len() as u32
}

/// Refuse when fewer than `threshold_n` distinct trusted member signatures verify.
pub fn require_threshold_signatures(
    issuer_signatures: &[IssuerMemberSignature],
    legacy_public_key_hex: &str,
    legacy_signature_hex: &str,
    message: &str,
    trusted_keys: &[String],
    biscuit_public_key_hex: &str,
    threshold_n: u32,
    artifact_name: &str,
) -> Result<()> {
    if threshold_n < 1 {
        return Err(Error::denied(format!(
            "The threshold_n value must be at least 1. The {artifact_name} check fails closed."
        )));
    }
    let collected = collect_member_signatures(
        issuer_signatures,
        legacy_public_key_hex,
        legacy_signature_hex,
    );
    if collected.is_empty() {
        return Err(Error::denied(format!(
            "The {artifact_name} issuer signature is missing. A planted record cannot act. The store JSON is not enough. The check fails closed."
        )));
    }
    if legacy_public_key_hex.trim().is_empty()
        && issuer_signatures
            .iter()
            .all(|signature| signature.public_key_hex.trim().is_empty())
    {
        return Err(Error::denied(format!(
            "The {artifact_name} issuer public key is missing. A planted record cannot act. The store JSON is not enough. The check fails closed."
        )));
    }
    let count =
        count_valid_threshold_signatures(&collected, message, trusted_keys, biscuit_public_key_hex);
    if count < threshold_n {
        if threshold_n == 1 && count == 0 {
            let only = &collected[0];
            let key = only.public_key_hex.trim();
            if key.is_empty() {
                return Err(Error::denied(format!(
                    "The {artifact_name} issuer public key is missing. A planted record cannot act. The store JSON is not enough. The check fails closed."
                )));
            }
            if !biscuit_public_key_hex.trim().is_empty() && key == biscuit_public_key_hex.trim() {
                return Err(Error::denied(format!(
                    "The {artifact_name} issuer signature is not from a trusted issuer key. The Biscuit envelope key is not a threshold member. The check fails closed."
                )));
            }
            if !trusted_keys.iter().any(|trusted| trusted.trim() == key) {
                return Err(Error::denied(format!(
                    "The {artifact_name} issuer signature is not from a trusted issuer key. The signature key must be the current key or a previous key still before its kill date. A planted record cannot act. The check fails closed."
                )));
            }
            return Err(Error::denied(format!(
                "The {artifact_name} issuer signature is not valid for the signed identity fields. A missing, wrong, or tampered signature cannot act. The store JSON is not enough. The check fails closed."
            )));
        }
        return Err(Error::denied(format!(
            "The {artifact_name} needs {threshold_n} distinct trusted Module-Lattice Digital Signature Algorithm member signatures. Found {count} valid member signatures. Missing, untrusted, duplicate-key, and Biscuit-envelope signatures do not count. The check fails closed."
        )));
    }
    Ok(())
}

/// Trusted keys that may count toward a local record signature.
/// Current key, additional public_keys members, and previous keys before kill_date.
/// The Biscuit envelope key never counts.
pub fn trusted_keys_for_record_threshold(issuer: &Issuer, now: DateTime<Utc>) -> Vec<String> {
    let mut keys = issuer.trusted_signing_member_public_keys();
    for previous in &issuer.previous_issuer_keys {
        if now < previous.kill_date && !issuer.is_biscuit_envelope_key(&previous.public_key_hex) {
            Issuer::push_unique_for_threshold(&mut keys, &previous.public_key_hex);
        }
    }
    keys.retain(|key| !issuer.is_biscuit_envelope_key(key));
    keys
}

impl Issuer {
    fn push_unique_for_threshold(keys: &mut Vec<String>, public_key_hex: &str) {
        let trimmed = public_key_hex.trim();
        if trimmed.is_empty() {
            return;
        }
        if !keys.iter().any(|existing| existing == trimmed) {
            keys.push(trimmed.to_string());
        }
    }
}

/// Sign `message` with each loaded member secret. Return the list and the
/// current-key signature hex (first member that matches current, else first).
pub fn sign_message_with_member_secrets(
    members: &[(String, String)],
    message: &str,
) -> Result<Vec<IssuerMemberSignature>> {
    let mut signatures = Vec::new();
    let mut seen = BTreeSet::new();
    for (secret, public_key) in members {
        let public_key = public_key.trim();
        if public_key.is_empty() || !seen.insert(public_key.to_string()) {
            continue;
        }
        let signature_hex = issuer_crypto::sign_with_module_lattice_secret(secret, message)?;
        signatures.push(IssuerMemberSignature {
            public_key_hex: public_key.to_string(),
            signature_hex,
        });
    }
    if signatures.is_empty() {
        return Err(Error::denied(
            "No trusted issuer member secret could sign. The check fails closed.",
        ));
    }
    Ok(signatures)
}

/// First signature hex for the legacy single-signature field.
pub fn first_signature_hex(signatures: &[IssuerMemberSignature]) -> String {
    signatures
        .first()
        .map(|signature| signature.signature_hex.clone())
        .unwrap_or_default()
}

/// Signature hex for the named public key, or the first signature.
pub fn signature_hex_for_public_key(
    signatures: &[IssuerMemberSignature],
    public_key_hex: &str,
) -> String {
    let wanted = public_key_hex.trim();
    signatures
        .iter()
        .find(|signature| signature.public_key_hex.trim() == wanted)
        .or(signatures.first())
        .map(|signature| signature.signature_hex.clone())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuer_crypto;

    #[test]
    fn a_biscuit_envelope_key_does_not_count() {
        let pair = issuer_crypto::generate_module_lattice_key_pair().expect("member key");
        let message = "prometheus-threshold-test|one";
        let signature =
            issuer_crypto::sign_with_module_lattice_secret(&pair.secret_key_hexadecimal, message)
                .expect("sign");
        let signatures = vec![IssuerMemberSignature {
            public_key_hex: pair.public_key_hexadecimal.clone(),
            signature_hex: signature,
        }];
        let count = count_valid_threshold_signatures(
            &signatures,
            message,
            &[pair.public_key_hexadecimal.clone()],
            &pair.public_key_hexadecimal,
        );
        assert_eq!(
            count, 0,
            "the Biscuit envelope key must not count as a member"
        );
    }

    #[test]
    fn duplicate_keys_count_once() {
        let pair = issuer_crypto::generate_module_lattice_key_pair().expect("member key");
        let message = "prometheus-threshold-test|dup";
        let signature =
            issuer_crypto::sign_with_module_lattice_secret(&pair.secret_key_hexadecimal, message)
                .expect("sign");
        let signatures = vec![
            IssuerMemberSignature {
                public_key_hex: pair.public_key_hexadecimal.clone(),
                signature_hex: signature.clone(),
            },
            IssuerMemberSignature {
                public_key_hex: pair.public_key_hexadecimal.clone(),
                signature_hex: signature,
            },
        ];
        let count = count_valid_threshold_signatures(
            &signatures,
            message,
            &[pair.public_key_hexadecimal.clone()],
            "",
        );
        assert_eq!(count, 1, "duplicate-key signatures must not count twice");
    }
}
