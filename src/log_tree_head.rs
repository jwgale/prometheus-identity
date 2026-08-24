//! Locally signed Merkle tree head over the hash-chained issuance log.
//!
//! This is a locally signed Merkle root. It is not Certificate Transparency,
//! not a gossip protocol, not a public log, and not a multi-witness signed tree head.
//!
//! The signed tree head is a signed statement derived from the issuer and issuance.log.
//! It is not a sixth identity record. The hash chain and the prove / check-proof
//! commands stay the inclusion surface.

use crate::error::{Error, Result};
use crate::log_proof::require_sha256_hexadecimal_digest;
use crate::tokens;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

/// Documented signed bytes for a local signed tree head.
///
/// The signature is Module-Lattice Digital Signature Algorithm over the UTF-8 bytes of this exact concatenation:
///
/// `prometheus-signed-tree-head|{merkle_root}|{leaf_count}|{signed_at}|{issuer_public_key_hex}`
///
/// - `merkle_root` is the 64-character SHA-256 hexadecimal Merkle root
/// - `leaf_count` is the decimal integer with no leading zeros, except the number 0
/// - `signed_at` is RFC3339 UTC with seconds precision and a `Z` suffix
/// - `issuer_public_key_hex` is the current issuer public key hexadecimal
///
/// The pipe character is literal ASCII 0x7C. This is not JSON. Parsing the JSON
/// container and re-signing it is refused by design: check reconstructs these
/// bytes from the fields and never signs the JSON object. Field reorder in the
/// JSON container cannot change the signed bytes.
pub fn signed_tree_head_message(
    merkle_root: &str,
    leaf_count: u64,
    signed_at: DateTime<Utc>,
    issuer_public_key_hex: &str,
) -> String {
    format!(
        "prometheus-signed-tree-head|{merkle_root}|{leaf_count}|{}|{issuer_public_key_hex}",
        signed_at.to_rfc3339_opts(SecondsFormat::Secs, true)
    )
}

/// Locally signed Merkle root and leaf count. This is not a sixth identity record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTreeHead {
    pub merkle_root: String,
    pub leaf_count: u64,
    pub signed_at: DateTime<Utc>,
    pub issuer_public_key_hex: String,
    pub signature_hex: String,
    /// Distinct trusted member signatures. Empty when threshold_n is 1.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuer_signatures: Vec<crate::records::IssuerMemberSignature>,
}

impl SignedTreeHead {
    pub fn canonical_message(&self) -> String {
        signed_tree_head_message(
            &self.merkle_root,
            self.leaf_count,
            self.signed_at,
            &self.issuer_public_key_hex,
        )
    }
}

/// Refuse empty or missing signed-tree-head fields after the JSON parses.
pub fn require_signed_tree_head_fields(tree_head: &SignedTreeHead) -> Result<()> {
    if tree_head.merkle_root.trim().is_empty() {
        return Err(Error::denied(
            "The signed tree head is missing a Merkle root. The check fails closed.",
        ));
    }
    require_sha256_hexadecimal_digest(&tree_head.merkle_root, "merkle_root")?;
    if tree_head.issuer_public_key_hex.trim().is_empty() {
        return Err(Error::denied(
            "The signed tree head is missing an issuer public key. The check fails closed.",
        ));
    }
    if tree_head.signature_hex.trim().is_empty() {
        return Err(Error::denied(
            "The signed tree head is missing a signature. The check fails closed.",
        ));
    }
    Ok(())
}

fn require_json_string_field(value: &serde_json::Value, field_name: &str) -> Result<String> {
    match value.get(field_name) {
        None => Err(Error::denied(format!(
            "The signed tree head is missing {field_name}. The check fails closed."
        ))),
        Some(serde_json::Value::Null) => Err(Error::denied(format!(
            "The signed tree head {field_name} is empty. The check fails closed."
        ))),
        Some(serde_json::Value::String(text)) => {
            if text.trim().is_empty() {
                return Err(Error::denied(format!(
                    "The signed tree head {field_name} is empty. The check fails closed."
                )));
            }
            Ok(text.clone())
        }
        Some(other) => Err(Error::denied(format!(
            "The signed tree head {field_name} must be a string. Found {other}. The check fails closed."
        ))),
    }
}

fn require_json_leaf_count(value: &serde_json::Value) -> Result<u64> {
    match value.get("leaf_count") {
        None => Err(Error::denied(
            "The signed tree head is missing leaf_count. The check fails closed.",
        )),
        Some(serde_json::Value::Null) => Err(Error::denied(
            "The signed tree head leaf_count is empty. The check fails closed.",
        )),
        Some(serde_json::Value::String(text)) => {
            if text.trim().is_empty() {
                return Err(Error::denied(
                    "The signed tree head leaf_count is empty. The check fails closed.",
                ));
            }
            text.trim().parse::<u64>().map_err(|_| {
                Error::denied(
                    "The signed tree head leaf_count must be a non-negative integer. The check fails closed.",
                )
            })
        }
        Some(serde_json::Value::Number(number)) => number.as_u64().ok_or_else(|| {
            Error::denied(
                "The signed tree head leaf_count must be a non-negative integer. The check fails closed.",
            )
        }),
        Some(_) => Err(Error::denied(
            "The signed tree head leaf_count must be a non-negative integer. The check fails closed.",
        )),
    }
}

/// Parse a signed tree head JSON container. Missing or empty fields fail closed.
/// The JSON is a container only. The signed bytes are the documented concatenation.
pub fn parse_signed_tree_head_json(text: &str) -> Result<SignedTreeHead> {
    if text.trim().is_empty() {
        return Err(Error::denied(
            "The signed tree head is empty. The check fails closed.",
        ));
    }
    let value: serde_json::Value = serde_json::from_str(text).map_err(|error| {
        Error::denied(format!(
            "The signed tree head fields did not parse: {error}. The check fails closed."
        ))
    })?;
    if !value.is_object() {
        return Err(Error::denied(
            "The signed tree head must be a JSON object. The check fails closed.",
        ));
    }
    require_json_string_field(&value, "merkle_root")?;
    require_json_leaf_count(&value)?;
    require_json_string_field(&value, "signed_at")?;
    require_json_string_field(&value, "issuer_public_key_hex")?;
    require_json_string_field(&value, "signature_hex")?;
    let tree_head: SignedTreeHead = serde_json::from_value(value).map_err(|error| {
        Error::denied(format!(
            "The signed tree head fields did not parse: {error}. The check fails closed."
        ))
    })?;
    require_signed_tree_head_fields(&tree_head)?;
    Ok(tree_head)
}

/// Verify the signature against the issuer public key named in the file.
/// This does not consult the accept list. The kernel adds that check.
pub fn verify_signed_tree_head_signature(tree_head: &SignedTreeHead) -> Result<()> {
    require_signed_tree_head_fields(tree_head)?;
    tokens::verify_decision_receipt_signature(
        tree_head.issuer_public_key_hex.trim(),
        &tree_head.canonical_message(),
        tree_head.signature_hex.trim(),
    )
    .map_err(|error| {
        let text = error.to_string();
        if text.contains("not valid hexadecimal") || text.contains("must decode to 64 bytes") {
            Error::denied(format!(
                "The signed tree head signature is not valid: {text} The check fails closed."
            ))
        } else if text.contains("not a valid Module-Lattice")
            || text.contains("forged Ed25519-only")
        {
            Error::denied(
                "The signed tree head issuer public key is not a valid Module-Lattice Digital Signature Algorithm key. The check fails closed."
                    .to_string(),
            )
        } else {
            Error::denied(
                "The signed tree head signature is not valid for the issuer public key in the file. A tampered Merkle root fails closed."
                    .to_string(),
            )
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_chain::sha256_hexadecimal;
    use chrono::TimeZone;

    fn fixture_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 19, 7, 30, 0).unwrap()
    }

    #[test]
    fn the_canonical_message_is_the_documented_concatenation() {
        let merkle_root = sha256_hexadecimal(b"root");
        let public_key = "ab".repeat(32);
        let message = signed_tree_head_message(&merkle_root, 3, fixture_time(), &public_key);
        assert_eq!(
            message,
            format!(
                "prometheus-signed-tree-head|{merkle_root}|3|2026-08-19T07:30:00Z|{public_key}"
            )
        );
    }

    #[test]
    fn an_empty_merkle_root_fails_closed() {
        let tree_head = SignedTreeHead {
            merkle_root: String::new(),
            leaf_count: 1,
            signed_at: fixture_time(),
            issuer_public_key_hex: "ab".repeat(32),
            signature_hex: "cd".repeat(32),
            issuer_signatures: Vec::new(),
        };
        let error = require_signed_tree_head_fields(&tree_head)
            .expect_err("an empty Merkle root must fail closed");
        assert!(
            error.to_string().contains("missing a Merkle root"),
            "unexpected empty-root error: {error}"
        );
    }

    #[test]
    fn an_empty_signature_fails_closed() {
        let tree_head = SignedTreeHead {
            merkle_root: sha256_hexadecimal(b"root"),
            leaf_count: 1,
            signed_at: fixture_time(),
            issuer_public_key_hex: "ab".repeat(32),
            signature_hex: String::new(),
            issuer_signatures: Vec::new(),
        };
        let error = require_signed_tree_head_fields(&tree_head)
            .expect_err("an empty signature must fail closed");
        assert!(
            error.to_string().contains("missing a signature"),
            "unexpected empty-signature error: {error}"
        );
    }

    #[test]
    fn a_missing_leaf_count_fails_closed() {
        let error = parse_signed_tree_head_json(
            r#"{"merkle_root":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","signed_at":"2026-08-19T07:30:00Z","issuer_public_key_hex":"aa","signature_hex":"bb"}"#,
        )
        .expect_err("a missing leaf_count must fail closed");
        assert!(
            error.to_string().contains("leaf_count"),
            "unexpected missing-leaf-count error: {error}"
        );
    }

    #[test]
    fn an_empty_leaf_count_string_fails_closed() {
        let error = parse_signed_tree_head_json(
            r#"{"merkle_root":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","leaf_count":"","signed_at":"2026-08-19T07:30:00Z","issuer_public_key_hex":"aa","signature_hex":"bb"}"#,
        )
        .expect_err("an empty leaf_count must fail closed");
        assert!(
            error.to_string().contains("leaf_count"),
            "unexpected empty-leaf-count error: {error}"
        );
    }

    #[test]
    fn a_missing_signature_in_json_fails_closed() {
        let error = parse_signed_tree_head_json(
            r#"{"merkle_root":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","leaf_count":1,"signed_at":"2026-08-19T07:30:00Z","issuer_public_key_hex":"aa"}"#,
        )
        .expect_err("a missing signature must fail closed");
        assert!(
            error.to_string().contains("signature_hex"),
            "unexpected missing-signature error: {error}"
        );
    }

    #[test]
    fn an_empty_tree_head_document_fails_closed() {
        let error =
            parse_signed_tree_head_json(" \n").expect_err("an empty document must fail closed");
        assert!(
            error.to_string().contains("empty"),
            "unexpected empty-document error: {error}"
        );
    }
}
