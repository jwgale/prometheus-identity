//! Local SHA-256 hash chain for issuance.log.
//!
//! This is a local hash chain. This is not a public append-only service.
//! This is not a public transparency log.

use crate::error::{Error, Result};
use crate::records::{issuance_log_line_issuer_signature_message, LogEvent};
use sha2::{Digest, Sha256};

/// SHA-256 of empty input. The first issuance-log line uses this as previous_line_hash.
/// Hexadecimal: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
pub const EMPTY_PREVIOUS_LINE_HASH: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// SHA-256 hexadecimal digest of `data`.
pub fn sha256_hexadecimal(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// previous_line_hash for a new line. The first line uses EMPTY_PREVIOUS_LINE_HASH.
/// Later lines use the SHA-256 hexadecimal digest of the previous raw line, without the newline.
pub fn previous_line_hash_of(previous_raw_line: Option<&str>) -> String {
    match previous_raw_line {
        Some(line) if !line.is_empty() => sha256_hexadecimal(line.as_bytes()),
        _ => EMPTY_PREVIOUS_LINE_HASH.to_string(),
    }
}

/// Compact JSON of the event with line_hash, issuer_signature_hex, and issuer_signatures omitted.
/// previous_line_hash and issuer_public_key_hex stay in the canonical form.
/// This is the documented hash input. The signature is applied after hashing.
pub fn line_hash_content(event: &LogEvent) -> Result<String> {
    let mut event = event.clone();
    event.line_hash.clear();
    event.issuer_signature_hex.clear();
    event.issuer_signatures.clear();
    Ok(serde_json::to_string(&event)?)
}

/// Fill previous_line_hash and line_hash. The signature field is excluded from the hash.
/// Return the JSON before the issuer signature is applied. The kernel signs after this.
pub fn seal_log_event(event: &mut LogEvent, previous_raw_line: Option<&str>) -> Result<String> {
    event.previous_line_hash = previous_line_hash_of(previous_raw_line);
    event.line_hash.clear();
    event.issuer_signature_hex.clear();
    event.issuer_signatures.clear();
    let content_without_line_hash = serde_json::to_string(&*event)?;
    event.line_hash = sha256_hexadecimal(content_without_line_hash.as_bytes());
    Ok(serde_json::to_string(&*event)?)
}

fn require_present_text_field(
    object: &serde_json::Map<String, serde_json::Value>,
    field_name: &str,
) -> Result<String> {
    let value = object.get(field_name).ok_or_else(|| {
        Error::denied(format!(
            "The issuance log line is missing {field_name}. A hash-chain-only append without issuer.secret is refused. The check fails closed."
        ))
    })?;
    let text = value.as_str().ok_or_else(|| {
        Error::denied(format!(
            "The {field_name} value must be a string. A hash-chain-only append without issuer.secret is refused. The check fails closed."
        ))
    })?;
    if text.trim().is_empty() {
        return Err(Error::denied(format!(
            "The issuance log line is missing {field_name}. A hash-chain-only append without issuer.secret is refused. The check fails closed."
        )));
    }
    Ok(text.to_string())
}

/// Verify the laboratory issuer signature on one issuance-log line.
/// Missing, wrong, or untrusted signatures fail closed.
/// This is still a local log. This is not Certificate Transparency.
pub fn require_issuance_log_line_issuer_signature(
    event: &LogEvent,
    trusted_keys: &[String],
) -> Result<()> {
    require_issuance_log_line_issuer_signature_with_threshold(event, trusted_keys, 1, "")
}

pub fn require_issuance_log_line_issuer_signature_with_threshold(
    event: &LogEvent,
    trusted_keys: &[String],
    threshold_n: u32,
    biscuit_public_key_hex: &str,
) -> Result<()> {
    if event.line_hash.trim().is_empty() {
        return Err(Error::denied(
            "The issuance log line is missing line_hash. The issuance log hash chain is broken. The check fails closed.",
        ));
    }
    let message = issuance_log_line_issuer_signature_message(event);
    crate::threshold::require_threshold_signatures(
        &event.issuer_signatures,
        &event.issuer_public_key_hex,
        &event.issuer_signature_hex,
        &message,
        trusted_keys,
        biscuit_public_key_hex,
        threshold_n,
        "issuance log line",
    )
    .map_err(|error| {
        let text = error.to_string();
        if text.contains("missing") && text.contains("issuer signature") {
            Error::denied(
                "The issuance log line issuer signature is missing. A hash-chain-only append without issuer.secret is refused. The check fails closed.",
            )
        } else if text.contains("not from a trusted") || text.contains("Biscuit envelope") {
            Error::denied(
                "The issuance log line issuer signature is not from a trusted issuer key. The signature key must be this store current key, a previous key, or an accepted foreign key when this is a copied foreign log. The check fails closed.",
            )
        } else if text.contains("needs") && text.contains("member signatures") {
            error
        } else if text.contains("not valid") {
            Error::denied(
                "The issuance log line issuer signature is not valid for this line_hash and issuer public key. A missing, wrong, or tampered signature is refused. The check fails closed.",
            )
        } else {
            error
        }
    })
}

/// Verify the issuer signature on the exact bound receipt line.
/// The field must be present. An unsigned bound line is refused.
pub fn require_bound_issuance_log_line_issuer_signature(
    raw_line: &str,
    trusted_keys: &[String],
) -> Result<()> {
    require_bound_issuance_log_line_issuer_signature_with_threshold(raw_line, trusted_keys, 1, "")
}

pub fn require_bound_issuance_log_line_issuer_signature_with_threshold(
    raw_line: &str,
    trusted_keys: &[String],
    _threshold_n: u32,
    biscuit_public_key_hex: &str,
) -> Result<()> {
    let trimmed = raw_line.trim();
    if trimmed.is_empty() {
        return Err(Error::denied(
            "The receipt is missing an issuance-log line. A signature alone is not enough. The check fails closed.",
        ));
    }
    let event: LogEvent = serde_json::from_str(trimmed).map_err(|error| {
        Error::denied(format!(
            "The receipt bound issuance-log line did not parse: {error}. The check fails closed."
        ))
    })?;
    let line_threshold = event.threshold_n.max(1);
    require_issuance_log_line_issuer_signature_with_threshold(
        &event,
        trusted_keys,
        line_threshold,
        biscuit_public_key_hex,
    )
}

fn require_present_hash_field(
    object: &serde_json::Map<String, serde_json::Value>,
    field_name: &str,
) -> Result<String> {
    let value = object.get(field_name).ok_or_else(|| {
        Error::denied(format!(
            "The issuance log line is missing {field_name}. The issuance log hash chain is broken. The check fails closed."
        ))
    })?;
    let text = value.as_str().ok_or_else(|| {
        Error::denied(format!(
            "The {field_name} value must be a string. The issuance log hash chain is broken. The check fails closed."
        ))
    })?;
    if text.is_empty() {
        return Err(Error::denied(format!(
            "The issuance log line is missing {field_name}. The issuance log hash chain is broken. The check fails closed."
        )));
    }
    if text.len() != 64 || !text.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err(Error::denied(format!(
            "The {field_name} value must be a 64-character SHA-256 hexadecimal digest. The issuance log hash chain is broken. The check fails closed."
        )));
    }
    Ok(text.to_string())
}

/// Walk issuance.log. A missing field, a wrong previous_line_hash, a wrong line_hash,
/// or a missing or untrusted issuer signature fails closed.
/// An empty log is an intact empty chain.
/// trusted_keys are this store current and previous keys, or the accept list
/// when this is a copied foreign log.
pub fn verify_issuance_log_text(text: &str, trusted_keys: &[String]) -> Result<()> {
    verify_issuance_log_text_with_threshold(text, trusted_keys, 1, "")
}

pub fn verify_issuance_log_text_with_threshold(
    text: &str,
    trusted_keys: &[String],
    _threshold_n: u32,
    biscuit_public_key_hex: &str,
) -> Result<()> {
    let mut expected_previous_line_hash = EMPTY_PREVIOUS_LINE_HASH.to_string();
    for raw_line in text.lines() {
        if raw_line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(raw_line).map_err(|error| {
            Error::denied(format!(
                "The issuance log line is not valid JSON: {error}. The issuance log hash chain is broken. The check fails closed."
            ))
        })?;
        let object = value.as_object().ok_or_else(|| {
            Error::denied(
                "The issuance log line is not a JSON object. The issuance log hash chain is broken. The check fails closed.",
            )
        })?;
        let previous_line_hash = require_present_hash_field(object, "previous_line_hash")?;
        let line_hash = require_present_hash_field(object, "line_hash")?;
        let _issuer_public_key_hex = require_present_text_field(object, "issuer_public_key_hex")?;
        let _issuer_signature_hex = require_present_text_field(object, "issuer_signature_hex")?;
        if previous_line_hash != expected_previous_line_hash {
            return Err(Error::denied(
                "The previous_line_hash does not match the previous raw line. The issuance log hash chain is broken. The check fails closed.",
            ));
        }
        let event: LogEvent = serde_json::from_value(value).map_err(|error| {
            Error::denied(format!(
                "The issuance log line did not parse: {error}. The issuance log hash chain is broken. The check fails closed."
            ))
        })?;
        let content_without_line_hash = line_hash_content(&event)?;
        let computed_line_hash = sha256_hexadecimal(content_without_line_hash.as_bytes());
        if computed_line_hash != line_hash {
            return Err(Error::denied(
                "The line_hash does not match this line. The issuance log hash chain is broken. The check fails closed.",
            ));
        }
        require_issuance_log_line_issuer_signature_with_threshold(
            &event,
            trusted_keys,
            event.threshold_n.max(1),
            biscuit_public_key_hex,
        )?;
        expected_previous_line_hash = sha256_hexadecimal(raw_line.as_bytes());
    }
    Ok(())
}

/// Collect line_hash values in order after the hash chain verifies.
/// A broken chain fails closed. Merkle proofs use this sequence as leaves.
pub fn issuance_log_line_hashes(text: &str, trusted_keys: &[String]) -> Result<Vec<String>> {
    issuance_log_line_hashes_with_threshold(text, trusted_keys, 1, "")
}

pub fn issuance_log_line_hashes_with_threshold(
    text: &str,
    trusted_keys: &[String],
    _threshold_n: u32,
    biscuit_public_key_hex: &str,
) -> Result<Vec<String>> {
    verify_issuance_log_text_with_threshold(
        text,
        trusted_keys,
        _threshold_n,
        biscuit_public_key_hex,
    )?;
    let mut line_hashes = Vec::new();
    for raw_line in text.lines() {
        if raw_line.trim().is_empty() {
            continue;
        }
        let event: LogEvent = serde_json::from_str(raw_line).map_err(|error| {
            Error::denied(format!(
                "The issuance log line did not parse: {error}. The issuance log hash chain is broken. The check fails closed."
            ))
        })?;
        if event.line_hash.is_empty() {
            return Err(Error::denied(
                "The issuance log line is missing line_hash. The issuance log hash chain is broken. The check fails closed.",
            ));
        }
        line_hashes.push(event.line_hash);
    }
    Ok(line_hashes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_empty_previous_line_hash_is_sha256_of_empty_input() {
        assert_eq!(
            EMPTY_PREVIOUS_LINE_HASH,
            sha256_hexadecimal(b""),
            "the documented empty-hash must be SHA-256 of empty input"
        );
        assert_eq!(EMPTY_PREVIOUS_LINE_HASH.len(), 64);
    }
}
