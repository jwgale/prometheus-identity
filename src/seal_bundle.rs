//! Local seal bundle: issuer_seal issuance-log line + Merkle inclusion proof + signed tree head.
//!
//! This is a local export of existing artifacts. It is not a sixth identity record.
//! It is not a global name system, not SPIFFE federation, and not Certificate
//! Transparency gossip. The second store must already have the first issuer
//! public key on its accept list.
//!
//! Accept is verify-only. It does not mint, does not create instance records,
//! and does not write a second issuance.log line. Accepted seal is verifier
//! state on the issuer record. This store does not copy issuer.secret.

use crate::error::{Error, Result};
use crate::log_proof::IssuanceLogInclusionProof;
use crate::log_tree_head::{parse_signed_tree_head_json, SignedTreeHead};
use crate::records::LogEvent;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Documented bundle file names. Full words. STE100.
pub const EVENT_FILE_NAME: &str = "event.json";
pub const PROOF_FILE_NAME: &str = "proof.json";
pub const TREE_HEAD_FILE_NAME: &str = "tree-head.json";

/// Seal event type that may travel as a seal bundle.
pub const ISSUER_SEAL_EVENT: &str = "issuer_seal";

/// Small seal document. This is an artifact, not a sixth identity record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealDocument {
    pub event: String,
    pub issuer_public_key_hex: String,
    pub kill_date: DateTime<Utc>,
    pub issuance_log_line: String,
}

/// The three existing artifacts a second store can check without becoming a second identity kernel.
#[derive(Debug, Clone)]
pub struct SealBundle {
    pub document: SealDocument,
    pub proof: IssuanceLogInclusionProof,
    pub tree_head: SignedTreeHead,
}

/// True when the operation is a portable issuer seal event.
pub fn is_seal_event(operation: &str) -> bool {
    operation == ISSUER_SEAL_EVENT
}

/// Build a seal document from one issuance-log line and the store-wide kill date.
/// Refuse a non-seal event.
pub fn seal_document_from_issuance_log_line(
    issuance_log_line: &str,
    kill_date: DateTime<Utc>,
) -> Result<SealDocument> {
    let event = require_seal_issuance_log_line(issuance_log_line)?;
    require_note_names_kill_date(event.note.as_deref(), kill_date)?;
    Ok(SealDocument {
        event: event.operation,
        issuer_public_key_hex: event.issuer_public_key_hex,
        kill_date,
        issuance_log_line: issuance_log_line.trim().to_string(),
    })
}

/// Parse the bound seal issuance-log line and refuse a non-seal event.
pub fn require_seal_issuance_log_line(issuance_log_line: &str) -> Result<LogEvent> {
    let trimmed = issuance_log_line.trim();
    if trimmed.is_empty() {
        return Err(Error::denied(
            "The seal bundle is missing an issuance-log line. The seal accept fails closed.",
        ));
    }
    let event: LogEvent = serde_json::from_str(trimmed).map_err(|error| {
        Error::denied(format!(
            "The seal issuance-log line did not parse: {error}. The seal accept fails closed."
        ))
    })?;
    if !is_seal_event(event.operation.trim()) {
        return Err(Error::denied(
            "The issuance-log line is not an issuer_seal event. The seal accept fails closed.",
        ));
    }
    if event.issuer_public_key_hex.trim().is_empty() {
        return Err(Error::denied(
            "The seal issuance-log line is missing an issuer public key. The seal accept fails closed.",
        ));
    }
    Ok(event)
}

/// Refuse when the unsigned seal document does not match the bound issuance-log line.
pub fn require_seal_document_agrees_with_line(
    document: &SealDocument,
    event: &LogEvent,
) -> Result<()> {
    if !is_seal_event(document.event.trim()) {
        return Err(Error::denied(
            "The seal bundle event is not an issuer_seal event. The seal accept fails closed.",
        ));
    }
    if document.event.trim() != event.operation.trim() {
        return Err(Error::denied(
            "The seal document event does not match the bound issuance-log line. The seal accept fails closed.",
        ));
    }
    if document.issuer_public_key_hex.trim() != event.issuer_public_key_hex.trim() {
        return Err(Error::denied(
            "The seal document issuer public key does not match the bound issuance-log line. The seal accept fails closed.",
        ));
    }
    require_note_names_kill_date(event.note.as_deref(), document.kill_date)?;
    Ok(())
}

fn require_note_names_kill_date(note: Option<&str>, kill_date: DateTime<Utc>) -> Result<()> {
    let note = note.unwrap_or("").trim();
    let named = kill_date.to_rfc3339();
    if note.is_empty() || !note.contains(&named) {
        return Err(Error::denied(
            "The seal issuance-log note does not name this store-wide kill_date. Extra or missing seal dates are refused. The check fails closed.",
        ));
    }
    Ok(())
}

fn require_bundle_file(bundle_directory: &Path, file_name: &str) -> Result<std::path::PathBuf> {
    let path = bundle_directory.join(file_name);
    if !path.exists() {
        return Err(Error::denied(format!(
            "The seal bundle is missing {file_name}. The seal accept fails closed."
        )));
    }
    Ok(path)
}

fn read_required_text(path: &Path, file_name: &str) -> Result<String> {
    let text = fs::read_to_string(path).map_err(|error| {
        Error::denied(format!(
            "The seal bundle {file_name} could not be read: {error}. The accept check fails closed."
        ))
    })?;
    if text.trim().is_empty() {
        return Err(Error::denied(format!(
            "The seal bundle {file_name} is empty. The accept check fails closed."
        )));
    }
    Ok(text)
}

/// Write event.json, proof.json, and tree-head.json under `output_directory`.
pub fn write_seal_bundle(output_directory: &Path, bundle: &SealBundle) -> Result<()> {
    if output_directory.as_os_str().is_empty() {
        return Err(Error::denied(
            "The output directory is empty. The seal export fails closed.",
        ));
    }
    fs::create_dir_all(output_directory)?;
    let event_text = serde_json::to_string_pretty(&bundle.document)?;
    let proof_text = serde_json::to_string_pretty(&bundle.proof)?;
    let tree_head_text = serde_json::to_string_pretty(&bundle.tree_head)?;
    fs::write(
        output_directory.join(EVENT_FILE_NAME),
        format!("{event_text}\n"),
    )?;
    fs::write(
        output_directory.join(PROOF_FILE_NAME),
        format!("{proof_text}\n"),
    )?;
    fs::write(
        output_directory.join(TREE_HEAD_FILE_NAME),
        format!("{tree_head_text}\n"),
    )?;
    Ok(())
}

/// Load the three documented files. Any missing or empty file refuses.
pub fn load_seal_bundle(bundle_directory: &Path) -> Result<SealBundle> {
    let event_path = require_bundle_file(bundle_directory, EVENT_FILE_NAME)?;
    let proof_path = require_bundle_file(bundle_directory, PROOF_FILE_NAME)?;
    let tree_head_path = require_bundle_file(bundle_directory, TREE_HEAD_FILE_NAME)?;
    let event_text = read_required_text(&event_path, EVENT_FILE_NAME)?;
    let proof_text = read_required_text(&proof_path, PROOF_FILE_NAME)?;
    let tree_head_text = read_required_text(&tree_head_path, TREE_HEAD_FILE_NAME)?;
    let document: SealDocument = serde_json::from_str(&event_text).map_err(|error| {
        Error::denied(format!(
            "The seal bundle event fields did not parse: {error}. The accept check fails closed."
        ))
    })?;
    let proof: IssuanceLogInclusionProof = serde_json::from_str(&proof_text).map_err(|error| {
        Error::denied(format!(
            "The seal bundle proof fields did not parse: {error}. The accept check fails closed."
        ))
    })?;
    let tree_head = parse_signed_tree_head_json(&tree_head_text)?;
    Ok(SealBundle {
        document,
        proof,
        tree_head,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_event_file_fails_closed() {
        let directory = tempfile::tempdir().expect("create a temporary directory");
        std::fs::write(directory.path().join(PROOF_FILE_NAME), "{}\n").expect("write proof");
        std::fs::write(directory.path().join(TREE_HEAD_FILE_NAME), "{}\n")
            .expect("write tree head");
        let error =
            load_seal_bundle(directory.path()).expect_err("a missing event file must fail closed");
        assert!(
            error.to_string().contains("missing event.json"),
            "unexpected missing-event error: {error}"
        );
    }

    #[test]
    fn a_non_seal_line_fails_closed() {
        let kill_date = DateTime::parse_from_rfc3339("2026-08-20T00:00:00Z")
            .expect("parse a timestamp")
            .with_timezone(&Utc);
        let error = seal_document_from_issuance_log_line(
            r#"{"operation":"mint","timestamp":"2026-08-19T00:00:00Z","issuer_public_key_hex":"aa"}"#,
            kill_date,
        )
        .expect_err("a mint line must not export as a seal");
        assert!(
            error.to_string().contains("issuer_seal"),
            "unexpected non-seal error: {error}"
        );
    }
}
