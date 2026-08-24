//! Local kill bundle: kill issuance-log line + Merkle inclusion proof + signed tree head.
//!
//! This is a local export of existing artifacts. It is not a sixth identity record.
//! It is not a global name system, not SPIFFE federation, and not Certificate
//! Transparency gossip. The second store must already have the first issuer
//! public key on its accept list.
//!
//! Accept is verify-only. It does not mint, does not create instance records,
//! and does not write a second issuance.log line. Accepted death is verifier
//! state on the issuer record.

use crate::error::{Error, Result};
use crate::log_proof::IssuanceLogInclusionProof;
use crate::log_tree_head::{parse_signed_tree_head_json, SignedTreeHead};
use crate::records::LogEvent;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Documented bundle file names. Full words. STE100.
pub const EVENT_FILE_NAME: &str = "event.json";
pub const PROOF_FILE_NAME: &str = "proof.json";
pub const TREE_HEAD_FILE_NAME: &str = "tree-head.json";

/// Kill event types that may travel as a kill bundle.
pub const KILL_INSTANCE_EVENT: &str = "kill_instance";
pub const KILL_CAPABILITY_EVENT: &str = "kill_capability";

/// Small kill document. This is an artifact, not a sixth identity record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillDocument {
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub killed_instance_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub killed_capability_ids: Vec<String>,
    pub issuance_log_line: String,
}

/// The three existing artifacts a second store can check without becoming a second identity kernel.
#[derive(Debug, Clone)]
pub struct KillBundle {
    pub document: KillDocument,
    pub proof: IssuanceLogInclusionProof,
    pub tree_head: SignedTreeHead,
}

/// True when the operation is a portable kill event.
pub fn is_kill_event(operation: &str) -> bool {
    operation == KILL_INSTANCE_EVENT || operation == KILL_CAPABILITY_EVENT
}

/// Build a kill document from one issuance-log line. Refuse a non-kill event.
pub fn kill_document_from_issuance_log_line(issuance_log_line: &str) -> Result<KillDocument> {
    let trimmed = issuance_log_line.trim();
    if trimmed.is_empty() {
        return Err(Error::denied(
            "The kill bundle is missing an issuance-log line. The kill export fails closed.",
        ));
    }
    let event: LogEvent = serde_json::from_str(trimmed).map_err(|error| {
        Error::denied(format!(
            "The kill issuance-log line did not parse: {error}. The kill export fails closed."
        ))
    })?;
    if !is_kill_event(event.operation.trim()) {
        return Err(Error::denied(
            "The issuance-log line is not a kill_instance or kill_capability event. The kill export fails closed.",
        ));
    }
    Ok(KillDocument {
        event: event.operation,
        instance_id: event.instance_id.filter(|value| !value.trim().is_empty()),
        capability_id: event.capability_id.filter(|value| !value.trim().is_empty()),
        revoke_identifier: event
            .revoke_identifier
            .filter(|value| !value.trim().is_empty()),
        killed_instance_ids: normalize_identifier_list(&event.killed_instance_ids),
        killed_capability_ids: normalize_identifier_list(&event.killed_capability_ids),
        issuance_log_line: trimmed.to_string(),
    })
}

/// Parse the bound kill issuance-log line and refuse a non-kill event.
pub fn require_kill_issuance_log_line(issuance_log_line: &str) -> Result<LogEvent> {
    let trimmed = issuance_log_line.trim();
    if trimmed.is_empty() {
        return Err(Error::denied(
            "The kill bundle is missing an issuance-log line. The kill accept fails closed.",
        ));
    }
    let event: LogEvent = serde_json::from_str(trimmed).map_err(|error| {
        Error::denied(format!(
            "The kill issuance-log line did not parse: {error}. The kill accept fails closed."
        ))
    })?;
    if !is_kill_event(event.operation.trim()) {
        return Err(Error::denied(
            "The issuance-log line is not a kill_instance or kill_capability event. The kill accept fails closed.",
        ));
    }
    Ok(event)
}

fn normalize_identifier(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalize_optional_identifier(value: &Option<String>) -> Option<String> {
    value.as_deref().and_then(normalize_identifier)
}

fn normalize_identifier_list(values: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for value in values {
        if let Some(trimmed) = normalize_identifier(value) {
            if !out.iter().any(|existing| existing == &trimmed) {
                out.push(trimmed);
            }
        }
    }
    out
}

fn sorted_identifier_list(values: &[String]) -> Vec<String> {
    let mut out = normalize_identifier_list(values);
    out.sort();
    out
}

fn optional_identifiers_agree(document: &Option<String>, line: &Option<String>) -> bool {
    normalize_optional_identifier(document) == normalize_optional_identifier(line)
}

fn identifier_lists_agree(document: &[String], line: &[String]) -> bool {
    sorted_identifier_list(document) == sorted_identifier_list(line)
}

/// Refuse when the unsigned kill document does not match the bound issuance-log line.
/// Extra identifiers that appear only on event.json are refused.
pub fn require_kill_document_agrees_with_line(
    document: &KillDocument,
    event: &LogEvent,
) -> Result<()> {
    if event.operation.trim() != document.event.trim() {
        return Err(Error::denied(
            "The kill document event does not match the bound issuance-log line. The kill accept fails closed.",
        ));
    }
    if !optional_identifiers_agree(&document.instance_id, &event.instance_id) {
        return Err(Error::denied(
            "The kill document instance identifier does not match the bound issuance-log line. The kill accept fails closed.",
        ));
    }
    if !optional_identifiers_agree(&document.capability_id, &event.capability_id) {
        return Err(Error::denied(
            "The kill document capability identifier does not match the bound issuance-log line. The kill accept fails closed.",
        ));
    }
    if !optional_identifiers_agree(&document.revoke_identifier, &event.revoke_identifier) {
        return Err(Error::denied(
            "The kill document revoke identifier does not match the bound issuance-log line. The kill accept fails closed.",
        ));
    }
    if !identifier_lists_agree(&document.killed_instance_ids, &event.killed_instance_ids) {
        return Err(Error::denied(
            "The kill document killed_instance_ids list does not match the bound issuance-log line. Extra identifiers on event.json are refused. The kill accept fails closed.",
        ));
    }
    if !identifier_lists_agree(
        &document.killed_capability_ids,
        &event.killed_capability_ids,
    ) {
        return Err(Error::denied(
            "The kill document killed_capability_ids list does not match the bound issuance-log line. Extra identifiers on event.json are refused. The kill accept fails closed.",
        ));
    }
    Ok(())
}

fn require_bundle_file(bundle_directory: &Path, file_name: &str) -> Result<std::path::PathBuf> {
    if bundle_directory.as_os_str().is_empty() {
        return Err(Error::denied(
            "The bundle directory is empty. The kill accept fails closed.",
        ));
    }
    let path = bundle_directory.join(file_name);
    if !path.exists() {
        return Err(Error::denied(format!(
            "The kill bundle is missing {file_name}. The accept check fails closed."
        )));
    }
    Ok(path)
}

fn read_required_text(path: &Path, file_name: &str) -> Result<String> {
    let text = fs::read_to_string(path).map_err(|error| {
        Error::denied(format!(
            "The kill bundle {file_name} could not be read: {error}. The accept check fails closed."
        ))
    })?;
    if text.trim().is_empty() {
        return Err(Error::denied(format!(
            "The kill bundle {file_name} is empty. The accept check fails closed."
        )));
    }
    Ok(text)
}

/// Write event.json, proof.json, and tree-head.json under `output_directory`.
pub fn write_kill_bundle(output_directory: &Path, bundle: &KillBundle) -> Result<()> {
    if output_directory.as_os_str().is_empty() {
        return Err(Error::denied(
            "The output directory is empty. The kill export fails closed.",
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
pub fn load_kill_bundle(bundle_directory: &Path) -> Result<KillBundle> {
    let event_path = require_bundle_file(bundle_directory, EVENT_FILE_NAME)?;
    let proof_path = require_bundle_file(bundle_directory, PROOF_FILE_NAME)?;
    let tree_head_path = require_bundle_file(bundle_directory, TREE_HEAD_FILE_NAME)?;
    let event_text = read_required_text(&event_path, EVENT_FILE_NAME)?;
    let proof_text = read_required_text(&proof_path, PROOF_FILE_NAME)?;
    let tree_head_text = read_required_text(&tree_head_path, TREE_HEAD_FILE_NAME)?;
    let document: KillDocument = serde_json::from_str(&event_text).map_err(|error| {
        Error::denied(format!(
            "The kill bundle event fields did not parse: {error}. The accept check fails closed."
        ))
    })?;
    let proof: IssuanceLogInclusionProof = serde_json::from_str(&proof_text).map_err(|error| {
        Error::denied(format!(
            "The kill bundle proof fields did not parse: {error}. The accept check fails closed."
        ))
    })?;
    let tree_head = parse_signed_tree_head_json(&tree_head_text)?;
    Ok(KillBundle {
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
            load_kill_bundle(directory.path()).expect_err("a missing event file must fail closed");
        assert!(
            error.to_string().contains("missing event.json"),
            "unexpected missing-event error: {error}"
        );
    }

    #[test]
    fn a_non_kill_line_fails_closed() {
        let error = kill_document_from_issuance_log_line(
            r#"{"operation":"mint","timestamp":"2026-08-19T00:00:00Z"}"#,
        )
        .expect_err("a mint line must not export as a kill");
        assert!(
            error.to_string().contains("kill_instance")
                || error.to_string().contains("kill_capability"),
            "unexpected non-kill error: {error}"
        );
    }

    #[test]
    fn an_empty_output_directory_fails_closed() {
        let bundle = KillBundle {
            document: KillDocument {
                event: KILL_INSTANCE_EVENT.to_string(),
                instance_id: Some("example".to_string()),
                capability_id: None,
                revoke_identifier: None,
                killed_instance_ids: Vec::new(),
                killed_capability_ids: Vec::new(),
                issuance_log_line: "{}".to_string(),
            },
            proof: IssuanceLogInclusionProof {
                line_hash: "aa".repeat(32),
                leaf_index: 0,
                sibling_hashes: Vec::new(),
                root: "bb".repeat(32),
            },
            tree_head: SignedTreeHead {
                merkle_root: "bb".repeat(32),
                leaf_count: 1,
                signed_at: chrono::DateTime::parse_from_rfc3339("2026-08-19T00:00:00Z")
                    .expect("parse a timestamp")
                    .with_timezone(&chrono::Utc),
                issuer_public_key_hex: "aa".to_string(),
                signature_hex: "bb".to_string(),
                issuer_signatures: Vec::new(),
            },
        };
        let error = write_kill_bundle(Path::new(""), &bundle)
            .expect_err("an empty output directory must fail closed");
        assert!(
            error.to_string().contains("empty"),
            "unexpected empty-output error: {error}"
        );
    }
}
