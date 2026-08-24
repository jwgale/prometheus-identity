//! Local act bundle: decision receipt + Merkle inclusion proof + signed tree head.
//!
//! This is a local export of three existing artifacts. It is not a global name
//! system, not SPIFFE federation, and not Certificate Transparency gossip.
//! The second store must already have the first issuer public key on its accept list.
//! This is not a sixth record.
//!
//! Accept is verify-only. It does not mint, does not create instance records,
//! and does not write a second issuance.log line.

use crate::error::{Error, Result};
use crate::kernel::DecisionReceipt;
use crate::log_chain;
use crate::log_proof::IssuanceLogInclusionProof;
use crate::log_tree_head::{parse_signed_tree_head_json, SignedTreeHead};
use crate::records::LogEvent;
use std::fs;
use std::path::Path;

/// Documented bundle file names. Full words. STE100.
pub const RECEIPT_FILE_NAME: &str = "receipt.json";
pub const PROOF_FILE_NAME: &str = "proof.json";
pub const TREE_HEAD_FILE_NAME: &str = "tree-head.json";

/// The three existing artifacts a second store can check without becoming a second identity kernel.
#[derive(Debug, Clone)]
pub struct ActBundle {
    pub receipt: DecisionReceipt,
    pub proof: IssuanceLogInclusionProof,
    pub tree_head: SignedTreeHead,
}

/// Read `line_hash` from the receipt bound issuance-log line.
/// The receipt stores `issuance_log_line`, the exact JSON line. That line already
/// carries `line_hash`. Recompute it and refuse a mismatch.
pub fn line_hash_from_bound_issuance_log_line(issuance_log_line: &str) -> Result<String> {
    let trimmed = issuance_log_line.trim();
    if trimmed.is_empty() {
        return Err(Error::denied(
            "The receipt is missing an issuance-log line. The act bundle fails closed.",
        ));
    }
    let value: serde_json::Value = serde_json::from_str(trimmed).map_err(|error| {
        Error::denied(format!(
            "The receipt bound issuance-log line is not valid JSON: {error}. The act bundle fails closed."
        ))
    })?;
    let object = value.as_object().ok_or_else(|| {
        Error::denied(
            "The receipt bound issuance-log line is not a JSON object. The act bundle fails closed.",
        )
    })?;
    let recorded = object
        .get("line_hash")
        .and_then(|field| field.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if recorded.is_empty() {
        return Err(Error::denied(
            "The receipt bound issuance-log line is missing line_hash. The act bundle fails closed.",
        ));
    }
    crate::log_proof::require_sha256_hexadecimal_digest(&recorded, "line_hash")?;
    let event: LogEvent = serde_json::from_value(value).map_err(|error| {
        Error::denied(format!(
            "The receipt bound issuance-log line did not parse: {error}. The act bundle fails closed."
        ))
    })?;
    let content_without_line_hash = log_chain::line_hash_content(&event)?;
    let computed = log_chain::sha256_hexadecimal(content_without_line_hash.as_bytes());
    if computed != recorded {
        return Err(Error::denied(
            "The receipt bound issuance-log line_hash does not match this line. The act bundle fails closed.",
        ));
    }
    Ok(computed)
}

fn require_bundle_file(bundle_directory: &Path, file_name: &str) -> Result<std::path::PathBuf> {
    if bundle_directory.as_os_str().is_empty() {
        return Err(Error::denied(
            "The bundle directory is empty. The act accept fails closed.",
        ));
    }
    let path = bundle_directory.join(file_name);
    if !path.exists() {
        return Err(Error::denied(format!(
            "The act bundle is missing {file_name}. The accept check fails closed."
        )));
    }
    Ok(path)
}

fn read_required_text(path: &Path, file_name: &str) -> Result<String> {
    let text = fs::read_to_string(path).map_err(|error| {
        Error::denied(format!(
            "The act bundle {file_name} could not be read: {error}. The accept check fails closed."
        ))
    })?;
    if text.trim().is_empty() {
        return Err(Error::denied(format!(
            "The act bundle {file_name} is empty. The accept check fails closed."
        )));
    }
    Ok(text)
}

/// Write the three existing artifacts under `output_directory`.
pub fn write_act_bundle(output_directory: &Path, bundle: &ActBundle) -> Result<()> {
    if output_directory.as_os_str().is_empty() {
        return Err(Error::denied(
            "The output directory is empty. The act export fails closed.",
        ));
    }
    fs::create_dir_all(output_directory)?;
    let receipt_text = serde_json::to_string_pretty(&bundle.receipt)?;
    let proof_text = serde_json::to_string_pretty(&bundle.proof)?;
    let tree_head_text = serde_json::to_string_pretty(&bundle.tree_head)?;
    fs::write(
        output_directory.join(RECEIPT_FILE_NAME),
        format!("{receipt_text}\n"),
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
pub fn load_act_bundle(bundle_directory: &Path) -> Result<ActBundle> {
    let receipt_path = require_bundle_file(bundle_directory, RECEIPT_FILE_NAME)?;
    let proof_path = require_bundle_file(bundle_directory, PROOF_FILE_NAME)?;
    let tree_head_path = require_bundle_file(bundle_directory, TREE_HEAD_FILE_NAME)?;
    let receipt_text = read_required_text(&receipt_path, RECEIPT_FILE_NAME)?;
    let proof_text = read_required_text(&proof_path, PROOF_FILE_NAME)?;
    let tree_head_text = read_required_text(&tree_head_path, TREE_HEAD_FILE_NAME)?;
    let receipt: DecisionReceipt = serde_json::from_str(&receipt_text).map_err(|error| {
        Error::denied(format!(
            "The act bundle receipt fields did not parse: {error}. The accept check fails closed."
        ))
    })?;
    let proof: IssuanceLogInclusionProof = serde_json::from_str(&proof_text).map_err(|error| {
        Error::denied(format!(
            "The act bundle proof fields did not parse: {error}. The accept check fails closed."
        ))
    })?;
    let tree_head = parse_signed_tree_head_json(&tree_head_text)?;
    Ok(ActBundle {
        receipt,
        proof,
        tree_head,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_proof_file_fails_closed() {
        let directory = tempfile::tempdir().expect("create a temporary directory");
        std::fs::write(directory.path().join(RECEIPT_FILE_NAME), "{}\n").expect("write receipt");
        std::fs::write(directory.path().join(TREE_HEAD_FILE_NAME), "{}\n")
            .expect("write tree head");
        let error =
            load_act_bundle(directory.path()).expect_err("a missing proof file must fail closed");
        assert!(
            error.to_string().contains("missing proof.json"),
            "unexpected missing-proof error: {error}"
        );
    }

    #[test]
    fn an_empty_bound_line_fails_closed() {
        let error = line_hash_from_bound_issuance_log_line("  ")
            .expect_err("an empty bound line must fail closed");
        assert!(
            error.to_string().contains("missing an issuance-log line"),
            "unexpected empty-line error: {error}"
        );
    }
}
