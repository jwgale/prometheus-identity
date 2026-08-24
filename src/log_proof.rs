//! Local Merkle inclusion proof over the hash-chained issuance log.
//!
//! This is a local Merkle tree over the sequence of line_hash values.
//! It is not a public transparency log, not Certificate Transparency,
//! and not a gossiped signed tree head across the internet.
//!
//! Proofs are derived from the existing issuance.log lines. This is not a sixth record.
//! The hash chain stays the integrity walk. Merkle is an inclusion index on top of it.

use crate::error::{Error, Result};
use crate::log_chain::{sha256_hexadecimal, EMPTY_PREVIOUS_LINE_HASH};
use serde::{Deserialize, Serialize};

/// Leaf choice (documented, do not invent a third hash chain):
/// `line_hash` is already the SHA-256 hexadecimal digest of the compact JSON line
/// with the `line_hash` field omitted. The Merkle leaf is that existing `line_hash`.
/// The leaf is not SHA-256 of the line_hash hexadecimal text.
fn merkle_leaf_from_line_hash(line_hash: &str) -> Result<String> {
    require_sha256_hexadecimal_digest(line_hash, "line_hash")
}

/// Parent node: SHA-256 hexadecimal digest of the UTF-8 bytes of
/// `left_hexadecimal` concatenated with `right_hexadecimal`.
/// Both children are 64-character lowercase hexadecimal SHA-256 digests.
pub fn merkle_parent_hash(left_hexadecimal: &str, right_hexadecimal: &str) -> String {
    let mut joined = String::with_capacity(left_hexadecimal.len() + right_hexadecimal.len());
    joined.push_str(left_hexadecimal);
    joined.push_str(right_hexadecimal);
    sha256_hexadecimal(joined.as_bytes())
}

/// Current Merkle root and the number of real leaves (issuance-log lines).
/// Padding leaves are not counted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuanceLogMerkleRoot {
    pub root: String,
    pub leaf_count: u64,
}

/// Inclusion proof for one issuance-log line_hash.
/// A second store can check this proof against a known root without copying the log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuanceLogInclusionProof {
    pub line_hash: String,
    pub leaf_index: u64,
    pub sibling_hashes: Vec<String>,
    pub root: String,
}

/// Require a 64-character hexadecimal SHA-256 digest. Empty is refused.
pub fn require_sha256_hexadecimal_digest(value: &str, field_name: &str) -> Result<String> {
    let text = value.trim();
    if text.is_empty() {
        return Err(Error::denied(format!(
            "The {field_name} value is empty. The inclusion proof fails closed."
        )));
    }
    if text.len() != 64 || !text.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err(Error::denied(format!(
            "The {field_name} value must be a 64-character SHA-256 hexadecimal digest. The inclusion proof fails closed."
        )));
    }
    Ok(text.to_string())
}

fn padded_leaf_count(leaf_count: usize) -> usize {
    match leaf_count {
        0 => 0,
        1 => 1,
        count => count.next_power_of_two(),
    }
}

/// Pad the real leaves to the next power of two with the documented empty-hash.
/// An empty list stays empty. A single leaf is not padded.
fn padded_leaves(line_hashes: &[String]) -> Result<Vec<String>> {
    if line_hashes.is_empty() {
        return Ok(Vec::new());
    }
    let mut leaves = Vec::with_capacity(padded_leaf_count(line_hashes.len()));
    for line_hash in line_hashes {
        leaves.push(merkle_leaf_from_line_hash(line_hash)?);
    }
    let padded_count = padded_leaf_count(leaves.len());
    while leaves.len() < padded_count {
        leaves.push(EMPTY_PREVIOUS_LINE_HASH.to_string());
    }
    Ok(leaves)
}

fn merkle_levels(padded_leaves: &[String]) -> Vec<Vec<String>> {
    if padded_leaves.is_empty() {
        return Vec::new();
    }
    let mut levels = Vec::new();
    levels.push(padded_leaves.to_vec());
    while levels.last().expect("a non-empty tree has a level").len() > 1 {
        let current = levels.last().expect("a non-empty tree has a level");
        let mut next = Vec::with_capacity(current.len() / 2);
        for pair in current.chunks(2) {
            next.push(merkle_parent_hash(&pair[0], &pair[1]));
        }
        levels.push(next);
    }
    levels
}

/// Merkle root over the sequence of line_hash values.
/// An empty log uses the documented empty-hash and leaf_count 0.
pub fn merkle_root_from_line_hashes(line_hashes: &[String]) -> Result<IssuanceLogMerkleRoot> {
    if line_hashes.is_empty() {
        return Ok(IssuanceLogMerkleRoot {
            root: EMPTY_PREVIOUS_LINE_HASH.to_string(),
            leaf_count: 0,
        });
    }
    let leaves = padded_leaves(line_hashes)?;
    let levels = merkle_levels(&leaves);
    let root = levels
        .last()
        .and_then(|level| level.first())
        .cloned()
        .ok_or_else(|| {
            Error::denied("The Merkle tree has no root. The inclusion proof fails closed.")
        })?;
    Ok(IssuanceLogMerkleRoot {
        root,
        leaf_count: line_hashes.len() as u64,
    })
}

fn sibling_hashes_for_leaf(levels: &[Vec<String>], leaf_index: usize) -> Result<Vec<String>> {
    if levels.is_empty() {
        return Err(Error::denied(
            "The Merkle tree is empty. The inclusion proof fails closed.",
        ));
    }
    let mut sibling_hashes = Vec::new();
    let mut index = leaf_index;
    for level in levels.iter().take(levels.len().saturating_sub(1)) {
        if index >= level.len() {
            return Err(Error::denied(
                "The leaf index is outside this Merkle tree. The inclusion proof fails closed.",
            ));
        }
        let sibling_index = index ^ 1;
        if sibling_index >= level.len() {
            return Err(Error::denied(
                "The Merkle sibling is missing. The inclusion proof fails closed.",
            ));
        }
        sibling_hashes.push(level[sibling_index].clone());
        index /= 2;
    }
    Ok(sibling_hashes)
}

/// Prove that `line_hash` is a leaf of this sequence. Fail closed if it is not.
pub fn prove_inclusion(
    line_hashes: &[String],
    line_hash: &str,
) -> Result<IssuanceLogInclusionProof> {
    let claimed = require_sha256_hexadecimal_digest(line_hash, "line_hash")?;
    let leaf_index = line_hashes
        .iter()
        .position(|existing| existing == &claimed)
        .ok_or_else(|| {
            Error::denied(
                "The line_hash is not present in this issuance log. The inclusion proof fails closed.",
            )
        })?;
    let leaves = padded_leaves(line_hashes)?;
    let levels = merkle_levels(&leaves);
    let sibling_hashes = sibling_hashes_for_leaf(&levels, leaf_index)?;
    let root = merkle_root_from_line_hashes(line_hashes)?.root;
    Ok(IssuanceLogInclusionProof {
        line_hash: claimed,
        leaf_index: leaf_index as u64,
        sibling_hashes,
        root,
    })
}

fn recompute_root_from_proof(proof: &IssuanceLogInclusionProof) -> Result<String> {
    if proof.line_hash.trim().is_empty()
        && proof.sibling_hashes.is_empty()
        && proof.root.trim().is_empty()
    {
        return Err(Error::denied(
            "The inclusion proof is empty. The check fails closed.",
        ));
    }
    let leaf = merkle_leaf_from_line_hash(&proof.line_hash)?;
    if leaf != proof.line_hash.trim() {
        return Err(Error::denied(
            "The inclusion proof leaf is not the claimed line_hash. The check fails closed.",
        ));
    }
    let mut current = leaf;
    let mut index = proof.leaf_index;
    for sibling in &proof.sibling_hashes {
        let sibling = require_sha256_hexadecimal_digest(sibling, "sibling_hashes")?;
        if index % 2 == 0 {
            current = merkle_parent_hash(&current, &sibling);
        } else {
            current = merkle_parent_hash(&sibling, &current);
        }
        index /= 2;
    }
    Ok(current)
}

/// Recompute the Merkle root from the proof. Refuse an empty proof, a truncated
/// sibling list, a leaf that is not the claimed line_hash, or a root mismatch.
pub fn check_inclusion_proof(proof: &IssuanceLogInclusionProof, expected_root: &str) -> Result<()> {
    let expected = require_sha256_hexadecimal_digest(expected_root, "root")?;
    if proof.sibling_hashes.is_empty()
        && !proof.root.trim().is_empty()
        && proof.root.trim() != proof.line_hash.trim()
    {
        // A multi-leaf tree always has at least one sibling after padding to a power of two
        // except the single-leaf case, where root equals the leaf. An empty sibling list
        // with a different claimed root is a truncated proof.
        return Err(Error::denied(
            "The inclusion proof sibling list is truncated. The check fails closed.",
        ));
    }
    let recomputed = recompute_root_from_proof(proof)?;
    if recomputed != proof.root.trim() {
        if proof.sibling_hashes.is_empty() {
            return Err(Error::denied(
                "The inclusion proof sibling list is truncated. The check fails closed.",
            ));
        }
        return Err(Error::denied(
            "The recomputed Merkle root does not match the proof root. The inclusion proof fails closed.",
        ));
    }
    if recomputed != expected {
        return Err(Error::denied(
            "The recomputed Merkle root does not match. The inclusion proof fails closed.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_line_hash(tag: u8) -> String {
        sha256_hexadecimal(&[tag])
    }

    #[test]
    fn a_single_line_hash_is_its_own_merkle_root() {
        let leaves = vec![fixture_line_hash(1)];
        let root = merkle_root_from_line_hashes(&leaves).expect("single-leaf root");
        assert_eq!(root.leaf_count, 1);
        assert_eq!(root.root, leaves[0]);
    }

    #[test]
    fn two_injected_line_hashes_hash_as_one_parent() {
        let left = fixture_line_hash(1);
        let right = fixture_line_hash(2);
        let root =
            merkle_root_from_line_hashes(&[left.clone(), right.clone()]).expect("two-leaf root");
        assert_eq!(root.leaf_count, 2);
        assert_eq!(root.root, merkle_parent_hash(&left, &right));
    }

    #[test]
    fn an_empty_log_uses_the_documented_empty_hash() {
        let root = merkle_root_from_line_hashes(&[]).expect("empty root");
        assert_eq!(root.leaf_count, 0);
        assert_eq!(root.root, EMPTY_PREVIOUS_LINE_HASH);
    }

    #[test]
    fn prove_a_real_injected_line_and_check_proof_succeeds() {
        let leaves = vec![
            fixture_line_hash(1),
            fixture_line_hash(2),
            fixture_line_hash(3),
        ];
        let proof = prove_inclusion(&leaves, &leaves[1]).expect("prove a real line");
        assert_eq!(proof.line_hash, leaves[1]);
        assert_eq!(proof.leaf_index, 1);
        assert_eq!(
            proof.sibling_hashes.len(),
            2,
            "three leaves pad to four, so the path has two siblings"
        );
        check_inclusion_proof(&proof, &proof.root).expect("check-proof must accept a real proof");
        let current = merkle_root_from_line_hashes(&leaves).expect("current root");
        check_inclusion_proof(&proof, &current.root)
            .expect("the proof must match the current root");
    }

    #[test]
    fn altering_one_sibling_makes_check_proof_fail() {
        let leaves = vec![
            fixture_line_hash(1),
            fixture_line_hash(2),
            fixture_line_hash(3),
        ];
        let mut proof = prove_inclusion(&leaves, &leaves[0]).expect("prove a real line");
        assert!(!proof.sibling_hashes.is_empty());
        proof.sibling_hashes[0] = fixture_line_hash(99);
        let error = check_inclusion_proof(&proof, &proof.root)
            .expect_err("a tampered sibling must fail closed");
        let text = error.to_string();
        assert!(
            text.contains("does not match") || text.contains("fails closed"),
            "unexpected tampered-sibling error: {error}"
        );
    }

    #[test]
    fn proving_a_missing_line_hash_fails_closed() {
        let leaves = vec![fixture_line_hash(1), fixture_line_hash(2)];
        let missing = fixture_line_hash(99);
        let error =
            prove_inclusion(&leaves, &missing).expect_err("a missing line_hash must fail closed");
        assert!(
            error
                .to_string()
                .contains("not present in this issuance log"),
            "unexpected missing-line error: {error}"
        );
    }

    #[test]
    fn an_old_proof_checks_against_the_old_root_and_fails_against_the_new_root() {
        let mut leaves = vec![fixture_line_hash(1), fixture_line_hash(2)];
        let old_root = merkle_root_from_line_hashes(&leaves).expect("old root");
        let old_proof = prove_inclusion(&leaves, &leaves[0]).expect("prove the first line");
        check_inclusion_proof(&old_proof, &old_root.root).expect("old proof against old root");
        leaves.push(fixture_line_hash(3));
        let new_root = merkle_root_from_line_hashes(&leaves).expect("new root");
        assert_ne!(
            old_root.root, new_root.root,
            "a new append must change the Merkle root"
        );
        check_inclusion_proof(&old_proof, &old_root.root)
            .expect("an old proof must still check against the old root");
        let error = check_inclusion_proof(&old_proof, &new_root.root)
            .expect_err("an old proof must fail against the new root");
        assert!(
            error.to_string().contains("does not match"),
            "unexpected old-proof-against-new-root error: {error}"
        );
    }

    #[test]
    fn an_empty_proof_fails_closed() {
        let empty = IssuanceLogInclusionProof {
            line_hash: String::new(),
            leaf_index: 0,
            sibling_hashes: Vec::new(),
            root: String::new(),
        };
        let error = check_inclusion_proof(&empty, EMPTY_PREVIOUS_LINE_HASH)
            .expect_err("an empty proof must fail closed");
        assert!(
            error.to_string().contains("empty") || error.to_string().contains("fails closed"),
            "unexpected empty-proof error: {error}"
        );
    }

    #[test]
    fn a_truncated_sibling_list_fails_closed() {
        let leaves = vec![
            fixture_line_hash(1),
            fixture_line_hash(2),
            fixture_line_hash(3),
        ];
        let mut proof = prove_inclusion(&leaves, &leaves[0]).expect("prove a real line");
        assert!(proof.sibling_hashes.len() >= 2);
        proof.sibling_hashes.pop();
        let error = check_inclusion_proof(&proof, &proof.root)
            .expect_err("a truncated sibling list must fail closed");
        let text = error.to_string();
        assert!(
            text.contains("truncated") || text.contains("does not match"),
            "unexpected truncated-sibling error: {error}"
        );
    }

    #[test]
    fn a_proof_leaf_that_is_not_the_claimed_line_hash_fails_closed() {
        let leaves = vec![fixture_line_hash(1), fixture_line_hash(2)];
        let mut proof = prove_inclusion(&leaves, &leaves[0]).expect("prove a real line");
        proof.line_hash = fixture_line_hash(99);
        let error = check_inclusion_proof(&proof, &proof.root)
            .expect_err("a leaf that is not the claimed line_hash must fail closed");
        let text = error.to_string();
        assert!(
            text.contains("line_hash")
                || text.contains("does not match")
                || text.contains("fails closed"),
            "unexpected leaf-mismatch error: {error}"
        );
    }
}
