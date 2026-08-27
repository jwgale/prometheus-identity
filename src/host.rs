//! Local tool-boundary host. A runtime calls this host before a tool action.
//! The host binds to a loopback address only.

use crate::error::{Error, Result};
use crate::interface::INTERFACE_HTML;
use crate::kernel::{
    CheckDecision, DecisionReceipt, HolderProof, Kernel,
    LABORATORY_ISSUER_ROTATE_KILL_AFTER_SECONDS,
};
use crate::kill_bundle::KillDocument;
use crate::log_proof::IssuanceLogInclusionProof;
use crate::log_tree_head::SignedTreeHead;
use crate::operator_page::OPERATOR_PAGE_HTML;
use crate::records::InstanceStatus;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct CheckRequest {
    instance_id: String,
    #[serde(default)]
    capability_id: Option<String>,
    intent: String,
    audience: String,
    #[serde(default)]
    holder_secret_path: Option<String>,
    #[serde(default)]
    holder_proof: Option<String>,
    #[serde(default)]
    challenge_nonce: Option<String>,
    /// Act authority. Required. Empty is not autonomous. The exact word autonomous is required.
    #[serde(default)]
    on_behalf_of: Option<String>,
    /// Optional. Path only. After issuance threshold_n is 2 this path is required.
    /// Kernel check signs a receipt and appends issuance.log. This is not verify-only.
    /// A live host that already registered member two still requires this path on the check body.
    #[serde(default)]
    member_secret_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChallengeRequest {
    instance_id: String,
    /// Optional. Path only. After issuance threshold_n is 2 this path is required.
    /// Kernel challenge appends a signed issuance.log line. This is not a nonce-only write.
    /// A live host that already registered member two still requires this path on the challenge body.
    #[serde(default)]
    member_secret_path: Option<String>,
}

/// POST /present-svid body. Reuse Kernel::present_x509_svid.
/// POST /present-wimse uses this same operator body and reuses Kernel::present_wimse.
/// Intent, audience, and on_behalf_of are accepted when a later present API needs them.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct PresentSvidRequest {
    instance_id: String,
    #[serde(default)]
    capability_id: Option<String>,
    #[serde(default)]
    capability: Option<String>,
    #[serde(default)]
    intent: Option<String>,
    #[serde(default)]
    audience: Option<String>,
    #[serde(default)]
    holder_secret_path: Option<String>,
    #[serde(default)]
    holder_proof: Option<String>,
    #[serde(default)]
    challenge_nonce: Option<String>,
    #[serde(default)]
    on_behalf_of: Option<String>,
    /// Optional. Path only. After issuance threshold_n is 2 this path is required.
    /// Present signs with member secrets. This is not verify-only.
    /// A live host that already registered member two still requires this path on the present body.
    #[serde(default)]
    member_secret_path: Option<String>,
}

#[derive(Debug, Serialize)]
struct InstanceListing {
    instance_id: String,
    /// Already on the instance record. Omitted when birth has no parent.
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_instance_id: Option<String>,
    status: String,
    /// Capability identifiers for this instance. Tokens are not included.
    capability_ids: Vec<String>,
    /// Already on the instance record. Omitted when empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_type_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct InstancesResponse {
    instances: Vec<InstanceListing>,
}

#[derive(Debug, Serialize)]
struct ChallengeResponse {
    challenge_nonce: String,
}

/// POST /verifier-challenge response. Short-lived nonce for this host process.
/// This is an artifact. This is not an instance record.
#[derive(Debug, Serialize)]
struct VerifierChallengeResponse {
    challenge_nonce: String,
    challenge_message: String,
}

/// POST /sign-holder-nonce body. The issuing-side host reads the typed path.
/// Secret bytes are not uploaded and not returned.
#[derive(Debug, Deserialize)]
struct SignHolderNonceRequest {
    #[serde(default)]
    challenge_nonce: Option<String>,
    #[serde(default)]
    challenge_message: Option<String>,
    holder_secret_path: String,
}

/// POST /sign-holder-nonce response. The holder signature hexadecimal only.
#[derive(Debug, Serialize)]
struct SignHolderNonceResponse {
    holder_proof: String,
}

#[derive(Debug, Serialize)]
struct PresentSvidResponse {
    presentation_json: String,
    certificate_pem: String,
}

/// GET /agent-types listing. Identifiers and allowed intents only.
#[derive(Debug, Serialize)]
struct AgentTypeListing {
    agent_type_id: String,
    allowed_intents: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AgentTypesResponse {
    agent_types: Vec<AgentTypeListing>,
}

/// GET /issuer-public. Full current issuer public key hexadecimal and crypto profile only.
/// Secret bytes are not included. GET /status stays truncated.
#[derive(Debug, Serialize)]
struct IssuerPublicResponse {
    current_issuer_public_key_hex: String,
    crypto_profile: String,
}

/// Laboratory well-known check discovery path.
/// A runtime GETs this path. Then the runtime POSTs /check-svid or /check-wimse.
/// The instance identifier is not in this path. A later market name stays open.
const LABORATORY_WELL_KNOWN_CHECK_PATH: &str = "/.well-known/prometheus-check";

/// Loopback bind named in the well-known document when the operator is still on loopback.
pub const LABORATORY_LOOPBACK_BIND: &str = "127.0.0.1";

/// Locked laboratory public check name. Jason Gale locked this name.
/// This lock is a name only. This crate does not start a public listener.
pub const LABORATORY_PUBLIC_CHECK_NAME: &str = "check.prestigeworldwide.digital";

/// Listen mode for the loopback host. Laptop host without check-only stays issuing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostMode {
    pub check_only: bool,
    pub well_known_bind: String,
}

impl HostMode {
    pub fn issuing_loopback() -> Self {
        Self {
            check_only: false,
            well_known_bind: LABORATORY_LOOPBACK_BIND.to_string(),
        }
    }

    pub fn check_only_loopback() -> Self {
        Self {
            check_only: true,
            well_known_bind: LABORATORY_LOOPBACK_BIND.to_string(),
        }
    }

    pub fn check_only_public() -> Self {
        Self {
            check_only: true,
            well_known_bind: LABORATORY_PUBLIC_CHECK_NAME.to_string(),
        }
    }
}

/// Build a listen mode from command flags. A public check name is accepted
/// only on a check-only host. Only check.prestigeworldwide.digital is accepted.
pub fn host_mode_from_flags(check_only: bool, public_check_name: Option<&str>) -> Result<HostMode> {
    match public_check_name
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        None => Ok(HostMode {
            check_only,
            well_known_bind: LABORATORY_LOOPBACK_BIND.to_string(),
        }),
        Some(name) => {
            if !check_only {
                return Err(Error::denied(
                    "A public check name is accepted only on a check-only host. The laptop host stays loopback only. The check fails closed.",
                ));
            }
            if name != LABORATORY_PUBLIC_CHECK_NAME {
                return Err(Error::denied(
                    "The public check name must be check.prestigeworldwide.digital. www.prestigeworldwide.digital is not the check name. The apex prestigeworldwide.digital is not the check listener. The check fails closed.",
                ));
            }
            Ok(HostMode::check_only_public())
        }
    }
}

fn check_only_path_allowed(method: &str, path: &str) -> bool {
    matches!(
        (method, path),
        ("GET", "/")
            | ("GET", "/health")
            | ("GET", LABORATORY_WELL_KNOWN_CHECK_PATH)
            | ("POST", "/check-svid")
            | ("POST", "/check-wimse")
            | ("POST", "/verifier-challenge")
            | ("POST", "/issuer-accept")
            | ("POST", "/kill-accept")
            | ("POST", "/seal-accept")
            | ("POST", "/previous-key-accept")
            | ("POST", "/act-accept")
    )
}

fn check_only_root_json(mode: &HostMode) -> String {
    serde_json::json!({
        "status": "live",
        "role": "check-only",
        "bind": mode.well_known_bind,
        "refuses_other_interfaces": true
    })
    .to_string()
}

/// Laboratory well-known check discovery document.
/// This document is not a sixth identity record. This document is not a public listener.
/// Secret bytes, tokens, instance identifiers, and issuer secret material are not included.
/// A public bind names check.prestigeworldwide.digital and names every check-only
/// operator pin that is actually allowed. Export write verbs stay off the public document.
/// Loopback stays 127.0.0.1 and may still name operator export pins.
/// Operator pins stay in operator_pin_paths. They do not move into checks[].
pub(crate) fn laboratory_well_known_check_document(mode: &HostMode) -> String {
    let public = mode.well_known_bind == LABORATORY_PUBLIC_CHECK_NAME;
    let operator_pin_paths = if public {
        serde_json::json!([
            {"method": "POST", "path": "/issuer-accept"},
            {"method": "POST", "path": "/kill-accept"},
            {"method": "POST", "path": "/seal-accept"},
            {"method": "POST", "path": "/previous-key-accept"},
            {"method": "POST", "path": "/act-accept"}
        ])
    } else {
        serde_json::json!([
            {"method": "POST", "path": "/issuer-accept"},
            {"method": "POST", "path": "/kill-accept"},
            {"method": "POST", "path": "/seal-export"},
            {"method": "POST", "path": "/seal-accept"},
            {"method": "POST", "path": "/previous-key-export"},
            {"method": "POST", "path": "/previous-key-accept"},
            {"method": "POST", "path": "/act-accept"}
        ])
    };
    serde_json::json!({
        "laboratory_name": "prometheus-check",
        "bind": mode.well_known_bind,
        "refuses_other_interfaces": true,
        "checks": [
            {"method": "POST", "path": "/check-svid"},
            {"method": "POST", "path": "/check-wimse"}
        ],
        "verifier_challenge": {"method": "POST", "path": "/verifier-challenge"},
        "store_b_check": "A Store B check needs a holder signature over that nonce. The holder secret does not live on the verifier.",
        "operator_pin_paths": operator_pin_paths,
        "present": "document",
        "on_ramp_artifacts": ["X.509-SVID", "WIMSE"],
        "death_wins": true,
        "short_life_is_not_kill": true,
        "instance_identifier_in_path": false
    })
    .to_string()
}

/// POST /agent-type body. Reuse Kernel::add_agent_type. No second write path.
/// Authorization limit is the highest destination the kernel already stores.
/// Allowed intents freeze after the first write.
#[derive(Debug, Deserialize)]
struct AgentTypeAddRequest {
    #[serde(default)]
    agent_type_id: Option<String>,
    #[serde(default)]
    allowed_intents: Vec<String>,
    #[serde(default)]
    authorization_limit: Option<String>,
    /// Accepted as the same field as authorization_limit. The kernel uses authorization_limit.
    #[serde(default)]
    destination: Option<String>,
    #[serde(default)]
    owner: Option<String>,
    /// Optional. Path only. After issuance threshold_n is 2 this path is required.
    /// The host process reads the file. Secret bytes are not uploaded.
    /// A live host that already registered member two still requires this path on the agent-type body.
    #[serde(default)]
    member_secret_path: Option<String>,
}

/// POST /agent-type response. Identifiers and allowed intents only.
#[derive(Debug, Serialize)]
struct AgentTypeAddResponse {
    agent_type_id: String,
    allowed_intents: Vec<String>,
}

/// POST /birth body. Fields match Kernel::birth_write.
/// The kernel uses audience. destination is accepted as the same field.
#[derive(Debug, Deserialize)]
struct BirthRequest {
    agent_type_id: String,
    #[serde(default)]
    owner: Option<String>,
    intent: String,
    #[serde(default)]
    audience: Option<String>,
    #[serde(default)]
    destination: Option<String>,
    #[serde(default)]
    on_behalf_of: Option<String>,
    #[serde(default)]
    site: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    runtime: Option<String>,
    /// Optional. Path only. After issuance threshold_n is 2 this path is required.
    /// The host process reads the file. Secret bytes are not uploaded.
    /// A live host that already registered member two still requires this path on the birth body.
    #[serde(default)]
    member_secret_path: Option<String>,
}

/// POST /birth response. Secret bytes and issuer keys are not included.
#[derive(Debug, Serialize)]
struct BirthResponse {
    instance_id: String,
    capability_id: String,
    holder_secret_path: String,
    revoke_identifier: String,
}

/// POST /kill body. Reuse Kernel::kill_instance. No second kill path.
#[derive(Debug, Deserialize)]
struct KillRequest {
    instance_id: String,
    /// Must equal instance_id. Missing or a mismatch is refused so a wrong click does not kill.
    #[serde(default)]
    confirm: Option<String>,
    /// Optional. Path only. After issuance threshold_n is 2 this path is required.
    /// Kernel kill needs the outside member. A live host that already registered member two still requires this path on the kill body.
    #[serde(default)]
    member_secret_path: Option<String>,
}

/// POST /kill response. Secret bytes and issuer keys are not included.
#[derive(Debug, Serialize)]
struct KillResponse {
    instance_id: String,
    status: String,
}

/// POST /kill-export body. Reuse Kernel::build_kill_bundle. No second export path.
/// Confirm must equal instance_id, same as POST /kill.
#[derive(Debug, Deserialize)]
struct KillExportRequest {
    instance_id: String,
    /// Must equal instance_id. Missing or a mismatch is refused.
    #[serde(default)]
    confirm: Option<String>,
    /// Optional. Passed to kernel export when the CLI already supports capability kill.
    #[serde(default)]
    capability_id: Option<String>,
    /// Optional. Path only. After issuance threshold_n is 2 this path is required.
    /// Kill export signs a tree head. A live host that already registered member two still requires this path on the kill-export body.
    #[serde(default)]
    member_secret_path: Option<String>,
}

/// POST /kill-export response. The three public artifacts. Secret bytes are not included.
/// POST /kill-accept body uses this same shape. Reuse Kernel accept. No second accept path.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KillExportResponse {
    event: KillDocument,
    proof: IssuanceLogInclusionProof,
    tree_head: SignedTreeHead,
}

/// POST /kill-accept response. Accepted death identifiers as the kernel already stores.
/// This store writes no instance record.
#[derive(Debug, Serialize)]
struct KillAcceptResponse {
    accepted_killed_instance_ids: Vec<String>,
    accepted_killed_capability_ids: Vec<String>,
    accepted_revoke_identifiers: Vec<String>,
}

/// POST /issuer-accept body. Public key hex. Optional previous-key kill_date.
/// No secrets.
#[derive(Debug, Deserialize)]
struct IssuerAcceptRequest {
    public_key_hex: String,
    #[serde(default)]
    kill_date: Option<String>,
}

/// POST /issuer-accept response. The pinned public key hex only. Secret bytes are not included.
#[derive(Debug, Serialize)]
struct IssuerAcceptResponse {
    public_key_hex: String,
}

/// POST /act-export body. A signed check receipt. Reuse Kernel::build_act_bundle.
/// Extra check-decision fields are ignored so a check response can be posted as-is.
#[derive(Debug, Deserialize)]
struct ActExportRequest {
    receipt: DecisionReceipt,
    /// Optional. Path only. After issuance threshold_n is 2 this path is required.
    /// Act export signs a tree head. A live host that already registered member two still requires this path on the act-export body.
    #[serde(default)]
    member_secret_path: Option<String>,
}

/// POST /act-export response. The three public artifacts. Secret bytes are not included.
/// POST /act-accept body uses this same shape. Reuse Kernel accept. No second accept path.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActExportResponse {
    receipt: DecisionReceipt,
    proof: IssuanceLogInclusionProof,
    tree_head: SignedTreeHead,
}

/// POST /act-accept response. Verify-only. This store writes no instance record.
#[derive(Debug, Serialize)]
struct ActAcceptResponse {
    result: String,
}

/// POST /spawn body. Reuse Kernel::spawn_child. No second spawn path.
/// The kernel uses audience. destination is accepted as the same field.
#[derive(Debug, Deserialize)]
struct SpawnRequest {
    parent_instance_id: String,
    #[serde(default)]
    parent_capability_id: Option<String>,
    #[serde(default)]
    parent_capability: Option<String>,
    #[serde(default)]
    owner: Option<String>,
    intent: String,
    #[serde(default)]
    audience: Option<String>,
    #[serde(default)]
    destination: Option<String>,
    #[serde(default)]
    on_behalf_of: Option<String>,
    #[serde(default)]
    holder_secret_path: Option<String>,
    #[serde(default)]
    holder_proof: Option<String>,
    #[serde(default)]
    challenge_nonce: Option<String>,
    /// Optional. Path only. After issuance threshold_n is 2 this path is required.
    /// The host process reads the file. Secret bytes are not uploaded.
    /// A live host that already registered member two still requires this path on the spawn body.
    #[serde(default)]
    member_secret_path: Option<String>,
}

/// POST /spawn response. Secret bytes and issuer keys are not included.
/// The holder secret path is a path only.
#[derive(Debug, Serialize)]
struct SpawnResponse {
    instance_id: String,
    capability_id: String,
    holder_secret_path: String,
}

/// POST /rotate body. Reuse Kernel::rotate_issuer_key. No second rotate path.
/// Confirm must equal the exact word rotate. Missing or a mismatch is refused.
#[derive(Debug, Deserialize)]
struct RotateRequest {
    /// Must equal the exact word rotate. Missing or a mismatch is refused so a wrong click does not rotate.
    #[serde(default)]
    confirm: Option<String>,
    /// Seconds until the previous issuer key is past its kill date.
    /// Missing uses the laboratory default. The kernel already writes that kill date.
    #[serde(default)]
    kill_after_seconds: Option<u64>,
    /// Optional. Path only. After issuance threshold_n is 2 this path is required.
    /// The host process reads the file. Secret bytes are not uploaded.
    /// A live host that already registered member two still requires this path on the rotate body.
    #[serde(default)]
    member_secret_path: Option<String>,
}

/// POST /rotate response. New current public key and previous key plus kill date only.
/// Secret bytes and the issuer.secret path are not included.
#[derive(Debug, Serialize)]
struct RotateResponse {
    current_issuer_public_key_hex: String,
    previous_public_key_hex: String,
    previous_kill_date: String,
}

/// POST /seal body. Reuse Kernel::seal_issuer. No second seal path.
/// POST /backup body. Reuse Kernel::export_issuer_backup. No second backup path.
/// Confirm must equal the exact word backup.
#[derive(Debug, Deserialize)]
struct BackupRequest {
    path: String,
    /// Must equal the exact word backup. Missing or a mismatch is refused so a wrong click does not write a backup.
    #[serde(default)]
    confirm: Option<String>,
}

/// POST /backup response. Path only. Secret bytes are not included.
#[derive(Debug, Serialize)]
struct BackupResponse {
    path: String,
}

/// POST /restore body. Reuse Kernel::restore_from_backup. No second restore path.
/// Confirm must equal the exact word restore. Empty dest only.
#[derive(Debug, Deserialize)]
struct RestoreRequest {
    from: String,
    /// Must equal the exact word restore. Missing or a mismatch is refused so a wrong click does not restore.
    #[serde(default)]
    confirm: Option<String>,
}

/// POST /diagnose body. Reuse Kernel::restore_diagnostics. Secret bytes are not included.
#[derive(Debug, Deserialize)]
struct DiagnoseRequest {
    from: String,
}

/// Confirm must equal the exact word seal. Missing or a mismatch is refused.
#[derive(Debug, Deserialize)]
struct SealRequest {
    /// Must equal the exact word seal. Missing or a mismatch is refused so a wrong click does not seal.
    #[serde(default)]
    confirm: Option<String>,
    /// Seconds until store-wide issuer death. Must be greater than zero.
    /// A later seal may only shorten remaining life. The kernel already enforces that.
    #[serde(default)]
    after_seconds: Option<u64>,
    /// Optional. Path only. After issuance threshold_n is 2 this path is required.
    /// The host process reads the file. Secret bytes are not uploaded.
    /// A live host that already registered member two still requires this path on the seal body.
    #[serde(default)]
    member_secret_path: Option<String>,
}

/// POST /seal response. Secret bytes and issuer keys are not included.
#[derive(Debug, Serialize)]
struct SealResponse {
    status: String,
    kill_date: String,
}

/// POST /member-two body. Reuse Kernel::add_issuer_member_with_secret_path.
/// The operator types a local outside path. The host process writes the new
/// member secret only at that path. Secret bytes are not uploaded and not returned.
/// A third laboratory member is allowed. A fourth member is refused.
/// After issuer seal this write is refused.
#[derive(Debug, Deserialize)]
struct MemberTwoRequest {
    member_secret_path: String,
}

/// POST /member-two response. The new member public key hexadecimal only.
/// Secret bytes and the member-secret path are not included.
#[derive(Debug, Serialize)]
struct MemberTwoResponse {
    public_key_hex: String,
}

/// POST /set-verify-threshold body. Reuse Kernel::set_verify_threshold.
/// Confirm must equal the exact word verify-threshold.
/// Persist the member-two public key before raising verify_threshold_n.
/// After issuance threshold_n is 2 this path is required.
/// Kernel set_verify_threshold appends a signed issuance.log line when verify_threshold_n rises.
/// A live host that already registered member two still requires this path on this body.
#[derive(Debug, Deserialize)]
struct SetVerifyThresholdRequest {
    /// Must equal the exact word verify-threshold. Missing or a mismatch is refused.
    #[serde(default)]
    confirm: Option<String>,
    /// Required number of distinct accepted issuer signatures on a foreign artifact.
    #[serde(default)]
    n: Option<u32>,
    #[serde(default)]
    verify_threshold_n: Option<u32>,
    /// Optional. Path only. After issuance threshold_n is 2 this path is required.
    /// Secret bytes are not uploaded.
    #[serde(default)]
    member_secret_path: Option<String>,
}

/// POST /set-verify-threshold response. The verify threshold only. Secret bytes are not included.
#[derive(Debug, Serialize)]
struct SetVerifyThresholdResponse {
    verify_threshold_n: u32,
}

/// POST /set-issuer-threshold body. Reuse Kernel::set_issuer_threshold.
/// Confirm must equal the exact word issuer-threshold.
/// Persist member public keys before raising issuance threshold_n.
/// n=3 is allowed when three members exist. After issuer seal this write is refused.
#[derive(Debug, Deserialize)]
struct SetIssuerThresholdRequest {
    /// Must equal the exact word issuer-threshold. Missing or a mismatch is refused.
    #[serde(default)]
    confirm: Option<String>,
    /// Required number of distinct trusted Module-Lattice member signatures on a mint.
    #[serde(default)]
    n: Option<u32>,
    #[serde(default)]
    threshold_n: Option<u32>,
}

/// POST /set-issuer-threshold response. The issuance threshold only. Secret bytes are not included.
#[derive(Debug, Serialize)]
struct SetIssuerThresholdResponse {
    threshold_n: u32,
}

/// POST /seal-export body. After issuance threshold_n is 2 this path is required.
/// Seal export signs a tree head. A live host that already registered member two still requires this path.
#[derive(Debug, Deserialize)]
struct SealExportRequest {
    #[serde(default)]
    member_secret_path: Option<String>,
}

/// POST /seal-export response. The three public artifacts. Secret bytes are not included.
/// POST /seal-accept body uses this same shape. Reuse Kernel accept. No second accept path.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SealExportResponse {
    event: crate::seal_bundle::SealDocument,
    proof: IssuanceLogInclusionProof,
    tree_head: SignedTreeHead,
}

/// POST /seal-accept response. Accepted seal on the issuer record. No secrets.
#[derive(Debug, Serialize)]
struct SealAcceptResponse {
    public_key_hex: String,
    kill_date: String,
}

/// POST /previous-key-export response. Public previous-key artifacts only.
/// POST /previous-key-accept body uses this same shape. Reuse Kernel accept. No second accept path.
/// Signed proof and tree_head are not this shape. Previous-key kill is issuer-record verifier state.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PreviousKeyExportResponse {
    public_key_hex: String,
    kill_date: String,
}

/// POST /check-svid body. The historical POST /check JSON body does not change.
/// The presentation JSON field is the exact document bytes hashed into the wrap.
#[derive(Debug, Deserialize)]
struct CheckSvidRequest {
    presentation_json: String,
    certificate_pem: String,
    intent: String,
    audience: String,
    #[serde(default)]
    holder_secret_path: Option<String>,
    #[serde(default)]
    holder_proof: Option<String>,
    #[serde(default)]
    challenge_nonce: Option<String>,
    /// Act authority. Required. Empty is not autonomous. The exact word autonomous is required.
    #[serde(default)]
    on_behalf_of: Option<String>,
    /// Optional. Path only. After issuance threshold_n is 2 this path is required
    /// when this store has the instance. Kernel check then signs a receipt.
    /// A Store B check with no instance must not require issuer member material.
    #[serde(default)]
    member_secret_path: Option<String>,
}

/// POST /present-wimse response. Present JSON bytes, Workload Identity Token,
/// Content-Digest, and the HTTP Message Signature over POST /check-wimse.
/// That signature covers @method, @request-target, and content-digest.
/// Secret bytes are not included.
#[derive(Debug, Serialize)]
struct PresentWimseResponse {
    presentation_json: String,
    workload_identity_token: String,
    content_digest: String,
    signature_input: String,
    signature: String,
}

/// POST /check-wimse body. Present bytes, Workload Identity Token, and
/// Content-Digest, plus the same tool-action fields as POST /check-svid.
/// Signature-Input and Signature HTTP fields are preferred. These JSON
/// fields hold the same laboratory HTTP Message Signature when the
/// operator page or a test posts the bind in the body.
#[derive(Debug, Deserialize)]
struct CheckWimseRequest {
    presentation_json: String,
    workload_identity_token: String,
    content_digest: String,
    intent: String,
    audience: String,
    #[serde(default)]
    holder_secret_path: Option<String>,
    #[serde(default)]
    holder_proof: Option<String>,
    #[serde(default)]
    challenge_nonce: Option<String>,
    /// Act authority. Required. Empty is not autonomous. The exact word autonomous is required.
    #[serde(default)]
    on_behalf_of: Option<String>,
    #[serde(default)]
    signature_input: Option<String>,
    #[serde(default)]
    signature: Option<String>,
    /// Optional. Path only. After issuance threshold_n is 2 this path is required
    /// when this store has the instance. Kernel check then signs a receipt.
    /// A Store B check with no instance must not require issuer member material.
    #[serde(default)]
    member_secret_path: Option<String>,
}

/// POST /runtime-check body. The later user interface types a check base.
/// This issuing-store host drives LaboratoryRuntime. This host does not become
/// the agent. This host does not spawn AgentProcess. Holder secret bytes are
/// not uploaded. A typed local holder secret path is holder-key use on this
/// host. A live instance is not required for that sign. After local
/// Decommission, Check again still hits the typed check base. The path is not
/// sent to the check base.
#[derive(Debug, Deserialize)]
struct RuntimeCheckRequest {
    check_base: String,
    #[serde(default)]
    presentation_json: Option<String>,
    #[serde(default)]
    certificate_pem: Option<String>,
    #[serde(default)]
    workload_identity_token: Option<String>,
    #[serde(default)]
    content_digest: Option<String>,
    #[serde(default)]
    signature_input: Option<String>,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    holder_secret_path: Option<String>,
    #[serde(default)]
    holder_proof: Option<String>,
    /// Secret bytes. Always refused. Type a local path instead.
    #[serde(default)]
    holder_secret: Option<String>,
}

/// POST /well-known-follow body. GET / asks this issuing host for the parsed
/// well-known document of a typed verifier base. The browser does not fetch
/// the public name. Off-name and HTTP public stay refused.
#[derive(Debug, Deserialize)]
struct WellKnownFollowRequest {
    check_base: String,
    /// Secret bytes. Always refused.
    #[serde(default)]
    holder_secret: Option<String>,
}

/// POST /operator-pin body. GET / pins a foreign verifier using only a path
/// listed in that base's well-known document. The issuing-store host posts
/// the pin. This host does not spawn AgentProcess.
#[derive(Debug, Deserialize)]
struct OperatorPinRequest {
    check_base: String,
    pin: String,
    #[serde(default)]
    body: serde_json::Value,
    /// Secret bytes. Always refused.
    #[serde(default)]
    holder_secret: Option<String>,
}

fn require_loopback(listen_address: &str) -> Result<SocketAddr> {
    let address: SocketAddr = listen_address.parse().map_err(|error| {
        Error::kernel(format!(
            "The listen_address value is not a valid socket address: {error}"
        ))
    })?;
    if !address.ip().is_loopback() {
        return Err(Error::kernel(
            "The check host must bind to a loopback address. Binding to all interfaces is not permitted.",
        ));
    }
    Ok(address)
}

fn holder_proof_from_fields(
    holder_secret_path: Option<&str>,
    holder_proof: Option<&str>,
) -> Option<HolderProof> {
    if let Some(path) = holder_secret_path {
        if !path.is_empty() {
            return Some(HolderProof::SecretPath(std::path::PathBuf::from(path)));
        }
    }
    if let Some(signature) = holder_proof {
        if !signature.is_empty() {
            return Some(HolderProof::SignatureHexadecimal(signature.to_string()));
        }
    }
    None
}

fn holder_proof_from_request(request: &CheckRequest) -> Option<HolderProof> {
    holder_proof_from_fields(
        request.holder_secret_path.as_deref(),
        request.holder_proof.as_deref(),
    )
}

fn holder_proof_from_svid_request(request: &CheckSvidRequest) -> Option<HolderProof> {
    holder_proof_from_fields(
        request.holder_secret_path.as_deref(),
        request.holder_proof.as_deref(),
    )
}

fn holder_proof_from_wimse_request(request: &CheckWimseRequest) -> Option<HolderProof> {
    holder_proof_from_fields(
        request.holder_secret_path.as_deref(),
        request.holder_proof.as_deref(),
    )
}

fn read_http_request(stream: &mut TcpStream) -> Result<(String, Vec<u8>)> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| Error::kernel(error.to_string()))?;
    let mut buffer = Vec::new();
    let mut block = [0u8; 1024];
    loop {
        let count = stream
            .read(&mut block)
            .map_err(|error| Error::kernel(error.to_string()))?;
        if count == 0 {
            break;
        }
        buffer.extend_from_slice(&block[..count]);
        if let Some(split) = find_header_end(&buffer) {
            let header_text = String::from_utf8_lossy(&buffer[..split]).to_string();
            let content_length = content_length_from_headers(&header_text);
            let body_start = split + 4;
            while buffer.len() < body_start + content_length {
                let count = stream
                    .read(&mut block)
                    .map_err(|error| Error::kernel(error.to_string()))?;
                if count == 0 {
                    break;
                }
                buffer.extend_from_slice(&block[..count]);
            }
            let body = if buffer.len() >= body_start {
                buffer[body_start..].to_vec()
            } else {
                Vec::new()
            };
            return Ok((header_text, body));
        }
        if buffer.len() > 1024 * 1024 {
            return Err(Error::kernel(
                "The HTTP request is larger than one megabyte.",
            ));
        }
    }
    Err(Error::kernel("The HTTP request ended before the headers."))
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length_from_headers(headers: &str) -> usize {
    header_value(headers, "content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

fn header_value(headers: &str, name: &str) -> Option<String> {
    for line in headers.lines() {
        let line = line.trim();
        if let Some((header_name, value)) = line.split_once(':') {
            if header_name.eq_ignore_ascii_case(name) {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

fn write_json_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &str,
) -> Result<()> {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|error| Error::kernel(error.to_string()))?;
    Ok(())
}

fn write_html_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &str,
) -> Result<()> {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|error| Error::kernel(error.to_string()))?;
    Ok(())
}

/// Truncate the issuer public key the same way StoreStatus::format_human does.
fn truncated_issuer_public_key_hex(hexadecimal: &str) -> String {
    let trimmed = hexadecimal.trim();
    if trimmed.len() <= 16 {
        return trimmed.to_string();
    }
    format!("{}...{}", &trimmed[..8], &trimmed[trimmed.len() - 8..])
}

fn write_refused_response(stream: &mut TcpStream, error: Error) -> Result<()> {
    write_json_response(
        stream,
        403,
        "Forbidden",
        &serde_json::json!({
            "result": "refused",
            "reason": error.to_string()
        })
        .to_string(),
    )
}

fn write_bad_request_response(stream: &mut TcpStream, error: impl std::fmt::Display) -> Result<()> {
    write_json_response(
        stream,
        400,
        "Bad Request",
        &serde_json::json!({
            "result": "refused",
            "reason": format!("The request body is not valid JSON: {error}")
        })
        .to_string(),
    )
}

/// JSON list of instance identifiers, live or revoked status, capability identifiers,
/// and parent_instance_id when the instance is a spawn child.
/// Holder public keys, secrets, and capability tokens are not included.
fn instances_json(kernel: &Kernel) -> Result<String> {
    let _issuer = kernel.store().load_issuer()?;
    let mut capability_ids_by_instance: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for capability in kernel.store().list_capabilities()? {
        capability_ids_by_instance
            .entry(capability.instance_id)
            .or_default()
            .push(capability.id);
    }
    for identifiers in capability_ids_by_instance.values_mut() {
        identifiers.sort();
    }
    let mut listings: Vec<InstanceListing> = kernel
        .store()
        .list_instances()?
        .into_iter()
        .map(|instance| {
            let capability_ids = capability_ids_by_instance
                .remove(&instance.id)
                .unwrap_or_default();
            let agent_type_id = if instance.agent_type_id.is_empty() {
                None
            } else {
                Some(instance.agent_type_id)
            };
            let parent_instance_id = instance.parent_instance_id.filter(|id| !id.is_empty());
            InstanceListing {
                instance_id: instance.id,
                parent_instance_id,
                status: instance.status.as_label().to_string(),
                capability_ids,
                agent_type_id,
            }
        })
        .collect();
    listings.sort_by(|left, right| left.instance_id.cmp(&right.instance_id));
    serde_json::to_string(&InstancesResponse {
        instances: listings,
    })
    .map_err(Error::from)
}

/// JSON list of agent type identifiers and allowed intents only.
/// Issuer public keys, signatures, and secrets are not included.
fn agent_types_json(kernel: &Kernel) -> Result<String> {
    let _issuer = kernel.store().load_issuer()?;
    let mut listings: Vec<AgentTypeListing> = kernel
        .store()
        .list_agent_types()?
        .into_iter()
        .map(|agent_type| AgentTypeListing {
            agent_type_id: agent_type.id,
            allowed_intents: agent_type.allowed_intents,
        })
        .collect();
    listings.sort_by(|left, right| left.agent_type_id.cmp(&right.agent_type_id));
    serde_json::to_string(&AgentTypesResponse {
        agent_types: listings,
    })
    .map_err(Error::from)
}

fn trimmed_optional(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(|text| text.to_string())
}

/// After issuance threshold_n is 2, the live host body must carry
/// member_secret_path even when this process already registered member two.
fn register_member_secret_path_after_issuance_threshold_two(
    kernel: &Kernel,
    member_secret_path: Option<&str>,
    path_name: &str,
) -> Result<()> {
    let issuer = kernel.store().load_issuer()?;
    if issuer.threshold_n.max(1) < 2 {
        if let Some(path) = trimmed_optional(member_secret_path) {
            kernel
                .store()
                .register_extra_member_secret_path(std::path::PathBuf::from(path))?;
        }
        return Ok(());
    }
    let Some(path) = trimmed_optional(member_secret_path) else {
        return Err(Error::denied(format!(
            "After issuance threshold_n is 2, the {path_name} path requires member_secret_path. The host reads a local outside path. A live host that already registered member two still requires that path on this {path_name} body. Secret bytes are not uploaded. The check fails closed.",
        )));
    };
    kernel
        .store()
        .register_extra_member_secret_path(std::path::PathBuf::from(path))
}

/// Require the outside member only when this store has the instance.
/// Store B verify has no instance and must stay free of issuer member material.
fn register_member_secret_path_when_local_instance_signs(
    kernel: &Kernel,
    instance_id: &str,
    member_secret_path: Option<&str>,
    path_name: &str,
) -> Result<()> {
    if kernel.store().load_instance(instance_id).is_err() {
        return Ok(());
    }
    register_member_secret_path_after_issuance_threshold_two(kernel, member_secret_path, path_name)
}

fn audience_from_birth_request(request: &BirthRequest) -> Result<String> {
    if let Some(audience) = trimmed_optional(request.audience.as_deref()) {
        return Ok(audience);
    }
    if let Some(destination) = trimmed_optional(request.destination.as_deref()) {
        return Ok(destination);
    }
    Err(Error::denied(
        "The birth path requires audience. The kernel uses audience. The check fails closed.",
    ))
}

fn owner_from_birth_request(
    kernel: &Kernel,
    agent_type_id: &str,
    request: &BirthRequest,
) -> Result<String> {
    if let Some(owner) = trimmed_optional(request.owner.as_deref()) {
        return Ok(owner);
    }
    let agent_type = kernel.store().load_agent_type(agent_type_id)?;
    if agent_type.owner.trim().is_empty() {
        return Err(Error::denied(
            "The birth path requires owner. The check fails closed.",
        ));
    }
    Ok(agent_type.owner)
}

fn insert_optional_attribute(
    attributes: &mut BTreeMap<String, String>,
    name: &str,
    value: Option<&str>,
) {
    if let Some(text) = trimmed_optional(value) {
        attributes.insert(name.to_string(), text);
    }
}

fn on_behalf_of_from_birth_request(request: &BirthRequest) -> Option<String> {
    trimmed_optional(request.on_behalf_of.as_deref())
}

/// Reuse Kernel::birth_write. Do not invent a second birth path.
fn apply_birth_request(kernel: &Kernel, request: &BirthRequest) -> Result<String> {
    let agent_type_id = request.agent_type_id.trim();
    if agent_type_id.is_empty() {
        return Err(Error::denied(
            "The birth path requires agent_type_id. The check fails closed.",
        ));
    }
    let intent = request.intent.trim();
    if intent.is_empty() {
        return Err(Error::denied(
            "The birth path requires intent. The check fails closed.",
        ));
    }
    let audience = audience_from_birth_request(request)?;
    let owner = owner_from_birth_request(kernel, agent_type_id, request)?;
    let mut attributes = BTreeMap::new();
    insert_optional_attribute(&mut attributes, "site", request.site.as_deref());
    insert_optional_attribute(&mut attributes, "region", request.region.as_deref());
    insert_optional_attribute(&mut attributes, "runtime", request.runtime.as_deref());
    register_member_secret_path_after_issuance_threshold_two(
        kernel,
        request.member_secret_path.as_deref(),
        "birth",
    )?;
    let birth = kernel.birth_write(
        agent_type_id,
        owner,
        attributes,
        intent,
        &audience,
        on_behalf_of_from_birth_request(request),
    )?;
    serde_json::to_string(&BirthResponse {
        instance_id: birth.instance.id,
        capability_id: birth.capability.id,
        holder_secret_path: birth.holder_secret_path,
        revoke_identifier: birth.capability.revoke_identifier,
    })
    .map_err(Error::from)
}

/// Reuse Kernel::kill_instance. Do not invent a second kill path.
fn apply_kill_request(kernel: &Kernel, request: &KillRequest) -> Result<String> {
    let instance_id = request.instance_id.trim();
    if instance_id.is_empty() {
        return Err(Error::denied(
            "The kill path requires instance_id. The check fails closed.",
        ));
    }
    let confirm = trimmed_optional(request.confirm.as_deref());
    if confirm.as_deref() != Some(instance_id) {
        return Err(Error::denied(
            "The confirm field must equal the instance identifier. A missing confirm or a confirm mismatch is refused so a wrong click does not kill. The check fails closed.",
        ));
    }
    let instance = kernel.store().load_instance(instance_id)?;
    if instance.status != InstanceStatus::Live {
        return Err(Error::denied(
            "The instance was already revoked. A second local kill is refused. The check fails closed.",
        ));
    }
    register_member_secret_path_after_issuance_threshold_two(
        kernel,
        request.member_secret_path.as_deref(),
        "kill",
    )?;
    let killed = kernel.kill_instance(&instance.id)?;
    serde_json::to_string(&KillResponse {
        instance_id: killed.id,
        status: killed.status.as_label().to_string(),
    })
    .map_err(Error::from)
}

/// Reuse Kernel::add_issuer_member_with_secret_path. Do not invent a second member-add path.
/// The host writes the new member secret only at the typed outside path.
/// Secret bytes are not returned. A third laboratory member is allowed.
/// A fourth member is refused. After issuer seal this write is refused.
fn apply_member_two_request(kernel: &Kernel, request: &MemberTwoRequest) -> Result<String> {
    let path = request.member_secret_path.trim();
    if path.is_empty() {
        return Err(Error::denied(
            "The member-two path requires member_secret_path. The host reads a local outside path. Secret bytes are not uploaded. The check fails closed.",
        ));
    }
    let issuer = kernel.store().load_issuer()?;
    if issuer.kill_date.is_some() {
        return Err(Error::denied(
            "The issuer is already sealed. After issuer seal this member-two write is refused. The check fails closed.",
        ));
    }
    if issuer.signing_member_count() >= 3 {
        return Err(Error::denied(
            "This host path registers up to three laboratory members. A fourth member is refused. The check fails closed.",
        ));
    }
    let before_keys = issuer.trusted_signing_member_public_keys();
    let issuer = kernel.add_issuer_member_with_secret_path(Some(std::path::Path::new(path)))?;
    let current = issuer.current_public_key_hex();
    let new_member = issuer
        .trusted_signing_member_public_keys()
        .into_iter()
        .find(|key| key != &current && !before_keys.iter().any(|existing| existing == key))
        .ok_or_else(|| {
            Error::kernel(
                "The member path did not persist a new member public key. The check fails closed.".to_string(),
            )
        })?;
    serde_json::to_string(&MemberTwoResponse {
        public_key_hex: new_member,
    })
    .map_err(Error::from)
}

/// Reuse Kernel::set_verify_threshold. Do not invent a second verify-threshold path.
/// Confirm must equal the exact word verify-threshold.
/// Persist the member-two public key before raising verify_threshold_n.
/// After issuance threshold_n is 2 this body requires member_secret_path.
/// A live host that already registered member two still requires that path.
/// After issuer seal this write is refused.
fn apply_set_verify_threshold_request(
    kernel: &Kernel,
    request: &SetVerifyThresholdRequest,
) -> Result<String> {
    let confirm = trimmed_optional(request.confirm.as_deref());
    if confirm.as_deref() != Some("verify-threshold") {
        return Err(Error::denied(
            "The confirm field must equal the exact word verify-threshold. A missing confirm or a confirm mismatch is refused so a wrong click does not raise verify_threshold_n. The check fails closed.",
        ));
    }
    let n = match request.n.or(request.verify_threshold_n) {
        Some(value) => value,
        None => {
            return Err(Error::denied(
                "The set-verify-threshold path requires n. The check fails closed.",
            ))
        }
    };
    if n > 2 {
        return Err(Error::denied(
            "This host path sets verify_threshold_n to 2 after member two exists. A verify threshold of 3 is not this path. The check fails closed.",
        ));
    }
    let issuer = kernel.store().load_issuer()?;
    if issuer.kill_date.is_some() {
        return Err(Error::denied(
            "The issuer is already sealed. After issuer seal this verify-threshold write is refused. The check fails closed.",
        ));
    }
    if n >= 2 && issuer.signing_member_count() < 2 {
        return Err(Error::denied(
            "The member two public key must be persisted before verify_threshold_n can be raised. Add member two first. The check fails closed.",
        ));
    }
    register_member_secret_path_after_issuance_threshold_two(
        kernel,
        request.member_secret_path.as_deref(),
        "set-verify-threshold",
    )?;
    let issuer = kernel.set_verify_threshold(n)?;
    serde_json::to_string(&SetVerifyThresholdResponse {
        verify_threshold_n: issuer.verify_threshold_n,
    })
    .map_err(Error::from)
}

/// Reuse Kernel::set_issuer_threshold. Do not invent a second issuer-threshold path.
/// Confirm must equal the exact word issuer-threshold.
/// Persist member public keys before raising issuance threshold_n.
/// n=3 is allowed when three members exist. After issuer seal this write is refused.
fn apply_set_issuer_threshold_request(
    kernel: &Kernel,
    request: &SetIssuerThresholdRequest,
) -> Result<String> {
    let confirm = trimmed_optional(request.confirm.as_deref());
    if confirm.as_deref() != Some("issuer-threshold") {
        return Err(Error::denied(
            "The confirm field must equal the exact word issuer-threshold. A missing confirm or a confirm mismatch is refused so a wrong click does not raise threshold_n. The check fails closed.",
        ));
    }
    let n = match request.n.or(request.threshold_n) {
        Some(value) => value,
        None => {
            return Err(Error::denied(
                "The set-issuer-threshold path requires n. The check fails closed.",
            ))
        }
    };
    if n > 3 {
        return Err(Error::denied(
            "This host path sets threshold_n to 2 or 3 after the matching members exist. An issuance threshold above 3 is not this path. The check fails closed.",
        ));
    }
    let issuer = kernel.store().load_issuer()?;
    if issuer.kill_date.is_some() {
        return Err(Error::denied(
            "The issuer is already sealed. After issuer seal this issuer-threshold write is refused. The check fails closed.",
        ));
    }
    if n >= 3 && issuer.signing_member_count() < 3 {
        return Err(Error::denied(
            "The third member public key must be persisted before threshold_n can be raised to 3. Add a third member first. The check fails closed.",
        ));
    }
    if n >= 2 && issuer.signing_member_count() < 2 {
        return Err(Error::denied(
            "The member two public key must be persisted before threshold_n can be raised. Add member two first. The check fails closed.",
        ));
    }
    let issuer = kernel.set_issuer_threshold(n)?;
    serde_json::to_string(&SetIssuerThresholdResponse {
        threshold_n: issuer.threshold_n,
    })
    .map_err(Error::from)
}

/// Reuse Kernel::rotate_issuer_key. Do not invent a second rotate path.
/// Confirm must equal the exact word rotate. Member-two rules stay on the kernel.
/// After issuer seal this rotate is refused. Rotate writes a new issuer key.
/// Secret bytes and the issuer.secret path are not returned.
fn apply_rotate_request(kernel: &Kernel, request: &RotateRequest) -> Result<String> {
    let confirm = trimmed_optional(request.confirm.as_deref());
    if confirm.as_deref() != Some("rotate") {
        return Err(Error::denied(
            "The confirm field must equal the exact word rotate. A missing confirm or a confirm mismatch is refused so a wrong click does not rotate. The check fails closed.",
        ));
    }
    register_member_secret_path_after_issuance_threshold_two(
        kernel,
        request.member_secret_path.as_deref(),
        "rotate",
    )?;
    let kill_after_seconds = request
        .kill_after_seconds
        .unwrap_or(LABORATORY_ISSUER_ROTATE_KILL_AFTER_SECONDS);
    let issuer = kernel.rotate_issuer_key(kill_after_seconds)?;
    let previous = issuer.previous_issuer_keys.last().ok_or_else(|| {
        Error::kernel(
            "The issuer rotate did not keep the previous key with a kill date. Rotate cannot drop a previous public key. The check fails closed.".to_string(),
        )
    })?;
    serde_json::to_string(&RotateResponse {
        current_issuer_public_key_hex: issuer.current_public_key_hex(),
        previous_public_key_hex: previous.public_key_hex.clone(),
        previous_kill_date: previous.kill_date.to_rfc3339(),
    })
    .map_err(Error::from)
}

/// Reuse Kernel::export_issuer_backup. Do not invent a second backup path.
/// Confirm must equal the exact word backup.
fn apply_backup_request(kernel: &Kernel, request: &BackupRequest) -> Result<String> {
    let confirm = trimmed_optional(request.confirm.as_deref());
    if confirm.as_deref() != Some("backup") {
        return Err(Error::denied(
            "The confirm field must equal the exact word backup. A missing confirm or a confirm mismatch is refused so a wrong click does not write a backup. The check fails closed.",
        ));
    }
    let path = request.path.trim();
    if path.is_empty() {
        return Err(Error::denied(
            "The backup path is required. The path must live outside the data directory. The check fails closed.",
        ));
    }
    let dest = Path::new(path);
    kernel.export_issuer_backup(dest)?;
    serde_json::to_string(&BackupResponse {
        path: dest.display().to_string(),
    })
    .map_err(Error::from)
}

/// Reuse Kernel::restore_from_backup. Do not invent a second restore path.
/// Confirm must equal the exact word restore. Empty dest only.
/// Restore onto a dest that already has an issuer is refused.
fn apply_restore_request(kernel: &Kernel, request: &RestoreRequest) -> Result<String> {
    let confirm = trimmed_optional(request.confirm.as_deref());
    if confirm.as_deref() != Some("restore") {
        return Err(Error::denied(
            "The confirm field must equal the exact word restore. A missing confirm or a confirm mismatch is refused so a wrong click does not restore. The check fails closed.",
        ));
    }
    let from = request.from.trim();
    if from.is_empty() {
        return Err(Error::denied(
            "The restore from path is required. The check fails closed.",
        ));
    }
    Kernel::restore_from_backup(Path::new(from), kernel.store().root())?;
    let diagnostics = kernel.restore_diagnostics(Path::new(from))?;
    serde_json::to_string(&diagnostics).map_err(Error::from)
}

/// Reuse Kernel::restore_diagnostics. Secret bytes are not returned.
fn apply_diagnose_request(kernel: &Kernel, request: &DiagnoseRequest) -> Result<String> {
    let from = request.from.trim();
    if from.is_empty() {
        return Err(Error::denied(
            "The diagnose from path is required. The check fails closed.",
        ));
    }
    let diagnostics = kernel.restore_diagnostics(Path::new(from))?;
    serde_json::to_string(&diagnostics).map_err(Error::from)
}

/// Reuse Kernel::seal_issuer. Do not invent a second seal path.
/// Confirm must equal the exact word seal. Member-two rules stay on the kernel.
fn apply_seal_request(kernel: &Kernel, request: &SealRequest) -> Result<String> {
    let confirm = trimmed_optional(request.confirm.as_deref());
    if confirm.as_deref() != Some("seal") {
        return Err(Error::denied(
            "The confirm field must equal the exact word seal. A missing confirm or a confirm mismatch is refused so a wrong click does not seal. The check fails closed.",
        ));
    }
    let after_seconds = match request.after_seconds {
        Some(value) if value > 0 => value,
        _ => {
            return Err(Error::denied(
                "The seal path requires after_seconds greater than zero. An issuer seal cannot be empty or zero. The check fails closed.",
            ))
        }
    };
    register_member_secret_path_after_issuance_threshold_two(
        kernel,
        request.member_secret_path.as_deref(),
        "seal",
    )?;
    let issuer = kernel.seal_issuer(after_seconds)?;
    let kill_date = issuer.kill_date.ok_or_else(|| {
        Error::kernel(
            "The issuer seal did not write kill_date. The check fails closed.".to_string(),
        )
    })?;
    serde_json::to_string(&SealResponse {
        status: "sealed".to_string(),
        kill_date: kill_date.to_rfc3339(),
    })
    .map_err(Error::from)
}

/// Reuse Kernel::build_seal_bundle. Do not invent a second export path.
/// Export after local seal. Refuse a live (unsealed) issuer.
fn apply_seal_export_request(kernel: &Kernel, request: &SealExportRequest) -> Result<String> {
    register_member_secret_path_after_issuance_threshold_two(
        kernel,
        request.member_secret_path.as_deref(),
        "seal-export",
    )?;
    let bundle = kernel.build_seal_bundle()?;
    serde_json::to_string(&SealExportResponse {
        event: bundle.document,
        proof: bundle.proof,
        tree_head: bundle.tree_head,
    })
    .map_err(Error::from)
}

/// Reuse Kernel::accept_seal_bundle_artifacts. Do not invent a second accept path.
/// Body is the three public artifacts in the same shape POST /seal-export returns.
fn apply_seal_accept_request(kernel: &Kernel, request: &SealExportResponse) -> Result<String> {
    let bundle = crate::seal_bundle::SealBundle {
        document: request.event.clone(),
        proof: request.proof.clone(),
        tree_head: request.tree_head.clone(),
    };
    let issuer = kernel.accept_seal_bundle_artifacts(&bundle)?;
    let sealed = issuer
        .accepted_sealed_issuer_keys
        .iter()
        .find(|previous| {
            previous.public_key_hex.trim() == request.event.issuer_public_key_hex.trim()
        })
        .ok_or_else(|| {
            Error::kernel(
                "The seal accept did not pin the issuer public key. The check fails closed."
                    .to_string(),
            )
        })?;
    serde_json::to_string(&SealAcceptResponse {
        public_key_hex: sealed.public_key_hex.clone(),
        kill_date: sealed.kill_date.to_rfc3339(),
    })
    .map_err(Error::from)
}

/// Export the previous issuer public key hexadecimal and its kill date.
/// Refuse when this store has no previous key with a kill date.
/// Public artifacts only. Secret bytes are not included.
fn apply_previous_key_export_request(kernel: &Kernel) -> Result<String> {
    let issuer = kernel.store().load_issuer()?;
    let previous = issuer.previous_issuer_keys.last().ok_or_else(|| {
        Error::denied(
            "The previous issuer key has no kill date. Export the previous key after rotate writes a kill date. The check fails closed.",
        )
    })?;
    serde_json::to_string(&PreviousKeyExportResponse {
        public_key_hex: previous.public_key_hex.clone(),
        kill_date: previous.kill_date.to_rfc3339(),
    })
    .map_err(Error::from)
}

/// Reuse Kernel::accept_previous_issuer_key. Do not invent a second accept path.
/// Body is public_key_hex and kill_date in the same shape POST /previous-key-export returns.
/// This store writes no instance. This store does not copy issuer.secret.
/// Truncated hex, the envelope key, postpone, remove, and clearing are refused.
fn apply_previous_key_accept_request(
    kernel: &Kernel,
    request: &PreviousKeyExportResponse,
) -> Result<String> {
    let public_key_hex = request.public_key_hex.trim();
    if public_key_hex.is_empty() {
        return Err(Error::denied(
            "The previous-key-accept path requires public_key_hex. Clearing an accepted previous key is refused. The check fails closed.",
        ));
    }
    if public_key_hex.contains("...") || public_key_hex.len() <= 64 {
        return Err(Error::denied(
            "The previous-key-accept path refuses a truncated issuer public key hexadecimal. Paste the full key. The envelope key is not an issuer identity root. The check fails closed.",
        ));
    }
    let issuer = kernel.store().load_issuer()?;
    if issuer.is_biscuit_envelope_key(public_key_hex) {
        return Err(Error::denied(
            "The previous-key-accept path refuses the Biscuit envelope key. The envelope key is not an issuer identity root. The check fails closed.",
        ));
    }
    let kill_date_text = request.kill_date.trim();
    if kill_date_text.is_empty() {
        return Err(Error::denied(
            "The previous-key-accept path requires kill_date. Clearing an accepted previous key is refused. The check fails closed.",
        ));
    }
    let kill_date = DateTime::parse_from_rfc3339(kill_date_text)
        .map_err(|_| {
            Error::denied("The kill_date value must be RFC3339 UTC. The check fails closed.")
        })?
        .with_timezone(&Utc);
    kernel.accept_previous_issuer_key(public_key_hex, kill_date)?;
    serde_json::to_string(&PreviousKeyExportResponse {
        public_key_hex: public_key_hex.to_string(),
        kill_date: kill_date.to_rfc3339(),
    })
    .map_err(Error::from)
}

/// Reuse Kernel::build_kill_bundle. Do not invent a second export path.
/// Export after local kill. Refuse while the instance is still live.
fn apply_kill_export_request(kernel: &Kernel, request: &KillExportRequest) -> Result<String> {
    let instance_id = request.instance_id.trim();
    if instance_id.is_empty() {
        return Err(Error::denied(
            "The kill-export path requires instance_id. The check fails closed.",
        ));
    }
    let confirm = trimmed_optional(request.confirm.as_deref());
    if confirm.as_deref() != Some(instance_id) {
        return Err(Error::denied(
            "The confirm field must equal the instance identifier. A missing confirm or a confirm mismatch is refused. The check fails closed.",
        ));
    }
    let instance = kernel.store().load_instance(instance_id)?;
    if instance.status == InstanceStatus::Live {
        return Err(Error::denied(
            "The instance is still live. Export the kill bundle after local kill. The check fails closed.",
        ));
    }
    register_member_secret_path_after_issuance_threshold_two(
        kernel,
        request.member_secret_path.as_deref(),
        "kill-export",
    )?;
    let capability_id = trimmed_optional(request.capability_id.as_deref());
    let bundle = kernel.build_kill_bundle(Some(&instance.id), capability_id.as_deref())?;
    serde_json::to_string(&KillExportResponse {
        event: bundle.document,
        proof: bundle.proof,
        tree_head: bundle.tree_head,
    })
    .map_err(Error::from)
}

/// Reuse Kernel::accept_issuer_public_key. Public key hex only. Do not copy secrets.
fn apply_issuer_accept_request(kernel: &Kernel, request: &IssuerAcceptRequest) -> Result<String> {
    let public_key_hex = request.public_key_hex.trim();
    if public_key_hex.is_empty() {
        return Err(Error::denied(
            "The issuer-accept path requires public_key_hex. An empty issuer public key cannot be accepted. The check fails closed.",
        ));
    }
    if let Some(kill_date_text) = request
        .kill_date
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let kill_date = DateTime::parse_from_rfc3339(kill_date_text)
            .map_err(|_| {
                Error::denied("The kill_date value must be RFC3339 UTC. The check fails closed.")
            })?
            .with_timezone(&Utc);
        kernel.accept_previous_issuer_key(public_key_hex, kill_date)?;
    } else {
        kernel.accept_issuer_public_key(public_key_hex)?;
    }
    serde_json::to_string(&IssuerAcceptResponse {
        public_key_hex: public_key_hex.to_string(),
    })
    .map_err(Error::from)
}

/// Reuse Kernel::accept_kill_bundle_artifacts. Do not invent a second accept path.
/// Body is the three public artifacts in the same shape POST /kill-export returns.
fn apply_kill_accept_request(kernel: &Kernel, request: &KillExportResponse) -> Result<String> {
    let bundle = crate::kill_bundle::KillBundle {
        document: request.event.clone(),
        proof: request.proof.clone(),
        tree_head: request.tree_head.clone(),
    };
    let issuer = kernel.accept_kill_bundle_artifacts(&bundle)?;
    serde_json::to_string(&KillAcceptResponse {
        accepted_killed_instance_ids: issuer.accepted_killed_instance_ids,
        accepted_killed_capability_ids: issuer.accepted_killed_capability_ids,
        accepted_revoke_identifiers: issuer.accepted_revoke_identifiers,
    })
    .map_err(Error::from)
}

/// Reuse Kernel::build_act_bundle. Do not invent a second export path.
/// Body is a signed check receipt. The same field lives on a successful check response.
fn apply_act_export_request(kernel: &Kernel, request: &ActExportRequest) -> Result<String> {
    register_member_secret_path_after_issuance_threshold_two(
        kernel,
        request.member_secret_path.as_deref(),
        "act-export",
    )?;
    let bundle = kernel.build_act_bundle(&request.receipt)?;
    serde_json::to_string(&ActExportResponse {
        receipt: bundle.receipt,
        proof: bundle.proof,
        tree_head: bundle.tree_head,
    })
    .map_err(Error::from)
}

/// Reuse Kernel::accept_act_bundle_artifacts. Do not invent a second accept path.
/// Body is the three public artifacts in the same shape POST /act-export returns.
fn apply_act_accept_request(kernel: &Kernel, request: &ActExportResponse) -> Result<String> {
    let bundle = crate::act_bundle::ActBundle {
        receipt: request.receipt.clone(),
        proof: request.proof.clone(),
        tree_head: request.tree_head.clone(),
    };
    kernel.accept_act_bundle_artifacts(&bundle)?;
    serde_json::to_string(&ActAcceptResponse {
        result: "accepted".to_string(),
    })
    .map_err(Error::from)
}

fn audience_from_spawn_request(request: &SpawnRequest) -> Result<String> {
    if let Some(audience) = trimmed_optional(request.audience.as_deref()) {
        return Ok(audience);
    }
    if let Some(destination) = trimmed_optional(request.destination.as_deref()) {
        return Ok(destination);
    }
    Err(Error::denied(
        "The spawn path requires audience. The kernel uses audience. The check fails closed.",
    ))
}

fn parent_capability_from_spawn_request(request: &SpawnRequest) -> Result<String> {
    for value in [
        request.parent_capability_id.as_deref(),
        request.parent_capability.as_deref(),
    ] {
        if let Some(identifier) = trimmed_optional(value) {
            return Ok(identifier);
        }
    }
    Err(Error::denied(
        "The spawn path requires a parent capability identifier. The kernel does not guess which capability. The check fails closed.",
    ))
}

/// Reuse Kernel::spawn_child. Do not invent a second spawn path.
/// Spawn sits on an act. A holder proof and a challenge nonce are required.
fn apply_spawn_request(kernel: &Kernel, request: &SpawnRequest) -> Result<String> {
    let parent_instance_id = request.parent_instance_id.trim();
    if parent_instance_id.is_empty() {
        return Err(Error::denied(
            "The spawn path requires parent_instance_id. The check fails closed.",
        ));
    }
    let parent_capability_id = parent_capability_from_spawn_request(request)?;
    let intent = request.intent.trim();
    if intent.is_empty() {
        return Err(Error::denied(
            "The spawn path requires intent. The check fails closed.",
        ));
    }
    let audience = audience_from_spawn_request(request)?;
    let owner =
        trimmed_optional(request.owner.as_deref()).unwrap_or_else(|| "laboratory".to_string());
    let proof = holder_proof_from_fields(
        request.holder_secret_path.as_deref(),
        request.holder_proof.as_deref(),
    );
    if proof.is_none() {
        return Err(Error::denied(
            "A holder proof is required. Pass a holder secret path or a holder signature. Spawn sits on an act. The check fails closed.",
        ));
    }
    let nonce = request
        .challenge_nonce
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if nonce.is_none() {
        return Err(Error::denied(
            "A challenge nonce is required. Spawn sits on an act. The check fails closed.",
        ));
    }
    register_member_secret_path_after_issuance_threshold_two(
        kernel,
        request.member_secret_path.as_deref(),
        "spawn",
    )?;
    let spawn = kernel.spawn_child(
        parent_instance_id,
        &parent_capability_id,
        owner,
        BTreeMap::new(),
        intent,
        &audience,
        trimmed_optional(request.on_behalf_of.as_deref()),
        proof.as_ref(),
        nonce,
    )?;
    serde_json::to_string(&SpawnResponse {
        instance_id: spawn.instance.id,
        capability_id: spawn.capability.id,
        holder_secret_path: spawn.holder_secret_path,
    })
    .map_err(Error::from)
}

fn allowed_intents_from_agent_type_request(request: &AgentTypeAddRequest) -> Result<Vec<String>> {
    let intents: Vec<String> = request
        .allowed_intents
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
        .collect();
    if intents.is_empty() {
        return Err(Error::denied(
            "The agent type path requires at least one allowed intent. An empty intent list is refused. The check fails closed.",
        ));
    }
    Ok(intents)
}

fn authorization_limit_from_agent_type_request(request: &AgentTypeAddRequest) -> Result<String> {
    if let Some(limit) = trimmed_optional(request.authorization_limit.as_deref()) {
        return Ok(limit);
    }
    if let Some(destination) = trimmed_optional(request.destination.as_deref()) {
        return Ok(destination);
    }
    Err(Error::denied(
        "The agent type path requires authorization_limit. Authorization limit is the highest destination. The check fails closed.",
    ))
}

/// Reuse Kernel::add_agent_type. Do not invent a second write path.
/// A later add of intents after the first write reuses Kernel::add_allowed_intent and is refused.
fn apply_agent_type_request(kernel: &Kernel, request: &AgentTypeAddRequest) -> Result<String> {
    let allowed_intents = allowed_intents_from_agent_type_request(request)?;
    if let Some(agent_type_id) = trimmed_optional(request.agent_type_id.as_deref()) {
        let stored = kernel.store().load_agent_type(&agent_type_id)?;
        for intent in &allowed_intents {
            if !stored.allowed_intents.iter().any(|value| value == intent) {
                kernel.add_allowed_intent(&agent_type_id, intent)?;
            }
        }
        return Err(Error::denied(
            "The allowed intents are frozen after the first write. A later write that adds an intent is refused. Adding an intent is a golden-ticket-class raise. The type must not become more powerful than at birth. This is not a sixth identity record.",
        ));
    }
    let authorization_limit = authorization_limit_from_agent_type_request(request)?;
    let owner =
        trimmed_optional(request.owner.as_deref()).unwrap_or_else(|| "laboratory".to_string());
    register_member_secret_path_after_issuance_threshold_two(
        kernel,
        request.member_secret_path.as_deref(),
        "agent-type",
    )?;
    let agent_type = kernel.add_agent_type(
        owner,
        allowed_intents,
        authorization_limit,
        2,
        crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE.to_string(),
        3600,
    )?;
    serde_json::to_string(&AgentTypeAddResponse {
        agent_type_id: agent_type.id,
        allowed_intents: agent_type.allowed_intents,
    })
    .map_err(Error::from)
}

fn apply_challenge_request(kernel: &Kernel, request: &ChallengeRequest) -> Result<String> {
    kernel.require_issuer_not_sealed()?;
    register_member_secret_path_after_issuance_threshold_two(
        kernel,
        request.member_secret_path.as_deref(),
        "challenge",
    )?;
    let instance = kernel.store().load_instance(&request.instance_id)?;
    if instance.status != InstanceStatus::Live {
        return Err(Error::denied(
            "The instance was revoked. A challenge is refused. The check fails closed.",
        ));
    }
    let challenge = kernel.issue_holder_challenge(&instance.id)?;
    serde_json::to_string(&ChallengeResponse {
        challenge_nonce: challenge.nonce,
    })
    .map_err(Error::from)
}

/// Issue a short-lived verifier nonce. Do not look up an instance.
/// Do not write an instance record. Do not accept or store holder secrets.
fn apply_verifier_challenge_request(kernel: &Kernel) -> Result<String> {
    let challenge = kernel.issue_verifier_challenge()?;
    serde_json::to_string(&VerifierChallengeResponse {
        challenge_nonce: challenge.nonce,
        challenge_message: challenge.challenge_message,
    })
    .map_err(Error::from)
}

/// Sign a verifier nonce on this host. The host process reads the typed path
/// only when this store already holds the matching local instance.
/// Secret bytes are not returned. This helper does not write a record.
fn apply_sign_holder_nonce_request(
    kernel: &Kernel,
    request: &SignHolderNonceRequest,
) -> Result<String> {
    let path = request.holder_secret_path.trim();
    if path.is_empty() {
        return Err(Error::denied(
            "A holder secret path is required to sign a verifier nonce on this host. Secret bytes are not uploaded. The check fails closed.",
        ));
    }
    let message = request
        .challenge_message
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
        .or_else(|| {
            request
                .challenge_nonce
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(crate::tokens::verifier_challenge_message)
        })
        .ok_or_else(|| {
            Error::denied(
                "A verifier challenge nonce or challenge message is required. The check fails closed.",
            )
        })?;
    let holder_proof = kernel.sign_holder_nonce(&message, path)?;
    serde_json::to_string(&SignHolderNonceResponse { holder_proof }).map_err(Error::from)
}

fn capability_identifier_from_present_request(request: &PresentSvidRequest) -> Result<&str> {
    for value in [
        request.capability_id.as_deref(),
        request.capability.as_deref(),
    ] {
        if let Some(identifier) = value {
            let identifier = identifier.trim();
            if !identifier.is_empty() {
                return Ok(identifier);
            }
        }
    }
    Err(Error::denied(
        "The present path requires a capability identifier. The kernel does not guess which capability. The check fails closed.",
    ))
}

fn apply_present_svid_request(kernel: &Kernel, request: &PresentSvidRequest) -> Result<String> {
    let proof = holder_proof_from_fields(
        request.holder_secret_path.as_deref(),
        request.holder_proof.as_deref(),
    );
    if proof.is_none() {
        return Err(Error::denied(
            "A holder proof is required. Pass a holder secret path or a holder signature. Present is not a bearer document. The check fails closed.",
        ));
    }
    let capability_id = capability_identifier_from_present_request(request)?;
    let nonce = request
        .challenge_nonce
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if nonce.is_none() {
        return Err(Error::denied(
            "A challenge nonce is required. Present is not a bearer document. The check fails closed.",
        ));
    }
    register_member_secret_path_after_issuance_threshold_two(
        kernel,
        request.member_secret_path.as_deref(),
        "present-svid",
    )?;
    let artifact =
        kernel.present_x509_svid(&request.instance_id, capability_id, proof.as_ref(), nonce)?;
    serde_json::to_string(&PresentSvidResponse {
        presentation_json: artifact.presentation_json,
        certificate_pem: artifact.certificate_pem,
    })
    .map_err(Error::from)
}

/// Emit a laboratory Workload Identity Token plus Content-Digest.
/// Reuse Kernel::present_wimse. Secret file bytes are not uploaded and not returned.
/// Also emit the HTTP Message Signature over POST /check-wimse so the operator
/// page can include the bind without holding secret bytes. The signature covers
/// @method, @request-target, and content-digest.
fn apply_present_wimse_request(kernel: &Kernel, request: &PresentSvidRequest) -> Result<String> {
    let proof = holder_proof_from_fields(
        request.holder_secret_path.as_deref(),
        request.holder_proof.as_deref(),
    );
    if proof.is_none() {
        return Err(Error::denied(
            "A holder proof is required. Pass a holder secret path or a holder signature. Present is not a bearer document. The check fails closed.",
        ));
    }
    let capability_id = capability_identifier_from_present_request(request)?;
    let nonce = request
        .challenge_nonce
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if nonce.is_none() {
        return Err(Error::denied(
            "A challenge nonce is required. Present is not a bearer document. The check fails closed.",
        ));
    }
    register_member_secret_path_after_issuance_threshold_two(
        kernel,
        request.member_secret_path.as_deref(),
        "present-wimse",
    )?;
    let artifact =
        kernel.present_wimse(&request.instance_id, capability_id, proof.as_ref(), nonce)?;
    let envelope_secret = kernel.store().load_biscuit_secret()?;
    let (signature_input, signature) = crate::wimse::sign_laboratory_wimse_http_message(
        crate::wimse::LABORATORY_WIMSE_CHECK_METHOD,
        crate::wimse::LABORATORY_WIMSE_CHECK_PATH,
        &artifact.content_digest,
        &envelope_secret,
    )?;
    serde_json::to_string(&PresentWimseResponse {
        presentation_json: artifact.presentation_json,
        workload_identity_token: artifact.workload_identity_token,
        content_digest: artifact.content_digest,
        signature_input,
        signature,
    })
    .map_err(Error::from)
}

/// JSON of StoreStatus with no secrets. The raw issuer public key is truncated.
fn operator_status_json(kernel: &Kernel) -> Result<String> {
    let mut status = kernel.store_status()?;
    status.current_issuer_public_key_hex =
        truncated_issuer_public_key_hex(&status.current_issuer_public_key_hex);
    serde_json::to_string(&status).map_err(Error::from)
}

/// JSON of the full current issuer public key and crypto profile only.
/// Secret bytes, biscuit keys, member keys, and accepted-key lists are not included.
fn issuer_public_json(kernel: &Kernel) -> Result<String> {
    let status = kernel.store_status()?;
    serde_json::to_string(&IssuerPublicResponse {
        current_issuer_public_key_hex: status.current_issuer_public_key_hex,
        crypto_profile: status.crypto_profile,
    })
    .map_err(Error::from)
}

fn handle_client(kernel: &Kernel, stream: &mut TcpStream, mode: &HostMode) -> Result<()> {
    let (headers, body) = read_http_request(stream)?;
    let request_line = headers.lines().next().unwrap_or("");
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    let method = parts.first().copied().unwrap_or("");
    let path = parts.get(1).copied().unwrap_or("");
    if mode.check_only && !check_only_path_allowed(method, path) {
        return write_refused_response(
            stream,
            Error::denied(
                "This host is check-only. Create Agent Principal and mint paths are refused. The check fails closed.",
            ),
        );
    }
    if method == "GET" && path == "/health" {
        return write_json_response(stream, 200, "OK", r#"{"status":"live"}"#);
    }
    if method == "GET" && path == LABORATORY_WELL_KNOWN_CHECK_PATH {
        return write_json_response(
            stream,
            200,
            "OK",
            &laboratory_well_known_check_document(mode),
        );
    }
    if method == "GET" && path == "/status" {
        let body = operator_status_json(kernel)?;
        return write_json_response(stream, 200, "OK", &body);
    }
    if method == "GET" && path == "/issuer-public" {
        let body = issuer_public_json(kernel)?;
        return write_json_response(stream, 200, "OK", &body);
    }
    if method == "GET" && path == "/" {
        if mode.check_only {
            return write_json_response(stream, 200, "OK", &check_only_root_json(mode));
        }
        return write_html_response(stream, 200, "OK", INTERFACE_HTML);
    }
    if method == "GET" && path == "/laboratory" {
        return write_html_response(stream, 200, "OK", OPERATOR_PAGE_HTML);
    }
    if method == "GET" && path == "/instances" {
        let body = instances_json(kernel)?;
        return write_json_response(stream, 200, "OK", &body);
    }
    if method == "GET" && path == "/agent-types" {
        let body = agent_types_json(kernel)?;
        return write_json_response(stream, 200, "OK", &body);
    }
    if method == "POST" && path == "/agent-type" {
        let request: AgentTypeAddRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_agent_type_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/birth" {
        let request: BirthRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_birth_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/kill" {
        let request: KillRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_kill_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/member-two" {
        let request: MemberTwoRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_member_two_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/set-verify-threshold" {
        let request: SetVerifyThresholdRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_set_verify_threshold_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/set-issuer-threshold" {
        let request: SetIssuerThresholdRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_set_issuer_threshold_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/backup" {
        let request: BackupRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_backup_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/restore" {
        let request: RestoreRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_restore_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/diagnose" {
        let request: DiagnoseRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_diagnose_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/rotate" {
        let request: RotateRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_rotate_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/seal" {
        let request: SealRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_seal_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/seal-export" {
        let request: SealExportRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_seal_export_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/seal-accept" {
        let request: SealExportResponse = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_seal_accept_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/previous-key-export" {
        return match apply_previous_key_export_request(kernel) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/previous-key-accept" {
        let request: PreviousKeyExportResponse = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_previous_key_accept_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/kill-export" {
        let request: KillExportRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_kill_export_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/issuer-accept" {
        let request: IssuerAcceptRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_issuer_accept_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/kill-accept" {
        let request: KillExportResponse = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_kill_accept_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/act-export" {
        let request: ActExportRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_act_export_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/act-accept" {
        let request: ActExportResponse = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_act_accept_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/spawn" {
        let request: SpawnRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_spawn_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/verifier-challenge" {
        return match apply_verifier_challenge_request(kernel) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/sign-holder-nonce" {
        let request: SignHolderNonceRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_sign_holder_nonce_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/challenge" {
        let request: ChallengeRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_challenge_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/present-svid" {
        let request: PresentSvidRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_present_svid_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/present-wimse" {
        let request: PresentSvidRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_present_wimse_request(kernel, &request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/runtime-check" {
        let request: RuntimeCheckRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_runtime_check_request(kernel, &request) {
            Ok(decision) => write_decision_response(stream, &decision),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/well-known-follow" {
        let request: WellKnownFollowRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_well_known_follow_request(&request) {
            Ok(payload) => write_json_response(stream, 200, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method == "POST" && path == "/operator-pin" {
        let request: OperatorPinRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_operator_pin_request(&request) {
            Ok((200, payload)) => write_json_response(stream, 200, "OK", &payload),
            Ok((400, payload)) => write_json_response(stream, 400, "Bad Request", &payload),
            Ok((403, payload)) => write_json_response(stream, 403, "Forbidden", &payload),
            Ok((status, payload)) => write_json_response(stream, status, "OK", &payload),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if path == "/check-wimse" {
        if method != "POST" {
            return write_refused_response(
                stream,
                Error::denied(
                    "POST /check-wimse binds HTTP @method POST, @request-target /check-wimse, and content-digest. A different method is refused. The check fails closed.",
                ),
            );
        }
        let request: CheckWimseRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        let signature_input = header_value(&headers, crate::wimse::SIGNATURE_INPUT_HEADER)
            .or_else(|| request.signature_input.clone());
        let signature = header_value(&headers, crate::wimse::SIGNATURE_HEADER)
            .or_else(|| request.signature.clone());
        return match apply_check_wimse_request(
            kernel,
            &request,
            method,
            path,
            signature_input.as_deref(),
            signature.as_deref(),
        ) {
            Ok(decision) => write_decision_response(stream, &decision),
            Err(error) => write_refused_response(stream, error),
        };
    }
    if method != "POST" || (path != "/check" && path != "/check-svid") {
        return write_json_response(
            stream,
            404,
            "Not Found",
            r#"{"result":"refused","reason":"The path is not GET /, GET /laboratory, GET /health, GET /.well-known/prometheus-check, GET /status, GET /issuer-public, GET /instances, GET /agent-types, POST /check, POST /check-svid, POST /check-wimse, POST /challenge, POST /verifier-challenge, POST /sign-holder-nonce, POST /present-svid, POST /present-wimse, POST /birth, POST /kill, POST /seal, POST /rotate, POST /seal-export, POST /seal-accept, POST /previous-key-export, POST /previous-key-accept, POST /kill-export, POST /kill-accept, POST /issuer-accept, POST /act-export, POST /act-accept, POST /agent-type, POST /spawn, POST /member-two, POST /set-verify-threshold, POST /set-issuer-threshold, POST /backup, POST /restore, POST /diagnose, POST /runtime-check, POST /well-known-follow, or POST /operator-pin."}"#,
        );
    }
    if path == "/check-svid" {
        let request: CheckSvidRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return write_bad_request_response(stream, error),
        };
        return match apply_check_svid_request(kernel, &request) {
            Ok(decision) => write_decision_response(stream, &decision),
            Err(error) => write_refused_response(stream, error),
        };
    }
    let request: CheckRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => return write_bad_request_response(stream, error),
    };
    match apply_check_request(kernel, &request) {
        Ok(decision) => write_decision_response(stream, &decision),
        Err(error) => write_refused_response(stream, error),
    }
}

fn write_decision_response(stream: &mut TcpStream, decision: &CheckDecision) -> Result<()> {
    let body = serde_json::to_string(decision).map_err(Error::from)?;
    if decision.result == "allowed" {
        write_json_response(stream, 200, "OK", &body)
    } else {
        write_json_response(stream, 403, "Forbidden", &body)
    }
}

fn nonempty_optional_field(value: &Option<String>) -> bool {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some()
}

/// Drive LaboratoryRuntime against a typed check base.
/// The issuing-store host signs a verifier nonce from a local holder secret
/// path. The path is not sent to the check base. This host does not spawn
/// AgentProcess. This host does not persist holder secrets.
fn apply_runtime_check_request(
    _kernel: &Kernel,
    request: &RuntimeCheckRequest,
) -> Result<CheckDecision> {
    if nonempty_optional_field(&request.holder_secret) {
        return Err(Error::denied(
            "Holder secret bytes are refused. Type a local holder secret path. Secret bytes are not uploaded. The check fails closed.",
        ));
    }
    let runtime = crate::runtime_check::LaboratoryRuntime::connect(&request.check_base)?;
    let on_ramp = crate::runtime_check::one_shot_on_ramp(
        "runtime-check",
        nonempty_optional_field(&request.certificate_pem),
        nonempty_optional_field(&request.workload_identity_token),
        nonempty_optional_field(&request.content_digest),
        nonempty_optional_field(&request.signature_input),
        nonempty_optional_field(&request.signature),
    )?;
    let presentation_json = request
        .presentation_json
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::denied("A presentation JSON is required. The check fails closed."))?;
    let supplied_proof = request
        .holder_proof
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let holder_secret_path = request
        .holder_secret_path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if supplied_proof.is_none() && holder_secret_path.is_none() {
        return Err(Error::denied(
            "A holder signature is required. Pass a holder proof or a local holder secret path. Secret bytes are not uploaded. The check fails closed.",
        ));
    }
    let sign = |challenge: &crate::runtime_check::RuntimeVerifierChallenge| -> Result<String> {
        if let Some(proof) = supplied_proof.clone() {
            return Ok(proof);
        }
        let path = holder_secret_path.ok_or_else(|| {
            Error::denied(
                "A holder signature is required. The laboratory runtime does not read holder secrets. The check fails closed.",
            )
        })?;
        crate::holder_sign::sign_holder_proof(
            path,
            None,
            Some(challenge.challenge_message.as_str()),
        )
    };
    match on_ramp {
        crate::runtime_check::OneShotOnRamp::Svid => {
            let present = crate::runtime_check::SvidPresent {
                presentation_json: presentation_json.to_string(),
                certificate_pem: request.certificate_pem.clone().unwrap_or_default(),
            };
            runtime.complete_svid_check(&present, sign)
        }
        crate::runtime_check::OneShotOnRamp::Wimse => {
            let present = crate::runtime_check::WimsePresent {
                presentation_json: presentation_json.to_string(),
                workload_identity_token: request
                    .workload_identity_token
                    .clone()
                    .unwrap_or_default(),
                content_digest: request.content_digest.clone().unwrap_or_default(),
                signature_input: request.signature_input.clone().unwrap_or_default(),
                signature: request.signature.clone().unwrap_or_default(),
            };
            runtime.complete_wimse_check(&present, sign)
        }
    }
}

fn refuse_uploaded_secret_bytes(holder_secret: &Option<String>) -> Result<()> {
    if nonempty_optional_field(holder_secret) {
        return Err(Error::denied(
            "Holder secret bytes are refused. Type a local holder secret path. Secret bytes are not uploaded. The check fails closed.",
        ));
    }
    Ok(())
}

/// GET the parsed well-known document of an allowed typed verifier base.
/// Off-name and HTTP public stay refused. The browser does not fetch the public name.
fn apply_well_known_follow_request(request: &WellKnownFollowRequest) -> Result<String> {
    refuse_uploaded_secret_bytes(&request.holder_secret)?;
    let runtime = crate::runtime_check::LaboratoryRuntime::connect(&request.check_base)?;
    let document = runtime.load_document()?;
    serde_json::to_string(&crate::runtime_check::well_known_follow_payload(&document))
        .map_err(Error::from)
}

/// POST a named operator pin to an allowed typed verifier base.
/// The path comes from that base's well-known document. A missing pin is
/// refused. A write-verb pin is refused. A swapped document is refused.
fn apply_operator_pin_request(request: &OperatorPinRequest) -> Result<(u16, String)> {
    refuse_uploaded_secret_bytes(&request.holder_secret)?;
    let pin = request.pin.trim();
    if pin.is_empty() {
        return Err(Error::denied(
            "An operator pin name is required. The check fails closed.",
        ));
    }
    let body = if request.body.is_null() {
        "{}".to_string()
    } else {
        serde_json::to_string(&request.body).map_err(Error::from)?
    };
    let runtime = crate::runtime_check::LaboratoryRuntime::connect(&request.check_base)?;
    runtime.post_documented_pin(pin, &body)
}

fn apply_check_request(kernel: &Kernel, request: &CheckRequest) -> Result<CheckDecision> {
    register_member_secret_path_after_issuance_threshold_two(
        kernel,
        request.member_secret_path.as_deref(),
        "check",
    )?;
    let proof = holder_proof_from_request(request);
    kernel.check_tool_action(
        &request.instance_id,
        request.capability_id.as_deref(),
        &request.intent,
        &request.audience,
        proof.as_ref(),
        request.challenge_nonce.as_deref(),
        request.on_behalf_of.as_deref(),
    )
}

fn refused_svid_decision(request: &CheckSvidRequest, error: Error) -> CheckDecision {
    let presentation =
        crate::presentation::parse_presentation_json(&request.presentation_json).ok();
    CheckDecision {
        result: "refused".to_string(),
        instance_id: presentation
            .as_ref()
            .map(|document| document.instance_id.clone())
            .unwrap_or_default(),
        capability_id: presentation
            .as_ref()
            .map(|document| document.capability_id.clone()),
        intent: request.intent.clone(),
        audience: request.audience.clone(),
        reason: Some(error.to_string()),
        challenge_nonce: request.challenge_nonce.clone(),
        on_behalf_of: request.on_behalf_of.clone(),
        receipt: None,
    }
}

/// Verify the laboratory X.509-SVID wrap, then decide the tool action.
/// The present is not a bearer document. Holder proof remains required.
/// A verifier store has no instance record. Allow from the verified present.
/// Do not look up the issuing inode. Death still wins.
fn apply_check_svid_request(kernel: &Kernel, request: &CheckSvidRequest) -> Result<CheckDecision> {
    if let Err(error) = kernel.verify_x509_svid(
        &request.certificate_pem,
        request.presentation_json.as_bytes(),
    ) {
        return Ok(refused_svid_decision(request, error));
    }
    let presentation = crate::presentation::parse_presentation_json(&request.presentation_json)?;
    if request.intent != presentation.intent || request.audience != presentation.audience {
        return Ok(CheckDecision {
            result: "refused".to_string(),
            instance_id: presentation.instance_id,
            capability_id: Some(presentation.capability_id),
            intent: request.intent.clone(),
            audience: request.audience.clone(),
            reason: Some(
                "The requested intent and audience must match the present. The check fails closed."
                    .to_string(),
            ),
            challenge_nonce: request.challenge_nonce.clone(),
            on_behalf_of: request.on_behalf_of.clone(),
            receipt: None,
        });
    }
    let proof = holder_proof_from_svid_request(request);
    register_member_secret_path_when_local_instance_signs(
        kernel,
        &presentation.instance_id,
        request.member_secret_path.as_deref(),
        "check-svid",
    )?;
    kernel.decide_tool_action_after_verified_wimse(
        &presentation,
        &request.intent,
        &request.audience,
        proof.as_ref(),
        request.challenge_nonce.as_deref(),
        request.on_behalf_of.as_deref(),
    )
}

/// Apply a POST /check JSON body against a kernel. Tests inject a clock on that kernel.
pub fn check_request_from_json(kernel: &Kernel, body: &[u8]) -> Result<CheckDecision> {
    let request: CheckRequest = serde_json::from_slice(body)
        .map_err(|error| Error::kernel(format!("The request body is not valid JSON: {error}")))?;
    apply_check_request(kernel, &request)
}

/// Apply a POST /check-svid JSON body against a kernel. Tests inject a clock on that kernel.
pub fn check_svid_request_from_json(kernel: &Kernel, body: &[u8]) -> Result<CheckDecision> {
    let request: CheckSvidRequest = serde_json::from_slice(body)
        .map_err(|error| Error::kernel(format!("The request body is not valid JSON: {error}")))?;
    apply_check_svid_request(kernel, &request)
}

fn refused_wimse_decision(request: &CheckWimseRequest, error: Error) -> CheckDecision {
    let presentation =
        crate::presentation::parse_presentation_json(&request.presentation_json).ok();
    CheckDecision {
        result: "refused".to_string(),
        instance_id: presentation
            .as_ref()
            .map(|document| document.instance_id.clone())
            .unwrap_or_default(),
        capability_id: presentation
            .as_ref()
            .map(|document| document.capability_id.clone()),
        intent: request.intent.clone(),
        audience: request.audience.clone(),
        reason: Some(error.to_string()),
        challenge_nonce: request.challenge_nonce.clone(),
        on_behalf_of: request.on_behalf_of.clone(),
        receipt: None,
    }
}

/// Verify the laboratory HTTP Message Signature over the actual method,
/// request-target, and Content-Digest, then verify the Workload Identity Token
/// and Content-Digest, then decide the tool action. The present is not a bearer document.
/// Holder proof remains required. A verifier store has no instance record.
/// Allow from the verified present after holder proof against the signed
/// present holder public key. Do not look up the issuing inode. Death still wins.
fn apply_check_wimse_request(
    kernel: &Kernel,
    request: &CheckWimseRequest,
    method: &str,
    request_target: &str,
    signature_input: Option<&str>,
    signature: Option<&str>,
) -> Result<CheckDecision> {
    let envelope = crate::presentation::parse_presentation_json(&request.presentation_json)
        .ok()
        .map(|document| document.laboratory_envelope_public_key_hex)
        .unwrap_or_default();
    if let Err(error) = crate::wimse::require_laboratory_wimse_http_message_signature(
        method,
        request_target,
        request.content_digest.trim(),
        signature_input.unwrap_or(""),
        signature.unwrap_or(""),
        envelope.trim(),
    ) {
        return Ok(refused_wimse_decision(request, error));
    }
    if let Err(error) = kernel.verify_wimse(
        &request.workload_identity_token,
        &request.content_digest,
        request.presentation_json.as_bytes(),
    ) {
        return Ok(refused_wimse_decision(request, error));
    }
    let presentation = crate::presentation::parse_presentation_json(&request.presentation_json)?;
    if request.intent != presentation.intent || request.audience != presentation.audience {
        return Ok(CheckDecision {
            result: "refused".to_string(),
            instance_id: presentation.instance_id,
            capability_id: Some(presentation.capability_id),
            intent: request.intent.clone(),
            audience: request.audience.clone(),
            reason: Some(
                "The requested intent and audience must match the present. The check fails closed."
                    .to_string(),
            ),
            challenge_nonce: request.challenge_nonce.clone(),
            on_behalf_of: request.on_behalf_of.clone(),
            receipt: None,
        });
    }
    let proof = holder_proof_from_wimse_request(request);
    register_member_secret_path_when_local_instance_signs(
        kernel,
        &presentation.instance_id,
        request.member_secret_path.as_deref(),
        "check-wimse",
    )?;
    kernel.decide_tool_action_after_verified_wimse(
        &presentation,
        &request.intent,
        &request.audience,
        proof.as_ref(),
        request.challenge_nonce.as_deref(),
        request.on_behalf_of.as_deref(),
    )
}

/// Apply a POST /check-wimse JSON body against a kernel. Tests inject a clock on that kernel.
pub fn check_wimse_request_from_json(kernel: &Kernel, body: &[u8]) -> Result<CheckDecision> {
    let request: CheckWimseRequest = serde_json::from_slice(body)
        .map_err(|error| Error::kernel(format!("The request body is not valid JSON: {error}")))?;
    apply_check_wimse_request(
        kernel,
        &request,
        crate::wimse::LABORATORY_WIMSE_CHECK_METHOD,
        crate::wimse::LABORATORY_WIMSE_CHECK_PATH,
        request.signature_input.as_deref(),
        request.signature.as_deref(),
    )
}

/// Serve accepted connections on an already-bound loopback listener.
/// Host tests and the laboratory runtime use this so more than one request
/// can hit the same process. Verifier challenge nonces live in this process only.
/// This is not a public listener.
pub fn serve_loopback_listener(kernel: &Kernel, listener: TcpListener) -> Result<()> {
    serve_loopback_listener_with_mode(kernel, listener, &HostMode::issuing_loopback())
}

/// Serve accepted connections with an explicit listen mode.
pub fn serve_loopback_listener_with_mode(
    kernel: &Kernel,
    listener: TcpListener,
    mode: &HostMode,
) -> Result<()> {
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                if let Err(error) = handle_client(kernel, &mut stream, mode) {
                    let _ = write_json_response(
                        &mut stream,
                        500,
                        "Internal Server Error",
                        &serde_json::json!({
                            "result": "refused",
                            "reason": error.to_string()
                        })
                        .to_string(),
                    );
                }
            }
            Err(error) => {
                eprintln!("The check host rejected a connection: {error}");
            }
        }
    }
    Ok(())
}

/// Prepare a store for host start. A check-only host needs issuer.json and
/// does not require a live mint issuer. This host does not load issuer.secret.
pub fn prepare_host_store(kernel: &Kernel, mode: &HostMode) -> Result<()> {
    if !kernel.store().issuer_path().exists() && !kernel.store().secret_path().exists() {
        if mode.check_only {
            return Err(Error::denied(
                "A check-only host needs issuer.json. Create Agent Principal and mint paths are refused. The check fails closed.",
            ));
        }
        return Ok(());
    }
    let _issuer = kernel.store().load_issuer()?;
    if !mode.check_only {
        kernel.require_issuer_not_sealed()?;
    }
    Ok(())
}

/// Listen on a loopback address and answer tool-boundary checks.
/// Use the kernel the operator already opened so --member-secret applies at issuance threshold two.
pub fn run_host(kernel: &Kernel, listen_address: &str) -> Result<()> {
    run_host_with_mode(kernel, listen_address, HostMode::issuing_loopback())
}

/// Listen on a loopback address from command flags.
pub fn run_host_from_flags(
    kernel: &Kernel,
    listen_address: &str,
    check_only: bool,
    public_check_name: Option<&str>,
) -> Result<()> {
    let mode = host_mode_from_flags(check_only, public_check_name)?;
    run_host_with_mode(kernel, listen_address, mode)
}

fn run_host_with_mode(kernel: &Kernel, listen_address: &str, mode: HostMode) -> Result<()> {
    let address = require_loopback(listen_address)?;
    prepare_host_store(kernel, &mode)?;
    let listener = TcpListener::bind(address).map_err(|error| {
        Error::kernel(format!(
            "The check host could not bind to {address}: {error}"
        ))
    })?;
    if mode.check_only {
        eprintln!(
            "The Prometheus check-only host is listening on {address}. This host binds to a loopback address only. This host is a verifier. Create Agent Principal and mint paths are refused. GET /health, GET /.well-known/prometheus-check, POST /check-svid, POST /check-wimse, POST /verifier-challenge, POST /issuer-accept, POST /kill-accept, POST /seal-accept, POST /previous-key-accept, and POST /act-accept stay. The well-known document names bind {}.",
            mode.well_known_bind
        );
    } else {
        eprintln!(
            "The Prometheus check host is listening on {address}. This host binds to a loopback address only. This host answers GET /, GET /laboratory, GET /health, GET /.well-known/prometheus-check, GET /status, GET /issuer-public, GET /instances, GET /agent-types, POST /check, POST /check-svid, POST /check-wimse, POST /challenge, POST /verifier-challenge, POST /sign-holder-nonce, POST /present-svid, POST /present-wimse, POST /birth, POST /kill, POST /seal, POST /rotate, POST /seal-export, POST /seal-accept, POST /previous-key-export, POST /previous-key-accept, POST /kill-export, POST /kill-accept, POST /issuer-accept, POST /act-export, POST /act-accept, POST /agent-type, POST /spawn, POST /member-two, POST /set-verify-threshold, POST /set-issuer-threshold, POST /backup, POST /restore, POST /diagnose, POST /runtime-check, POST /well-known-follow, and POST /operator-pin. POST /check-wimse binds HTTP @method, @request-target, and content-digest. Open http://{address}/ in a browser to use the later user interface. The laboratory operator page remains at GET /laboratory."
        );
    }
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if let Err(error) = handle_client(kernel, &mut stream, &mode) {
                    let _ = write_json_response(
                        &mut stream,
                        500,
                        "Internal Server Error",
                        &serde_json::json!({
                            "result": "refused",
                            "reason": error.to_string()
                        })
                        .to_string(),
                    );
                }
            }
            Err(error) => {
                eprintln!("The check host rejected a connection: {error}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::require_loopback;

    #[test]
    fn the_host_refuses_a_non_loopback_address() {
        let error = require_loopback("0.0.0.0:18765").expect_err("all interfaces must be refused");
        assert!(error.to_string().contains("loopback"));
    }

    #[test]
    fn the_host_accepts_loopback() {
        require_loopback("127.0.0.1:18765").expect("127.0.0.1 must be accepted");
    }

    #[test]
    fn the_host_still_binds_loopback_only() {
        let error = require_loopback("0.0.0.0:18765").expect_err("all interfaces must be refused");
        assert!(error.to_string().contains("loopback"));
        require_loopback("127.0.0.1:18765").expect("127.0.0.1 must be accepted");
    }

    #[test]
    fn expired_capability_fails_on_the_host_check_path_without_a_long_sleep() {
        use crate::kernel::Kernel;
        use chrono::Duration;
        use std::collections::BTreeMap;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let agent_type = kernel
            .add_agent_type(
                "laboratory".to_string(),
                vec!["read".to_string()],
                "internal".to_string(),
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
                "internal",
                None,
            )
            .unwrap();
        kernel.set_now_for_test(birth.capability.expires + Duration::seconds(1));
        let nonce = kernel
            .issue_holder_challenge(&birth.instance.id)
            .expect("issue a holder challenge")
            .nonce;
        let secret = kernel
            .store()
            .holder_secret_path(&birth.instance.id)
            .display()
            .to_string();
        let body = serde_json::json!({
            "instance_id": birth.instance.id,
            "capability_id": birth.capability.id,
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": secret,
            "challenge_nonce": nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let decision = super::check_request_from_json(&kernel, body.as_bytes())
            .expect("the host check path must return a decision");
        assert_eq!(decision.result, "refused");
        assert!(
            decision.reason.unwrap().contains("expired"),
            "the host path must refuse an expired capability"
        );
    }

    #[test]
    fn the_host_check_path_refuses_a_wrong_act_authority() {
        use crate::kernel::Kernel;
        use std::collections::BTreeMap;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let agent_type = kernel
            .add_agent_type(
                "laboratory".to_string(),
                vec!["read".to_string()],
                "internal".to_string(),
                2,
                crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE.to_string(),
                3600,
            )
            .unwrap();
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
        let nonce = kernel
            .issue_holder_challenge(&birth.instance.id)
            .expect("issue a holder challenge")
            .nonce;
        let secret = kernel
            .store()
            .holder_secret_path(&birth.instance.id)
            .display()
            .to_string();
        let body = serde_json::json!({
            "instance_id": birth.instance.id,
            "capability_id": birth.capability.id,
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": secret,
            "challenge_nonce": nonce,
            "on_behalf_of": "jordan",
        })
        .to_string();
        let decision = super::check_request_from_json(&kernel, body.as_bytes())
            .expect("the host check path must return a decision");
        assert_eq!(decision.result, "refused");
        assert!(
            decision.reason.unwrap().contains("act authority"),
            "the host path must refuse a wrong act authority"
        );
        assert_eq!(decision.on_behalf_of.as_deref(), Some("autonomous"));
    }

    #[test]
    fn the_host_check_path_refuses_a_missing_on_behalf_of() {
        use crate::kernel::Kernel;
        use std::collections::BTreeMap;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let agent_type = kernel
            .add_agent_type(
                "laboratory".to_string(),
                vec!["read".to_string()],
                "internal".to_string(),
                2,
                crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE.to_string(),
                3600,
            )
            .unwrap();
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
        let nonce = kernel
            .issue_holder_challenge(&birth.instance.id)
            .expect("issue a holder challenge")
            .nonce;
        let secret = kernel
            .store()
            .holder_secret_path(&birth.instance.id)
            .display()
            .to_string();
        let body = serde_json::json!({
            "instance_id": birth.instance.id,
            "capability_id": birth.capability.id,
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": secret,
            "challenge_nonce": nonce,
        })
        .to_string();
        let decision = super::check_request_from_json(&kernel, body.as_bytes())
            .expect("the host check path must return a decision");
        assert_eq!(decision.result, "refused");
        assert!(
            decision.reason.unwrap().contains("must name on_behalf_of"),
            "the host path must refuse a missing on_behalf_of"
        );
    }

    #[test]
    fn the_host_check_path_refuses_after_issuer_seal() {
        use crate::kernel::Kernel;
        use chrono::Duration;
        use std::collections::BTreeMap;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let start = chrono::Utc::now();
        kernel.set_now_for_test(start);
        let agent_type = kernel
            .add_agent_type(
                "laboratory".to_string(),
                vec!["read".to_string()],
                "internal".to_string(),
                2,
                crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE.to_string(),
                3600,
            )
            .unwrap();
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
        let nonce = kernel
            .issue_holder_challenge(&birth.instance.id)
            .expect("issue a holder challenge before remaining life")
            .nonce;
        kernel.seal_issuer(60).expect("seal the issuer");
        kernel.set_now_for_test(start + Duration::seconds(60));
        let secret = kernel
            .store()
            .holder_secret_path(&birth.instance.id)
            .display()
            .to_string();
        let body = serde_json::json!({
            "instance_id": birth.instance.id,
            "capability_id": birth.capability.id,
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": secret,
            "challenge_nonce": nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let decision = super::check_request_from_json(&kernel, body.as_bytes())
            .expect("the host check path must return a decision");
        assert_eq!(decision.result, "refused");
        assert!(
            decision
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("issuer seal"),
            "the host path must refuse after the issuer seal kill_date: {:?}",
            decision.reason
        );
        assert!(
            decision.receipt.is_none(),
            "after seal the host must not sign a new decision receipt"
        );
    }

    #[test]
    fn the_host_check_path_refuses_a_sibling_prefix_audience() {
        use crate::kernel::Kernel;
        use std::collections::BTreeMap;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let agent_type = kernel
            .add_agent_type(
                "laboratory".to_string(),
                vec!["read".to_string()],
                "internal".to_string(),
                2,
                crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE.to_string(),
                3600,
            )
            .unwrap();
        let birth = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "internal/pay",
                None,
            )
            .unwrap();
        let nonce = kernel
            .issue_holder_challenge(&birth.instance.id)
            .expect("issue a holder challenge")
            .nonce;
        let secret = kernel
            .store()
            .holder_secret_path(&birth.instance.id)
            .display()
            .to_string();
        let body = serde_json::json!({
            "instance_id": birth.instance.id,
            "capability_id": birth.capability.id,
            "intent": "read",
            "audience": "internal/payroll",
            "holder_secret_path": secret,
            "challenge_nonce": nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let decision = super::check_request_from_json(&kernel, body.as_bytes())
            .expect("the host check path must return a decision");
        assert_eq!(decision.result, "refused");
        let reason = decision.reason.unwrap_or_default();
        assert!(
            reason.contains("exceeds the capability")
                || reason.contains("child path")
                || reason.contains("string prefix"),
            "the host path must refuse a sibling-prefix audience: {reason}"
        );
    }

    #[test]
    fn the_host_refuses_an_unspecified_ipv6_address() {
        let error =
            require_loopback("[::]:18765").expect_err("all IPv6 interfaces must be refused");
        assert!(error.to_string().contains("loopback"));
    }

    #[test]
    fn the_host_accepts_ipv6_loopback() {
        require_loopback("[::1]:18765").expect("[::1] must be accepted");
    }

    #[test]
    fn the_host_check_path_at_issuance_threshold_two_needs_the_outside_member_secret() {
        use crate::kernel::Kernel;
        use std::collections::BTreeMap;
        use tempfile::tempdir;

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
        let agent_type = signing
            .add_agent_type(
                "laboratory".to_string(),
                vec!["read".to_string()],
                "internal".to_string(),
                2,
                crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE.to_string(),
                3600,
            )
            .unwrap();
        let birth = signing
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "internal",
                None,
            )
            .unwrap();
        let nonce = signing
            .issue_holder_challenge(&birth.instance.id)
            .expect("issue a holder challenge")
            .nonce;
        let secret = signing
            .store()
            .holder_secret_path(&birth.instance.id)
            .display()
            .to_string();
        let body = serde_json::json!({
            "instance_id": birth.instance.id,
            "capability_id": birth.capability.id,
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": secret,
            "challenge_nonce": nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();

        let host_without_member_two = Kernel::open(store_directory.path());
        let error = super::check_request_from_json(&host_without_member_two, body.as_bytes())
            .expect_err("a host without member two must not sign a check at issuance n=2");
        let message = error.to_string();
        assert!(
            message.contains("threshold") || message.contains("member"),
            "the host must fail closed without member two: {message}"
        );

        let mut allowed = serde_json::from_str::<serde_json::Value>(&body)
            .expect("the laboratory check body must be JSON");
        allowed["member_secret_path"] = serde_json::json!(outside.to_string_lossy());
        let decision = super::check_request_from_json(&signing, allowed.to_string().as_bytes())
            .expect("the host with member two must return a decision");
        assert_eq!(decision.result, "allowed");
    }

    fn laboratory_host_birth(kernel: &crate::kernel::Kernel) -> crate::kernel::BirthWrite {
        use std::collections::BTreeMap;

        let agent_type = kernel
            .add_agent_type(
                "laboratory".to_string(),
                vec!["read".to_string()],
                "internal".to_string(),
                2,
                crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE.to_string(),
                3600,
            )
            .unwrap();
        kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "internal",
                None,
            )
            .unwrap()
    }

    fn raise_live_host_issuance_threshold_two(
        kernel: &crate::kernel::Kernel,
        outside: &std::path::Path,
    ) {
        let member_body = serde_json::json!({
            "member_secret_path": outside.to_string_lossy(),
        })
        .to_string();
        let member_response =
            exchange_one_http_request(kernel, &http_post_request("/member-two", &member_body));
        assert!(
            member_response.starts_with("HTTP/1.1 200"),
            "POST /member-two must return 200: {member_response}"
        );
        let threshold_body = serde_json::json!({
            "confirm": "issuer-threshold",
            "n": 2,
        })
        .to_string();
        let threshold_response = exchange_one_http_request(
            kernel,
            &http_post_request("/set-issuer-threshold", &threshold_body),
        );
        assert!(
            threshold_response.starts_with("HTTP/1.1 200"),
            "POST /set-issuer-threshold must return 200: {threshold_response}"
        );
    }

    fn assert_live_host_write_refuses_without_member_secret_path(
        kernel: &crate::kernel::Kernel,
        path: &str,
        body: &str,
        label: &str,
    ) -> String {
        let response = exchange_one_http_request(kernel, &http_post_request(path, body));
        assert!(
            response.contains("HTTP/1.1 403"),
            "after issuance threshold_n 2, POST {path} without member_secret_path on the live host must refuse: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("member_secret_path")
                || payload.contains("member secret")
                || payload.contains("outside"),
            "POST {path} without the outside member must name the required member path: {payload}"
        );
        assert_body_has_no_secrets(kernel, payload, None, label);
        payload.to_string()
    }

    fn laboratory_svid_wrap(
        kernel: &crate::kernel::Kernel,
        birth: &crate::kernel::BirthWrite,
    ) -> crate::svid::X509SvidArtifact {
        use crate::kernel::HolderProof;

        let nonce = kernel
            .issue_holder_challenge(&birth.instance.id)
            .expect("issue a holder challenge for present")
            .nonce;
        let secret = kernel.store().holder_secret_path(&birth.instance.id);
        kernel
            .present_x509_svid(
                &birth.instance.id,
                &birth.capability.id,
                Some(&HolderProof::SecretPath(secret)),
                Some(&nonce),
            )
            .expect("emit a live laboratory X.509-SVID wrap")
    }

    fn laboratory_host_present_svid_http(
        kernel: &crate::kernel::Kernel,
        instance_id: &str,
        capability_id: &str,
        holder_path: &str,
        audience: &str,
    ) -> (String, String) {
        let challenge_response = exchange_one_http_request(
            kernel,
            &http_post_request(
                "/challenge",
                &serde_json::json!({ "instance_id": instance_id }).to_string(),
            ),
        );
        assert!(
            challenge_response.starts_with("HTTP/1.1 200"),
            "POST /challenge must return 200: {challenge_response}"
        );
        let challenge_value: serde_json::Value =
            serde_json::from_str(http_body(&challenge_response))
                .expect("POST /challenge must return JSON");
        let present_body = serde_json::json!({
            "instance_id": instance_id,
            "capability_id": capability_id,
            "intent": "read",
            "audience": audience,
            "holder_secret_path": holder_path,
            "challenge_nonce": challenge_value["challenge_nonce"],
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let present_response =
            exchange_one_http_request(kernel, &http_post_request("/present-svid", &present_body));
        assert!(
            present_response.starts_with("HTTP/1.1 200"),
            "POST /present-svid must return 200: {present_response}"
        );
        let present_value: serde_json::Value = serde_json::from_str(http_body(&present_response))
            .expect("POST /present-svid must return JSON");
        (
            present_value["presentation_json"]
                .as_str()
                .expect("POST /present-svid must return presentation_json")
                .to_string(),
            present_value["certificate_pem"]
                .as_str()
                .expect("POST /present-svid must return certificate_pem")
                .to_string(),
        )
    }

    fn laboratory_host_independent_birth(
        kernel: &crate::kernel::Kernel,
        first: &crate::kernel::BirthWrite,
    ) -> crate::kernel::BirthWrite {
        use std::collections::BTreeMap;

        kernel
            .birth_write(
                &first.instance.agent_type_id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "internal",
                None,
            )
            .expect("birth a second independent instance")
    }

    fn laboratory_runtime_check_body(
        check_base: &str,
        presentation_json: &str,
        certificate_pem: &str,
        holder_path: &str,
    ) -> String {
        serde_json::json!({
            "check_base": check_base,
            "presentation_json": presentation_json,
            "certificate_pem": certificate_pem,
            "holder_secret_path": holder_path,
        })
        .to_string()
    }

    fn laboratory_host_present_wimse_http(
        kernel: &crate::kernel::Kernel,
        instance_id: &str,
        capability_id: &str,
        holder_path: &str,
        audience: &str,
    ) -> (String, String, String, String, String) {
        let challenge_response = exchange_one_http_request(
            kernel,
            &http_post_request(
                "/challenge",
                &serde_json::json!({ "instance_id": instance_id }).to_string(),
            ),
        );
        assert!(
            challenge_response.starts_with("HTTP/1.1 200"),
            "POST /challenge must return 200: {challenge_response}"
        );
        let challenge_value: serde_json::Value =
            serde_json::from_str(http_body(&challenge_response))
                .expect("POST /challenge must return JSON");
        let present_body = serde_json::json!({
            "instance_id": instance_id,
            "capability_id": capability_id,
            "intent": "read",
            "audience": audience,
            "holder_secret_path": holder_path,
            "challenge_nonce": challenge_value["challenge_nonce"],
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let present_response =
            exchange_one_http_request(kernel, &http_post_request("/present-wimse", &present_body));
        assert!(
            present_response.starts_with("HTTP/1.1 200"),
            "POST /present-wimse must return 200: {present_response}"
        );
        let present_value: serde_json::Value = serde_json::from_str(http_body(&present_response))
            .expect("POST /present-wimse must return JSON");
        (
            present_value["presentation_json"]
                .as_str()
                .expect("POST /present-wimse must return presentation_json")
                .to_string(),
            present_value["workload_identity_token"]
                .as_str()
                .expect("POST /present-wimse must return workload_identity_token")
                .to_string(),
            present_value["content_digest"]
                .as_str()
                .expect("POST /present-wimse must return content_digest")
                .to_string(),
            present_value["signature_input"]
                .as_str()
                .expect("POST /present-wimse must return signature_input")
                .to_string(),
            present_value["signature"]
                .as_str()
                .expect("POST /present-wimse must return signature")
                .to_string(),
        )
    }

    fn laboratory_runtime_check_wimse_body(
        check_base: &str,
        presentation_json: &str,
        workload_identity_token: &str,
        content_digest: &str,
        signature_input: &str,
        signature: &str,
        holder_path: &str,
    ) -> String {
        serde_json::json!({
            "check_base": check_base,
            "presentation_json": presentation_json,
            "workload_identity_token": workload_identity_token,
            "content_digest": content_digest,
            "signature_input": signature_input,
            "signature": signature,
            "holder_secret_path": holder_path,
        })
        .to_string()
    }

    fn assert_runtime_check_result(
        kernel: &crate::kernel::Kernel,
        body: &str,
        expect_allowed: bool,
        label: &str,
    ) -> serde_json::Value {
        let response =
            exchange_one_http_request(kernel, &http_post_request("/runtime-check", body));
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /runtime-check must return JSON");
        if expect_allowed {
            assert!(
                response.starts_with("HTTP/1.1 200"),
                "{label} must allow: {response}"
            );
            assert_eq!(
                value["result"].as_str(),
                Some("allowed"),
                "{label} must allow: {payload}"
            );
        } else {
            assert!(
                response.contains("HTTP/1.1 403"),
                "{label} must refuse: {response}"
            );
            assert_eq!(
                value["result"].as_str(),
                Some("refused"),
                "{label} must refuse: {payload}"
            );
        }
        assert!(
            !payload.contains("issuer.secret"),
            "{label} must not name issuer.secret"
        );
        value
    }

    fn check_svid_body(
        kernel: &crate::kernel::Kernel,
        birth: &crate::kernel::BirthWrite,
        artifact: &crate::svid::X509SvidArtifact,
        certificate_pem: &str,
    ) -> String {
        let nonce = kernel
            .issue_holder_challenge(&birth.instance.id)
            .expect("issue a holder challenge for check")
            .nonce;
        let secret = kernel
            .store()
            .holder_secret_path(&birth.instance.id)
            .display()
            .to_string();
        serde_json::json!({
            "presentation_json": artifact.presentation_json,
            "certificate_pem": certificate_pem,
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": secret,
            "challenge_nonce": nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string()
    }

    #[test]
    fn the_host_check_svid_path_allows_an_honest_wrap() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let artifact = laboratory_svid_wrap(&kernel, &birth);
        let body = check_svid_body(&kernel, &birth, &artifact, &artifact.certificate_pem);
        let decision = super::check_svid_request_from_json(&kernel, body.as_bytes())
            .expect("the host check-svid path must return a decision");
        assert_eq!(decision.result, "allowed");
        assert_eq!(decision.instance_id, birth.instance.id);
        assert_eq!(
            decision.capability_id.as_deref(),
            Some(birth.capability.id.as_str())
        );
        assert_eq!(decision.intent, "read");
        assert_eq!(decision.audience, "internal");
        assert_eq!(decision.on_behalf_of.as_deref(), Some("autonomous"));
        assert!(
            decision.receipt.is_some(),
            "an honest wrap that is allowed must still sign a check decision receipt"
        );
    }

    #[test]
    fn the_host_check_svid_path_refuses_after_local_kill() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let artifact = laboratory_svid_wrap(&kernel, &birth);
        kernel
            .verify_x509_svid(
                &artifact.certificate_pem,
                artifact.presentation_json.as_bytes(),
            )
            .expect("the live wrap must verify before local kill");
        let body = check_svid_body(&kernel, &birth, &artifact, &artifact.certificate_pem);
        kernel
            .kill_instance(&birth.instance.id)
            .expect("same store must persist local kill");
        let decision = super::check_svid_request_from_json(&kernel, body.as_bytes())
            .expect("the host check-svid path must return a decision");
        assert_eq!(decision.result, "refused");
        let reason = decision.reason.unwrap_or_default();
        assert!(
            reason.contains("local kill"),
            "the host check-svid path must refuse after local kill on the wrap, not only after check revoke: {reason}"
        );
        assert!(
            decision.receipt.is_none(),
            "a refused wrap must not sign a new decision receipt"
        );
    }

    #[test]
    fn the_host_check_svid_path_refuses_a_pem_resigned_with_a_foreign_envelope_key() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let artifact = laboratory_svid_wrap(&kernel, &birth);
        kernel
            .verify_x509_svid(
                &artifact.certificate_pem,
                artifact.presentation_json.as_bytes(),
            )
            .expect("the live wrap signed with the laboratory envelope key must verify");
        let foreign = crate::tokens::generate_keypair();
        let foreign_secret = crate::tokens::private_key_hexadecimal(&foreign);
        let resigned = crate::svid::emit_laboratory_x509_svid(
            artifact.presentation_json.as_bytes(),
            &foreign_secret,
            artifact.presentation.presented_at,
            artifact.presentation.expires_at,
        )
        .expect("emit a wrap signed with a foreign envelope key");
        let body = check_svid_body(&kernel, &birth, &artifact, &resigned);
        let decision = super::check_svid_request_from_json(&kernel, body.as_bytes())
            .expect("the host check-svid path must return a decision");
        assert_eq!(decision.result, "refused");
        let reason = decision.reason.unwrap_or_default();
        assert!(
            reason.contains("envelope key") || reason.contains("resigned"),
            "the host check-svid path must refuse a PEM resigned with a foreign envelope key: {reason}"
        );
        assert!(
            !reason.contains("kill"),
            "this refuse is envelope key mismatch, not kill: {reason}"
        );
        assert!(
            decision.receipt.is_none(),
            "a resigned wrap must not sign a new decision receipt"
        );
    }

    fn laboratory_wimse_artifact(
        kernel: &crate::kernel::Kernel,
        birth: &crate::kernel::BirthWrite,
    ) -> crate::wimse::WimseArtifact {
        use crate::kernel::HolderProof;

        let nonce = kernel
            .issue_holder_challenge(&birth.instance.id)
            .expect("issue a holder challenge for present")
            .nonce;
        let secret = kernel.store().holder_secret_path(&birth.instance.id);
        kernel
            .present_wimse(
                &birth.instance.id,
                &birth.capability.id,
                Some(&HolderProof::SecretPath(secret)),
                Some(&nonce),
            )
            .expect("emit a live laboratory Workload Identity Token")
    }

    fn check_wimse_body(
        kernel: &crate::kernel::Kernel,
        birth: &crate::kernel::BirthWrite,
        presentation_json: &str,
        workload_identity_token: &str,
        content_digest: &str,
    ) -> String {
        let nonce = kernel
            .issue_holder_challenge(&birth.instance.id)
            .expect("issue a holder challenge for check")
            .nonce;
        let secret = kernel
            .store()
            .holder_secret_path(&birth.instance.id)
            .display()
            .to_string();
        let envelope_secret = kernel
            .store()
            .load_biscuit_secret()
            .expect("load the laboratory Ed25519 envelope secret");
        let (signature_input, signature) = crate::wimse::sign_laboratory_wimse_http_message(
            crate::wimse::LABORATORY_WIMSE_CHECK_METHOD,
            crate::wimse::LABORATORY_WIMSE_CHECK_PATH,
            content_digest,
            &envelope_secret,
        )
        .expect("sign POST /check-wimse with the laboratory envelope key");
        serde_json::json!({
            "presentation_json": presentation_json,
            "workload_identity_token": workload_identity_token,
            "content_digest": content_digest,
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": secret,
            "challenge_nonce": nonce,
            "on_behalf_of": "autonomous",
            "signature_input": signature_input,
            "signature": signature,
        })
        .to_string()
    }

    fn laboratory_wimse_http_signature(
        kernel: &crate::kernel::Kernel,
        request_target: &str,
        content_digest: &str,
    ) -> (String, String) {
        let envelope_secret = kernel
            .store()
            .load_biscuit_secret()
            .expect("load the laboratory Ed25519 envelope secret");
        crate::wimse::sign_laboratory_wimse_http_message(
            "POST",
            request_target,
            content_digest,
            &envelope_secret,
        )
        .expect("sign the laboratory WIMSE HTTP Message Signature")
    }

    fn http_post_request_with_signature(
        path: &str,
        body: &str,
        signature_input: &str,
        signature: &str,
    ) -> String {
        format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nSignature-Input: {signature_input}\r\nSignature: {signature}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    #[test]
    fn the_host_wimse_path_allows_an_honest_present() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let artifact = laboratory_wimse_artifact(&kernel, &birth);
        assert!(
            artifact.presentation_json.contains(&birth.instance.id),
            "the instance identifier must stay inside the present"
        );
        assert!(
            !artifact
                .workload_identity_token
                .contains(&birth.instance.id),
            "the instance identifier must not appear in the Workload Identity Token"
        );
        assert!(
            !artifact.wimse_uri.contains(&birth.instance.id),
            "the instance identifier must not appear in the token subject"
        );
        let body = check_wimse_body(
            &kernel,
            &birth,
            &artifact.presentation_json,
            &artifact.workload_identity_token,
            &artifact.content_digest,
        );
        let decision = super::check_wimse_request_from_json(&kernel, body.as_bytes())
            .expect("the host check-wimse path must return a decision");
        assert_eq!(decision.result, "allowed");
        assert_eq!(decision.instance_id, birth.instance.id);
        assert_eq!(
            decision.capability_id.as_deref(),
            Some(birth.capability.id.as_str())
        );
        assert_eq!(decision.intent, "read");
        assert_eq!(decision.audience, "internal");
        assert_eq!(decision.on_behalf_of.as_deref(), Some("autonomous"));
        assert!(
            decision.receipt.is_some(),
            "an honest present that is allowed must still sign a check decision receipt"
        );
    }

    #[test]
    fn the_host_wimse_path_refuses_after_local_kill() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let artifact = laboratory_wimse_artifact(&kernel, &birth);
        kernel
            .verify_wimse(
                &artifact.workload_identity_token,
                &artifact.content_digest,
                artifact.presentation_json.as_bytes(),
            )
            .expect("the live token must verify before local kill");
        let body = check_wimse_body(
            &kernel,
            &birth,
            &artifact.presentation_json,
            &artifact.workload_identity_token,
            &artifact.content_digest,
        );
        kernel
            .kill_instance(&birth.instance.id)
            .expect("same store must persist local kill");
        let decision = super::check_wimse_request_from_json(&kernel, body.as_bytes())
            .expect("the host check-wimse path must return a decision");
        assert_eq!(decision.result, "refused");
        let reason = decision.reason.unwrap_or_default();
        assert!(
            reason.contains("local kill") || reason.contains("revoked instance"),
            "the host check-wimse path must refuse after local kill on the token, not only after check revoke: {reason}"
        );
        assert!(
            decision.receipt.is_none(),
            "a refused present must not sign a new decision receipt"
        );
    }

    #[test]
    fn the_host_wimse_path_refuses_a_swapped_present_body() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let artifact = laboratory_wimse_artifact(&kernel, &birth);
        let swapped = artifact
            .presentation_json
            .replace("\"intent\": \"read\"", "\"intent\": \"write\"");
        assert_ne!(
            swapped, artifact.presentation_json,
            "the swapped body must differ from the bound present bytes"
        );
        let body = check_wimse_body(
            &kernel,
            &birth,
            &swapped,
            &artifact.workload_identity_token,
            &artifact.content_digest,
        );
        let decision = super::check_wimse_request_from_json(&kernel, body.as_bytes())
            .expect("the host check-wimse path must return a decision");
        assert_eq!(decision.result, "refused");
        let reason = decision.reason.unwrap_or_default();
        assert!(
            reason.contains("Content-Digest") || reason.contains("swapped"),
            "the host check-wimse path must refuse a swapped present body: {reason}"
        );
        assert!(
            decision.receipt.is_none(),
            "a swapped present must not sign a new decision receipt"
        );
    }

    #[test]
    fn the_host_wimse_path_refuses_instance_identifier_in_sub() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let artifact = laboratory_wimse_artifact(&kernel, &birth);
        let envelope_secret = kernel
            .store()
            .load_biscuit_secret()
            .expect("load the laboratory Ed25519 envelope secret");
        let envelope_public = kernel
            .store()
            .load_issuer()
            .expect("load the issuer")
            .biscuit_public_key_hex;
        let illegal_sub = format!(
            "wimse://prometheus.laboratory/present/{}",
            birth.instance.id
        );
        let illegal = crate::wimse::emit_illegal_laboratory_wit(
            artifact.presentation_json.as_bytes(),
            &envelope_secret,
            &envelope_public,
            artifact.presentation.presented_at,
            artifact.presentation.expires_at,
            &illegal_sub,
        )
        .expect("emit a token with a forbidden subject");
        let body = check_wimse_body(
            &kernel,
            &birth,
            &artifact.presentation_json,
            &illegal,
            &artifact.content_digest,
        );
        let decision = super::check_wimse_request_from_json(&kernel, body.as_bytes())
            .expect("the host check-wimse path must return a decision");
        assert_eq!(decision.result, "refused");
        let reason = decision.reason.unwrap_or_default();
        assert!(
            reason.contains("instance identifier") || reason.contains("subject"),
            "the host check-wimse path must refuse an instance identifier in sub: {reason}"
        );
        assert!(
            decision.receipt.is_none(),
            "a forbidden subject must not sign a new decision receipt"
        );
    }

    #[test]
    fn the_host_wimse_check_allows_an_honest_method_and_target_signature() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let artifact = laboratory_wimse_artifact(&kernel, &birth);
        let (signature_input, signature) =
            laboratory_wimse_http_signature(&kernel, "/check-wimse", &artifact.content_digest);
        let body = check_wimse_body(
            &kernel,
            &birth,
            &artifact.presentation_json,
            &artifact.workload_identity_token,
            &artifact.content_digest,
        );
        let response = exchange_one_http_request(
            &kernel,
            &http_post_request_with_signature("/check-wimse", &body, &signature_input, &signature),
        );
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /check-wimse with an honest method and request-target signature must allow: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /check-wimse must return JSON");
        assert_eq!(value["result"].as_str(), Some("allowed"));
        assert_eq!(
            value["instance_id"].as_str(),
            Some(birth.instance.id.as_str())
        );
        assert!(
            value["receipt"].is_object(),
            "an honest signed WIMSE check must still sign a decision receipt"
        );
    }

    #[test]
    fn the_host_wimse_check_refuses_a_signature_for_a_different_path() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let artifact = laboratory_wimse_artifact(&kernel, &birth);
        let (signature_input, signature) =
            laboratory_wimse_http_signature(&kernel, "/check-svid", &artifact.content_digest);
        let body = serde_json::json!({
            "presentation_json": artifact.presentation_json,
            "workload_identity_token": artifact.workload_identity_token,
            "content_digest": artifact.content_digest,
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": kernel.store().holder_secret_path(&birth.instance.id).display().to_string(),
            "challenge_nonce": kernel.issue_holder_challenge(&birth.instance.id).expect("issue a holder challenge").nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let response = exchange_one_http_request(
            &kernel,
            &http_post_request_with_signature("/check-wimse", &body, &signature_input, &signature),
        );
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /check-wimse must refuse a signature over a different path: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /check-wimse must return JSON");
        assert_eq!(value["result"].as_str(), Some("refused"));
        let reason = value["reason"].as_str().unwrap_or("");
        assert!(
            reason.contains("request-target")
                || reason.contains("different")
                || reason.contains("envelope key")
                || reason.contains("HTTP Message Signature"),
            "the host must name the different-path signature refuse: {reason}"
        );
        assert!(
            value["receipt"].is_null(),
            "a refused different-path signature must not sign a new decision receipt"
        );
    }

    #[test]
    fn the_host_wimse_check_refuses_a_missing_signature() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let artifact = laboratory_wimse_artifact(&kernel, &birth);
        let body = serde_json::json!({
            "presentation_json": artifact.presentation_json,
            "workload_identity_token": artifact.workload_identity_token,
            "content_digest": artifact.content_digest,
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": kernel.store().holder_secret_path(&birth.instance.id).display().to_string(),
            "challenge_nonce": kernel.issue_holder_challenge(&birth.instance.id).expect("issue a holder challenge").nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let response =
            exchange_one_http_request(&kernel, &http_post_request("/check-wimse", &body));
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /check-wimse must refuse a missing HTTP Message Signature: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /check-wimse must return JSON");
        assert_eq!(value["result"].as_str(), Some("refused"));
        let reason = value["reason"].as_str().unwrap_or("");
        assert!(
            reason.contains("missing") || reason.contains("HTTP Message Signature"),
            "the host must name the missing-signature refuse: {reason}"
        );
        assert!(
            value["receipt"].is_null(),
            "a missing signature must not sign a new decision receipt"
        );
    }

    #[test]
    fn the_host_wimse_check_refuses_a_wrong_method() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let response = exchange_one_http_request(
            &kernel,
            "GET /check-wimse HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            response.contains("HTTP/1.1 403"),
            "GET /check-wimse must refuse the bound method: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("method") || payload.contains("@method"),
            "GET /check-wimse must name the method refuse: {payload}"
        );
    }

    #[test]
    fn the_host_wimse_check_refuses_a_signature_that_is_not_the_envelope_key() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let artifact = laboratory_wimse_artifact(&kernel, &birth);
        let foreign = crate::tokens::generate_keypair();
        let foreign_secret = crate::tokens::private_key_hexadecimal(&foreign);
        let (signature_input, signature) = crate::wimse::sign_laboratory_wimse_http_message(
            crate::wimse::LABORATORY_WIMSE_CHECK_METHOD,
            crate::wimse::LABORATORY_WIMSE_CHECK_PATH,
            &artifact.content_digest,
            &foreign_secret,
        )
        .expect("sign with a foreign envelope key");
        let body = serde_json::json!({
            "presentation_json": artifact.presentation_json,
            "workload_identity_token": artifact.workload_identity_token,
            "content_digest": artifact.content_digest,
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": kernel.store().holder_secret_path(&birth.instance.id).display().to_string(),
            "challenge_nonce": kernel.issue_holder_challenge(&birth.instance.id).expect("issue a holder challenge").nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let response = exchange_one_http_request(
            &kernel,
            &http_post_request_with_signature("/check-wimse", &body, &signature_input, &signature),
        );
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /check-wimse must refuse a signature that is not the envelope key: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /check-wimse must return JSON");
        assert_eq!(value["result"].as_str(), Some("refused"));
        let reason = value["reason"].as_str().unwrap_or("");
        assert!(
            reason.contains("envelope key") || reason.contains("HTTP Message Signature"),
            "the host must name the envelope-key signature refuse: {reason}"
        );
        assert!(
            value["receipt"].is_null(),
            "a foreign-key signature must not sign a new decision receipt"
        );
    }

    #[test]
    fn the_host_wimse_check_allows_when_the_signature_covers_content_digest() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let artifact = laboratory_wimse_artifact(&kernel, &birth);
        let (signature_input, signature) =
            laboratory_wimse_http_signature(&kernel, "/check-wimse", &artifact.content_digest);
        assert!(
            signature_input.contains("content-digest"),
            "Signature-Input must cover content-digest: {signature_input}"
        );
        let body = check_wimse_body(
            &kernel,
            &birth,
            &artifact.presentation_json,
            &artifact.workload_identity_token,
            &artifact.content_digest,
        );
        let response = exchange_one_http_request(
            &kernel,
            &http_post_request_with_signature("/check-wimse", &body, &signature_input, &signature),
        );
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /check-wimse with a signature that covers content-digest must allow: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /check-wimse must return JSON");
        assert_eq!(value["result"].as_str(), Some("allowed"));
        assert!(
            value["receipt"].is_object(),
            "an honest content-digest signature must still sign a decision receipt"
        );
    }

    #[test]
    fn the_host_wimse_check_refuses_a_signature_that_omits_content_digest() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let artifact = laboratory_wimse_artifact(&kernel, &birth);
        let envelope_secret = kernel
            .store()
            .load_biscuit_secret()
            .expect("load the laboratory Ed25519 envelope secret");
        let (signature_input, signature) =
            crate::wimse::sign_laboratory_wimse_http_message_omitting_content_digest(
                crate::wimse::LABORATORY_WIMSE_CHECK_METHOD,
                crate::wimse::LABORATORY_WIMSE_CHECK_PATH,
                &envelope_secret,
            )
            .expect("sign without content-digest");
        assert!(
            !signature_input.contains("content-digest"),
            "the omit fixture must not cover content-digest: {signature_input}"
        );
        let body = serde_json::json!({
            "presentation_json": artifact.presentation_json,
            "workload_identity_token": artifact.workload_identity_token,
            "content_digest": artifact.content_digest,
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": kernel.store().holder_secret_path(&birth.instance.id).display().to_string(),
            "challenge_nonce": kernel.issue_holder_challenge(&birth.instance.id).expect("issue a holder challenge").nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let response = exchange_one_http_request(
            &kernel,
            &http_post_request_with_signature("/check-wimse", &body, &signature_input, &signature),
        );
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /check-wimse must refuse a signature that omits content-digest: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /check-wimse must return JSON");
        assert_eq!(value["result"].as_str(), Some("refused"));
        let reason = value["reason"].as_str().unwrap_or("");
        assert!(
            reason.contains("content-digest") || reason.contains("Content-Digest"),
            "the host must name the omitted content-digest refuse: {reason}"
        );
        assert!(
            value["receipt"].is_null(),
            "a signature that omits content-digest must not sign a new decision receipt"
        );
    }

    #[test]
    fn the_host_wimse_check_refuses_a_signature_over_a_different_digest() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let artifact = laboratory_wimse_artifact(&kernel, &birth);
        let other_digest = crate::wimse::content_digest_sha256(b"other-present-bytes");
        assert_ne!(
            other_digest, artifact.content_digest,
            "the other digest must differ from the present digest"
        );
        let (signature_input, signature) =
            laboratory_wimse_http_signature(&kernel, "/check-wimse", &other_digest);
        let body = serde_json::json!({
            "presentation_json": artifact.presentation_json,
            "workload_identity_token": artifact.workload_identity_token,
            "content_digest": artifact.content_digest,
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": kernel.store().holder_secret_path(&birth.instance.id).display().to_string(),
            "challenge_nonce": kernel.issue_holder_challenge(&birth.instance.id).expect("issue a holder challenge").nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let response = exchange_one_http_request(
            &kernel,
            &http_post_request_with_signature("/check-wimse", &body, &signature_input, &signature),
        );
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /check-wimse must refuse a signature over a different digest: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /check-wimse must return JSON");
        assert_eq!(value["result"].as_str(), Some("refused"));
        let reason = value["reason"].as_str().unwrap_or("");
        assert!(
            reason.contains("digest")
                || reason.contains("envelope key")
                || reason.contains("HTTP Message Signature"),
            "the host must name the different-digest signature refuse: {reason}"
        );
        assert!(
            value["receipt"].is_null(),
            "a signature over a different digest must not sign a new decision receipt"
        );
    }

    fn exchange_one_http_request(kernel: &crate::kernel::Kernel, request: &str) -> String {
        exchange_one_http_request_with_mode(kernel, request, &super::HostMode::issuing_loopback())
    }

    fn exchange_one_http_request_with_mode(
        kernel: &crate::kernel::Kernel,
        request: &str,
        mode: &super::HostMode,
    ) -> String {
        use std::io::{Read, Write};
        use std::net::{Shutdown, TcpListener, TcpStream};
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback test listener");
        let address = listener
            .local_addr()
            .expect("read the bound loopback address");
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let (mut stream, _) = listener
                    .accept()
                    .expect("accept one loopback test connection");
                super::handle_client(kernel, &mut stream, mode).expect("handle the test client");
            });
            let mut client = TcpStream::connect(address).expect("connect to the test host");
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set a read timeout");
            client
                .set_write_timeout(Some(Duration::from_secs(5)))
                .expect("set a write timeout");
            client
                .write_all(request.as_bytes())
                .expect("write the HTTP request");
            let _ = client.shutdown(Shutdown::Write);
            let mut response = String::new();
            client
                .read_to_string(&mut response)
                .expect("read the HTTP response");
            response
        })
    }

    fn http_body(response: &str) -> &str {
        response.split("\r\n\r\n").nth(1).unwrap_or("")
    }

    #[test]
    fn the_host_status_path_returns_live_and_revoked_counts_without_secrets() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let live_birth = laboratory_host_birth(&kernel);
        let revoked_birth = kernel
            .birth_write(
                &live_birth.instance.agent_type_id,
                "laboratory".to_string(),
                std::collections::BTreeMap::new(),
                "read",
                "internal",
                None,
            )
            .expect("birth a second instance");
        kernel
            .kill_instance(&revoked_birth.instance.id)
            .expect("revoke the second instance");

        let response = exchange_one_http_request(
            &kernel,
            "GET /status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "GET /status must return 200: {response}"
        );
        assert!(
            response.contains("application/json"),
            "GET /status must return JSON: {response}"
        );
        let body = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(body).expect("GET /status must return JSON");
        assert_eq!(
            value["instance_live_count"].as_u64(),
            Some(1),
            "GET /status must include the live instance count"
        );
        assert_eq!(
            value["instance_revoked_count"].as_u64(),
            Some(1),
            "GET /status must include the revoked instance count"
        );

        let store_status = kernel
            .store_status()
            .expect("load store status for the key check");
        let full_key = store_status.current_issuer_public_key_hex.clone();
        let truncated = super::truncated_issuer_public_key_hex(&full_key);
        let shown = value["current_issuer_public_key_hex"]
            .as_str()
            .expect("GET /status must include the truncated issuer public key");
        assert_eq!(
            shown, truncated,
            "GET /status must truncate the issuer public key the same way format_human does"
        );
        if full_key.len() > 16 {
            assert_ne!(
                shown, full_key,
                "GET /status must not return the raw issuer public key"
            );
            assert!(
                !body.contains(&full_key),
                "GET /status must not embed the raw issuer public key"
            );
        }

        let issuer_secret = kernel.store().load_secret().expect("load issuer secret");
        let biscuit_secret = kernel
            .store()
            .load_biscuit_secret()
            .expect("load biscuit secret");
        let holder_secret =
            std::fs::read_to_string(kernel.store().holder_secret_path(&live_birth.instance.id))
                .expect("load holder secret");
        assert!(
            !body.contains(&issuer_secret),
            "the status path must not include issuer secret material"
        );
        assert!(
            !body.contains(&biscuit_secret),
            "the status path must not include biscuit secret material"
        );
        assert!(
            !body.contains(&holder_secret),
            "the status path must not include holder secret material"
        );
        assert!(
            !body.contains("issuer.secret"),
            "the status path must not name issuer.secret"
        );
        assert!(
            !body.contains("biscuit.secret"),
            "the status path must not name biscuit.secret"
        );
        assert!(
            !body.contains("member-two.secret"),
            "the status path must not name member-two.secret"
        );
    }

    #[test]
    fn the_host_issuer_public_path_returns_the_full_current_public_key() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");

        let response = exchange_one_http_request(
            &kernel,
            "GET /issuer-public HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "GET /issuer-public must return 200: {response}"
        );
        assert!(
            response.contains("application/json"),
            "GET /issuer-public must return JSON: {response}"
        );
        let body = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(body).expect("GET /issuer-public must return JSON");
        let object = value
            .as_object()
            .expect("GET /issuer-public must return a JSON object");
        assert_eq!(
            object.len(),
            2,
            "GET /issuer-public must return the full current issuer public key hexadecimal and the crypto profile only: {body}"
        );

        let store_status = kernel
            .store_status()
            .expect("load store status for the key check");
        let full_key = store_status.current_issuer_public_key_hex.clone();
        let truncated = super::truncated_issuer_public_key_hex(&full_key);
        let shown = value["current_issuer_public_key_hex"].as_str().expect(
            "GET /issuer-public must include the full current issuer public key hexadecimal",
        );
        assert_eq!(
            shown, full_key,
            "GET /issuer-public must return the full current issuer public key hexadecimal"
        );
        assert!(
            full_key.len() > 16,
            "the current issuer public key must be longer than the truncated status view"
        );
        assert_ne!(
            shown, truncated,
            "GET /issuer-public must not truncate the issuer public key"
        );
        assert_eq!(
            value["crypto_profile"].as_str(),
            Some(store_status.crypto_profile.as_str()),
            "GET /issuer-public must include the crypto profile only as the second field"
        );
    }

    #[test]
    fn the_host_issuer_public_path_does_not_return_secrets() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let live_birth = laboratory_host_birth(&kernel);

        let response = exchange_one_http_request(
            &kernel,
            "GET /issuer-public HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "GET /issuer-public must return 200: {response}"
        );
        let body = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(body).expect("GET /issuer-public must return JSON");
        let object = value
            .as_object()
            .expect("GET /issuer-public must return a JSON object");
        assert_eq!(
            object.len(),
            2,
            "GET /issuer-public must not grow past the public key and the crypto profile: {body}"
        );
        assert!(
            object.contains_key("current_issuer_public_key_hex"),
            "GET /issuer-public must name current_issuer_public_key_hex"
        );
        assert!(
            object.contains_key("crypto_profile"),
            "GET /issuer-public must name crypto_profile"
        );
        assert!(
            !object.contains_key("biscuit_public_key_hex"),
            "GET /issuer-public must not return the Biscuit envelope public key"
        );
        assert!(
            !object.contains_key("accepted_issuer_public_keys"),
            "GET /issuer-public must not return the accepted issuer public key list"
        );

        let issuer_secret = kernel.store().load_secret().expect("load issuer secret");
        let biscuit_secret = kernel
            .store()
            .load_biscuit_secret()
            .expect("load biscuit secret");
        let holder_secret =
            std::fs::read_to_string(kernel.store().holder_secret_path(&live_birth.instance.id))
                .expect("load holder secret");
        let issuer = kernel.store().load_issuer().expect("load issuer");
        assert!(
            !issuer_secret.is_empty(),
            "the issuer secret must exist so the absence check is real"
        );
        assert!(
            !body.contains(&issuer_secret),
            "the issuer-public path must not include issuer secret material"
        );
        assert!(
            !body.contains(&biscuit_secret),
            "the issuer-public path must not include biscuit secret material"
        );
        assert!(
            !body.contains(&holder_secret),
            "the issuer-public path must not include holder secret material"
        );
        assert!(
            !body.contains("issuer.secret"),
            "the issuer-public path must not name issuer.secret"
        );
        assert!(
            !body.contains("biscuit.secret"),
            "the issuer-public path must not name biscuit.secret"
        );
        assert!(
            !body.contains("member-two.secret"),
            "the issuer-public path must not name member-two.secret"
        );
        if !issuer.biscuit_public_key_hex.is_empty() {
            assert!(
                !body.contains(&issuer.biscuit_public_key_hex),
                "the issuer-public path must not include the Biscuit envelope public key"
            );
        }
    }

    #[test]
    fn the_host_well_known_check_document_is_served_on_loopback() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let response = exchange_one_http_request(
            &kernel,
            "GET /.well-known/prometheus-check HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "GET /.well-known/prometheus-check must return 200: {response}"
        );
        assert!(
            response.contains("application/json"),
            "GET /.well-known/prometheus-check must return JSON: {response}"
        );
        let body = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(body).expect("GET /.well-known/prometheus-check must return JSON");
        assert_eq!(
            value["laboratory_name"].as_str(),
            Some("prometheus-check"),
            "the well-known document must use the laboratory name"
        );
        assert_eq!(
            value["bind"].as_str(),
            Some("127.0.0.1"),
            "the well-known document must state bind 127.0.0.1"
        );
        assert_eq!(
            value["refuses_other_interfaces"].as_bool(),
            Some(true),
            "the well-known document must state that this host refuses other interfaces"
        );
        let checks = value["checks"]
            .as_array()
            .expect("the well-known document must list checks");
        let check_paths: Vec<&str> = checks
            .iter()
            .filter_map(|check| check["path"].as_str())
            .collect();
        assert!(
            check_paths.contains(&"/check-svid"),
            "the well-known document must point at POST /check-svid: {body}"
        );
        assert!(
            check_paths.contains(&"/check-wimse"),
            "the well-known document must point at POST /check-wimse: {body}"
        );
        assert!(
            checks
                .iter()
                .all(|check| check["method"].as_str() == Some("POST")),
            "the well-known document must name POST for each check path: {body}"
        );
        assert_eq!(
            value["verifier_challenge"]["method"].as_str(),
            Some("POST"),
            "the well-known document must name POST /verifier-challenge: {body}"
        );
        assert_eq!(
            value["verifier_challenge"]["path"].as_str(),
            Some("/verifier-challenge"),
            "the well-known document must name POST /verifier-challenge: {body}"
        );
        let store_b_check = value["store_b_check"]
            .as_str()
            .expect("the well-known document must describe the Store B check");
        assert!(
            store_b_check.contains("holder signature") && store_b_check.contains("nonce"),
            "the well-known document must say a Store B check needs a holder signature over that nonce: {body}"
        );
        let pin_paths = value["operator_pin_paths"]
            .as_array()
            .expect("the well-known document must name operator pin paths");
        let pin_names: Vec<&str> = pin_paths
            .iter()
            .filter_map(|path| path["path"].as_str())
            .collect();
        assert!(
            pin_names.contains(&"/seal-export"),
            "the well-known document must name POST /seal-export as an operator pin path: {body}"
        );
        assert!(
            pin_names.contains(&"/seal-accept"),
            "the well-known document must name POST /seal-accept as an operator pin path: {body}"
        );
        assert!(
            pin_names.contains(&"/previous-key-export"),
            "the well-known document must name POST /previous-key-export as an operator pin path: {body}"
        );
        assert!(
            pin_names.contains(&"/previous-key-accept"),
            "the well-known document must name POST /previous-key-accept as an operator pin path: {body}"
        );
        assert!(
            pin_paths
                .iter()
                .all(|path| path["method"].as_str() == Some("POST")),
            "operator pin paths must use POST: {body}"
        );
        assert_eq!(
            value["present"].as_str(),
            Some("document"),
            "present must stay a document"
        );
        let on_ramp = value["on_ramp_artifacts"]
            .as_array()
            .expect("the well-known document must name on-ramp artifacts");
        let on_ramp_names: Vec<&str> = on_ramp.iter().filter_map(|item| item.as_str()).collect();
        assert!(
            on_ramp_names.contains(&"X.509-SVID") && on_ramp_names.contains(&"WIMSE"),
            "X.509-SVID and WIMSE must stay on-ramp artifacts: {body}"
        );
        assert_eq!(
            value["death_wins"].as_bool(),
            Some(true),
            "death must still win"
        );
        assert_eq!(
            value["short_life_is_not_kill"].as_bool(),
            Some(true),
            "short certificate or token life is not kill"
        );
        assert_eq!(
            value["instance_identifier_in_path"].as_bool(),
            Some(false),
            "the instance identifier must not be in the well-known path"
        );
        let post = exchange_one_http_request(
            &kernel,
            &http_post_request("/.well-known/prometheus-check", "{}"),
        );
        assert!(
            post.contains("HTTP/1.1 404"),
            "POST /.well-known/prometheus-check must not dispatch a second check: {post}"
        );
    }

    #[test]
    fn the_host_well_known_check_document_contains_no_secrets_or_instance_identifiers() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let live_birth = laboratory_host_birth(&kernel);
        let response = exchange_one_http_request(
            &kernel,
            "GET /.well-known/prometheus-check HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "GET /.well-known/prometheus-check must return 200: {response}"
        );
        let body = http_body(&response);
        serde_json::from_str::<serde_json::Value>(body)
            .expect("GET /.well-known/prometheus-check must return JSON");
        assert!(
            !body.contains(&live_birth.instance.id),
            "the well-known document must not include an instance identifier"
        );
        assert!(
            !body.contains(&live_birth.capability.id),
            "the well-known document must not include a capability identifier"
        );
        let issuer_secret = kernel.store().load_secret().expect("load issuer secret");
        let biscuit_secret = kernel
            .store()
            .load_biscuit_secret()
            .expect("load biscuit secret");
        let holder_secret =
            std::fs::read_to_string(kernel.store().holder_secret_path(&live_birth.instance.id))
                .expect("load holder secret");
        assert!(
            !body.contains(&issuer_secret),
            "the well-known document must not include issuer secret material"
        );
        assert!(
            !body.contains(&biscuit_secret),
            "the well-known document must not include biscuit secret material"
        );
        assert!(
            !body.contains(&holder_secret),
            "the well-known document must not include holder secret material"
        );
        assert!(
            !body.contains("issuer.secret"),
            "the well-known document must not name issuer.secret"
        );
        assert!(
            !body.contains("biscuit.secret"),
            "the well-known document must not name biscuit.secret"
        );
        assert!(
            !body.contains("member-two.secret"),
            "the well-known document must not name member-two.secret"
        );
        let issuer = kernel
            .store()
            .load_issuer()
            .expect("load the issuer for the secret-material check");
        let current_public_key = issuer.current_public_key_hex();
        if !current_public_key.is_empty() {
            assert!(
                !body.contains(&current_public_key),
                "the well-known document must not include issuer public key material"
            );
        }
        if !issuer.biscuit_public_key_hex.is_empty() {
            assert!(
                !body.contains(&issuer.biscuit_public_key_hex),
                "the well-known document must not include the Biscuit envelope public key"
            );
        }
    }

    #[test]
    fn check_only_host_refuses_create_agent_principal_and_sign_holder_nonce() {
        let (_directory, kernel) = laboratory_verifier_kernel();
        let mode = super::HostMode::check_only_loopback();
        super::prepare_host_store(&kernel, &mode)
            .expect("a check-only host must start on a Store B verifier store");
        let birth_body = serde_json::json!({
            "agent_type_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "intent": "read",
            "audience": "internal",
        })
        .to_string();
        let birth_response = exchange_one_http_request_with_mode(
            &kernel,
            &http_post_request("/birth", &birth_body),
            &mode,
        );
        assert!(
            birth_response.contains("HTTP/1.1 403"),
            "check-only POST /birth must be refused: {birth_response}"
        );
        let birth_payload = http_body(&birth_response);
        assert!(
            birth_payload.contains("check-only")
                && birth_payload.contains("Create Agent Principal"),
            "check-only POST /birth must name Create Agent Principal: {birth_payload}"
        );
        let sign_body = serde_json::json!({
            "holder_secret_path": "/tmp/holder.secret",
        })
        .to_string();
        let sign_response = exchange_one_http_request_with_mode(
            &kernel,
            &http_post_request("/sign-holder-nonce", &sign_body),
            &mode,
        );
        assert!(
            sign_response.contains("HTTP/1.1 403"),
            "check-only POST /sign-holder-nonce must be refused: {sign_response}"
        );
        let root_response = exchange_one_http_request_with_mode(
            &kernel,
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            &mode,
        );
        assert!(
            root_response.starts_with("HTTP/1.1 200"),
            "check-only GET / may return a small JSON status: {root_response}"
        );
        let root_body = http_body(&root_response);
        assert!(
            !root_body.contains("Create Agent Principal"),
            "check-only GET / must not offer Create Agent Principal: {root_body}"
        );
        assert!(
            !root_body.contains("issuer.secret")
                && !root_body.contains("biscuit.secret")
                && !root_body.contains("holder.secret"),
            "check-only GET / must not include secrets: {root_body}"
        );
        let laboratory = exchange_one_http_request_with_mode(
            &kernel,
            "GET /laboratory HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            &mode,
        );
        assert!(
            laboratory.contains("HTTP/1.1 403"),
            "check-only GET /laboratory write forms must be refused: {laboratory}"
        );
        let laboratory_body = http_body(&laboratory);
        assert!(
            !laboratory_body.contains("<form")
                && !laboratory_body.contains("POST /birth")
                && !laboratory_body.contains("text/html"),
            "check-only GET /laboratory must not serve write forms: {laboratory_body}"
        );
    }

    #[test]
    fn check_only_host_refuses_spawn_and_assertion_act_mint() {
        let (_directory, kernel) = laboratory_verifier_kernel();
        let mode = super::HostMode::check_only_loopback();
        super::prepare_host_store(&kernel, &mode)
            .expect("a check-only host must start on a Store B verifier store");
        for path in [
            "/spawn",
            "/present-svid",
            "/present-wimse",
            "/agent-type",
            "/rotate",
            "/kill",
            "/seal",
            "/seal-export",
            "/challenge",
            "/act-export",
            "/kill-export",
        ] {
            let response =
                exchange_one_http_request_with_mode(&kernel, &http_post_request(path, "{}"), &mode);
            assert!(
                response.contains("HTTP/1.1 403"),
                "check-only POST {path} must be refused: {response}"
            );
            let payload = http_body(&response);
            assert!(
                payload.contains("check-only")
                    && (payload.contains("Create Agent Principal") || payload.contains("mint")),
                "check-only POST {path} must name Create Agent Principal or mint: {payload}"
            );
        }
        let public_mode = super::HostMode::check_only_public();
        let public_spawn = exchange_one_http_request_with_mode(
            &kernel,
            &http_post_request("/spawn", "{}"),
            &public_mode,
        );
        assert!(
            public_spawn.contains("HTTP/1.1 403"),
            "public check-only POST /spawn must be refused: {public_spawn}"
        );
    }

    #[test]
    fn the_host_backup_path_writes_outside_and_refuses_inside_the_data_directory() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let backup_directory = tempdir().expect("create a backup directory");
        let backup = backup_directory.path().join("issuer-backup");
        let body = serde_json::json!({
            "path": backup.display().to_string(),
            "confirm": "backup",
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/backup", &body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /backup must write an outside path: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /backup must return JSON");
        let expected_path = backup.display().to_string();
        assert_eq!(
            value["path"].as_str(),
            Some(expected_path.as_str()),
            "POST /backup must return path only: {payload}"
        );
        assert_eq!(
            value.as_object().map(|object| object.len()),
            Some(1),
            "POST /backup must return path only: {payload}"
        );
        assert!(
            backup.join("issuer.json").exists() && backup.join("issuer.secret").exists(),
            "POST /backup must write issuer.json and issuer.secret outside the data directory"
        );
        assert_body_has_no_secrets(&kernel, payload, None, "POST /backup secrets lock");

        let inside = kernel.store().root().join("inside-backup");
        let inside_body = serde_json::json!({
            "path": inside.display().to_string(),
            "confirm": "backup",
        })
        .to_string();
        let inside_response =
            exchange_one_http_request(&kernel, &http_post_request("/backup", &inside_body));
        assert!(
            inside_response.contains("HTTP/1.1 403"),
            "POST /backup inside the data directory must be refused: {inside_response}"
        );
        let inside_payload = http_body(&inside_response);
        assert!(
            inside_payload.contains("data directory"),
            "POST /backup inside the data directory must name the data directory refuse: {inside_payload}"
        );
        assert!(
            !inside.exists(),
            "a refused inside-data-directory backup must not write a backup directory"
        );
    }

    #[test]
    fn the_host_restore_path_refuses_a_store_that_already_has_an_issuer() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let backup_directory = tempdir().expect("create a backup directory");
        let backup = backup_directory.path().join("issuer-backup");
        let backup_body = serde_json::json!({
            "path": backup.display().to_string(),
            "confirm": "backup",
        })
        .to_string();
        let backup_response =
            exchange_one_http_request(&kernel, &http_post_request("/backup", &backup_body));
        assert!(
            backup_response.starts_with("HTTP/1.1 200"),
            "POST /backup must succeed before the restore refuse: {backup_response}"
        );
        let restore_body = serde_json::json!({
            "from": backup.display().to_string(),
            "confirm": "restore",
        })
        .to_string();
        let response =
            exchange_one_http_request(&kernel, &http_post_request("/restore", &restore_body));
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /restore on a live issuing store must be refused: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("already has an issuer") || payload.contains("already"),
            "POST /restore on a live issuing store must name the dest refuse: {payload}"
        );
    }

    #[test]
    fn the_host_restore_path_restores_onto_empty_data_and_diagnose_reports_operation_normal() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let source_directory = tempdir().expect("create a source directory");
        let source = Kernel::open(source_directory.path());
        source.initialize().expect("initialize the source issuer");
        let backup_directory = tempdir().expect("create a backup directory");
        let backup = backup_directory.path().join("issuer-backup");
        let backup_body = serde_json::json!({
            "path": backup.display().to_string(),
            "confirm": "backup",
        })
        .to_string();
        let backup_response =
            exchange_one_http_request(&source, &http_post_request("/backup", &backup_body));
        assert!(
            backup_response.starts_with("HTTP/1.1 200"),
            "POST /backup must succeed on the live issuing host: {backup_response}"
        );

        let dest_directory = tempdir().expect("create an empty restore destination");
        let dest = Kernel::open(dest_directory.path());
        super::prepare_host_store(&dest, &super::HostMode::issuing_loopback()).expect(
            "an issuing host with empty data must start so POST /restore can write",
        );
        let restore_body = serde_json::json!({
            "from": backup.display().to_string(),
            "confirm": "restore",
        })
        .to_string();
        let restore_response =
            exchange_one_http_request(&dest, &http_post_request("/restore", &restore_body));
        assert!(
            restore_response.starts_with("HTTP/1.1 200"),
            "POST /restore onto empty data must succeed: {restore_response}"
        );
        let restore_payload = http_body(&restore_response);
        let restore_value: serde_json::Value = serde_json::from_str(restore_payload)
            .expect("POST /restore must return RestoreDiagnostics JSON");
        assert_eq!(
            restore_value["operation_normal"].as_bool(),
            Some(true),
            "POST /restore must report operation_normal: {restore_payload}"
        );
        assert_eq!(
            restore_value["restore_succeeded"].as_bool(),
            Some(true),
            "POST /restore must report restore_succeeded: {restore_payload}"
        );
        assert_body_has_no_secrets(&dest, restore_payload, None, "POST /restore secrets lock");

        let diagnose_body = serde_json::json!({
            "from": backup.display().to_string(),
        })
        .to_string();
        let diagnose_response =
            exchange_one_http_request(&dest, &http_post_request("/diagnose", &diagnose_body));
        assert!(
            diagnose_response.starts_with("HTTP/1.1 200"),
            "POST /diagnose must succeed after restore: {diagnose_response}"
        );
        let diagnose_payload = http_body(&diagnose_response);
        let diagnose_value: serde_json::Value = serde_json::from_str(diagnose_payload)
            .expect("POST /diagnose must return RestoreDiagnostics JSON");
        assert_eq!(
            diagnose_value["operation_normal"].as_bool(),
            Some(true),
            "POST /diagnose must report operation_normal: {diagnose_payload}"
        );
        assert_body_has_no_secrets(&dest, diagnose_payload, None, "POST /diagnose secrets lock");
    }

    #[test]
    fn cold_restore_present_verifies_on_a_host_that_pinned_the_original_issuer() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let source_directory = tempdir().expect("create a source directory");
        let source = Kernel::open(source_directory.path());
        source.initialize().expect("initialize the source issuer");
        let birth = laboratory_host_birth(&source);
        let backup_directory = tempdir().expect("create a backup directory");
        let backup = backup_directory.path().join("issuer-backup");
        let backup_body = serde_json::json!({
            "path": backup.display().to_string(),
            "confirm": "backup",
        })
        .to_string();
        let backup_response =
            exchange_one_http_request(&source, &http_post_request("/backup", &backup_body));
        assert!(
            backup_response.starts_with("HTTP/1.1 200"),
            "POST /backup must succeed on the live issuing host: {backup_response}"
        );

        let dest_directory = tempdir().expect("create an empty restore destination");
        let dest = Kernel::open(dest_directory.path());
        super::prepare_host_store(&dest, &super::HostMode::issuing_loopback()).expect(
            "an issuing host with empty data must start so POST /restore can write",
        );
        let restore_body = serde_json::json!({
            "from": backup.display().to_string(),
            "confirm": "restore",
        })
        .to_string();
        let restore_response =
            exchange_one_http_request(&dest, &http_post_request("/restore", &restore_body));
        assert!(
            restore_response.starts_with("HTTP/1.1 200"),
            "POST /restore onto empty data must succeed: {restore_response}"
        );
        let restore_payload = http_body(&restore_response);
        let restore_value: serde_json::Value = serde_json::from_str(restore_payload)
            .expect("POST /restore must return RestoreDiagnostics JSON");
        assert_eq!(
            restore_value["operation_normal"].as_bool(),
            Some(true),
            "POST /restore must report operation_normal: {restore_payload}"
        );

        let source_public = exchange_one_http_request(
            &source,
            "GET /issuer-public HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        let dest_public = exchange_one_http_request(
            &dest,
            "GET /issuer-public HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            source_public.starts_with("HTTP/1.1 200") && dest_public.starts_with("HTTP/1.1 200"),
            "GET /issuer-public must succeed on source and restored hosts"
        );
        let source_key = serde_json::from_str::<serde_json::Value>(http_body(&source_public))
            .expect("source issuer-public JSON")["current_issuer_public_key_hex"]
            .as_str()
            .expect("source current key")
            .to_string();
        let dest_key = serde_json::from_str::<serde_json::Value>(http_body(&dest_public))
            .expect("dest issuer-public JSON")["current_issuer_public_key_hex"]
            .as_str()
            .expect("dest current key")
            .to_string();
        assert_eq!(
            dest_key, source_key,
            "the restored host current issuer public key must equal the source"
        );

        let holder_path = dest
            .store()
            .holder_secret_path(&birth.instance.id)
            .display()
            .to_string();
        assert!(
            dest.store().holder_secret_path(&birth.instance.id).exists(),
            "the holder secret must restore from holders/"
        );
        let (presentation_json, certificate_pem) = laboratory_host_present_svid_http(
            &dest,
            &birth.instance.id,
            &birth.capability.id,
            &holder_path,
            "internal",
        );

        let (directory_c, store_c) = laboratory_verifier_kernel();
        std::fs::remove_file(store_c.store().secret_path()).expect(
            "remove Store C issuer.secret so check-only does not require a live mint issuer",
        );
        let mode = super::HostMode::check_only_loopback();
        super::prepare_host_store(&store_c, &mode).expect(
            "a check-only host must start on a Store C verifier store without issuer.secret",
        );
        let pin_body = serde_json::json!({
            "public_key_hex": source_key,
        })
        .to_string();
        let pin_response = exchange_one_http_request_with_mode(
            &store_c,
            &http_post_request("/issuer-accept", &pin_body),
            &mode,
        );
        assert!(
            pin_response.starts_with("HTTP/1.1 200"),
            "check-only POST /issuer-accept must pin the original public key: {pin_response}"
        );

        let challenge_response = exchange_one_http_request_with_mode(
            &store_c,
            &http_post_request("/verifier-challenge", "{}"),
            &mode,
        );
        assert!(
            challenge_response.starts_with("HTTP/1.1 200"),
            "check-only POST /verifier-challenge must return a nonce: {challenge_response}"
        );
        let challenge_value: serde_json::Value =
            serde_json::from_str(http_body(&challenge_response))
                .expect("POST /verifier-challenge must return JSON");
        let nonce = challenge_value["challenge_nonce"]
            .as_str()
            .expect("challenge_nonce")
            .to_string();
        let message = challenge_value["challenge_message"]
            .as_str()
            .expect("challenge_message")
            .to_string();
        let sign_body = serde_json::json!({
            "challenge_message": message,
            "holder_secret_path": holder_path,
        })
        .to_string();
        let sign_response =
            exchange_one_http_request(&dest, &http_post_request("/sign-holder-nonce", &sign_body));
        assert!(
            sign_response.starts_with("HTTP/1.1 200"),
            "the restored host must sign the verifier nonce: {sign_response}"
        );
        let holder_proof = serde_json::from_str::<serde_json::Value>(http_body(&sign_response))
            .expect("sign JSON")["holder_proof"]
            .as_str()
            .expect("holder_proof")
            .to_string();
        let check_body = serde_json::json!({
            "presentation_json": presentation_json,
            "certificate_pem": certificate_pem,
            "intent": "read",
            "audience": "internal",
            "holder_proof": holder_proof,
            "challenge_nonce": nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let check_response = exchange_one_http_request_with_mode(
            &store_c,
            &http_post_request("/check-svid", &check_body),
            &mode,
        );
        assert!(
            check_response.starts_with("HTTP/1.1 200"),
            "Store C POST /check-svid must allow the restored present: {check_response}"
        );
        let check_payload = http_body(&check_response);
        let check_value: serde_json::Value =
            serde_json::from_str(check_payload).expect("check-svid JSON");
        assert_eq!(
            check_value["result"].as_str(),
            Some("allowed"),
            "Store C that pinned the original issuer public key must allow the restored present: {check_payload}"
        );

        let kill_body = serde_json::json!({
            "instance_id": birth.instance.id,
            "confirm": birth.instance.id,
        })
        .to_string();
        let kill_response =
            exchange_one_http_request(&dest, &http_post_request("/kill", &kill_body));
        assert!(
            kill_response.starts_with("HTTP/1.1 200"),
            "POST /kill on the restored host must return 200: {kill_response}"
        );
        let export_response =
            exchange_one_http_request(&dest, &http_post_request("/kill-export", &kill_body));
        assert!(
            export_response.starts_with("HTTP/1.1 200"),
            "POST /kill-export on the restored host must return 200: {export_response}"
        );
        let export_value: serde_json::Value = serde_json::from_str(http_body(&export_response))
            .expect("POST /kill-export must return JSON");
        let accept_body = serde_json::json!({
            "event": export_value["event"],
            "proof": export_value["proof"],
            "tree_head": export_value["tree_head"],
        })
        .to_string();
        let accept_response = exchange_one_http_request_with_mode(
            &store_c,
            &http_post_request("/kill-accept", &accept_body),
            &mode,
        );
        assert!(
            accept_response.starts_with("HTTP/1.1 200"),
            "Store C POST /kill-accept must return 200: {accept_response}"
        );
        let refuse_response = exchange_one_http_request_with_mode(
            &store_c,
            &http_post_request("/check-svid", &check_body),
            &mode,
        );
        assert!(
            refuse_response.contains("HTTP/1.1 403"),
            "Store C POST /check-svid must refuse after kill-accept: {refuse_response}"
        );
        let refuse_payload = http_body(&refuse_response);
        let refuse_value: serde_json::Value =
            serde_json::from_str(refuse_payload).expect("check-svid refuse JSON");
        assert_eq!(
            refuse_value["result"].as_str(),
            Some("refused"),
            "Store C must refuse the same present after kill-accept: {refuse_payload}"
        );
        let refuse_reason = refuse_value["reason"].as_str().unwrap_or("");
        assert!(
            refuse_reason.contains("kill accept") || refuse_reason.contains("accepted a kill"),
            "Store C must refuse from accepted death: {refuse_reason}"
        );
        assert!(
            store_c.store().load_instance(&birth.instance.id).is_err(),
            "Store C must not copy the issuing inode"
        );
        let _keep = directory_c;
    }

    #[test]
    fn cold_restore_at_threshold_two_host_birth_and_present_need_the_outside_member() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let source_directory = tempdir().expect("create a source directory");
        let source = Kernel::open(source_directory.path());
        source.initialize().expect("initialize the source issuer");
        let custody_directory = tempdir().expect("create a member-two custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        raise_live_host_issuance_threshold_two(&source, &outside);
        let agent_type = laboratory_agent_type(&source);

        let backup_directory = tempdir().expect("create a backup directory");
        let backup = backup_directory.path().join("issuer-backup");
        let backup_body = serde_json::json!({
            "path": backup.display().to_string(),
            "confirm": "backup",
        })
        .to_string();
        let backup_response =
            exchange_one_http_request(&source, &http_post_request("/backup", &backup_body));
        assert!(
            backup_response.starts_with("HTTP/1.1 200"),
            "POST /backup must succeed on the live issuing host at n=2: {backup_response}"
        );
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
            "POST /backup at n=2 must not copy issuer-member secrets"
        );

        let dest_directory = tempdir().expect("create an empty restore destination");
        let dest = Kernel::open(dest_directory.path());
        super::prepare_host_store(&dest, &super::HostMode::issuing_loopback()).expect(
            "an issuing host with empty data must start so POST /restore can write",
        );
        let restore_body = serde_json::json!({
            "from": backup.display().to_string(),
            "confirm": "restore",
        })
        .to_string();
        let restore_response =
            exchange_one_http_request(&dest, &http_post_request("/restore", &restore_body));
        assert!(
            restore_response.starts_with("HTTP/1.1 200"),
            "POST /restore onto empty data must succeed: {restore_response}"
        );
        let restore_payload = http_body(&restore_response);
        let restore_value: serde_json::Value = serde_json::from_str(restore_payload)
            .expect("POST /restore must return RestoreDiagnostics JSON");
        assert_eq!(
            restore_value["operation_normal"].as_bool(),
            Some(true),
            "POST /restore at n=2 must report operation_normal: {restore_payload}"
        );
        assert_eq!(
            restore_value["restore_succeeded"].as_bool(),
            Some(true),
            "POST /restore at n=2 must report restore_succeeded: {restore_payload}"
        );
        assert_body_has_no_secrets(&dest, restore_payload, None, "POST /restore at n=2 secrets lock");

        let birth_without = serde_json::json!({
            "agent_type_id": agent_type.id,
            "owner": "laboratory",
            "intent": "read",
            "audience": "internal",
            "on_behalf_of": "autonomous",
        })
        .to_string();
        assert_live_host_write_refuses_without_member_secret_path(
            &dest,
            "/birth",
            &birth_without,
            "POST /birth on restored dest at n=2 without the outside member",
        );
        let instances_after_refuse = dest
            .store()
            .list_instances()
            .expect("a refused dest birth must leave the instance list");
        assert!(
            instances_after_refuse.is_empty(),
            "a refused dest birth without the outside member must not persist an instance"
        );

        let birth_with = serde_json::json!({
            "agent_type_id": agent_type.id,
            "owner": "laboratory",
            "intent": "read",
            "audience": "internal",
            "on_behalf_of": "autonomous",
            "member_secret_path": outside.to_string_lossy(),
        })
        .to_string();
        let birth_response =
            exchange_one_http_request(&dest, &http_post_request("/birth", &birth_with));
        assert!(
            birth_response.starts_with("HTTP/1.1 200"),
            "POST /birth on restored dest at n=2 with the outside member must return 200: {birth_response}"
        );
        let birth_payload = http_body(&birth_response);
        let birth_value: serde_json::Value =
            serde_json::from_str(birth_payload).expect("POST /birth must return JSON");
        let instance_id = birth_value["instance_id"]
            .as_str()
            .expect("POST /birth must return instance_id")
            .to_string();
        let capability_id = birth_value["capability_id"]
            .as_str()
            .expect("POST /birth must return capability_id")
            .to_string();
        let holder_path = dest
            .store()
            .holder_secret_path(&instance_id)
            .display()
            .to_string();
        assert_body_has_no_secrets(
            &dest,
            birth_payload,
            Some(&instance_id),
            "POST /birth on restored dest at n=2 with the outside member",
        );

        let challenge_body = serde_json::json!({
            "instance_id": instance_id,
            "member_secret_path": outside.to_string_lossy(),
        })
        .to_string();
        let challenge_response =
            exchange_one_http_request(&dest, &http_post_request("/challenge", &challenge_body));
        assert!(
            challenge_response.starts_with("HTTP/1.1 200"),
            "POST /challenge on restored dest at n=2 with the outside member must return 200: {challenge_response}"
        );
        let challenge_value: serde_json::Value =
            serde_json::from_str(http_body(&challenge_response))
                .expect("POST /challenge must return JSON");
        let present_body = serde_json::json!({
            "instance_id": instance_id,
            "capability_id": capability_id,
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": holder_path,
            "challenge_nonce": challenge_value["challenge_nonce"],
            "on_behalf_of": "autonomous",
            "member_secret_path": outside.to_string_lossy(),
        })
        .to_string();
        let present_response =
            exchange_one_http_request(&dest, &http_post_request("/present-svid", &present_body));
        assert!(
            present_response.starts_with("HTTP/1.1 200"),
            "POST /present-svid on restored dest at n=2 with the outside member must return 200: {present_response}"
        );
        let present_payload = http_body(&present_response);
        let present_value: serde_json::Value =
            serde_json::from_str(present_payload).expect("POST /present-svid must return JSON");
        assert!(
            present_value["presentation_json"].as_str().is_some(),
            "POST /present-svid must return presentation_json"
        );
        assert_body_has_no_secrets(
            &dest,
            present_payload,
            Some(&instance_id),
            "POST /present-svid on restored dest at n=2 with the outside member",
        );
        let _keep_custody = custody_directory;
    }

    #[test]
    fn check_only_host_refuses_backup_and_restore() {
        let (_directory, kernel) = laboratory_verifier_kernel();
        let mode = super::HostMode::check_only_loopback();
        super::prepare_host_store(&kernel, &mode)
            .expect("a check-only host must start on a Store B verifier store");
        for path in ["/backup", "/restore", "/diagnose"] {
            let response =
                exchange_one_http_request_with_mode(&kernel, &http_post_request(path, "{}"), &mode);
            assert!(
                response.contains("HTTP/1.1 403"),
                "check-only POST {path} must be refused: {response}"
            );
            let payload = http_body(&response);
            assert!(
                payload.contains("check-only")
                    && (payload.contains("Create Agent Principal") || payload.contains("mint")),
                "check-only POST {path} must name Create Agent Principal or mint: {payload}"
            );
        }
        let public_mode = super::HostMode::check_only_public();
        let public_backup = exchange_one_http_request_with_mode(
            &kernel,
            &http_post_request("/backup", "{}"),
            &public_mode,
        );
        assert!(
            public_backup.contains("HTTP/1.1 403"),
            "public check-only POST /backup must be refused: {public_backup}"
        );
    }

    #[test]
    fn the_laboratory_operator_page_includes_backup_restore_diagnose_controls() {
        let laboratory = laboratory_operator_page_html();
        assert!(
            laboratory.contains("fetch(\"/backup\"") && laboratory.contains("confirm") && laboratory.contains("backup"),
            "GET /laboratory must post POST /backup with confirm backup: {laboratory}"
        );
        assert!(
            laboratory.contains("fetch(\"/restore\"")
                && (laboratory.contains("exact word restore")
                    || laboratory.contains("Type the word restore")),
            "GET /laboratory must post POST /restore with confirm restore"
        );
        assert!(
            laboratory.contains("fetch(\"/diagnose\""),
            "GET /laboratory must post POST /diagnose"
        );
        let later = later_user_interface_html();
        assert!(
            later.contains("fetch(\"/backup\"") || later.contains("postJson(\"/backup\""),
            "GET / must post POST /backup"
        );
        assert!(
            later.contains("fetch(\"/restore\"") || later.contains("postJson(\"/restore\""),
            "GET / must post POST /restore"
        );
        assert!(
            later.contains("fetch(\"/diagnose\"") || later.contains("postJson(\"/diagnose\""),
            "GET / must post POST /diagnose"
        );
    }

    #[test]
    fn the_later_user_interface_includes_backup_restore_diagnose_controls() {
        let later = later_user_interface_html();
        assert!(
            later.contains("fetch(\"/backup\"") || later.contains("postJson(\"/backup\""),
            "GET / must post POST /backup"
        );
        assert!(
            later.contains("fetch(\"/restore\"") || later.contains("postJson(\"/restore\""),
            "GET / must post POST /restore"
        );
        assert!(
            later.contains("fetch(\"/diagnose\"") || later.contains("postJson(\"/diagnose\""),
            "GET / must post POST /diagnose"
        );
        assert!(
            later.contains("Laboratory restore")
                && later.contains("backup-path")
                && later.contains("restore-from")
                && later.contains("diagnose-from"),
            "GET / must show backup, restore, and diagnose controls"
        );
    }

    #[test]
    fn check_only_host_allows_store_b_check_svid_without_copying_issuer_secret() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let birth = laboratory_host_birth(&store_a);
        let svid = laboratory_svid_wrap(&store_a, &birth);
        let issuer_secret_a = store_a
            .store()
            .load_secret()
            .expect("load store A issuer.secret");

        let (directory_b, store_b) = laboratory_verifier_kernel();
        std::fs::remove_file(store_b.store().secret_path()).expect(
            "remove Store B issuer.secret so check-only does not require a live mint issuer",
        );
        let mode = super::HostMode::check_only_loopback();
        super::prepare_host_store(&store_b, &mode).expect(
            "a check-only host must start on a Store B verifier store without issuer.secret",
        );
        assert!(
            !store_b.store().secret_path().exists(),
            "a check-only store must not receive issuer.secret"
        );
        assert!(
            std::fs::read_to_string(directory_b.path().join("issuer.secret")).is_err(),
            "Store B must not copy store A issuer.secret"
        );

        let public_key_hex = store_a
            .store()
            .load_issuer()
            .expect("load store A issuer")
            .current_public_key_hex();
        let pin_body = serde_json::json!({
            "public_key_hex": public_key_hex,
        })
        .to_string();
        let pin_response = exchange_one_http_request_with_mode(
            &store_b,
            &http_post_request("/issuer-accept", &pin_body),
            &mode,
        );
        assert!(
            pin_response.starts_with("HTTP/1.1 200"),
            "check-only POST /issuer-accept must pin the foreign public key: {pin_response}"
        );

        let challenge_response = exchange_one_http_request_with_mode(
            &store_b,
            &http_post_request("/verifier-challenge", "{}"),
            &mode,
        );
        assert!(
            challenge_response.starts_with("HTTP/1.1 200"),
            "check-only POST /verifier-challenge must return a nonce: {challenge_response}"
        );
        let challenge_value: serde_json::Value =
            serde_json::from_str(http_body(&challenge_response))
                .expect("POST /verifier-challenge must return JSON");
        let nonce = challenge_value["challenge_nonce"]
            .as_str()
            .expect("challenge_nonce")
            .to_string();
        let message = challenge_value["challenge_message"]
            .as_str()
            .expect("challenge_message")
            .to_string();
        let sign_body = serde_json::json!({
            "challenge_message": message,
            "holder_secret_path": store_a
                .store()
                .holder_secret_path(&birth.instance.id)
                .display()
                .to_string(),
        })
        .to_string();
        let sign_response = exchange_one_http_request(
            &store_a,
            &http_post_request("/sign-holder-nonce", &sign_body),
        );
        assert!(
            sign_response.starts_with("HTTP/1.1 200"),
            "the issuing host must still sign the verifier nonce: {sign_response}"
        );
        let holder_proof = serde_json::from_str::<serde_json::Value>(http_body(&sign_response))
            .expect("sign JSON")["holder_proof"]
            .as_str()
            .expect("holder_proof")
            .to_string();
        let check_body = serde_json::json!({
            "presentation_json": svid.presentation_json,
            "certificate_pem": svid.certificate_pem,
            "intent": "read",
            "audience": "internal",
            "holder_proof": holder_proof,
            "challenge_nonce": nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let check_response = exchange_one_http_request_with_mode(
            &store_b,
            &http_post_request("/check-svid", &check_body),
            &mode,
        );
        assert!(
            check_response.starts_with("HTTP/1.1 200"),
            "check-only Store B POST /check-svid must allow: {check_response}"
        );
        let check_payload = http_body(&check_response);
        let check_value: serde_json::Value =
            serde_json::from_str(check_payload).expect("check-svid JSON");
        assert_eq!(
            check_value["result"].as_str(),
            Some("allowed"),
            "check-only Store B POST /check-svid must allow the way existing verifier tests do: {check_payload}"
        );
        assert!(
            !check_payload.contains(&issuer_secret_a),
            "check-only check-svid must not return issuer.secret"
        );
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "Store B must write no instance record"
        );
        assert!(
            !store_b.store().secret_path().exists(),
            "check-only must still not copy issuer.secret after check-svid"
        );
    }

    #[test]
    fn check_only_well_known_document_names_loopback_or_the_locked_public_check_name() {
        let (_directory, kernel) = laboratory_verifier_kernel();
        let loopback = exchange_one_http_request_with_mode(
            &kernel,
            "GET /.well-known/prometheus-check HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            &super::HostMode::check_only_loopback(),
        );
        assert!(
            loopback.starts_with("HTTP/1.1 200"),
            "check-only well-known must return 200: {loopback}"
        );
        let loopback_body = http_body(&loopback);
        let loopback_value: serde_json::Value =
            serde_json::from_str(loopback_body).expect("well-known JSON");
        assert_eq!(
            loopback_value["bind"].as_str(),
            Some("127.0.0.1"),
            "a loopback check-only host names bind 127.0.0.1: {loopback_body}"
        );
        assert_eq!(
            loopback_value["checks"][0]["path"].as_str(),
            Some("/check-svid")
        );
        assert_eq!(
            loopback_value["checks"][1]["path"].as_str(),
            Some("/check-wimse")
        );
        assert!(
            !loopback_body.contains("issuer.secret"),
            "check-only well-known must not name issuer.secret: {loopback_body}"
        );
        assert_eq!(
            loopback_value["instance_identifier_in_path"].as_bool(),
            Some(false),
            "check-only well-known must not name instance identifiers in paths"
        );

        let public = exchange_one_http_request_with_mode(
            &kernel,
            "GET /.well-known/prometheus-check HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            &super::HostMode::check_only_public(),
        );
        let public_body = http_body(&public);
        let public_value: serde_json::Value =
            serde_json::from_str(public_body).expect("public well-known JSON");
        assert_eq!(
            public_value["bind"].as_str(),
            Some(super::LABORATORY_PUBLIC_CHECK_NAME),
            "a configured public check-only host names bind check.prestigeworldwide.digital: {public_body}"
        );
        assert_eq!(
            public_value["checks"][0]["path"].as_str(),
            Some("/check-svid")
        );
        assert_eq!(
            public_value["checks"][1]["path"].as_str(),
            Some("/check-wimse")
        );
        assert_eq!(
            public_value["instance_identifier_in_path"].as_bool(),
            Some(false)
        );
        assert!(
            !public_body.contains("issuer.secret"),
            "the public check-only well-known document must not contain secrets: {public_body}"
        );
        for write_verb in [
            "/birth",
            "/spawn",
            "/present-svid",
            "/present-wimse",
            "/seal-export",
            "/previous-key-export",
            "/act-export",
            "/sign-holder-nonce",
            "/agent-type",
            "/rotate",
            "/kill-export",
            "/runtime-check",
        ] {
            assert!(
                !public_body.contains(write_verb),
                "the public well-known document must not name write verb {write_verb}: {public_body}"
            );
        }
        let pin_names: Vec<&str> = public_value["operator_pin_paths"]
            .as_array()
            .expect("public well-known must name allowed operator pins")
            .iter()
            .filter_map(|path| path["path"].as_str())
            .collect();
        assert_eq!(
            pin_names,
            vec![
                "/issuer-accept",
                "/kill-accept",
                "/seal-accept",
                "/previous-key-accept",
                "/act-accept",
            ],
            "the public well-known document must name every allowed check-only pin: {public_body}"
        );
        assert!(
            !pin_names.contains(&"/seal-export")
                && !pin_names.contains(&"/previous-key-export")
                && !pin_names.contains(&"/act-export")
                && !pin_names.contains(&"/kill-export"),
            "the public well-known document must not name export write verbs: {public_body}"
        );
        let public_check_paths: Vec<&str> = public_value["checks"]
            .as_array()
            .expect("public well-known must list checks")
            .iter()
            .filter_map(|check| check["path"].as_str())
            .collect();
        assert_eq!(
            public_check_paths,
            vec!["/check-svid", "/check-wimse"],
            "public checks[] stay check-svid and check-wimse: {public_body}"
        );
        for pin in &pin_names {
            assert!(
                !public_check_paths.contains(pin),
                "operator pins must stay out of checks[]: {public_body}"
            );
        }
        crate::runtime_check::parse_well_known_document(public_body)
            .expect("the laboratory runtime must follow the public well-known document");
    }

    #[test]
    fn public_well_known_document_omits_write_verbs_and_runtime_follows_it() {
        let (_directory, kernel) = laboratory_verifier_kernel();
        let public = exchange_one_http_request_with_mode(
            &kernel,
            "GET /.well-known/prometheus-check HTTP/1.1\r\nHost: check.prestigeworldwide.digital\r\nConnection: close\r\n\r\n",
            &super::HostMode::check_only_public(),
        );
        assert!(
            public.starts_with("HTTP/1.1 200"),
            "public well-known must return 200: {public}"
        );
        let public_body = http_body(&public);
        let document = crate::runtime_check::parse_well_known_document(public_body)
            .expect("the laboratory runtime must follow the public well-known document");
        assert_eq!(document.bind, super::LABORATORY_PUBLIC_CHECK_NAME);
        assert_eq!(document.checks[0].path, "/check-svid");
        assert_eq!(document.checks[1].path, "/check-wimse");
        assert_eq!(document.verifier_challenge.path, "/verifier-challenge");
        for write_verb in [
            "/birth",
            "/spawn",
            "/present-svid",
            "/present-wimse",
            "/seal-export",
            "/previous-key-export",
            "/act-export",
            "/sign-holder-nonce",
            "/agent-type",
            "/rotate",
            "/kill-export",
            "/runtime-check",
        ] {
            assert!(
                !public_body.contains(write_verb),
                "the public well-known document must not name write verb {write_verb}: {public_body}"
            );
        }
        let public_value: serde_json::Value =
            serde_json::from_str(public_body).expect("public well-known JSON");
        let pin_names: Vec<&str> = public_value["operator_pin_paths"]
            .as_array()
            .expect("public well-known must name allowed operator pins")
            .iter()
            .filter_map(|path| path["path"].as_str())
            .collect();
        assert_eq!(
            pin_names,
            vec![
                "/issuer-accept",
                "/kill-accept",
                "/seal-accept",
                "/previous-key-accept",
                "/act-accept",
            ],
            "the public well-known document must name every allowed check-only pin: {public_body}"
        );
        let documented_paths: Vec<&str> = public_value["checks"]
            .as_array()
            .into_iter()
            .flatten()
            .chain(
                public_value["operator_pin_paths"]
                    .as_array()
                    .into_iter()
                    .flatten(),
            )
            .filter_map(|item| item["path"].as_str())
            .chain(public_value["verifier_challenge"]["path"].as_str())
            .collect();
        for exact_write in ["/kill", "/seal", "/rotate", "/birth", "/spawn"] {
            assert!(
                !documented_paths.iter().any(|path| *path == exact_write),
                "the public well-known document must not name write verb {exact_write}: {public_body}"
            );
        }
        let mut write_doc: serde_json::Value =
            serde_json::from_str(public_body).expect("public well-known JSON");
        write_doc["checks"][0]["path"] = serde_json::json!("/birth");
        crate::runtime_check::parse_well_known_document(&write_doc.to_string())
            .expect_err("the laboratory runtime must refuse a public document that points at Create Agent Principal");
        write_doc["checks"][0]["path"] = serde_json::json!("/kill");
        crate::runtime_check::parse_well_known_document(&write_doc.to_string())
            .expect_err("the laboratory runtime must refuse a public document that points Decommission at checks[]");
        write_doc["checks"][0]["path"] = serde_json::json!("/act-export");
        crate::runtime_check::parse_well_known_document(&write_doc.to_string()).expect_err(
            "the laboratory runtime must refuse a public document that points at act-export",
        );
    }

    #[test]
    fn public_well_known_document_names_every_allowed_check_only_pin() {
        let (_directory, kernel) = laboratory_verifier_kernel();
        let public = exchange_one_http_request_with_mode(
            &kernel,
            "GET /.well-known/prometheus-check HTTP/1.1\r\nHost: check.prestigeworldwide.digital\r\nConnection: close\r\n\r\n",
            &super::HostMode::check_only_public(),
        );
        assert!(
            public.starts_with("HTTP/1.1 200"),
            "public well-known must return 200: {public}"
        );
        let public_body = http_body(&public);
        let public_value: serde_json::Value =
            serde_json::from_str(public_body).expect("public well-known JSON");
        assert_eq!(
            public_value["bind"].as_str(),
            Some(super::LABORATORY_PUBLIC_CHECK_NAME)
        );
        assert_eq!(
            public_value["checks"][0]["path"].as_str(),
            Some("/check-svid")
        );
        assert_eq!(
            public_value["checks"][1]["path"].as_str(),
            Some("/check-wimse")
        );
        assert_eq!(
            public_value["verifier_challenge"]["path"].as_str(),
            Some("/verifier-challenge"),
            "verifier-challenge stays a named discovery field: {public_body}"
        );
        let pin_names: Vec<&str> = public_value["operator_pin_paths"]
            .as_array()
            .expect("public well-known must name allowed operator pins")
            .iter()
            .filter_map(|path| path["path"].as_str())
            .collect();
        assert_eq!(
            pin_names,
            vec![
                "/issuer-accept",
                "/kill-accept",
                "/seal-accept",
                "/previous-key-accept",
                "/act-accept",
            ],
            "public operator_pin_paths must name every allowed check-only pin and only those pins: {public_body}"
        );
        assert!(
            public_value["operator_pin_paths"]
                .as_array()
                .expect("pins")
                .iter()
                .all(|path| path["method"].as_str() == Some("POST")),
            "operator pin paths must use POST: {public_body}"
        );
        for write_verb in [
            "/birth",
            "/spawn",
            "/present-svid",
            "/present-wimse",
            "/seal-export",
            "/previous-key-export",
            "/act-export",
            "/kill-export",
            "/rotate",
            "/runtime-check",
        ] {
            assert!(
                !public_body.contains(write_verb),
                "the public well-known document must not name write verb {write_verb}: {public_body}"
            );
        }
        let documented_paths: Vec<&str> = public_value["checks"]
            .as_array()
            .into_iter()
            .flatten()
            .chain(
                public_value["operator_pin_paths"]
                    .as_array()
                    .into_iter()
                    .flatten(),
            )
            .filter_map(|item| item["path"].as_str())
            .chain(public_value["verifier_challenge"]["path"].as_str())
            .collect();
        for exact_write in ["/kill", "/seal"] {
            assert!(
                !documented_paths.iter().any(|path| *path == exact_write),
                "the public well-known document must not name write verb {exact_write}: {public_body}"
            );
        }
        let check_paths: Vec<&str> = public_value["checks"]
            .as_array()
            .expect("checks")
            .iter()
            .filter_map(|check| check["path"].as_str())
            .collect();
        for pin in &pin_names {
            assert!(
                !check_paths.contains(pin),
                "operator pins must stay out of checks[]: {public_body}"
            );
        }
        crate::runtime_check::parse_well_known_document(public_body)
            .expect("the laboratory runtime must follow the public well-known document");
        let mut write_doc = public_value.clone();
        write_doc["checks"][0]["path"] = serde_json::json!("/birth");
        crate::runtime_check::parse_well_known_document(&write_doc.to_string())
            .expect_err("the laboratory runtime must refuse a public document that points at Create Agent Principal");
        write_doc["checks"][0]["path"] = serde_json::json!("/act-export");
        crate::runtime_check::parse_well_known_document(&write_doc.to_string()).expect_err(
            "the laboratory runtime must refuse a public document that points at act-export",
        );

        let loopback = exchange_one_http_request_with_mode(
            &kernel,
            "GET /.well-known/prometheus-check HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            &super::HostMode::check_only_loopback(),
        );
        let loopback_body = http_body(&loopback);
        let loopback_value: serde_json::Value =
            serde_json::from_str(loopback_body).expect("loopback well-known JSON");
        assert_eq!(loopback_value["bind"].as_str(), Some("127.0.0.1"));
        let loopback_pins: Vec<&str> = loopback_value["operator_pin_paths"]
            .as_array()
            .expect("loopback well-known must name operator pin paths")
            .iter()
            .filter_map(|path| path["path"].as_str())
            .collect();
        for pin in [
            "/seal-export",
            "/seal-accept",
            "/previous-key-export",
            "/previous-key-accept",
        ] {
            assert!(
                loopback_pins.contains(&pin),
                "the loopback well-known document must keep operator pin {pin}: {loopback_body}"
            );
        }
        assert_eq!(
            loopback_value["checks"][0]["path"].as_str(),
            Some("/check-svid")
        );
        assert_eq!(
            loopback_value["checks"][1]["path"].as_str(),
            Some("/check-wimse")
        );
        assert_eq!(
            loopback_value["verifier_challenge"]["path"].as_str(),
            Some("/verifier-challenge")
        );
        crate::runtime_check::parse_well_known_document(loopback_body)
            .expect("the laboratory runtime must follow the loopback well-known document");
    }

    #[test]
    fn check_only_public_host_wimse_allows_then_refuses_after_kill_accept() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let birth = laboratory_host_birth(&store_a);
        let artifact = laboratory_wimse_artifact(&store_a, &birth);

        let (directory_b, store_b) = laboratory_verifier_kernel();
        std::fs::remove_file(store_b.store().secret_path()).expect(
            "remove Store B issuer.secret so check-only does not require a live mint issuer",
        );
        let mode = super::HostMode::check_only_public();
        super::prepare_host_store(&store_b, &mode).expect(
            "a public check-only host must start on a Store B verifier store without issuer.secret",
        );
        assert!(
            !store_b.store().secret_path().exists(),
            "a check-only store must not receive issuer.secret"
        );

        let public_key_hex = store_a
            .store()
            .load_issuer()
            .expect("load store A issuer")
            .current_public_key_hex();
        let pin_body = serde_json::json!({
            "public_key_hex": public_key_hex,
        })
        .to_string();
        let pin_response = exchange_one_http_request_with_mode(
            &store_b,
            &http_post_request("/issuer-accept", &pin_body),
            &mode,
        );
        assert!(
            pin_response.starts_with("HTTP/1.1 200"),
            "public check-only POST /issuer-accept must pin the foreign public key: {pin_response}"
        );

        let well_known = exchange_one_http_request_with_mode(
            &store_b,
            "GET /.well-known/prometheus-check HTTP/1.1\r\nHost: check.prestigeworldwide.digital\r\nConnection: close\r\n\r\n",
            &mode,
        );
        assert!(
            well_known.starts_with("HTTP/1.1 200"),
            "public check-only well-known must return 200: {well_known}"
        );
        let well_known_body = http_body(&well_known);
        assert!(
            well_known_body.contains("/check-wimse"),
            "the public document must name POST /check-wimse: {well_known_body}"
        );
        assert!(
            !well_known_body.contains("/seal-export")
                && !well_known_body.contains("/previous-key-export")
                && !well_known_body.contains("/birth")
                && !well_known_body.contains("/present-wimse"),
            "the public document must not name write verbs: {well_known_body}"
        );
        let document = crate::runtime_check::parse_well_known_document(well_known_body)
            .expect("the laboratory runtime must follow the public well-known document");
        assert_eq!(document.bind, super::LABORATORY_PUBLIC_CHECK_NAME);
        assert_eq!(document.checks[1].path, "/check-wimse");

        let challenge_response = exchange_one_http_request_with_mode(
            &store_b,
            &http_post_request("/verifier-challenge", "{}"),
            &mode,
        );
        assert!(
            challenge_response.starts_with("HTTP/1.1 200"),
            "public check-only POST /verifier-challenge must return a nonce: {challenge_response}"
        );
        let challenge_value: serde_json::Value =
            serde_json::from_str(http_body(&challenge_response))
                .expect("POST /verifier-challenge must return JSON");
        let nonce = challenge_value["challenge_nonce"]
            .as_str()
            .expect("challenge_nonce")
            .to_string();
        let message = challenge_value["challenge_message"]
            .as_str()
            .expect("challenge_message")
            .to_string();
        let sign_body = serde_json::json!({
            "challenge_message": message,
            "holder_secret_path": store_a
                .store()
                .holder_secret_path(&birth.instance.id)
                .display()
                .to_string(),
        })
        .to_string();
        let sign_response = exchange_one_http_request(
            &store_a,
            &http_post_request("/sign-holder-nonce", &sign_body),
        );
        assert!(
            sign_response.starts_with("HTTP/1.1 200"),
            "the issuing host must still sign the verifier nonce: {sign_response}"
        );
        let holder_proof = serde_json::from_str::<serde_json::Value>(http_body(&sign_response))
            .expect("sign JSON")["holder_proof"]
            .as_str()
            .expect("holder_proof")
            .to_string();

        let envelope_secret = store_a
            .store()
            .load_biscuit_secret()
            .expect("load the issuing envelope secret");
        let (signature_input, signature) = crate::wimse::sign_laboratory_wimse_http_message(
            crate::wimse::LABORATORY_WIMSE_CHECK_METHOD,
            crate::wimse::LABORATORY_WIMSE_CHECK_PATH,
            &artifact.content_digest,
            &envelope_secret,
        )
        .expect("sign POST /check-wimse with the issuing envelope key");
        let check_body = serde_json::json!({
            "presentation_json": artifact.presentation_json,
            "workload_identity_token": artifact.workload_identity_token,
            "content_digest": artifact.content_digest,
            "intent": "read",
            "audience": "internal",
            "holder_proof": holder_proof,
            "challenge_nonce": nonce,
            "on_behalf_of": "autonomous",
            "signature_input": signature_input,
            "signature": signature,
        })
        .to_string();
        let allow_response = exchange_one_http_request_with_mode(
            &store_b,
            &http_post_request_with_signature(
                "/check-wimse",
                &check_body,
                &signature_input,
                &signature,
            ),
            &mode,
        );
        assert!(
            allow_response.starts_with("HTTP/1.1 200"),
            "public check-only POST /check-wimse must allow an honest present before kill accept: {allow_response}"
        );
        let allow_payload = http_body(&allow_response);
        let allow_value: serde_json::Value =
            serde_json::from_str(allow_payload).expect("POST /check-wimse must return JSON");
        assert_eq!(
            allow_value["result"].as_str(),
            Some("allowed"),
            "public check-only must allow the honest WIMSE present: {allow_payload}"
        );
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "public check-only must not copy the issuing inode after the honest allow"
        );
        assert!(
            !store_b.store().secret_path().exists(),
            "public check-only must still not copy issuer.secret after check-wimse"
        );

        store_a
            .kill_instance(&birth.instance.id)
            .expect("store A must persist local kill");
        let bundle = host_kill_export_bundle(&store_a, &birth.instance.id);
        let export_body = serde_json::to_string(&bundle).expect("serialize the export bundle");
        let accept_response = exchange_one_http_request_with_mode(
            &store_b,
            &http_post_request("/kill-accept", &export_body),
            &mode,
        );
        assert!(
            accept_response.starts_with("HTTP/1.1 200"),
            "public check-only POST /kill-accept must accept the signed death bundle: {accept_response}"
        );

        let refuse_response = exchange_one_http_request_with_mode(
            &store_b,
            &http_post_request_with_signature(
                "/check-wimse",
                &check_body,
                &signature_input,
                &signature,
            ),
            &mode,
        );
        assert!(
            refuse_response.contains("HTTP/1.1 403"),
            "public check-only POST /check-wimse must refuse after kill accept: {refuse_response}"
        );
        let refuse_payload = http_body(&refuse_response);
        let refuse_value: serde_json::Value =
            serde_json::from_str(refuse_payload).expect("POST /check-wimse must return JSON");
        assert_eq!(
            refuse_value["result"].as_str(),
            Some("refused"),
            "public check-only POST /check-wimse must refuse: {refuse_payload}"
        );
        let reason = refuse_value["reason"].as_str().unwrap_or("");
        assert!(
            reason.contains("kill accept") || reason.contains("accepted a kill"),
            "public check-only must refuse from accepted death, not from an inode lookup: {reason}"
        );
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "public check-only must not copy the issuing inode after kill accept"
        );
        assert!(
            !store_b.store().secret_path().exists(),
            "public check-only must still not copy issuer.secret after kill accept"
        );
        assert!(
            std::fs::read_to_string(directory_b.path().join("issuer.secret")).is_err(),
            "Store B must not copy store A issuer.secret"
        );
    }

    #[test]
    fn check_only_host_starts_without_a_live_mint_issuer_and_stays_loopback() {
        use chrono::Duration;

        let error =
            require_loopback("0.0.0.0:18765").expect_err("check-only still refuses all interfaces");
        assert!(error.to_string().contains("loopback"));
        require_loopback("127.0.0.1:18765").expect("check-only still binds loopback");

        let issuing = super::host_mode_from_flags(false, None).expect("laptop host");
        assert!(!issuing.check_only);
        assert_eq!(issuing.well_known_bind, "127.0.0.1");
        let with_public =
            super::host_mode_from_flags(false, Some("check.prestigeworldwide.digital"))
                .expect_err("a laptop host must not take a public check name");
        assert!(
            with_public.to_string().contains("check-only")
                || with_public.to_string().contains("loopback"),
            "the refuse must keep the laptop host loopback only: {with_public}"
        );
        let wrong_name = super::host_mode_from_flags(true, Some("www.prestigeworldwide.digital"))
            .expect_err("www is not the check name");
        assert!(
            wrong_name
                .to_string()
                .contains("check.prestigeworldwide.digital"),
            "the refuse must name the locked check name: {wrong_name}"
        );
        let apex = super::host_mode_from_flags(true, Some("prestigeworldwide.digital"))
            .expect_err("the apex is not the check listener");
        assert!(apex.to_string().contains("check.prestigeworldwide.digital"));

        let (_directory, kernel) = laboratory_verifier_kernel();
        let sealed_at = chrono::Utc::now();
        kernel.set_now_for_test(sealed_at);
        kernel.seal_issuer(1).expect("seal the unused mint issuer");
        kernel.set_now_for_test(sealed_at + Duration::seconds(2));
        super::prepare_host_store(&kernel, &super::HostMode::issuing_loopback())
            .expect_err("the laptop host still requires a live mint issuer");
        super::prepare_host_store(&kernel, &super::HostMode::check_only_loopback())
            .expect("a check-only host must not require a live mint issuer");
        std::fs::remove_file(kernel.store().secret_path()).expect("remove issuer.secret");
        super::prepare_host_store(&kernel, &super::HostMode::check_only_loopback())
            .expect("a check-only host must start without issuer.secret");
    }

    #[test]
    fn the_host_operator_page_is_served_on_get_root() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let response = exchange_one_http_request(
            &kernel,
            "GET /laboratory HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "GET /laboratory must return 200: {response}"
        );
        assert!(
            response.contains("text/html"),
            "GET /laboratory must return HTML: {response}"
        );
        let body = http_body(&response);
        assert!(
            body.contains("Prometheus loopback operator page"),
            "GET /laboratory must serve the operator page"
        );
        assert!(
            body.contains("/check-svid"),
            "the operator page must post to /check-svid"
        );
        assert!(
            body.contains("/.well-known/prometheus-check"),
            "the operator page must show the laboratory well-known check URL"
        );
        assert!(
            body.contains("fetch(\"/.well-known/prometheus-check\")"),
            "the operator page must load the well-known check JSON"
        );
        assert!(
            body.contains("The laboratory runtime starts from GET")
                && body.contains("/.well-known/prometheus-check"),
            "the operator page must say the laboratory runtime starts from GET /.well-known/prometheus-check"
        );
        assert!(
            body.contains("presentation_json") || body.contains("Presentation JSON"),
            "the operator page must have a presentation JSON field"
        );
        assert!(
            body.contains("certificate_pem") || body.contains("Certificate PEM"),
            "the operator page must have a certificate PEM field"
        );
        assert!(
            body.contains("holder_proof") || body.contains("Holder proof"),
            "the operator page must have a holder proof field"
        );
        assert!(
            body.contains("challenge_nonce") || body.contains("Challenge nonce"),
            "the operator page must have a challenge nonce field"
        );
        assert!(
            body.contains("on_behalf_of"),
            "the operator page must have an on_behalf_of field"
        );
        assert!(
            !body.contains("issuer.secret"),
            "the operator page must not name issuer.secret"
        );
        assert!(
            !body.contains("biscuit.secret"),
            "the operator page must not name biscuit.secret"
        );
        assert!(
            !body.contains("type=\"file\""),
            "the operator page must not ask the browser to read files from disk"
        );
        assert!(
            body.contains("/issuer-public"),
            "the operator page must load GET /issuer-public"
        );
        assert!(
            body.contains("Copy the issuer public key"),
            "the operator page must show a copyable full issuer public key"
        );
        assert!(
            !body.contains("fetch(\"http://"),
            "the operator page must not fetch a foreign host"
        );
        assert!(
            body.contains("/instances"),
            "the operator page must load GET /instances"
        );
        assert!(
            body.contains("parent_instance_id"),
            "the operator page must show parent next to a child"
        );
        assert!(
            body.contains("/challenge"),
            "the operator page must post to /challenge"
        );
        assert!(
            body.contains("/verifier-challenge"),
            "the operator page must post to /verifier-challenge"
        );
        assert!(
            body.contains("/sign-holder-nonce"),
            "the operator page must post to /sign-holder-nonce"
        );
        assert!(
            body.contains("/present-svid"),
            "the operator page must post to /present-svid"
        );
        assert!(
            body.contains("/present-wimse"),
            "the operator page must post to /present-wimse"
        );
        assert!(
            body.contains("/check-wimse"),
            "the operator page must post to /check-wimse"
        );
        assert!(
            body.contains("Workload Identity Token") || body.contains("workload_identity_token"),
            "the operator page must have a Workload Identity Token field"
        );
        assert!(
            body.contains("Content-Digest") || body.contains("content_digest"),
            "the operator page must have a Content-Digest field"
        );
        assert!(
            body.contains("@method") && body.contains("@request-target") && body.contains("content-digest"),
            "the operator page must name the covered @method, @request-target, and content-digest components"
        );
        assert!(
            body.contains("Signature-Input") && body.contains("Signature"),
            "the operator page must send the HTTP Message Signature the host will verify"
        );
        assert!(
            !body.contains("remain the next unfinished"),
            "the operator page must not call the method and request-target bind unfinished"
        );
        assert!(
            body.contains("/agent-types"),
            "the operator page must load GET /agent-types"
        );
        assert!(
            body.contains("/birth"),
            "the operator page must post to /birth"
        );
        assert!(
            body.contains("birth-member-secret-path")
                || body.contains("id=\"birth-member-secret-path\""),
            "the operator page must have a typed local birth member-secret path field"
        );
        assert!(
            body.contains("agent-type-member-secret-path"),
            "the operator page must have a typed local agent-type member-secret path field"
        );
        assert!(
            body.contains("spawn-member-secret-path"),
            "the operator page must have a typed local spawn member-secret path field"
        );
        assert!(
            body.contains("present-member-secret-path"),
            "the operator page must have a typed local present member-secret path field"
        );
        assert!(
            body.contains("kill-member-secret-path"),
            "the operator page must have a typed local kill member-secret path field"
        );
        assert!(
            body.contains("kill-export-member-secret-path"),
            "the operator page must have a typed local kill-export member-secret path field"
        );
        assert!(
            body.contains("act-export-member-secret-path"),
            "the operator page must have a typed local act-export member-secret path field"
        );
        assert!(
            body.contains("/kill"),
            "the operator page must post to /kill"
        );
        assert!(
            body.contains("confirm") || body.contains("Confirm"),
            "the operator page must have a confirm field for local kill"
        );
        assert!(
            body.contains("fetch(\"/seal\""),
            "the operator page must post to /seal"
        );
        assert!(
            body.contains("Seal the issuer"),
            "the operator page must have a destructive confirm field for issuer seal"
        );
        assert!(
            body.contains("exact word seal") || body.contains("Type the word seal"),
            "the operator page must ask the operator to type the word seal"
        );
        assert!(
            body.contains("fetch(\"/rotate\""),
            "the operator page must post to /rotate"
        );
        assert!(
            body.contains("Rotate the issuer"),
            "the operator page must have a destructive confirm field for issuer rotate"
        );
        assert!(
            body.contains("exact word rotate") || body.contains("Type the word rotate"),
            "the operator page must ask the operator to type the word rotate"
        );

        assert!(
            body.contains("fetch(\"/member-two\""),
            "the operator page must post to /member-two"
        );
        assert!(
            body.contains("Register member two") || body.contains("member-two"),
            "the operator page must have a thin member-two control"
        );
        assert!(
            body.contains("member-two-secret-path") || body.contains("member_secret_path"),
            "the operator page must have a typed local member-two path field"
        );
        assert!(
            body.contains("fetch(\"/set-verify-threshold\""),
            "the operator page must post to /set-verify-threshold"
        );
        assert!(
            body.contains("exact word verify-threshold")
                || body.contains("Type the word verify-threshold"),
            "the operator page must ask the operator to type the word verify-threshold"
        );
        assert!(
            body.contains("verify-threshold-member-secret-path"),
            "the operator page must have a typed local set-verify-threshold member-secret path field"
        );
        assert!(
            body.contains("fetch(\"/set-issuer-threshold\""),
            "the operator page must post to /set-issuer-threshold"
        );
        assert!(
            body.contains("exact word issuer-threshold")
                || body.contains("Type the word issuer-threshold"),
            "the operator page must ask the operator to type the word issuer-threshold"
        );
        assert!(
            body.contains("fetch(\"/seal-export\""),
            "the operator page must post to /seal-export"
        );
        assert!(
            body.contains("Export a seal bundle") || body.contains("export-seal-bundle"),
            "the operator page must have a control to export the seal bundle after seal"
        );
        assert!(
            body.contains("followWellKnownThenPin(\"seal-accept\"")
                && body.contains("\"/well-known-follow\"")
                && body.contains("\"/operator-pin\""),
            "the operator page must follow well-known for seal-accept"
        );
        assert!(
            body.contains("Accept a seal bundle") || body.contains("accept-seal-bundle"),
            "the operator page must have a form to accept a seal bundle"
        );
        assert!(
            body.contains("/previous-key-export"),
            "the operator page must post to /previous-key-export"
        );
        assert!(
            body.contains("Export a previous issuer key") || body.contains("export-previous-key"),
            "the operator page must have a control to export the previous issuer key after rotate"
        );
        assert!(
            body.contains("/previous-key-accept"),
            "the operator page must post to /previous-key-accept"
        );
        assert!(
            body.contains("Accept a previous issuer key") || body.contains("accept-previous-key"),
            "the operator page must have a form to accept a previous issuer key"
        );
        assert!(
            body.contains("fetch(\"/agent-type\""),
            "the operator page must post to /agent-type"
        );
        assert!(
            body.contains("Add an agent type"),
            "the operator page must have a form to add an agent type"
        );
        assert!(
            body.contains("authorization_limit") || body.contains("Authorization limit"),
            "the operator page must have an authorization limit field"
        );
        assert!(
            body.contains("fetch(\"/spawn\""),
            "the operator page must post to /spawn"
        );
        assert!(
            body.contains("Spawn a narrower child"),
            "the operator page must have a form to spawn a narrower child"
        );
        assert!(
            body.contains("fetch(\"/kill-export\""),
            "the operator page must post to /kill-export"
        );
        assert!(
            body.contains("Export a kill bundle"),
            "the operator page must have a control to export the kill bundle after kill"
        );
        assert!(
            body.contains("followWellKnownThenPin(\"kill-accept\""),
            "the operator page must follow well-known for kill-accept"
        );
        assert!(
            body.contains("followWellKnownThenPin(\"issuer-accept\""),
            "the operator page must follow well-known for issuer-accept"
        );
        assert!(
            body.contains("Accept a kill bundle"),
            "the operator page must have a form to accept a kill bundle"
        );
        assert!(
            body.contains("fetch(\"/act-export\""),
            "the operator page must post to /act-export"
        );
        assert!(
            body.contains("Export an act bundle"),
            "the operator page must have a control to export the act bundle after a successful check"
        );
        assert!(
            body.contains("followWellKnownThenPin(\"act-accept\""),
            "the operator page must follow well-known for act-accept"
        );
        assert!(
            body.contains("Accept an act bundle"),
            "the operator page must have a form to accept an act bundle"
        );
        assert!(
            body.contains("wrote no instance record") || body.contains("writes no instance record"),
            "the operator page must show that this store wrote no instance record"
        );
        assert!(
            !body.contains("<h2>Role catalog") && !body.contains("fetch(\"/roles\""),
            "the operator page must not add a role catalog"
        );
    }

    #[test]
    fn the_host_serves_the_later_user_interface_on_loopback() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let response = exchange_one_http_request(
            &kernel,
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "GET / must return 200: {response}"
        );
        assert!(
            response.contains("text/html"),
            "GET / must return HTML: {response}"
        );
        let body = http_body(&response);
        assert!(
            body.contains("Prometheus later user interface"),
            "GET / must serve the later user interface"
        );
        assert!(
            body.contains("127.0.0.1"),
            "the later user interface must state bind 127.0.0.1"
        );
        assert!(
            body.contains("not a public listener"),
            "the later user interface must say this is not a public listener"
        );
        assert!(
            body.contains("/laboratory"),
            "the later user interface must link to the laboratory operator page"
        );
        assert!(
            !body.contains("0.0.0.0"),
            "the later user interface must not name all-interfaces bind"
        );
    }

    #[test]
    fn the_later_user_interface_contains_no_secrets_or_issuer_secret_path() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let response = exchange_one_http_request(
            &kernel,
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        let body = http_body(&response);
        assert_body_has_no_secrets(&kernel, body, None, "the later user interface");
        assert!(
            !body.contains("issuer.secret"),
            "the later user interface must not name issuer.secret"
        );
        assert!(
            !body.contains("type=\"file\""),
            "the later user interface must not ask the browser to read files from disk"
        );
    }

    #[test]
    fn the_later_user_interface_names_create_agent_principal_assertion_act_check_and_decommission()
    {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let response = exchange_one_http_request(
            &kernel,
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        let body = http_body(&response);
        assert!(
            body.contains("<h2>Create Agent Principal</h2>"),
            "the later user interface must name Create Agent Principal"
        );
        assert!(
            body.contains("<h2>Spawn</h2>"),
            "the later user interface must name spawn on GET /"
        );
        assert!(
            body.contains("<h2>Assertion Act</h2>"),
            "the later user interface must name Assertion Act"
        );
        assert!(
            body.contains("<h2>Check</h2>"),
            "the later user interface must name check"
        );
        assert!(
            body.contains("<h2>Decommission</h2>"),
            "the later user interface must name Decommission"
        );
        assert!(
            !body.contains("<h2>Birth</h2>") && !body.contains("<h2>Death</h2>"),
            "GET / must not use Birth or Death as the product headings"
        );
        assert!(
            !body.contains("<h2>Present</h2>"),
            "GET / must not use Present as the product heading"
        );
        assert!(
            body.contains("Create Agent Principal writes a live agent")
                && body.contains("narrower child")
                && body.contains("Assertion Act")
                && body.contains("check")
                && body.contains("Decommission ends the identity"),
            "the later user interface must tell the kernel story first with the locked product names, including spawn"
        );
        assert!(
            body.contains("POST /birth")
                && body.contains("POST /present-svid")
                && body.contains("POST /kill")
                && body.contains("setCarriedFromBirth")
                && body.contains("id=\"birth\"")
                && body.contains("id=\"present\"")
                && body.contains("id=\"death\""),
            "GET / must keep POST paths and JavaScript identifiers mapped"
        );
    }

    #[test]
    fn the_later_user_interface_keeps_story_headings_and_omits_issuer_secret() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let response = exchange_one_http_request(
            &kernel,
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        let body = http_body(&response);
        let status = body
            .find("<h2>Status</h2>")
            .expect("the later user interface must keep the Status heading");
        let birth = body
            .find("<h2>Create Agent Principal</h2>")
            .expect("the later user interface must keep the Create Agent Principal heading");
        let spawn = body
            .find("<h2>Spawn</h2>")
            .expect("the later user interface must keep the Spawn heading");
        let present = body
            .find("<h2>Assertion Act</h2>")
            .expect("the later user interface must keep the Assertion Act heading");
        let check = body
            .find("<h2>Check</h2>")
            .expect("the later user interface must keep the Check heading");
        let death = body
            .find("<h2>Decommission</h2>")
            .expect("the later user interface must keep the Decommission heading");
        let verifier = body
            .find("<h2>Verifier</h2>")
            .expect("the later user interface must keep the Verifier heading");
        let advanced = body
            .find("Advanced issuer writes")
            .expect("the later user interface must keep Advanced last");
        assert!(
            status < birth
                && birth < spawn
                && spawn < present
                && present < check
                && check < death,
            "the later user interface must keep the story headings in order: status, Create Agent Principal, spawn, Assertion Act, check, Decommission"
        );
        assert!(
            death < verifier && verifier < advanced,
            "the later user interface must keep Verifier after death and Advanced last"
        );
        let nav_birth = body
            .find("href=\"#birth\"")
            .expect("the kernel story nav must link to birth");
        let nav_spawn = body
            .find("href=\"#spawn\"")
            .expect("the kernel story nav must link to spawn");
        let nav_present = body
            .find("href=\"#present\"")
            .expect("the kernel story nav must link to present");
        assert!(
            nav_birth < nav_spawn && nav_spawn < nav_present,
            "the kernel story nav must place spawn after birth and before present"
        );
        assert!(
            !body.contains("issuer.secret"),
            "the later user interface must not name issuer.secret"
        );
        let counts = body
            .find("id=\"status-counts\"")
            .expect("the later user interface must show live and revoked counts");
        let status_json = body
            .find("<summary>Store status JSON</summary>")
            .expect("raw store status JSON must sit inside a details block");
        let status_pre = body
            .find("id=\"store-status\"")
            .expect("the later user interface must keep the store-status body");
        assert!(
            counts < status_json && status_json < status_pre,
            "Status must lead with live and revoked counts before the raw JSON details"
        );
        assert!(
            body.contains("setCarriedFromBirth")
                && body.contains("loadInstances(data.instance_id)")
                && body.contains("id=\"instance-id\"")
                && body.contains("id=\"check-instance-id\"")
                && body.contains("id=\"kill-instance-id\"")
                && body.contains("fetch(\"/instances\")"),
            "after birth the live instance identifier must be carried into present, check, and death from GET /instances"
        );
        let spawn_section = body
            .find("<section id=\"spawn\"")
            .expect("spawn must be a kernel-story beat on GET /");
        assert!(
            spawn_section < advanced,
            "spawn must sit in the story column before Advanced"
        );
        let advanced_start = body
            .find("<details class=\"advanced\">")
            .expect("Advanced issuer writes must stay in a details block");
        let advanced_end = advanced_start
            + body[advanced_start..]
                .find("</details>")
                .expect("Advanced issuer writes must close");
        let advanced_html = &body[advanced_start..advanced_end];
        assert!(
            !advanced_html.contains("id=\"spawn-child\"")
                && !advanced_html.contains("<h2>Spawn</h2>")
                && !advanced_html.contains("<h3>Spawn a narrower child</h3>"),
            "spawn controls must leave Advanced"
        );
        assert!(
            advanced_html.contains("Rotate the issuer")
                && advanced_html.contains("Seal the issuer")
                && advanced_html.contains("Register member two")
                && advanced_html.contains("Set verify threshold")
                && advanced_html.contains("Set issuer threshold"),
            "Advanced must keep issuer writes: rotate, seal, member two, and thresholds"
        );
        assert!(
            !body.contains("<details class=\"advanced\" open"),
            "Advanced issuer writes must stay collapsed"
        );
        assert!(
            !body.contains("0.0.0.0"),
            "the later user interface must not bind 0.0.0.0"
        );
    }

    fn later_user_interface_html() -> String {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let response = exchange_one_http_request(
            &kernel,
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "GET / must return 200: {response}"
        );
        http_body(&response).to_string()
    }

    fn later_user_interface_script_function<'a>(html: &'a str, name: &str) -> &'a str {
        script_function_named(html, name, "GET /")
    }

    fn laboratory_operator_page_html() -> String {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let response = exchange_one_http_request(
            &kernel,
            "GET /laboratory HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "GET /laboratory must return 200: {response}"
        );
        http_body(&response).to_string()
    }

    fn laboratory_operator_page_script_function<'a>(html: &'a str, name: &str) -> &'a str {
        script_function_named(html, name, "GET /laboratory")
    }

    fn script_function_named<'a>(html: &'a str, name: &str, page: &str) -> &'a str {
        let marker = format!("function {name}(");
        let start = html
            .find(&marker)
            .unwrap_or_else(|| panic!("{page} must include function {name}"));
        let after = start + marker.len();
        let next = html[after..]
            .find("\nfunction ")
            .map(|offset| after + offset)
            .unwrap_or(html.len());
        &html[start..next]
    }

    #[test]
    fn the_later_user_interface_puts_spawn_on_get_root_and_carries_the_child() {
        let body = later_user_interface_html();
        assert!(
            body.contains("<section id=\"spawn\"") && body.contains("<h2>Spawn</h2>"),
            "GET / must put spawn in the kernel story"
        );
        assert!(
            body.contains("postJson(\"/spawn\"") || body.contains("fetch(\"/spawn\""),
            "GET / must reuse POST /spawn"
        );
        assert!(
            body.contains("This is not a role catalog")
                || body.contains("this is not a role catalog")
                || body.contains("not a role catalog"),
            "GET / must say spawn is not a role catalog"
        );
        assert!(
            body.contains("fillOneInstanceSelect(\"spawn-parent-instance-id\"")
                && body.contains("fetch(\"/instances\")"),
            "GET / must fill the spawn parent from GET /instances"
        );
        assert!(
            body.contains("el(\"spawn-parent-capability-id\").value = data.capability_id")
                && body.contains("el(\"spawn-holder-secret-path\").value = data.holder_secret_path"),
            "after birth GET / must carry the parent instance into spawn without inventing identifiers"
        );
        assert!(
            !body.contains("issuer.secret") && !body.contains("0.0.0.0"),
            "GET / spawn must not name issuer.secret or bind all interfaces"
        );

        let spawn_fn = later_user_interface_script_function(&body, "spawnChild");
        assert!(
            spawn_fn.contains("postJson(\"/spawn\"")
                && spawn_fn.contains("parent_instance_id: parentInstanceId")
                && spawn_fn.contains("el(\"spawn-parent-instance-id\").value"),
            "GET / spawn must send the selected parent to POST /spawn: {spawn_fn}"
        );
        let empty_parent = spawn_fn
            .find("if (!parentInstanceId)")
            .expect("GET / spawn must refuse an empty parent before POST /spawn");
        assert!(
            spawn_fn.contains("Select a live parent before you spawn.")
                && spawn_fn[empty_parent..].contains("return;"),
            "GET / spawn must refuse an empty parent and must not invent a parent instance identifier: {spawn_fn}"
        );
        let post_spawn = spawn_fn
            .find("postJson(\"/spawn\"")
            .expect("GET / spawn must post to POST /spawn");
        let member_path = spawn_fn
            .find("addIssuingMemberSecretPath(body)")
            .expect("GET / spawn must still send member_secret_path on an issuing store");
        assert!(
            empty_parent < post_spawn && empty_parent < member_path,
            "GET / spawn must not post or send a member secret path when the parent is empty: {spawn_fn}"
        );
        assert!(
            !spawn_fn.contains("member_secret_path:"),
            "GET / spawn must not put member_secret_path on the body unless this store has a live parent: {spawn_fn}"
        );
        assert!(
            spawn_fn.contains(
                "setCarriedFromBirth(data.instance_id, data.capability_id, data.holder_secret_path)"
            ) && spawn_fn.contains("loadInstances(data.instance_id)")
                && spawn_fn.contains("el(\"wrap-intent\").value = el(\"spawn-intent\").value")
                && spawn_fn.contains("el(\"wrap-audience\").value = el(\"spawn-audience\").value"),
            "after spawn GET / must carry the child into present, check, and death the same way birth carries a parent: {spawn_fn}"
        );
        assert!(
            !spawn_fn.contains("crypto.randomUUID")
                && !spawn_fn.contains("new_identifier")
                && !spawn_fn.contains("invent"),
            "GET / must not invent a spawn identifier: {spawn_fn}"
        );

        let spawn_html_start = body
            .find("<section id=\"spawn\"")
            .expect("spawn must be a kernel-story beat on GET /");
        let spawn_html_end = body[spawn_html_start..]
            .find("<section id=\"present\"")
            .map(|offset| spawn_html_start + offset)
            .expect("present must follow spawn");
        let spawn_html = &body[spawn_html_start..spawn_html_end];
        assert!(
            !spawn_html.contains("issuer.secret")
                && !spawn_html.contains("type=\"file\"")
                && !spawn_html.contains("FileReader")
                && !spawn_fn.contains("issuer.secret")
                && !spawn_fn.contains("type=\"file\"")
                && !spawn_fn.contains("FileReader"),
            "GET / spawn HTML and JS must not name issuer.secret, holder secret bytes, or a file-upload control"
        );

        let spawn_challenge = later_user_interface_script_function(&body, "requestSpawnChallenge");
        assert!(
            spawn_challenge.contains("if (!instanceId)")
                && spawn_challenge.contains("Select a live parent before you request a challenge."),
            "GET / spawn must refuse an empty parent before it requests a challenge: {spawn_challenge}"
        );
    }

    fn json_object_keys(body: &str) -> Vec<String> {
        let value: serde_json::Value =
            serde_json::from_str(body).expect("the request body must be JSON");
        let mut keys: Vec<String> = value
            .as_object()
            .expect("the request body must be a JSON object")
            .keys()
            .cloned()
            .collect();
        keys.sort();
        keys
    }

    #[test]
    fn the_later_user_interface_script_checks_a_verifier_without_birth() {
        let body = later_user_interface_html();
        assert!(
            body.contains("An empty live-instance field is correct"),
            "GET / must say an empty live-instance field is correct on a verifier"
        );
        assert!(
            body.contains("Do not birth on a verifier"),
            "GET / must tell the operator not to birth on a verifier"
        );
        assert!(
            body.contains("does not invent an instance identifier"),
            "GET / must not invent an instance identifier on a verifier check"
        );
        assert!(
            body.contains("function thisStoreHasLocalLiveInstance"),
            "GET / must detect a local live instance before it sends secret paths on check"
        );
        assert!(
            body.contains("function followWellKnownThenPin(")
                && body.contains("function documentedPinPath(")
                && body.contains("\"verifier-challenge\""),
            "GET / must follow well-known for verifier-challenge"
        );
        assert!(
            !body.contains("0.0.0.0"),
            "GET / must not name all-interfaces bind"
        );

        let check_body = later_user_interface_script_function(&body, "checkBody");
        assert!(
            !check_body.contains("instance_id"),
            "GET / checkBody must not send or invent an instance identifier: {check_body}"
        );
        assert!(
            check_body.contains("thisStoreHasLocalLiveInstance()"),
            "GET / checkBody must omit secret paths unless this store has a local live instance: {check_body}"
        );
        assert!(
            check_body.contains("holder_secret_path"),
            "GET / checkBody must still send holder_secret_path on an issuing store with a local live instance: {check_body}"
        );
        assert!(
            check_body.contains("addIssuingMemberSecretPath(body)"),
            "GET / checkBody must still send member_secret_path on an issuing store with a local live instance: {check_body}"
        );
        let check_if = check_body
            .find("if (thisStoreHasLocalLiveInstance())")
            .expect("GET / checkBody must gate secret paths on a local live instance");
        let holder_path_assign = check_body.find("body.holder_secret_path").expect(
            "GET / checkBody must assign holder_secret_path only inside the local-live gate",
        );
        let member_path_assign = check_body
            .find("addIssuingMemberSecretPath(body)")
            .expect("GET / checkBody must add member_secret_path only inside the local-live gate");
        assert!(
            holder_path_assign > check_if && member_path_assign > check_if,
            "GET / checkBody must not send holder_secret_path or member_secret_path on a verifier store: {check_body}"
        );

        let submit_svid = later_user_interface_script_function(&body, "submitCheckSvid");
        assert!(
            !submit_svid.contains("selectedInstanceId")
                && !submit_svid.contains("check-instance-id"),
            "GET / Check must work with an empty live-instance field: {submit_svid}"
        );
        let submit_wimse = later_user_interface_script_function(&body, "submitCheckWimse");
        assert!(
            !submit_wimse.contains("selectedInstanceId")
                && !submit_wimse.contains("check-instance-id"),
            "GET / WIMSE Check must work with an empty live-instance field: {submit_wimse}"
        );

        let verifier_challenge =
            later_user_interface_script_function(&body, "requestVerifierChallenge");
        assert!(
            !verifier_challenge.contains("member_secret_path")
                && !verifier_challenge.contains("holder_secret_path"),
            "GET / verifier-challenge must not send secret paths: {verifier_challenge}"
        );
        assert!(
            verifier_challenge.contains("followWellKnownThenPin")
                && verifier_challenge.contains("verifier-challenge")
                && verifier_challenge.contains("{}"),
            "GET / verifier-challenge must follow well-known: {verifier_challenge}"
        );

        let issuer_accept = later_user_interface_script_function(&body, "acceptIssuerKey");
        assert!(
            issuer_accept.contains("public_key_hex")
                && !issuer_accept.contains("member_secret_path")
                && !issuer_accept.contains("holder_secret_path"),
            "GET / issuer-accept must send the public key hex only: {issuer_accept}"
        );

        let kill_accept = later_user_interface_script_function(&body, "acceptKillBundle");
        assert!(
            !kill_accept.contains("member_secret_path")
                && !kill_accept.contains("holder_secret_path"),
            "GET / kill-accept must not send secret paths: {kill_accept}"
        );

        let sign_nonce = later_user_interface_script_function(&body, "signVerifierNonce");
        assert!(
            sign_nonce.contains("/sign-holder-nonce")
                && sign_nonce.contains("holder_secret_path"),
            "POST /sign-holder-nonce must stay on the issuing store with a local holder secret path: {sign_nonce}"
        );
    }

    #[test]
    fn the_later_user_interface_types_a_check_base_and_posts_runtime_check() {
        let body = later_user_interface_html();
        assert!(
            body.contains("id=\"check-base\"") && body.contains("name=\"check_base\""),
            "GET / Check must offer a typed check base"
        );
        assert!(
            body.contains("http://127.0.0.1")
                && body.contains("https://check.prestigeworldwide.digital"),
            "GET / Check must name the two accepted check bases"
        );
        assert!(
            body.contains("function refuseTypedCheckBase(")
                && body.contains("function typedCheckBase(")
                && body.contains("function followWellKnownThenCheck(")
                && body.contains("postJson(\"/runtime-check\""),
            "GET / Check must validate the typed base and post POST /runtime-check"
        );
        assert!(
            body.contains("/.well-known/prometheus-check"),
            "GET / Check must follow the well-known document"
        );
        assert!(
            !body.contains("issuer.secret") && !body.contains("type=\"file\""),
            "GET / Check must not name issuer.secret or offer a file upload"
        );
        let submit_svid = later_user_interface_script_function(&body, "submitCheckSvid");
        assert!(
            submit_svid.contains("refuseTypedCheckBase")
                && submit_svid.contains("/runtime-check")
                && submit_svid.contains("followWellKnownThenCheck"),
            "GET / Check X.509-SVID must refuse an off-name base and follow well-known on this host: {submit_svid}"
        );
        let submit_wimse = later_user_interface_script_function(&body, "submitCheckWimse");
        assert!(
            submit_wimse.contains("refuseTypedCheckBase")
                && submit_wimse.contains("/runtime-check"),
            "GET / Check WIMSE must reuse the typed check base: {submit_wimse}"
        );
        let runtime_body = later_user_interface_script_function(&body, "runtimeCheckBody");
        assert!(
            !runtime_body.contains("member_secret_path")
                && !runtime_body.contains("addIssuingMemberSecretPath"),
            "GET / runtime-check must not send an issuing member secret to the check base: {runtime_body}"
        );
        assert!(
            runtime_body.contains("holder_secret_path"),
            "GET / runtime-check may send a local holder secret path so this host can sign: {runtime_body}"
        );
        assert!(
            body.contains("id=\"check-again\"")
                && body.contains("function checkAgain(")
                && body.contains("Each click hits the host"),
            "GET / Check must offer Check again as a later-UI before-next-tool analog"
        );
        assert!(
            !body.contains("localStorage") && !body.contains("sessionStorage"),
            "GET / must not cache ALLOWED in the browser"
        );
        let again = later_user_interface_script_function(&body, "checkAgain");
        assert!(
            again.contains("submitCheckSvid") && again.contains("submitCheckWimse"),
            "Check again must reuse the last present and typed base: {again}"
        );
        assert!(
            !again.contains("localStorage") && !again.contains("allowed"),
            "Check again must not treat a stored ALLOWED as authority: {again}"
        );
    }

    #[test]
    fn the_later_user_interface_check_again_hits_the_host_and_does_not_cache_allowed() {
        let body = later_user_interface_html();
        assert!(
            body.contains("id=\"check-again\"") && body.contains("Check again"),
            "GET / must show Check again"
        );
        assert!(
            !body.contains("localStorage") && !body.contains("sessionStorage"),
            "GET / must not cache ALLOWED in browser storage"
        );
        let again = later_user_interface_script_function(&body, "checkAgain");
        assert!(
            again.contains("submitCheckSvid")
                && again.contains("submitCheckWimse")
                && again.contains("lastCheckKind"),
            "Check again must replay the last check without retyping: {again}"
        );
        let submit = later_user_interface_script_function(&body, "submitCheckSvid");
        assert!(
            submit.contains("postJson(\"/runtime-check\"")
                || submit.contains("followWellKnownThenCheck"),
            "each Check again click must hit the host: {submit}"
        );
    }

    fn spawn_lasting_loopback_host(
        kernel: crate::kernel::Kernel,
        mode: super::HostMode,
    ) -> (String, std::thread::JoinHandle<()>) {
        use std::net::{TcpListener, TcpStream};
        use std::time::Duration;

        let listener =
            TcpListener::bind("127.0.0.1:0").expect("bind a lasting loopback test listener");
        let address = listener
            .local_addr()
            .expect("read the lasting loopback address");
        let handle = std::thread::spawn(move || {
            let _ = super::serve_loopback_listener_with_mode(&kernel, listener, &mode);
        });
        let base = format!("http://127.0.0.1:{}", address.port());
        for _ in 0..50 {
            if TcpStream::connect_timeout(&address, Duration::from_millis(40)).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        (base, handle)
    }

    fn exchange_lasting_http(base: &str, request: &str) -> String {
        use std::io::{Read, Write};
        use std::net::{Shutdown, TcpStream};
        use std::time::Duration;

        let port: u16 = base
            .rsplit(':')
            .next()
            .expect("a lasting base has a port")
            .parse()
            .expect("the lasting base port is a number");
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let mut client = TcpStream::connect(address).expect("connect to the lasting host");
        client
            .set_read_timeout(Some(Duration::from_secs(8)))
            .expect("set a read timeout");
        client
            .set_write_timeout(Some(Duration::from_secs(8)))
            .expect("set a write timeout");
        client
            .write_all(request.as_bytes())
            .expect("write the HTTP request");
        let _ = client.shutdown(Shutdown::Write);
        let mut response = String::new();
        client
            .read_to_string(&mut response)
            .expect("read the HTTP response");
        response
    }

    #[test]
    fn later_user_interface_runtime_check_refuses_off_name_http_public_holder_bytes_and_missing_proof(
    ) {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let wrap = laboratory_svid_wrap(&kernel, &birth);
        let holder_path = kernel
            .store()
            .holder_secret_path(&birth.instance.id)
            .display()
            .to_string();

        let off_name = serde_json::json!({
            "check_base": "http://127.0.0.2:18765",
            "presentation_json": wrap.presentation_json,
            "certificate_pem": wrap.certificate_pem,
            "holder_secret_path": holder_path,
        })
        .to_string();
        let off_response =
            exchange_one_http_request(&kernel, &http_post_request("/runtime-check", &off_name));
        assert!(
            off_response.contains("HTTP/1.1 403"),
            "POST /runtime-check must refuse an off-name base: {off_response}"
        );
        let off_payload = http_body(&off_response);
        assert!(
            off_payload.contains("127.0.0.1")
                && off_payload.contains("check.prestigeworldwide.digital"),
            "the off-name refuse must name the accepted bases: {off_payload}"
        );
        assert!(
            !off_payload.contains("issuer.secret"),
            "the off-name refuse must not name issuer.secret"
        );

        let http_public = serde_json::json!({
            "check_base": "http://check.prestigeworldwide.digital",
            "presentation_json": wrap.presentation_json,
            "certificate_pem": wrap.certificate_pem,
            "holder_secret_path": holder_path,
        })
        .to_string();
        let http_response =
            exchange_one_http_request(&kernel, &http_post_request("/runtime-check", &http_public));
        assert!(
            http_response.contains("HTTP/1.1 403"),
            "POST /runtime-check must refuse HTTP to the public name: {http_response}"
        );
        let http_payload = http_body(&http_response);
        assert!(
            http_payload.contains("HTTPS") || http_payload.contains("HTTP to"),
            "the public HTTP refuse must name HTTPS: {http_payload}"
        );

        let missing_proof = serde_json::json!({
            "check_base": "http://127.0.0.1:18765",
            "presentation_json": wrap.presentation_json,
            "certificate_pem": wrap.certificate_pem,
        })
        .to_string();
        let missing_response = exchange_one_http_request(
            &kernel,
            &http_post_request("/runtime-check", &missing_proof),
        );
        assert!(
            missing_response.contains("HTTP/1.1 403"),
            "POST /runtime-check must refuse a missing holder proof: {missing_response}"
        );
        let missing_payload = http_body(&missing_response);
        assert!(
            missing_payload.contains("holder"),
            "the missing-proof refuse must name holder proof: {missing_payload}"
        );

        let secret_bytes = serde_json::json!({
            "check_base": "http://127.0.0.1:18765",
            "presentation_json": wrap.presentation_json,
            "certificate_pem": wrap.certificate_pem,
            "holder_secret": "00",
        })
        .to_string();
        let secret_response =
            exchange_one_http_request(&kernel, &http_post_request("/runtime-check", &secret_bytes));
        assert!(
            secret_response.contains("HTTP/1.1 403"),
            "POST /runtime-check must refuse holder secret bytes: {secret_response}"
        );
        let secret_payload = http_body(&secret_response);
        assert!(
            secret_payload.contains("not uploaded") || secret_payload.contains("path"),
            "the holder-secret refuse must say secret bytes are not uploaded: {secret_payload}"
        );
        assert!(
            !secret_payload.contains("issuer.secret"),
            "the holder-secret refuse must not name issuer.secret"
        );

        let check_only = exchange_one_http_request_with_mode(
            &kernel,
            &http_post_request("/runtime-check", &off_name),
            &super::HostMode::check_only_loopback(),
        );
        assert!(
            check_only.contains("HTTP/1.1 403"),
            "check-only must refuse POST /runtime-check: {check_only}"
        );
        let check_only_payload = http_body(&check_only);
        assert!(
            check_only_payload.contains("check-only"),
            "check-only POST /runtime-check must stay check-only: {check_only_payload}"
        );
    }

    #[test]
    fn later_user_interface_runtime_check_allows_then_refuses_against_a_typed_store_b_base() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let birth = laboratory_host_birth(&store_a);
        let holder_path = store_a
            .store()
            .holder_secret_path(&birth.instance.id)
            .display()
            .to_string();
        let challenge_response = exchange_one_http_request(
            &store_a,
            &http_post_request(
                "/challenge",
                &serde_json::json!({ "instance_id": birth.instance.id }).to_string(),
            ),
        );
        assert!(
            challenge_response.starts_with("HTTP/1.1 200"),
            "GET / POST /challenge on store A must return 200: {challenge_response}"
        );
        let challenge_value: serde_json::Value =
            serde_json::from_str(http_body(&challenge_response))
                .expect("POST /challenge must return JSON");
        let present_body = serde_json::json!({
            "instance_id": birth.instance.id,
            "capability_id": birth.capability.id,
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": holder_path,
            "challenge_nonce": challenge_value["challenge_nonce"],
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let present_response =
            exchange_one_http_request(&store_a, &http_post_request("/present-svid", &present_body));
        assert!(
            present_response.starts_with("HTTP/1.1 200"),
            "GET / POST /present-svid on store A must return 200: {present_response}"
        );
        let present_value: serde_json::Value = serde_json::from_str(http_body(&present_response))
            .expect("POST /present-svid must return JSON");
        let presentation_json = present_value["presentation_json"]
            .as_str()
            .expect("POST /present-svid must return presentation_json")
            .to_string();
        let certificate_pem = present_value["certificate_pem"]
            .as_str()
            .expect("POST /present-svid must return certificate_pem")
            .to_string();

        let directory_b = tempdir().expect("create store B");
        let store_b = Kernel::open(directory_b.path());
        store_b.initialize().expect("initialize store B");
        let public_key = store_a
            .store()
            .load_issuer()
            .expect("load store A issuer")
            .current_public_key_hex();
        store_b
            .accept_issuer_public_key(&public_key)
            .expect("pin the foreign issuer public key");
        let (base_b, _handle) =
            spawn_lasting_loopback_host(store_b, super::HostMode::issuing_loopback());

        let runtime_body = serde_json::json!({
            "check_base": base_b,
            "presentation_json": presentation_json,
            "certificate_pem": certificate_pem,
            "holder_secret_path": holder_path,
        })
        .to_string();
        assert!(
            !runtime_body.contains("issuer.secret"),
            "POST /runtime-check must not send issuer.secret"
        );
        let allow_response = exchange_one_http_request(
            &store_a,
            &http_post_request("/runtime-check", &runtime_body),
        );
        assert!(
            allow_response.starts_with("HTTP/1.1 200"),
            "GET / POST /runtime-check against Store B must allow: {allow_response}"
        );
        let allow_payload = http_body(&allow_response);
        let allow_value: serde_json::Value =
            serde_json::from_str(allow_payload).expect("POST /runtime-check must return JSON");
        assert_eq!(
            allow_value["result"].as_str(),
            Some("allowed"),
            "GET / runtime-check must allow before death: {allow_payload}"
        );
        assert!(
            !allow_payload.contains("issuer.secret"),
            "POST /runtime-check must not return issuer.secret"
        );

        let kill_body = serde_json::json!({
            "instance_id": birth.instance.id,
            "confirm": birth.instance.id,
        })
        .to_string();
        let kill_response =
            exchange_one_http_request(&store_a, &http_post_request("/kill", &kill_body));
        assert!(
            kill_response.starts_with("HTTP/1.1 200"),
            "GET / POST /kill on store A must return 200: {kill_response}"
        );
        let export_response =
            exchange_one_http_request(&store_a, &http_post_request("/kill-export", &kill_body));
        assert!(
            export_response.starts_with("HTTP/1.1 200"),
            "GET / POST /kill-export on store A must return 200: {export_response}"
        );
        let export_value: serde_json::Value = serde_json::from_str(http_body(&export_response))
            .expect("POST /kill-export must return JSON");
        let accept_body = serde_json::json!({
            "event": export_value["event"],
            "proof": export_value["proof"],
            "tree_head": export_value["tree_head"],
        })
        .to_string();
        let accept_response =
            exchange_lasting_http(&base_b, &http_post_request("/kill-accept", &accept_body));
        assert!(
            accept_response.starts_with("HTTP/1.1 200"),
            "Store B POST /kill-accept must return 200: {accept_response}"
        );

        let refuse_response = exchange_one_http_request(
            &store_a,
            &http_post_request("/runtime-check", &runtime_body),
        );
        assert!(
            refuse_response.contains("HTTP/1.1 403"),
            "GET / Check again of the same present against Store B must refuse after kill-accept: {refuse_response}"
        );
        let refuse_payload = http_body(&refuse_response);
        let refuse_value: serde_json::Value =
            serde_json::from_str(refuse_payload).expect("POST /runtime-check must return JSON");
        assert_eq!(
            refuse_value["result"].as_str(),
            Some("refused"),
            "GET / runtime-check must refuse after death: {refuse_payload}"
        );
        let refuse_reason = refuse_value["reason"].as_str().unwrap_or("");
        assert!(
            refuse_reason.contains("kill accept") || refuse_reason.contains("accepted a kill"),
            "Store B must refuse from accepted death: {refuse_reason}"
        );
        assert!(
            !refuse_payload.contains("issuer.secret"),
            "the refuse body must not name issuer.secret"
        );

        let store_b_after = Kernel::open(directory_b.path());
        assert!(
            store_b_after
                .store()
                .load_instance(&birth.instance.id)
                .is_err(),
            "Store B must not copy the issuing inode"
        );
    }

    #[test]
    fn later_user_interface_runtime_check_refuses_www_apex_port_variant_cors_skip_and_wimse_trim() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let wrap = laboratory_svid_wrap(&kernel, &birth);
        let holder_path = kernel
            .store()
            .holder_secret_path(&birth.instance.id)
            .display()
            .to_string();

        for check_base in [
            "https://www.prestigeworldwide.digital",
            "https://prestigeworldwide.digital",
            "https://check.prestigeworldwide.digital:8443",
            "https://www.prestigeworldwide.digital/",
            "http://check.prestigeworldwide.digital:80/",
        ] {
            let body = serde_json::json!({
                "check_base": check_base,
                "presentation_json": wrap.presentation_json,
                "certificate_pem": wrap.certificate_pem,
                "holder_secret_path": holder_path,
            })
            .to_string();
            let response =
                exchange_one_http_request(&kernel, &http_post_request("/runtime-check", &body));
            assert!(
                response.contains("HTTP/1.1 403"),
                "POST /runtime-check must refuse {check_base}: {response}"
            );
            let payload = http_body(&response);
            assert!(
                payload.contains("127.0.0.1")
                    && payload.contains("check.prestigeworldwide.digital"),
                "the refuse must name the accepted bases for {check_base}: {payload}"
            );
            assert!(
                !payload.contains("issuer.secret"),
                "the refuse must not name issuer.secret"
            );
        }

        let public_check_only = exchange_one_http_request_with_mode(
            &kernel,
            &http_post_request(
                "/runtime-check",
                &serde_json::json!({
                    "check_base": "https://check.prestigeworldwide.digital",
                    "presentation_json": wrap.presentation_json,
                    "certificate_pem": wrap.certificate_pem,
                    "holder_secret_path": holder_path,
                })
                .to_string(),
            ),
            &super::HostMode::check_only_public(),
        );
        assert!(
            public_check_only.contains("HTTP/1.1 403"),
            "public check-only must refuse POST /runtime-check: {public_check_only}"
        );
        let public_payload = http_body(&public_check_only);
        assert!(
            public_payload.contains("check-only"),
            "public check-only POST /runtime-check must stay check-only: {public_payload}"
        );

        let html = later_user_interface_html();
        assert!(
            !html.contains("fetch(\"https://")
                && !html.contains("fetch(\"http://")
                && !html.contains("postJson(\"https://")
                && !html.contains("postJson(\"http://"),
            "GET / JS must not fetch the public check host and skip POST /runtime-check"
        );
        let refuse = later_user_interface_script_function(&html, "refuseTypedCheckBase");
        assert!(
            refuse.contains("127.0.0.1")
                && refuse.contains("check.prestigeworldwide.digital")
                && refuse.contains("(?::443)?"),
            "GET / JS must allow-list only loopback and the locked public HTTPS name: {refuse}"
        );
        assert!(
            !refuse.contains("www.prestigeworldwide")
                && !refuse.contains("https://prestigeworldwide.digital"),
            "GET / JS must not treat www or the apex as an accepted check base: {refuse}"
        );
        let runtime_body = later_user_interface_script_function(&html, "runtimeCheckBody");
        assert!(
            runtime_body.contains("holder_secret_path")
                && !runtime_body.contains("holder_secret:"),
            "GET / runtime-check may send a local holder secret path and must not send holder secret bytes: {runtime_body}"
        );
        assert!(
            runtime_body.contains("el(\"workload-identity-token\").value")
                && runtime_body.contains("el(\"content-digest\").value")
                && runtime_body.contains("el(\"wimse-signature-input\").value")
                && runtime_body.contains("el(\"wimse-signature\").value")
                && !runtime_body.contains(".value.trim()"),
            "GET / must not trim WIMSE token, digest, or signature fields: {runtime_body}"
        );
        let submit_svid = later_user_interface_script_function(&html, "submitCheckSvid");
        let submit_wimse = later_user_interface_script_function(&html, "submitCheckWimse");
        assert!(
            submit_svid.contains("isThisOriginCheckBase")
                && submit_svid.contains("typedCheckBase")
                && submit_svid.contains("/runtime-check")
                && submit_wimse.contains("isThisOriginCheckBase")
                && submit_wimse.contains("/runtime-check"),
            "same-origin check must follow the typed base; off-origin must post POST /runtime-check"
        );

        let host_source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/host.rs"));
        let apply_start = host_source
            .find("fn apply_runtime_check_request(")
            .expect("apply_runtime_check_request must exist");
        let apply = &host_source[apply_start..];
        let apply_end = apply
            .find("\nfn apply_check_request(")
            .expect("apply_check_request must follow apply_runtime_check_request");
        let apply = &apply[..apply_end];
        assert!(
            apply.contains("complete_wimse_check")
                && apply.contains("workload_identity_token")
                && apply.contains("content_digest"),
            "POST /runtime-check must drive WIMSE on the typed-base path"
        );
        assert!(
            !apply.contains("presentation_json.trim(")
                && !apply.contains("workload_identity_token.trim(")
                && !apply.contains("content_digest.trim(")
                && !apply.contains("signature_input.trim(")
                && !apply.contains("certificate_pem.trim("),
            "POST /runtime-check must not trim present, WIMSE token, or digest fields: {apply}"
        );
    }

    #[test]
    fn later_user_interface_follows_well_known_operator_pin_paths() {
        let html = later_user_interface_html();
        assert!(
            html.contains("function documentedPinPath(")
                && html.contains("function followWellKnownThenPin(")
                && html.contains("\"/well-known-follow\"")
                && html.contains("\"/operator-pin\""),
            "GET / must follow well-known pin paths through a loopback helper"
        );
        assert!(
            !html.contains("fetch(\"https://")
                && !html.contains("fetch(\"http://")
                && !html.contains("postJson(\"https://")
                && !html.contains("postJson(\"http://"),
            "GET / JS must not CORS-fetch the public check host for pins"
        );
        for name in [
            "acceptIssuerKey",
            "acceptKillBundle",
            "acceptSealBundle",
            "acceptPreviousKey",
            "acceptActBundle",
            "requestVerifierChallenge",
        ] {
            let function = later_user_interface_script_function(&html, name);
            assert!(
                function.contains("followWellKnownThenPin"),
                "GET / {name} must follow well-known pin paths: {function}"
            );
        }
        let issuer_accept = later_user_interface_script_function(&html, "acceptIssuerKey");
        assert!(
            issuer_accept.contains("public_key_hex")
                && !issuer_accept.contains("holder_secret_path"),
            "GET / issuer-accept must still send the public key hex only: {issuer_accept}"
        );
        let birth = later_user_interface_script_function(&html, "birthInstance");
        let spawn = later_user_interface_script_function(&html, "spawnChild");
        let kill = later_user_interface_script_function(&html, "killInstance");
        let export_kill = later_user_interface_script_function(&html, "exportKillBundle");
        assert!(
            birth.contains("postJson(\"/birth\"")
                && spawn.contains("postJson(\"/spawn\"")
                && kill.contains("postJson(\"/kill\"")
                && export_kill.contains("postJson(\"/kill-export\""),
            "same-origin issuing-store write paths stay hardcoded"
        );
    }

    #[test]
    fn laboratory_operator_page_follows_well_known_operator_pin_paths() {
        let html = laboratory_operator_page_html();
        assert!(
            html.contains("function documentedPinPath(")
                && html.contains("function followWellKnownThenPin(")
                && html.contains("\"/well-known-follow\"")
                && html.contains("\"/operator-pin\"")
                && html.contains("id=\"check-base\"")
                && html.contains("name=\"check_base\""),
            "GET /laboratory must follow well-known pin paths through a loopback helper"
        );
        assert!(
            !html.contains("fetch(\"https://")
                && !html.contains("fetch(\"http://")
                && !html.contains("postJson(\"https://")
                && !html.contains("postJson(\"http://"),
            "GET /laboratory JS must not CORS-fetch the public check host for pins"
        );
        assert!(
            !html.contains("fetch(\"/issuer-accept\"")
                && !html.contains("fetch(\"/kill-accept\"")
                && !html.contains("fetch(\"/seal-accept\"")
                && !html.contains("fetch(\"/previous-key-accept\"")
                && !html.contains("fetch(\"/act-accept\""),
            "GET /laboratory must not hardcode verifier accept posts"
        );
        assert!(
            !html.contains("fetch(\"/verifier-challenge\""),
            "GET /laboratory must not hardcode verifier-challenge"
        );
        for name in [
            "acceptIssuerKey",
            "acceptKillBundle",
            "acceptSealBundle",
            "acceptPreviousKey",
            "acceptActBundle",
            "requestVerifierChallenge",
        ] {
            let function = laboratory_operator_page_script_function(&html, name);
            assert!(
                function.contains("followWellKnownThenPin"),
                "GET /laboratory {name} must follow well-known pin paths: {function}"
            );
            assert!(
                !function.contains("fetch(\"/issuer-accept\"")
                    && !function.contains("fetch(\"/kill-accept\"")
                    && !function.contains("fetch(\"/seal-accept\"")
                    && !function.contains("fetch(\"/previous-key-accept\"")
                    && !function.contains("fetch(\"/act-accept\""),
                "GET /laboratory {name} must not hardcode a verifier accept post: {function}"
            );
        }
        let issuer_accept = laboratory_operator_page_script_function(&html, "acceptIssuerKey");
        assert!(
            issuer_accept.contains("public_key_hex")
                && !issuer_accept.contains("holder_secret_path")
                && !issuer_accept.contains("member_secret_path"),
            "GET /laboratory issuer-accept must still send the public key hex only: {issuer_accept}"
        );
        let documented = laboratory_operator_page_script_function(&html, "documentedPinPath");
        assert!(
            documented.contains("does not name that operator pin")
                && documented.contains("write verb")
                && documented.contains("/birth")
                && documented.contains("/seal-export"),
            "GET /laboratory documentedPinPath must refuse a missing pin and a write-verb pin: {documented}"
        );
        let follow = laboratory_operator_page_script_function(&html, "followWellKnownThenPin");
        assert!(
            follow.contains("\"/well-known-follow\"")
                && follow.contains("\"/operator-pin\"")
                && follow.contains("refuseTypedCheckBase")
                && follow.contains("isThisOriginCheckBase"),
            "GET /laboratory must reuse POST /well-known-follow and POST /operator-pin: {follow}"
        );
        let birth = laboratory_operator_page_script_function(&html, "birthInstance");
        let spawn = laboratory_operator_page_script_function(&html, "spawnChild");
        let kill = laboratory_operator_page_script_function(&html, "killInstance");
        let export_kill = laboratory_operator_page_script_function(&html, "exportKillBundle");
        let seal = laboratory_operator_page_script_function(&html, "sealIssuer");
        let rotate = laboratory_operator_page_script_function(&html, "rotateIssuer");
        let export_act = laboratory_operator_page_script_function(&html, "exportActBundle");
        assert!(
            birth.contains("fetch(\"/birth\"")
                && spawn.contains("fetch(\"/spawn\"")
                && kill.contains("fetch(\"/kill\"")
                && export_kill.contains("fetch(\"/kill-export\"")
                && seal.contains("fetch(\"/seal\"")
                && rotate.contains("fetch(\"/rotate\"")
                && export_act.contains("fetch(\"/act-export\""),
            "same-origin issuing-store write paths stay hardcoded on GET /laboratory"
        );
        assert!(
            html.contains("<h2>Birth an instance</h2>")
                && !html.contains("<h2>Create Agent Principal</h2>"),
            "GET /laboratory Birth heading stays parked polish"
        );
    }

    #[test]
    fn laboratory_operator_page_check_follows_typed_base_well_known_and_runtime_check() {
        let html = laboratory_operator_page_html();
        assert!(
            html.contains("function documentedCheckPath(")
                && html.contains("function followWellKnownThenCheck(")
                && html.contains("function runtimeCheckBody(")
                && html.contains("function submitCheckSvid(")
                && html.contains("function submitCheckWimse(")
                && html.contains("postJson(\"/runtime-check\""),
            "GET /laboratory Check must follow well-known and post POST /runtime-check"
        );
        assert!(
            !html.contains("fetch(\"/check-svid\"")
                && !html.contains("fetch(\"/check-wimse\""),
            "GET /laboratory Check must not hardcode fetch(\"/check-svid\") or fetch(\"/check-wimse\") as the only check path"
        );
        assert!(
            !html.contains("fetch(\"https://")
                && !html.contains("fetch(\"http://")
                && !html.contains("postJson(\"https://")
                && !html.contains("postJson(\"http://"),
            "GET /laboratory Check must not CORS-fetch the public check host"
        );
        let submit_svid = laboratory_operator_page_script_function(&html, "submitCheckSvid");
        assert!(
            submit_svid.contains("refuseTypedCheckBase")
                && submit_svid.contains("followWellKnownThenCheck")
                && submit_svid.contains("\"/runtime-check\""),
            "GET /laboratory Check X.509-SVID must refuse an off-name base and follow well-known on this host: {submit_svid}"
        );
        assert!(
            !submit_svid.contains("fetch(\"/check-svid\""),
            "GET /laboratory Check X.509-SVID must not hardcode fetch(\"/check-svid\"): {submit_svid}"
        );
        let submit_wimse = laboratory_operator_page_script_function(&html, "submitCheckWimse");
        assert!(
            submit_wimse.contains("refuseTypedCheckBase")
                && submit_wimse.contains("followWellKnownThenCheck")
                && submit_wimse.contains("\"/runtime-check\""),
            "GET /laboratory Check WIMSE must reuse the typed check base: {submit_wimse}"
        );
        assert!(
            !submit_wimse.contains("fetch(\"/check-wimse\""),
            "GET /laboratory Check WIMSE must not hardcode fetch(\"/check-wimse\"): {submit_wimse}"
        );
        let documented = laboratory_operator_page_script_function(&html, "documentedCheckPath");
        assert!(
            documented.contains("on_ramp_artifacts")
                && documented.contains("checks")
                && documented.contains("does not name"),
            "GET /laboratory documentedCheckPath must read checks[] from the well-known document: {documented}"
        );
        let follow = laboratory_operator_page_script_function(&html, "followWellKnownThenCheck");
        assert!(
            follow.contains("fetch(\"/.well-known/prometheus-check\")")
                && follow.contains("documentedCheckPath"),
            "same-origin GET /laboratory Check must GET this host well-known then POST the documented path: {follow}"
        );
        let runtime_body = laboratory_operator_page_script_function(&html, "runtimeCheckBody");
        assert!(
            !runtime_body.contains("member_secret_path")
                && !runtime_body.contains("addMemberSecretPath"),
            "GET /laboratory runtime-check must not send an issuing member secret to the check base: {runtime_body}"
        );
        assert!(
            runtime_body.contains("holder_secret_path"),
            "GET /laboratory runtime-check may send a local holder secret path so this host can sign: {runtime_body}"
        );
        let refuse = laboratory_operator_page_script_function(&html, "refuseTypedCheckBase");
        assert!(
            refuse.contains("http://check.prestigeworldwide.digital")
                && refuse.contains("127.0.0.1")
                && refuse.contains("check.prestigeworldwide.digital"),
            "GET /laboratory Check must refuse HTTP to the public name and off-name bases: {refuse}"
        );
        assert!(
            html.contains("<h2>Birth an instance</h2>")
                && !html.contains("<h2>Create Agent Principal</h2>"),
            "GET /laboratory Birth heading stays parked polish"
        );
    }

    #[test]
    fn laboratory_operator_page_check_again_hits_the_host_and_does_not_cache_allowed() {
        let html = laboratory_operator_page_html();
        assert!(
            html.contains("id=\"check-again\"")
                && html.contains("Check again")
                && html.contains("function checkAgain(")
                && html.contains("Each click hits the host"),
            "GET /laboratory Check must offer Check again as a later-UI before-next-tool analog"
        );
        assert!(
            !html.contains("localStorage") && !html.contains("sessionStorage"),
            "GET /laboratory must not cache ALLOWED in the browser"
        );
        let again = laboratory_operator_page_script_function(&html, "checkAgain");
        assert!(
            again.contains("submitCheckSvid")
                && again.contains("submitCheckWimse")
                && again.contains("lastCheckKind"),
            "GET /laboratory Check again must replay the last check without retyping: {again}"
        );
        assert!(
            !again.contains("localStorage") && !again.contains("allowed"),
            "GET /laboratory Check again must not treat a stored ALLOWED as authority: {again}"
        );
        let submit_svid = laboratory_operator_page_script_function(&html, "submitCheckSvid");
        assert!(
            submit_svid.contains("lastCheckKind")
                && (submit_svid.contains("postJson(\"/runtime-check\"")
                    || submit_svid.contains("followWellKnownThenCheck")),
            "each GET /laboratory Check again click must hit the host: {submit_svid}"
        );
        let submit_wimse = laboratory_operator_page_script_function(&html, "submitCheckWimse");
        assert!(
            submit_wimse.contains("lastCheckKind")
                && (submit_wimse.contains("postJson(\"/runtime-check\"")
                    || submit_wimse.contains("followWellKnownThenCheck")),
            "GET /laboratory Check again WIMSE must hit the host: {submit_wimse}"
        );
        assert!(
            !html.contains("id=\"check-both\"") && !html.contains("id=\"check-this-act\""),
            "GET /laboratory must not invent Check both or a named act"
        );
        assert!(
            html.contains("<h2>Birth an instance</h2>")
                && !html.contains("<h2>Create Agent Principal</h2>"),
            "GET /laboratory Birth heading stays parked polish"
        );
    }

    #[test]
    fn well_known_follow_and_operator_pin_follow_the_typed_verifier_document() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let directory_b = tempdir().expect("create store B");
        let store_b = Kernel::open(directory_b.path());
        store_b.initialize().expect("initialize store B");
        let (base_b, _handle) =
            spawn_lasting_loopback_host(store_b, super::HostMode::issuing_loopback());

        let follow_ok = exchange_one_http_request(
            &store_a,
            &http_post_request(
                "/well-known-follow",
                &serde_json::json!({ "check_base": base_b }).to_string(),
            ),
        );
        assert!(
            follow_ok.starts_with("HTTP/1.1 200"),
            "POST /well-known-follow of Store B must return 200: {follow_ok}"
        );
        let document: serde_json::Value =
            serde_json::from_str(http_body(&follow_ok)).expect("well-known-follow JSON");
        assert_eq!(document["bind"].as_str(), Some("127.0.0.1"));
        let pin_names: Vec<&str> = document["operator_pin_paths"]
            .as_array()
            .expect("operator_pin_paths")
            .iter()
            .filter_map(|item| item["path"].as_str())
            .collect();
        assert!(
            pin_names.contains(&"/issuer-accept") && pin_names.contains(&"/kill-accept"),
            "Store B well-known must name accept pins: {document}"
        );
        assert!(
            !http_body(&follow_ok).contains("issuer.secret"),
            "well-known-follow must not return secrets"
        );

        for check_base in [
            "http://127.0.0.2:18765",
            "https://www.prestigeworldwide.digital",
            "https://prestigeworldwide.digital",
            "http://check.prestigeworldwide.digital",
            "https://check.prestigeworldwide.digital:8443",
        ] {
            let refuse = exchange_one_http_request(
                &store_a,
                &http_post_request(
                    "/well-known-follow",
                    &serde_json::json!({ "check_base": check_base }).to_string(),
                ),
            );
            assert!(
                refuse.contains("HTTP/1.1 403"),
                "POST /well-known-follow must refuse {check_base}: {refuse}"
            );
            let payload = http_body(&refuse);
            assert!(
                payload.contains("127.0.0.1")
                    || payload.contains("check.prestigeworldwide.digital")
                    || payload.contains("HTTPS"),
                "the refuse must name the accepted bases for {check_base}: {payload}"
            );
            let pin_refuse = exchange_one_http_request(
                &store_a,
                &http_post_request(
                    "/operator-pin",
                    &serde_json::json!({
                        "check_base": check_base,
                        "pin": "issuer-accept",
                        "body": { "public_key_hex": "aa" }
                    })
                    .to_string(),
                ),
            );
            assert!(
                pin_refuse.contains("HTTP/1.1 403"),
                "POST /operator-pin must refuse {check_base}: {pin_refuse}"
            );
        }

        let check_only = exchange_one_http_request_with_mode(
            &store_a,
            &http_post_request(
                "/well-known-follow",
                &serde_json::json!({ "check_base": base_b }).to_string(),
            ),
            &super::HostMode::check_only_public(),
        );
        assert!(
            check_only.contains("HTTP/1.1 403"),
            "check-only must refuse POST /well-known-follow: {check_only}"
        );
        let check_only_pin = exchange_one_http_request_with_mode(
            &store_a,
            &http_post_request(
                "/operator-pin",
                &serde_json::json!({
                    "check_base": base_b,
                    "pin": "issuer-accept",
                    "body": {}
                })
                .to_string(),
            ),
            &super::HostMode::check_only_loopback(),
        );
        assert!(
            check_only_pin.contains("HTTP/1.1 403"),
            "check-only must refuse POST /operator-pin: {check_only_pin}"
        );

        let public_a = exchange_one_http_request(
            &store_a,
            "GET /issuer-public HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        let public_value: serde_json::Value =
            serde_json::from_str(http_body(&public_a)).expect("issuer-public JSON");
        let public_key_hex = public_value["current_issuer_public_key_hex"]
            .as_str()
            .expect("issuer public key");
        let pin_ok = exchange_one_http_request(
            &store_a,
            &http_post_request(
                "/operator-pin",
                &serde_json::json!({
                    "check_base": base_b,
                    "pin": "issuer-accept",
                    "body": { "public_key_hex": public_key_hex }
                })
                .to_string(),
            ),
        );
        assert!(
            pin_ok.starts_with("HTTP/1.1 200"),
            "POST /operator-pin issuer-accept against Store B must return 200: {pin_ok}"
        );
        let pin_value: serde_json::Value =
            serde_json::from_str(http_body(&pin_ok)).expect("operator-pin JSON");
        assert_eq!(
            pin_value["public_key_hex"].as_str(),
            Some(public_key_hex),
            "Store B must pin the foreign public key: {pin_ok}"
        );

        let missing = exchange_one_http_request(
            &store_a,
            &http_post_request(
                "/operator-pin",
                &serde_json::json!({
                    "check_base": base_b,
                    "pin": "not-a-pin",
                    "body": {}
                })
                .to_string(),
            ),
        );
        assert!(
            missing.contains("HTTP/1.1 403"),
            "POST /operator-pin must refuse a missing pin: {missing}"
        );
        assert!(
            http_body(&missing).contains("does not name that operator pin"),
            "the missing pin refuse must name the hole: {}",
            http_body(&missing)
        );

        let write_verb = exchange_one_http_request(
            &store_a,
            &http_post_request(
                "/operator-pin",
                &serde_json::json!({
                    "check_base": base_b,
                    "pin": "seal-export",
                    "body": {}
                })
                .to_string(),
            ),
        );
        assert!(
            write_verb.contains("HTTP/1.1 403"),
            "POST /operator-pin must refuse a write-verb pin: {write_verb}"
        );
        assert!(
            http_body(&write_verb).contains("write verb"),
            "the write-verb refuse must name a write verb: {}",
            http_body(&write_verb)
        );

        let secret = exchange_one_http_request(
            &store_a,
            &http_post_request(
                "/well-known-follow",
                &serde_json::json!({
                    "check_base": base_b,
                    "holder_secret": "stolen"
                })
                .to_string(),
            ),
        );
        assert!(
            secret.contains("HTTP/1.1 403"),
            "POST /well-known-follow must refuse holder secret bytes: {secret}"
        );
    }

    #[test]
    fn later_user_interface_runtime_check_wimse_allows_then_refuses_against_a_typed_store_b_base() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let birth = laboratory_host_birth(&store_a);
        let holder_path = store_a
            .store()
            .holder_secret_path(&birth.instance.id)
            .display()
            .to_string();
        let challenge_response = exchange_one_http_request(
            &store_a,
            &http_post_request(
                "/challenge",
                &serde_json::json!({ "instance_id": birth.instance.id }).to_string(),
            ),
        );
        assert!(
            challenge_response.starts_with("HTTP/1.1 200"),
            "GET / POST /challenge on store A must return 200: {challenge_response}"
        );
        let challenge_value: serde_json::Value =
            serde_json::from_str(http_body(&challenge_response))
                .expect("POST /challenge must return JSON");
        let present_body = serde_json::json!({
            "instance_id": birth.instance.id,
            "capability_id": birth.capability.id,
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": holder_path,
            "challenge_nonce": challenge_value["challenge_nonce"],
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let present_response = exchange_one_http_request(
            &store_a,
            &http_post_request("/present-wimse", &present_body),
        );
        assert!(
            present_response.starts_with("HTTP/1.1 200"),
            "GET / POST /present-wimse on store A must return 200: {present_response}"
        );
        let present_value: serde_json::Value = serde_json::from_str(http_body(&present_response))
            .expect("POST /present-wimse must return JSON");
        let presentation_json = present_value["presentation_json"]
            .as_str()
            .expect("POST /present-wimse must return presentation_json")
            .to_string();
        let workload_identity_token = present_value["workload_identity_token"]
            .as_str()
            .expect("POST /present-wimse must return workload_identity_token")
            .to_string();
        let content_digest = present_value["content_digest"]
            .as_str()
            .expect("POST /present-wimse must return content_digest")
            .to_string();
        let signature_input = present_value["signature_input"]
            .as_str()
            .expect("POST /present-wimse must return signature_input")
            .to_string();
        let signature = present_value["signature"]
            .as_str()
            .expect("POST /present-wimse must return signature")
            .to_string();

        let directory_b = tempdir().expect("create store B");
        let store_b = Kernel::open(directory_b.path());
        store_b.initialize().expect("initialize store B");
        let public_key = store_a
            .store()
            .load_issuer()
            .expect("load store A issuer")
            .current_public_key_hex();
        store_b
            .accept_issuer_public_key(&public_key)
            .expect("pin the foreign issuer public key");
        let (base_b, _handle) =
            spawn_lasting_loopback_host(store_b, super::HostMode::issuing_loopback());

        let runtime_body = serde_json::json!({
            "check_base": base_b,
            "presentation_json": presentation_json,
            "workload_identity_token": workload_identity_token,
            "content_digest": content_digest,
            "signature_input": signature_input,
            "signature": signature,
            "holder_secret_path": holder_path,
        })
        .to_string();
        assert!(
            !runtime_body.contains("issuer.secret") && !runtime_body.contains("holder_secret\":"),
            "POST /runtime-check WIMSE must not send issuer.secret or holder secret bytes"
        );
        let allow_response = exchange_one_http_request(
            &store_a,
            &http_post_request("/runtime-check", &runtime_body),
        );
        assert!(
            allow_response.starts_with("HTTP/1.1 200"),
            "GET / POST /runtime-check WIMSE against Store B must allow: {allow_response}"
        );
        let allow_payload = http_body(&allow_response);
        let allow_value: serde_json::Value =
            serde_json::from_str(allow_payload).expect("POST /runtime-check must return JSON");
        assert_eq!(
            allow_value["result"].as_str(),
            Some("allowed"),
            "GET / runtime-check WIMSE must allow before death: {allow_payload}"
        );
        assert!(
            !allow_payload.contains("issuer.secret"),
            "POST /runtime-check WIMSE must not return issuer.secret"
        );

        let kill_body = serde_json::json!({
            "instance_id": birth.instance.id,
            "confirm": birth.instance.id,
        })
        .to_string();
        let kill_response =
            exchange_one_http_request(&store_a, &http_post_request("/kill", &kill_body));
        assert!(
            kill_response.starts_with("HTTP/1.1 200"),
            "GET / POST /kill on store A must return 200: {kill_response}"
        );
        let export_response =
            exchange_one_http_request(&store_a, &http_post_request("/kill-export", &kill_body));
        assert!(
            export_response.starts_with("HTTP/1.1 200"),
            "GET / POST /kill-export on store A must return 200: {export_response}"
        );
        let export_value: serde_json::Value = serde_json::from_str(http_body(&export_response))
            .expect("POST /kill-export must return JSON");
        let accept_body = serde_json::json!({
            "event": export_value["event"],
            "proof": export_value["proof"],
            "tree_head": export_value["tree_head"],
        })
        .to_string();
        let accept_response =
            exchange_lasting_http(&base_b, &http_post_request("/kill-accept", &accept_body));
        assert!(
            accept_response.starts_with("HTTP/1.1 200"),
            "Store B POST /kill-accept must return 200: {accept_response}"
        );

        let refuse_response = exchange_one_http_request(
            &store_a,
            &http_post_request("/runtime-check", &runtime_body),
        );
        assert!(
            refuse_response.contains("HTTP/1.1 403"),
            "GET / Check again of the same WIMSE present against Store B must refuse after kill-accept: {refuse_response}"
        );
        let refuse_payload = http_body(&refuse_response);
        let refuse_value: serde_json::Value =
            serde_json::from_str(refuse_payload).expect("POST /runtime-check must return JSON");
        assert_eq!(
            refuse_value["result"].as_str(),
            Some("refused"),
            "GET / runtime-check WIMSE must refuse after death: {refuse_payload}"
        );
        let refuse_reason = refuse_value["reason"].as_str().unwrap_or("");
        assert!(
            refuse_reason.contains("kill accept") || refuse_reason.contains("accepted a kill"),
            "Store B must refuse the WIMSE present from accepted death: {refuse_reason}"
        );
        assert!(
            !refuse_payload.contains("issuer.secret"),
            "the WIMSE refuse body must not name issuer.secret"
        );

        let store_b_after = Kernel::open(directory_b.path());
        assert!(
            store_b_after
                .store()
                .load_instance(&birth.instance.id)
                .is_err(),
            "Store B must not copy the issuing inode"
        );
    }

    #[test]
    fn the_later_user_interface_holds_two_acts_and_check_both_posts_runtime_check() {
        let body = later_user_interface_html();
        assert!(
            body.contains("id=\"check-both\"")
                && body.contains("Check both")
                && body.contains("id=\"held-acts\"")
                && body.contains("id=\"check-this-act\"")
                && body.contains("id=\"check-act-number\""),
            "GET / must offer Check both and a named check of a held act"
        );
        assert!(
            body.contains("ALLOWED only if both allow")
                && body.contains("kill cascade")
                && body.contains("Each present is a separate host hit")
                && body.contains("named check of the live act")
                && body.contains("X.509-SVID wrap")
                && body.contains("WIMSE Assertion Act")
                && body.contains("parent laboratory X.509-SVID wrap")
                && body.contains("child WIMSE Assertion Act"),
            "GET / Check both must say ALLOWED only if both allow and name cascade, independent live named check, SVID plus WIMSE, and parent X.509-SVID plus child WIMSE"
        );
        assert!(
            !body.contains("localStorage") && !body.contains("sessionStorage"),
            "GET / must not cache ALLOWED in the browser"
        );
        assert!(
            !body.contains("issuer.secret") && !body.contains("type=\"file\""),
            "GET / Check both must not name issuer.secret or offer a file upload"
        );
        assert!(
            !body.contains("AgentProcess") && !body.contains("agent-process"),
            "GET / Check both must not spawn AgentProcess on the issuing store"
        );
        let emit_wrap = later_user_interface_script_function(&body, "emitWrap");
        assert!(
            emit_wrap.contains("holdPresentAct(\"svid\")"),
            "after present X.509-SVID GET / must hold that Assertion Act: {emit_wrap}"
        );
        let emit_wimse = later_user_interface_script_function(&body, "emitWimse");
        assert!(
            emit_wimse.contains("holdPresentAct(\"wimse\")"),
            "after present WIMSE GET / must hold that Assertion Act: {emit_wimse}"
        );
        let hold = later_user_interface_script_function(&body, "holdPresentAct");
        assert!(
            hold.contains("heldActs.push")
                && hold.contains("heldActs.length > 2")
                && hold.contains("holder_secret_path"),
            "GET / must hold two present payloads and their holder paths: {hold}"
        );
        let from_act = later_user_interface_script_function(&body, "runtimeCheckBodyFromAct");
        assert!(
            from_act.contains("mix")
                && from_act.contains("holder secret path")
                && from_act.contains("check_base"),
            "a present row must refuse a mixed on-ramp and a missing holder path: {from_act}"
        );
        let both = later_user_interface_script_function(&body, "checkBoth");
        let first_post = both
            .find("postJson(\"/runtime-check\", firstBody)")
            .expect("Check both must post POST /runtime-check for the first present");
        let second_post = both
            .find("postJson(\"/runtime-check\", secondBody)")
            .expect("Check both must post POST /runtime-check for the second present");
        assert!(
            first_post < second_post,
            "Check both must hit the host once per present: {both}"
        );
        assert!(
            !both.contains("localStorage") && !both.contains("AgentProcess"),
            "Check both must not cache ALLOWED and must not spawn AgentProcess: {both}"
        );
        let show_both = later_user_interface_script_function(&body, "showBothDecisions");
        assert!(
            show_both.contains("first.ok && second.ok && firstData.result === \"allowed\" && secondData.result === \"allowed\"")
                && show_both.contains("ALLOWED only if both allow"),
            "Check both must claim allow only when both host hits allow: {show_both}"
        );
        let named = later_user_interface_script_function(&body, "checkThisActOnly");
        assert!(
            named.contains("postJson(\"/runtime-check\"")
                && named.contains("Act 0")
                && named.contains("heldActs[n - 1]"),
            "Check this act only must post one present and refuse act 0: {named}"
        );
        let again = later_user_interface_script_function(&body, "checkAgain");
        assert!(
            again.contains("checkBoth") && again.contains("checkThisActOnly"),
            "Check again must replay Check both or the named act: {again}"
        );
        assert!(
            !again.contains("allowed"),
            "Check again must not treat a stored ALLOWED as authority: {again}"
        );
    }

    #[test]
    fn later_user_interface_check_both_parent_child_allows_then_refuses_after_parent_kill_accept() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let parent = laboratory_host_birth(&store_a);
        let parent_holder = store_a
            .store()
            .holder_secret_path(&parent.instance.id)
            .display()
            .to_string();
        let (parent_json, parent_pem) = laboratory_host_present_svid_http(
            &store_a,
            &parent.instance.id,
            &parent.capability.id,
            &parent_holder,
            "internal",
        );
        let child = laboratory_host_spawn_child(&store_a, &parent);
        let child_holder = store_a
            .store()
            .holder_secret_path(&child.instance.id)
            .display()
            .to_string();
        let (child_json, child_pem) = laboratory_host_present_svid_http(
            &store_a,
            &child.instance.id,
            &child.capability.id,
            &child_holder,
            "internal/prod",
        );
        assert_ne!(
            parent.instance.id, child.instance.id,
            "GET / spawn must write a child instance, not reuse the parent"
        );

        let directory_b = tempdir().expect("create store B");
        let store_b = Kernel::open(directory_b.path());
        store_b.initialize().expect("initialize store B");
        let public_key = store_a
            .store()
            .load_issuer()
            .expect("load store A issuer")
            .current_public_key_hex();
        store_b
            .accept_issuer_public_key(&public_key)
            .expect("pin the foreign issuer public key");
        let (base_b, _handle) =
            spawn_lasting_loopback_host(store_b, super::HostMode::issuing_loopback());

        let parent_body =
            laboratory_runtime_check_body(&base_b, &parent_json, &parent_pem, &parent_holder);
        let child_body =
            laboratory_runtime_check_body(&base_b, &child_json, &child_pem, &child_holder);
        assert!(
            !parent_body.contains("issuer.secret") && !child_body.contains("issuer.secret"),
            "Check both must not send issuer.secret"
        );
        assert_runtime_check_result(
            &store_a,
            &parent_body,
            true,
            "GET / Check both parent against Store B",
        );
        assert_runtime_check_result(
            &store_a,
            &child_body,
            true,
            "GET / Check both child against Store B",
        );

        let kill_body = serde_json::json!({
            "instance_id": parent.instance.id,
            "confirm": parent.instance.id,
        })
        .to_string();
        let kill_response =
            exchange_one_http_request(&store_a, &http_post_request("/kill", &kill_body));
        assert!(
            kill_response.starts_with("HTTP/1.1 200"),
            "GET / POST /kill of the parent must return 200: {kill_response}"
        );
        let export_response =
            exchange_one_http_request(&store_a, &http_post_request("/kill-export", &kill_body));
        assert!(
            export_response.starts_with("HTTP/1.1 200"),
            "GET / POST /kill-export of the parent must return 200: {export_response}"
        );
        let export_value: serde_json::Value = serde_json::from_str(http_body(&export_response))
            .expect("POST /kill-export must return JSON");
        let accept_body = serde_json::json!({
            "event": export_value["event"],
            "proof": export_value["proof"],
            "tree_head": export_value["tree_head"],
        })
        .to_string();
        let accept_response =
            exchange_lasting_http(&base_b, &http_post_request("/kill-accept", &accept_body));
        assert!(
            accept_response.starts_with("HTTP/1.1 200"),
            "Store B POST /kill-accept of the parent must return 200: {accept_response}"
        );

        let parent_refuse = assert_runtime_check_result(
            &store_a,
            &parent_body,
            false,
            "GET / Check both parent after parent kill-accept",
        );
        let child_refuse = assert_runtime_check_result(
            &store_a,
            &child_body,
            false,
            "GET / named check of the child after parent kill-accept",
        );
        let parent_reason = parent_refuse["reason"].as_str().unwrap_or("");
        let child_reason = child_refuse["reason"].as_str().unwrap_or("");
        assert!(
            parent_reason.contains("kill accept") || parent_reason.contains("kill"),
            "Store B must refuse the parent from accepted death: {parent_reason}"
        );
        assert!(
            child_reason.contains("kill accept")
                || child_reason.contains("kill")
                || child_reason.contains("cascade"),
            "Store B must refuse the child from accepted parent death cascade: {child_reason}"
        );

        let store_b_after = Kernel::open(directory_b.path());
        assert!(
            store_b_after
                .store()
                .load_instance(&parent.instance.id)
                .is_err()
                && store_b_after
                    .store()
                    .load_instance(&child.instance.id)
                    .is_err(),
            "Store B must not copy the issuing inode"
        );
    }

    #[test]
    fn later_user_interface_named_check_of_an_independent_live_act_allows_after_first_death() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let first = laboratory_host_birth(&store_a);
        let second = laboratory_host_independent_birth(&store_a, &first);
        assert_ne!(
            first.instance.id, second.instance.id,
            "two Create Agent Principal writes must be independent instances"
        );
        assert!(
            first.instance.parent_instance_id.is_none()
                && second.instance.parent_instance_id.is_none(),
            "two independent births must not be parent and child"
        );
        let first_holder = store_a
            .store()
            .holder_secret_path(&first.instance.id)
            .display()
            .to_string();
        let second_holder = store_a
            .store()
            .holder_secret_path(&second.instance.id)
            .display()
            .to_string();
        let (first_json, first_pem) = laboratory_host_present_svid_http(
            &store_a,
            &first.instance.id,
            &first.capability.id,
            &first_holder,
            "internal",
        );
        let (second_json, second_pem) = laboratory_host_present_svid_http(
            &store_a,
            &second.instance.id,
            &second.capability.id,
            &second_holder,
            "internal",
        );

        let directory_b = tempdir().expect("create store B");
        let store_b = Kernel::open(directory_b.path());
        store_b.initialize().expect("initialize store B");
        let public_key = store_a
            .store()
            .load_issuer()
            .expect("load store A issuer")
            .current_public_key_hex();
        store_b
            .accept_issuer_public_key(&public_key)
            .expect("pin the foreign issuer public key");
        let (base_b, _handle) =
            spawn_lasting_loopback_host(store_b, super::HostMode::issuing_loopback());

        let first_body =
            laboratory_runtime_check_body(&base_b, &first_json, &first_pem, &first_holder);
        let second_body =
            laboratory_runtime_check_body(&base_b, &second_json, &second_pem, &second_holder);
        assert_runtime_check_result(
            &store_a,
            &first_body,
            true,
            "GET / Check both first independent act against Store B",
        );
        assert_runtime_check_result(
            &store_a,
            &second_body,
            true,
            "GET / Check both second independent act against Store B",
        );

        let kill_body = serde_json::json!({
            "instance_id": first.instance.id,
            "confirm": first.instance.id,
        })
        .to_string();
        let kill_response =
            exchange_one_http_request(&store_a, &http_post_request("/kill", &kill_body));
        assert!(
            kill_response.starts_with("HTTP/1.1 200"),
            "GET / POST /kill of the first independent instance must return 200: {kill_response}"
        );
        let export_response =
            exchange_one_http_request(&store_a, &http_post_request("/kill-export", &kill_body));
        assert!(
            export_response.starts_with("HTTP/1.1 200"),
            "GET / POST /kill-export of the first independent instance must return 200: {export_response}"
        );
        let export_value: serde_json::Value = serde_json::from_str(http_body(&export_response))
            .expect("POST /kill-export must return JSON");
        let accept_body = serde_json::json!({
            "event": export_value["event"],
            "proof": export_value["proof"],
            "tree_head": export_value["tree_head"],
        })
        .to_string();
        let accept_response =
            exchange_lasting_http(&base_b, &http_post_request("/kill-accept", &accept_body));
        assert!(
            accept_response.starts_with("HTTP/1.1 200"),
            "Store B POST /kill-accept of the first independent instance must return 200: {accept_response}"
        );

        let first_refuse = assert_runtime_check_result(
            &store_a,
            &first_body,
            false,
            "GET / named check of the first independent act after kill-accept",
        );
        let first_reason = first_refuse["reason"].as_str().unwrap_or("");
        assert!(
            first_reason.contains("kill accept") || first_reason.contains("kill"),
            "Store B must refuse the dead independent act from accepted death: {first_reason}"
        );
        assert_runtime_check_result(
            &store_a,
            &second_body,
            true,
            "GET / named check of the live independent act after the first dies",
        );

        let store_b_after = Kernel::open(directory_b.path());
        assert!(
            store_b_after
                .store()
                .load_instance(&first.instance.id)
                .is_err()
                && store_b_after
                    .store()
                    .load_instance(&second.instance.id)
                    .is_err(),
            "Store B must not copy the issuing inode"
        );
    }

    #[test]
    fn later_user_interface_check_both_svid_and_independent_wimse_allows_then_named_wimse_after_svid_death(
    ) {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let first = laboratory_host_birth(&store_a);
        let second = laboratory_host_independent_birth(&store_a, &first);
        assert_ne!(
            first.instance.id, second.instance.id,
            "two Create Agent Principal writes must be independent instances"
        );
        assert!(
            first.instance.parent_instance_id.is_none()
                && second.instance.parent_instance_id.is_none(),
            "two independent births must not be parent and child"
        );
        let first_holder = store_a
            .store()
            .holder_secret_path(&first.instance.id)
            .display()
            .to_string();
        let second_holder = store_a
            .store()
            .holder_secret_path(&second.instance.id)
            .display()
            .to_string();
        let (first_json, first_pem) = laboratory_host_present_svid_http(
            &store_a,
            &first.instance.id,
            &first.capability.id,
            &first_holder,
            "internal",
        );
        let (second_json, second_token, second_digest, second_sig_input, second_sig) =
            laboratory_host_present_wimse_http(
                &store_a,
                &second.instance.id,
                &second.capability.id,
                &second_holder,
                "internal",
            );

        let directory_b = tempdir().expect("create store B");
        let store_b = Kernel::open(directory_b.path());
        store_b.initialize().expect("initialize store B");
        let public_key = store_a
            .store()
            .load_issuer()
            .expect("load store A issuer")
            .current_public_key_hex();
        store_b
            .accept_issuer_public_key(&public_key)
            .expect("pin the foreign issuer public key");
        let (base_b, _handle) =
            spawn_lasting_loopback_host(store_b, super::HostMode::issuing_loopback());

        let first_body =
            laboratory_runtime_check_body(&base_b, &first_json, &first_pem, &first_holder);
        let second_body = laboratory_runtime_check_wimse_body(
            &base_b,
            &second_json,
            &second_token,
            &second_digest,
            &second_sig_input,
            &second_sig,
            &second_holder,
        );
        assert!(
            !first_body.contains("issuer.secret")
                && !second_body.contains("issuer.secret")
                && !first_body.contains("holder_secret\":")
                && !second_body.contains("holder_secret\":"),
            "Check both must not send issuer.secret or holder secret bytes"
        );
        assert_runtime_check_result(
            &store_a,
            &first_body,
            true,
            "GET / Check both first X.509-SVID act against Store B",
        );
        assert_runtime_check_result(
            &store_a,
            &second_body,
            true,
            "GET / Check both second WIMSE act against Store B",
        );

        let kill_body = serde_json::json!({
            "instance_id": first.instance.id,
            "confirm": first.instance.id,
        })
        .to_string();
        let kill_response =
            exchange_one_http_request(&store_a, &http_post_request("/kill", &kill_body));
        assert!(
            kill_response.starts_with("HTTP/1.1 200"),
            "GET / POST /kill of the first independent instance must return 200: {kill_response}"
        );
        let export_response =
            exchange_one_http_request(&store_a, &http_post_request("/kill-export", &kill_body));
        assert!(
            export_response.starts_with("HTTP/1.1 200"),
            "GET / POST /kill-export of the first independent instance must return 200: {export_response}"
        );
        let export_value: serde_json::Value = serde_json::from_str(http_body(&export_response))
            .expect("POST /kill-export must return JSON");
        let accept_body = serde_json::json!({
            "event": export_value["event"],
            "proof": export_value["proof"],
            "tree_head": export_value["tree_head"],
        })
        .to_string();
        let accept_response =
            exchange_lasting_http(&base_b, &http_post_request("/kill-accept", &accept_body));
        assert!(
            accept_response.starts_with("HTTP/1.1 200"),
            "Store B POST /kill-accept of the first independent instance must return 200: {accept_response}"
        );

        let first_refuse = assert_runtime_check_result(
            &store_a,
            &first_body,
            false,
            "GET / named check of the dead X.509-SVID act after kill-accept",
        );
        let first_reason = first_refuse["reason"].as_str().unwrap_or("");
        assert!(
            first_reason.contains("kill accept") || first_reason.contains("kill"),
            "Store B must refuse the dead X.509-SVID act from accepted death: {first_reason}"
        );
        let second_after = assert_runtime_check_result(
            &store_a,
            &second_body,
            true,
            "GET / named check of the live independent WIMSE act after the first dies",
        );
        assert_eq!(
            second_after["result"].as_str(),
            Some("allowed"),
            "Check both after SVID death must still allow the live WIMSE act as a named check"
        );

        let store_b_after = Kernel::open(directory_b.path());
        assert!(
            store_b_after
                .store()
                .load_instance(&first.instance.id)
                .is_err()
                && store_b_after
                    .store()
                    .load_instance(&second.instance.id)
                    .is_err(),
            "Store B must not copy the issuing inode"
        );
    }

    #[test]
    fn later_user_interface_check_both_refuses_when_svid_allows_and_independent_wimse_is_dead() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let first = laboratory_host_birth(&store_a);
        let second = laboratory_host_independent_birth(&store_a, &first);
        assert_ne!(
            first.instance.id, second.instance.id,
            "two Create Agent Principal writes must be independent instances"
        );
        assert!(
            first.instance.parent_instance_id.is_none()
                && second.instance.parent_instance_id.is_none(),
            "two independent births must not be parent and child"
        );
        let first_holder = store_a
            .store()
            .holder_secret_path(&first.instance.id)
            .display()
            .to_string();
        let second_holder = store_a
            .store()
            .holder_secret_path(&second.instance.id)
            .display()
            .to_string();
        let (first_json, first_pem) = laboratory_host_present_svid_http(
            &store_a,
            &first.instance.id,
            &first.capability.id,
            &first_holder,
            "internal",
        );
        let (second_json, second_token, second_digest, second_sig_input, second_sig) =
            laboratory_host_present_wimse_http(
                &store_a,
                &second.instance.id,
                &second.capability.id,
                &second_holder,
                "internal",
            );

        let directory_b = tempdir().expect("create store B");
        let store_b = Kernel::open(directory_b.path());
        store_b.initialize().expect("initialize store B");
        let public_key = store_a
            .store()
            .load_issuer()
            .expect("load store A issuer")
            .current_public_key_hex();
        store_b
            .accept_issuer_public_key(&public_key)
            .expect("pin the foreign issuer public key");
        let (base_b, _handle) =
            spawn_lasting_loopback_host(store_b, super::HostMode::issuing_loopback());

        let first_body =
            laboratory_runtime_check_body(&base_b, &first_json, &first_pem, &first_holder);
        let second_body = laboratory_runtime_check_wimse_body(
            &base_b,
            &second_json,
            &second_token,
            &second_digest,
            &second_sig_input,
            &second_sig,
            &second_holder,
        );
        assert_runtime_check_result(
            &store_a,
            &first_body,
            true,
            "GET / Check both live X.509-SVID act before WIMSE death",
        );
        assert_runtime_check_result(
            &store_a,
            &second_body,
            true,
            "GET / Check both live WIMSE act before its death",
        );

        let kill_body = serde_json::json!({
            "instance_id": second.instance.id,
            "confirm": second.instance.id,
        })
        .to_string();
        let kill_response =
            exchange_one_http_request(&store_a, &http_post_request("/kill", &kill_body));
        assert!(
            kill_response.starts_with("HTTP/1.1 200"),
            "GET / POST /kill of the independent WIMSE instance must return 200: {kill_response}"
        );
        let export_response =
            exchange_one_http_request(&store_a, &http_post_request("/kill-export", &kill_body));
        assert!(
            export_response.starts_with("HTTP/1.1 200"),
            "GET / POST /kill-export of the independent WIMSE instance must return 200: {export_response}"
        );
        let export_value: serde_json::Value = serde_json::from_str(http_body(&export_response))
            .expect("POST /kill-export must return JSON");
        let accept_body = serde_json::json!({
            "event": export_value["event"],
            "proof": export_value["proof"],
            "tree_head": export_value["tree_head"],
        })
        .to_string();
        let accept_response =
            exchange_lasting_http(&base_b, &http_post_request("/kill-accept", &accept_body));
        assert!(
            accept_response.starts_with("HTTP/1.1 200"),
            "Store B POST /kill-accept of the independent WIMSE instance must return 200: {accept_response}"
        );

        assert_runtime_check_result(
            &store_a,
            &first_body,
            true,
            "GET / named check of the live X.509-SVID act after WIMSE death",
        );
        let wimse_refuse = assert_runtime_check_result(
            &store_a,
            &second_body,
            false,
            "GET / named check of the dead WIMSE act after kill-accept",
        );
        let wimse_reason = wimse_refuse["reason"].as_str().unwrap_or("");
        assert!(
            wimse_reason.contains("kill accept") || wimse_reason.contains("kill"),
            "Store B must refuse the dead WIMSE act from accepted death: {wimse_reason}"
        );

        let store_b_after = Kernel::open(directory_b.path());
        assert!(
            store_b_after
                .store()
                .load_instance(&first.instance.id)
                .is_err()
                && store_b_after
                    .store()
                    .load_instance(&second.instance.id)
                    .is_err(),
            "Store B must not copy the issuing inode"
        );
    }

    #[test]
    fn later_user_interface_check_both_two_independent_wimse_allows_then_named_live_after_first_death(
    ) {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let first = laboratory_host_birth(&store_a);
        let second = laboratory_host_independent_birth(&store_a, &first);
        assert_ne!(
            first.instance.id, second.instance.id,
            "two Create Agent Principal writes must be independent instances"
        );
        assert!(
            first.instance.parent_instance_id.is_none()
                && second.instance.parent_instance_id.is_none(),
            "two independent births must not be parent and child"
        );
        let first_holder = store_a
            .store()
            .holder_secret_path(&first.instance.id)
            .display()
            .to_string();
        let second_holder = store_a
            .store()
            .holder_secret_path(&second.instance.id)
            .display()
            .to_string();
        let (first_json, first_token, first_digest, first_sig_input, first_sig) =
            laboratory_host_present_wimse_http(
                &store_a,
                &first.instance.id,
                &first.capability.id,
                &first_holder,
                "internal",
            );
        let (second_json, second_token, second_digest, second_sig_input, second_sig) =
            laboratory_host_present_wimse_http(
                &store_a,
                &second.instance.id,
                &second.capability.id,
                &second_holder,
                "internal",
            );

        let directory_b = tempdir().expect("create store B");
        let store_b = Kernel::open(directory_b.path());
        store_b.initialize().expect("initialize store B");
        let public_key = store_a
            .store()
            .load_issuer()
            .expect("load store A issuer")
            .current_public_key_hex();
        store_b
            .accept_issuer_public_key(&public_key)
            .expect("pin the foreign issuer public key");
        let (base_b, _handle) =
            spawn_lasting_loopback_host(store_b, super::HostMode::issuing_loopback());

        let first_body = laboratory_runtime_check_wimse_body(
            &base_b,
            &first_json,
            &first_token,
            &first_digest,
            &first_sig_input,
            &first_sig,
            &first_holder,
        );
        let second_body = laboratory_runtime_check_wimse_body(
            &base_b,
            &second_json,
            &second_token,
            &second_digest,
            &second_sig_input,
            &second_sig,
            &second_holder,
        );
        assert!(
            !first_body.contains("issuer.secret") && !second_body.contains("issuer.secret"),
            "Check both must not send issuer.secret"
        );
        assert_runtime_check_result(
            &store_a,
            &first_body,
            true,
            "GET / Check both first independent WIMSE act against Store B",
        );
        assert_runtime_check_result(
            &store_a,
            &second_body,
            true,
            "GET / Check both second independent WIMSE act against Store B",
        );

        let kill_body = serde_json::json!({
            "instance_id": first.instance.id,
            "confirm": first.instance.id,
        })
        .to_string();
        let kill_response =
            exchange_one_http_request(&store_a, &http_post_request("/kill", &kill_body));
        assert!(
            kill_response.starts_with("HTTP/1.1 200"),
            "GET / POST /kill of the first independent WIMSE instance must return 200: {kill_response}"
        );
        let export_response =
            exchange_one_http_request(&store_a, &http_post_request("/kill-export", &kill_body));
        assert!(
            export_response.starts_with("HTTP/1.1 200"),
            "GET / POST /kill-export of the first independent WIMSE instance must return 200: {export_response}"
        );
        let export_value: serde_json::Value = serde_json::from_str(http_body(&export_response))
            .expect("POST /kill-export must return JSON");
        let accept_body = serde_json::json!({
            "event": export_value["event"],
            "proof": export_value["proof"],
            "tree_head": export_value["tree_head"],
        })
        .to_string();
        let accept_response =
            exchange_lasting_http(&base_b, &http_post_request("/kill-accept", &accept_body));
        assert!(
            accept_response.starts_with("HTTP/1.1 200"),
            "Store B POST /kill-accept of the first independent WIMSE instance must return 200: {accept_response}"
        );

        let first_refuse = assert_runtime_check_result(
            &store_a,
            &first_body,
            false,
            "GET / named check of the dead WIMSE act after kill-accept",
        );
        let first_reason = first_refuse["reason"].as_str().unwrap_or("");
        assert!(
            first_reason.contains("kill accept") || first_reason.contains("kill"),
            "Store B must refuse the dead WIMSE act from accepted death: {first_reason}"
        );
        assert_runtime_check_result(
            &store_a,
            &second_body,
            true,
            "GET / named check of the live independent WIMSE act after the first dies",
        );

        let store_b_after = Kernel::open(directory_b.path());
        assert!(
            store_b_after
                .store()
                .load_instance(&first.instance.id)
                .is_err()
                && store_b_after
                    .store()
                    .load_instance(&second.instance.id)
                    .is_err(),
            "Store B must not copy the issuing inode"
        );
    }

    #[test]
    fn later_user_interface_check_both_parent_svid_and_child_wimse_allows_then_refuses_after_parent_kill_accept(
    ) {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let parent = laboratory_host_birth(&store_a);
        let parent_holder = store_a
            .store()
            .holder_secret_path(&parent.instance.id)
            .display()
            .to_string();
        let (parent_json, parent_pem) = laboratory_host_present_svid_http(
            &store_a,
            &parent.instance.id,
            &parent.capability.id,
            &parent_holder,
            "internal",
        );
        let child = laboratory_host_spawn_child(&store_a, &parent);
        let child_holder = store_a
            .store()
            .holder_secret_path(&child.instance.id)
            .display()
            .to_string();
        let (child_json, child_token, child_digest, child_sig_input, child_sig) =
            laboratory_host_present_wimse_http(
                &store_a,
                &child.instance.id,
                &child.capability.id,
                &child_holder,
                "internal/prod",
            );
        assert_ne!(
            parent.instance.id, child.instance.id,
            "GET / spawn must write a child instance, not reuse the parent"
        );
        assert_eq!(
            child.instance.parent_instance_id.as_deref(),
            Some(parent.instance.id.as_str()),
            "GET / spawn must write a narrower child of the parent"
        );

        let directory_b = tempdir().expect("create store B");
        let store_b = Kernel::open(directory_b.path());
        store_b.initialize().expect("initialize store B");
        let public_key = store_a
            .store()
            .load_issuer()
            .expect("load store A issuer")
            .current_public_key_hex();
        store_b
            .accept_issuer_public_key(&public_key)
            .expect("pin the foreign issuer public key");
        let (base_b, _handle) =
            spawn_lasting_loopback_host(store_b, super::HostMode::issuing_loopback());

        let parent_body =
            laboratory_runtime_check_body(&base_b, &parent_json, &parent_pem, &parent_holder);
        let child_body = laboratory_runtime_check_wimse_body(
            &base_b,
            &child_json,
            &child_token,
            &child_digest,
            &child_sig_input,
            &child_sig,
            &child_holder,
        );
        assert!(
            !parent_body.contains("issuer.secret")
                && !child_body.contains("issuer.secret")
                && !parent_body.contains("holder_secret\":")
                && !child_body.contains("holder_secret\":"),
            "Check both must not send issuer.secret or holder secret bytes"
        );
        assert_runtime_check_result(
            &store_a,
            &parent_body,
            true,
            "GET / Check both parent X.509-SVID against Store B",
        );
        assert_runtime_check_result(
            &store_a,
            &child_body,
            true,
            "GET / Check both child WIMSE against Store B",
        );

        let kill_body = serde_json::json!({
            "instance_id": parent.instance.id,
            "confirm": parent.instance.id,
        })
        .to_string();
        let kill_response =
            exchange_one_http_request(&store_a, &http_post_request("/kill", &kill_body));
        assert!(
            kill_response.starts_with("HTTP/1.1 200"),
            "GET / POST /kill of the parent must return 200: {kill_response}"
        );
        let export_response =
            exchange_one_http_request(&store_a, &http_post_request("/kill-export", &kill_body));
        assert!(
            export_response.starts_with("HTTP/1.1 200"),
            "GET / POST /kill-export of the parent must return 200: {export_response}"
        );
        let export_value: serde_json::Value = serde_json::from_str(http_body(&export_response))
            .expect("POST /kill-export must return JSON");
        let accept_body = serde_json::json!({
            "event": export_value["event"],
            "proof": export_value["proof"],
            "tree_head": export_value["tree_head"],
        })
        .to_string();
        let accept_response =
            exchange_lasting_http(&base_b, &http_post_request("/kill-accept", &accept_body));
        assert!(
            accept_response.starts_with("HTTP/1.1 200"),
            "Store B POST /kill-accept of the parent must return 200: {accept_response}"
        );

        let parent_refuse = assert_runtime_check_result(
            &store_a,
            &parent_body,
            false,
            "GET / Check both parent X.509-SVID after parent kill-accept",
        );
        let child_refuse = assert_runtime_check_result(
            &store_a,
            &child_body,
            false,
            "GET / named check of the child WIMSE after parent kill-accept",
        );
        let parent_reason = parent_refuse["reason"].as_str().unwrap_or("");
        let child_reason = child_refuse["reason"].as_str().unwrap_or("");
        assert!(
            parent_reason.contains("kill accept") || parent_reason.contains("kill"),
            "Store B must refuse the parent X.509-SVID from accepted death: {parent_reason}"
        );
        assert!(
            child_reason.contains("kill accept")
                || child_reason.contains("kill")
                || child_reason.contains("cascade"),
            "Store B must refuse the child WIMSE from accepted parent death cascade: {child_reason}"
        );

        let store_b_after = Kernel::open(directory_b.path());
        assert!(
            store_b_after
                .store()
                .load_instance(&parent.instance.id)
                .is_err()
                && store_b_after
                    .store()
                    .load_instance(&child.instance.id)
                    .is_err(),
            "Store B must not copy the issuing inode"
        );
    }

    #[test]
    fn later_user_interface_check_both_refuses_mix_off_name_and_missing_holder_on_one_row() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let parent = laboratory_host_birth(&kernel);
        let parent_holder = kernel
            .store()
            .holder_secret_path(&parent.instance.id)
            .display()
            .to_string();
        let wrap = laboratory_svid_wrap(&kernel, &parent);
        let child = laboratory_host_spawn_child(&kernel, &parent);
        let child_holder = kernel
            .store()
            .holder_secret_path(&child.instance.id)
            .display()
            .to_string();
        let child_wrap = laboratory_svid_wrap(
            &kernel,
            &crate::kernel::BirthWrite {
                instance: child.instance.clone(),
                capability: child.capability.clone(),
                holder_secret_path: child.holder_secret_path.clone(),
            },
        );

        let mix = serde_json::json!({
            "check_base": "http://127.0.0.1:18765",
            "presentation_json": wrap.presentation_json,
            "certificate_pem": wrap.certificate_pem,
            "workload_identity_token": "mixed",
            "holder_secret_path": parent_holder,
        })
        .to_string();
        let mix_response =
            exchange_one_http_request(&kernel, &http_post_request("/runtime-check", &mix));
        assert!(
            mix_response.contains("HTTP/1.1 403"),
            "POST /runtime-check must refuse a mixed on-ramp on one present row: {mix_response}"
        );
        let mix_payload = http_body(&mix_response);
        assert!(
            mix_payload.contains("mix") || mix_payload.contains("on-ramp"),
            "the mix refuse must name the on-ramp mix: {mix_payload}"
        );
        assert!(
            !mix_payload.contains("issuer.secret"),
            "the mix refuse must not name issuer.secret"
        );

        let missing = serde_json::json!({
            "check_base": "http://127.0.0.1:18765",
            "presentation_json": child_wrap.presentation_json,
            "certificate_pem": child_wrap.certificate_pem,
        })
        .to_string();
        let missing_response =
            exchange_one_http_request(&kernel, &http_post_request("/runtime-check", &missing));
        assert!(
            missing_response.contains("HTTP/1.1 403"),
            "POST /runtime-check must refuse a missing holder path on one present row: {missing_response}"
        );
        let missing_payload = http_body(&missing_response);
        assert!(
            missing_payload.contains("holder"),
            "the missing-holder refuse must name holder proof: {missing_payload}"
        );

        let off_name = serde_json::json!({
            "check_base": "http://127.0.0.2:18765",
            "presentation_json": wrap.presentation_json,
            "certificate_pem": wrap.certificate_pem,
            "holder_secret_path": parent_holder,
        })
        .to_string();
        let off_response =
            exchange_one_http_request(&kernel, &http_post_request("/runtime-check", &off_name));
        assert!(
            off_response.contains("HTTP/1.1 403"),
            "POST /runtime-check must refuse an off-name base on a Check both row: {off_response}"
        );
        let off_payload = http_body(&off_response);
        assert!(
            off_payload.contains("127.0.0.1")
                && off_payload.contains("check.prestigeworldwide.digital"),
            "the off-name refuse must name the accepted bases: {off_payload}"
        );

        let http_public = serde_json::json!({
            "check_base": "http://check.prestigeworldwide.digital",
            "presentation_json": wrap.presentation_json,
            "certificate_pem": wrap.certificate_pem,
            "holder_secret_path": parent_holder,
        })
        .to_string();
        let http_response =
            exchange_one_http_request(&kernel, &http_post_request("/runtime-check", &http_public));
        assert!(
            http_response.contains("HTTP/1.1 403"),
            "POST /runtime-check must refuse HTTP to the public name on a Check both row: {http_response}"
        );

        let secret_bytes = serde_json::json!({
            "check_base": "http://127.0.0.1:18765",
            "presentation_json": wrap.presentation_json,
            "certificate_pem": wrap.certificate_pem,
            "holder_secret": "00",
            "holder_secret_path": parent_holder,
        })
        .to_string();
        let secret_response =
            exchange_one_http_request(&kernel, &http_post_request("/runtime-check", &secret_bytes));
        assert!(
            secret_response.contains("HTTP/1.1 403"),
            "POST /runtime-check must refuse holder secret bytes on a Check both row: {secret_response}"
        );
        let secret_payload = http_body(&secret_response);
        assert!(
            secret_payload.contains("not uploaded") || secret_payload.contains("path"),
            "the holder-secret refuse must say secret bytes are not uploaded: {secret_payload}"
        );
        assert!(
            !secret_payload.contains("issuer.secret") && !child_holder.is_empty(),
            "the holder-secret refuse must not name issuer.secret"
        );
    }

    #[test]
    fn the_later_user_interface_two_store_walk_allows_then_refuses_after_kill_accept() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let directory_b = tempdir().expect("create store B");
        let store_b = Kernel::open(directory_b.path());
        store_b.initialize().expect("initialize store B");
        let issuer_secret_a = store_a
            .store()
            .load_secret()
            .expect("load store A issuer.secret");
        let issuer_secret_b_before = store_b
            .store()
            .load_secret()
            .expect("load store B issuer.secret");
        assert_ne!(
            issuer_secret_a, issuer_secret_b_before,
            "store B must start with its own issuer.secret"
        );

        let page_a = exchange_one_http_request(
            &store_a,
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        let page_b = exchange_one_http_request(
            &store_b,
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            page_a.starts_with("HTTP/1.1 200") && page_b.starts_with("HTTP/1.1 200"),
            "both later user interface hosts must answer GET /: {page_a} {page_b}"
        );
        let page_a_body = http_body(&page_a);
        let page_b_body = http_body(&page_b);
        assert!(
            page_a_body.contains("Prometheus later user interface")
                && page_b_body.contains("Prometheus later user interface"),
            "the two-store walk must use GET /, not GET /laboratory"
        );
        assert!(
            page_a_body.contains("127.0.0.1") && page_b_body.contains("127.0.0.1"),
            "both later user interface hosts must state bind 127.0.0.1"
        );
        assert!(
            !page_a_body.contains("0.0.0.0") && !page_b_body.contains("0.0.0.0"),
            "both later user interface hosts must refuse all-interfaces bind copy"
        );

        let agent_type_body = serde_json::json!({
            "allowed_intents": ["read"],
            "authorization_limit": "internal",
            "owner": "laboratory",
        })
        .to_string();
        let agent_type_response = exchange_one_http_request(
            &store_a,
            &http_post_request("/agent-type", &agent_type_body),
        );
        assert!(
            agent_type_response.starts_with("HTTP/1.1 200"),
            "GET / POST /agent-type on store A must return 200: {agent_type_response}"
        );
        let agent_type_value: serde_json::Value =
            serde_json::from_str(http_body(&agent_type_response))
                .expect("POST /agent-type must return JSON");
        let agent_type_id = agent_type_value["agent_type_id"]
            .as_str()
            .expect("POST /agent-type must return agent_type_id");

        let birth_body = serde_json::json!({
            "agent_type_id": agent_type_id,
            "owner": "laboratory",
            "intent": "read",
            "audience": "internal",
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let birth_response =
            exchange_one_http_request(&store_a, &http_post_request("/birth", &birth_body));
        assert!(
            birth_response.starts_with("HTTP/1.1 200"),
            "GET / POST /birth on store A must return 200: {birth_response}"
        );
        let birth_value: serde_json::Value =
            serde_json::from_str(http_body(&birth_response)).expect("POST /birth must return JSON");
        let instance_id = birth_value["instance_id"]
            .as_str()
            .expect("POST /birth must return instance_id");
        let capability_id = birth_value["capability_id"]
            .as_str()
            .expect("POST /birth must return capability_id");
        let holder_secret_path = birth_value["holder_secret_path"]
            .as_str()
            .expect("POST /birth must return holder_secret_path");

        let challenge_body = serde_json::json!({ "instance_id": instance_id }).to_string();
        let challenge_response =
            exchange_one_http_request(&store_a, &http_post_request("/challenge", &challenge_body));
        assert!(
            challenge_response.starts_with("HTTP/1.1 200"),
            "GET / POST /challenge on store A must return 200: {challenge_response}"
        );
        let challenge_value: serde_json::Value =
            serde_json::from_str(http_body(&challenge_response))
                .expect("POST /challenge must return JSON");
        let present_nonce = challenge_value["challenge_nonce"]
            .as_str()
            .expect("POST /challenge must return challenge_nonce");

        let present_body = serde_json::json!({
            "instance_id": instance_id,
            "capability_id": capability_id,
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": holder_secret_path,
            "challenge_nonce": present_nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let present_response =
            exchange_one_http_request(&store_a, &http_post_request("/present-svid", &present_body));
        assert!(
            present_response.starts_with("HTTP/1.1 200"),
            "GET / POST /present-svid on store A must return 200: {present_response}"
        );
        let present_value: serde_json::Value = serde_json::from_str(http_body(&present_response))
            .expect("POST /present-svid must return JSON");
        let presentation_json = present_value["presentation_json"]
            .as_str()
            .expect("POST /present-svid must return presentation_json");
        let certificate_pem = present_value["certificate_pem"]
            .as_str()
            .expect("POST /present-svid must return certificate_pem");

        let instances_before = exchange_one_http_request(
            &store_b,
            "GET /instances HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            instances_before.starts_with("HTTP/1.1 200"),
            "GET /instances on store B must return 200: {instances_before}"
        );
        let instances_before_value: serde_json::Value =
            serde_json::from_str(http_body(&instances_before))
                .expect("GET /instances must return JSON");
        assert_eq!(
            instances_before_value["instances"].as_array().map(Vec::len),
            Some(0),
            "store B GET /instances must start empty: {}",
            http_body(&instances_before)
        );

        let public_response = exchange_one_http_request(
            &store_a,
            "GET /issuer-public HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        let public_value: serde_json::Value = serde_json::from_str(http_body(&public_response))
            .expect("GET /issuer-public must return JSON");
        let public_key_hex = public_value["current_issuer_public_key_hex"]
            .as_str()
            .expect("GET /issuer-public must return current_issuer_public_key_hex");
        let pin_body = serde_json::json!({ "public_key_hex": public_key_hex }).to_string();
        assert_eq!(
            json_object_keys(&pin_body),
            vec!["public_key_hex".to_string()],
            "GET / issuer-accept must send the public key hex only"
        );
        let pin_response =
            exchange_one_http_request(&store_b, &http_post_request("/issuer-accept", &pin_body));
        assert!(
            pin_response.starts_with("HTTP/1.1 200"),
            "GET / POST /issuer-accept on store B must return 200: {pin_response}"
        );

        let challenge_b_body = "{}".to_string();
        assert!(
            json_object_keys(&challenge_b_body).is_empty(),
            "GET / verifier-challenge must send an empty JSON object"
        );
        let challenge_b_response = exchange_one_http_request(
            &store_b,
            &http_post_request("/verifier-challenge", &challenge_b_body),
        );
        assert!(
            challenge_b_response.starts_with("HTTP/1.1 200"),
            "GET / POST /verifier-challenge on store B must return 200: {challenge_b_response}"
        );
        let challenge_b_value: serde_json::Value =
            serde_json::from_str(http_body(&challenge_b_response))
                .expect("POST /verifier-challenge must return JSON");
        let verifier_nonce = challenge_b_value["challenge_nonce"]
            .as_str()
            .expect("POST /verifier-challenge must return challenge_nonce");
        let verifier_message = challenge_b_value["challenge_message"]
            .as_str()
            .expect("POST /verifier-challenge must return challenge_message");

        let sign_body = serde_json::json!({
            "challenge_nonce": verifier_nonce,
            "challenge_message": verifier_message,
            "holder_secret_path": holder_secret_path,
        })
        .to_string();
        let sign_response = exchange_one_http_request(
            &store_a,
            &http_post_request("/sign-holder-nonce", &sign_body),
        );
        assert!(
            sign_response.starts_with("HTTP/1.1 200"),
            "GET / POST /sign-holder-nonce must stay on store A: {sign_response}"
        );
        let sign_value: serde_json::Value = serde_json::from_str(http_body(&sign_response))
            .expect("POST /sign-holder-nonce must return JSON");
        let holder_proof = sign_value["holder_proof"]
            .as_str()
            .expect("POST /sign-holder-nonce must return holder_proof");

        let check_body = serde_json::json!({
            "presentation_json": presentation_json,
            "certificate_pem": certificate_pem,
            "intent": "read",
            "audience": "internal",
            "holder_proof": holder_proof,
            "challenge_nonce": verifier_nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        assert_eq!(
            json_object_keys(&check_body),
            [
                "audience",
                "certificate_pem",
                "challenge_nonce",
                "holder_proof",
                "intent",
                "on_behalf_of",
                "presentation_json",
            ]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>(),
            "GET / check on store B must not send instance_id, holder_secret_path, or member_secret_path"
        );
        let allow_response =
            exchange_one_http_request(&store_b, &http_post_request("/check-svid", &check_body));
        assert!(
            allow_response.starts_with("HTTP/1.1 200"),
            "GET / POST /check-svid on store B must allow an honest present without a local instance: {allow_response}"
        );
        let allow_payload = http_body(&allow_response);
        let allow_value: serde_json::Value =
            serde_json::from_str(allow_payload).expect("POST /check-svid must return JSON");
        assert_eq!(
            allow_value["result"].as_str(),
            Some("allowed"),
            "store B GET / check must allow: {allow_payload}"
        );
        assert!(
            allow_value.get("receipt").is_none() || allow_value["receipt"].is_null(),
            "a verifier allow must not mint a check receipt: {allow_payload}"
        );

        let instances_after_allow = exchange_one_http_request(
            &store_b,
            "GET /instances HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        let instances_after_allow_value: serde_json::Value =
            serde_json::from_str(http_body(&instances_after_allow))
                .expect("GET /instances must return JSON");
        assert_eq!(
            instances_after_allow_value["instances"]
                .as_array()
                .map(Vec::len),
            Some(0),
            "store B GET /instances must stay empty after allow: {}",
            http_body(&instances_after_allow)
        );
        assert!(
            store_b.store().load_instance(instance_id).is_err(),
            "store B must not copy the issuing inode"
        );
        assert!(
            store_b.store().holder_secret_path(instance_id).exists() == false,
            "store B must not write a holder secret file"
        );

        let kill_body = serde_json::json!({
            "instance_id": instance_id,
            "confirm": instance_id,
        })
        .to_string();
        let kill_response =
            exchange_one_http_request(&store_a, &http_post_request("/kill", &kill_body));
        assert!(
            kill_response.starts_with("HTTP/1.1 200"),
            "GET / POST /kill on store A must return 200: {kill_response}"
        );
        let kill_export_body = serde_json::json!({
            "instance_id": instance_id,
            "confirm": instance_id,
        })
        .to_string();
        let kill_export_response = exchange_one_http_request(
            &store_a,
            &http_post_request("/kill-export", &kill_export_body),
        );
        assert!(
            kill_export_response.starts_with("HTTP/1.1 200"),
            "GET / POST /kill-export on store A must return 200: {kill_export_response}"
        );
        let kill_export_value: serde_json::Value =
            serde_json::from_str(http_body(&kill_export_response))
                .expect("POST /kill-export must return JSON");
        let accept_body = serde_json::json!({
            "event": kill_export_value["event"],
            "proof": kill_export_value["proof"],
            "tree_head": kill_export_value["tree_head"],
        })
        .to_string();
        assert_eq!(
            json_object_keys(&accept_body),
            ["event", "proof", "tree_head"]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>(),
            "GET / kill-accept must send the three public artifacts only"
        );
        let accept_response =
            exchange_one_http_request(&store_b, &http_post_request("/kill-accept", &accept_body));
        assert!(
            accept_response.starts_with("HTTP/1.1 200"),
            "GET / POST /kill-accept on store B must return 200: {accept_response}"
        );

        let refuse_response =
            exchange_one_http_request(&store_b, &http_post_request("/check-svid", &check_body));
        assert!(
            refuse_response.contains("HTTP/1.1 403"),
            "GET / check of the same historical present on store B must refuse after kill-accept: {refuse_response}"
        );
        let refuse_payload = http_body(&refuse_response);
        let refuse_value: serde_json::Value =
            serde_json::from_str(refuse_payload).expect("POST /check-svid must return JSON");
        assert_eq!(
            refuse_value["result"].as_str(),
            Some("refused"),
            "store B GET / check must refuse after death: {refuse_payload}"
        );
        let refuse_reason = refuse_value["reason"].as_str().unwrap_or("");
        assert!(
            refuse_reason.contains("kill accept"),
            "store B must refuse from accepted death, not from an inode lookup: {refuse_reason}"
        );

        let instances_after_kill = exchange_one_http_request(
            &store_b,
            "GET /instances HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        let instances_after_kill_value: serde_json::Value =
            serde_json::from_str(http_body(&instances_after_kill))
                .expect("GET /instances must return JSON");
        assert_eq!(
            instances_after_kill_value["instances"]
                .as_array()
                .map(Vec::len),
            Some(0),
            "store B GET /instances must stay empty after kill-accept: {}",
            http_body(&instances_after_kill)
        );
        let issuer_secret_b_after = store_b
            .store()
            .load_secret()
            .expect("load store B issuer.secret after the walk");
        assert_eq!(
            issuer_secret_b_before, issuer_secret_b_after,
            "store B must not copy issuer.secret"
        );
        assert_ne!(
            issuer_secret_a, issuer_secret_b_after,
            "store B must keep a different issuer.secret from store A"
        );
        assert_body_has_no_secrets(
            &store_a,
            allow_payload,
            Some(instance_id),
            "later UI store B allow",
        );
        assert_body_has_no_secrets(
            &store_b,
            allow_payload,
            None,
            "later UI store B allow secrets",
        );
        assert_body_has_no_secrets(
            &store_a,
            refuse_payload,
            Some(instance_id),
            "later UI store B refuse",
        );
        assert_body_has_no_secrets(
            &store_b,
            refuse_payload,
            None,
            "later UI store B refuse secrets",
        );
        assert_body_has_no_secrets(&store_a, page_a_body, Some(instance_id), "GET / on store A");
        assert_body_has_no_secrets(&store_b, page_b_body, None, "GET / on store B");
    }

    #[test]
    fn the_later_user_interface_spawn_walk_allows_then_refuses_after_child_kill() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create the issuing store");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuing store");

        let page = exchange_one_http_request(
            &kernel,
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            page.starts_with("HTTP/1.1 200"),
            "the spawn walk must use GET /: {page}"
        );
        let page_body = http_body(&page);
        assert!(
            page_body.contains("Prometheus later user interface"),
            "the spawn walk must use GET /, not GET /laboratory"
        );
        assert!(
            page_body.contains("<h2>Spawn</h2>")
                && (page_body.contains("not a role catalog")
                    || page_body.contains("This is not a role catalog")),
            "GET / must place spawn in the kernel story and say it is not a role catalog"
        );
        assert!(
            page_body.contains("127.0.0.1") && !page_body.contains("0.0.0.0"),
            "GET / must bind 127.0.0.1 only"
        );

        let agent_type_body = serde_json::json!({
            "allowed_intents": ["read"],
            "authorization_limit": "internal",
            "owner": "laboratory",
        })
        .to_string();
        let agent_type_response =
            exchange_one_http_request(&kernel, &http_post_request("/agent-type", &agent_type_body));
        assert!(
            agent_type_response.starts_with("HTTP/1.1 200"),
            "GET / POST /agent-type must return 200: {agent_type_response}"
        );
        let agent_type_id =
            serde_json::from_str::<serde_json::Value>(http_body(&agent_type_response))
                .expect("POST /agent-type must return JSON")["agent_type_id"]
                .as_str()
                .expect("POST /agent-type must return agent_type_id")
                .to_string();

        let birth_body = serde_json::json!({
            "agent_type_id": agent_type_id,
            "owner": "laboratory",
            "intent": "read",
            "audience": "internal/prod",
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let birth_response =
            exchange_one_http_request(&kernel, &http_post_request("/birth", &birth_body));
        assert!(
            birth_response.starts_with("HTTP/1.1 200"),
            "GET / POST /birth must return 200: {birth_response}"
        );
        let birth_value: serde_json::Value =
            serde_json::from_str(http_body(&birth_response)).expect("POST /birth must return JSON");
        let parent_instance_id = birth_value["instance_id"]
            .as_str()
            .expect("POST /birth must return instance_id")
            .to_string();
        let parent_capability_id = birth_value["capability_id"]
            .as_str()
            .expect("POST /birth must return capability_id")
            .to_string();
        let parent_holder_secret_path = birth_value["holder_secret_path"]
            .as_str()
            .expect("POST /birth must return holder_secret_path")
            .to_string();

        let wider_nonce =
            serde_json::from_str::<serde_json::Value>(http_body(&exchange_one_http_request(
                &kernel,
                &http_post_request(
                    "/challenge",
                    &serde_json::json!({ "instance_id": parent_instance_id }).to_string(),
                ),
            )))
            .expect("POST /challenge must return JSON")["challenge_nonce"]
                .as_str()
                .expect("POST /challenge must return challenge_nonce")
                .to_string();
        let wider_body = serde_json::json!({
            "parent_instance_id": parent_instance_id,
            "parent_capability_id": parent_capability_id,
            "owner": "laboratory",
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": parent_holder_secret_path,
            "challenge_nonce": wider_nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let wider_response =
            exchange_one_http_request(&kernel, &http_post_request("/spawn", &wider_body));
        assert!(
            wider_response.contains("HTTP/1.1 403") || wider_response.contains("HTTP/1.1 400"),
            "GET / POST /spawn must refuse a wider child: {wider_response}"
        );
        let wider_payload = http_body(&wider_response);
        assert!(
            wider_payload.contains("exceeds") || wider_payload.contains("cannot gain rights"),
            "GET / spawn must name the wider-child refuse: {wider_payload}"
        );
        let instances_after_wider: serde_json::Value =
            serde_json::from_str(http_body(&exchange_one_http_request(
                &kernel,
                "GET /instances HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            )))
            .expect("GET /instances must return JSON");
        assert_eq!(
            instances_after_wider["instances"].as_array().map(Vec::len),
            Some(1),
            "a refused wider spawn must not write a child: {instances_after_wider}"
        );

        let spawn_nonce =
            serde_json::from_str::<serde_json::Value>(http_body(&exchange_one_http_request(
                &kernel,
                &http_post_request(
                    "/challenge",
                    &serde_json::json!({ "instance_id": parent_instance_id }).to_string(),
                ),
            )))
            .expect("POST /challenge must return JSON")["challenge_nonce"]
                .as_str()
                .expect("POST /challenge must return challenge_nonce")
                .to_string();
        let spawn_body = serde_json::json!({
            "parent_instance_id": parent_instance_id,
            "parent_capability_id": parent_capability_id,
            "owner": "laboratory",
            "intent": "read",
            "audience": "internal/prod",
            "holder_secret_path": parent_holder_secret_path,
            "challenge_nonce": spawn_nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let spawn_response =
            exchange_one_http_request(&kernel, &http_post_request("/spawn", &spawn_body));
        assert!(
            spawn_response.starts_with("HTTP/1.1 200"),
            "GET / POST /spawn must write a narrower child: {spawn_response}"
        );
        let spawn_value: serde_json::Value =
            serde_json::from_str(http_body(&spawn_response)).expect("POST /spawn must return JSON");
        let child_instance_id = spawn_value["instance_id"]
            .as_str()
            .expect("POST /spawn must return instance_id")
            .to_string();
        let child_capability_id = spawn_value["capability_id"]
            .as_str()
            .expect("POST /spawn must return capability_id")
            .to_string();
        let child_holder_secret_path = spawn_value["holder_secret_path"]
            .as_str()
            .expect("POST /spawn must return holder_secret_path")
            .to_string();
        assert_ne!(
            child_instance_id, parent_instance_id,
            "the child instance identifier must come from POST /spawn, not from an invented parent identifier"
        );

        let instances_after_spawn: serde_json::Value =
            serde_json::from_str(http_body(&exchange_one_http_request(
                &kernel,
                "GET /instances HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            )))
            .expect("GET /instances must return JSON");
        let listings = instances_after_spawn["instances"]
            .as_array()
            .expect("GET /instances must return an instances array");
        let child_listing = listings
            .iter()
            .find(|listing| listing["instance_id"].as_str() == Some(child_instance_id.as_str()))
            .expect("GET /instances must list the spawn child");
        assert_eq!(
            child_listing["parent_instance_id"].as_str(),
            Some(parent_instance_id.as_str()),
            "GET /instances must lock the parent identifier on the child listing: {child_listing}"
        );
        assert_eq!(
            child_listing["status"].as_str(),
            Some("live"),
            "the spawn child must appear live: {child_listing}"
        );
        let parent_listing = listings
            .iter()
            .find(|listing| listing["instance_id"].as_str() == Some(parent_instance_id.as_str()))
            .expect("GET /instances must list the parent");
        assert!(
            parent_listing.get("parent_instance_id").is_none(),
            "birth with no parent must omit parent_instance_id: {parent_listing}"
        );

        let present_nonce =
            serde_json::from_str::<serde_json::Value>(http_body(&exchange_one_http_request(
                &kernel,
                &http_post_request(
                    "/challenge",
                    &serde_json::json!({ "instance_id": child_instance_id }).to_string(),
                ),
            )))
            .expect("POST /challenge must return JSON")["challenge_nonce"]
                .as_str()
                .expect("POST /challenge must return challenge_nonce")
                .to_string();
        let present_body = serde_json::json!({
            "instance_id": child_instance_id,
            "capability_id": child_capability_id,
            "intent": "read",
            "audience": "internal/prod",
            "holder_secret_path": child_holder_secret_path,
            "challenge_nonce": present_nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let present_response =
            exchange_one_http_request(&kernel, &http_post_request("/present-svid", &present_body));
        assert!(
            present_response.starts_with("HTTP/1.1 200"),
            "GET / POST /present-svid of the child must return 200: {present_response}"
        );
        let present_value: serde_json::Value = serde_json::from_str(http_body(&present_response))
            .expect("POST /present-svid must return JSON");
        let presentation_json = present_value["presentation_json"]
            .as_str()
            .expect("POST /present-svid must return presentation_json");
        let certificate_pem = present_value["certificate_pem"]
            .as_str()
            .expect("POST /present-svid must return certificate_pem");
        let presentation: serde_json::Value =
            serde_json::from_str(presentation_json).expect("presentation_json must be JSON");
        assert_eq!(
            presentation["instance_id"].as_str(),
            Some(child_instance_id.as_str()),
            "the present must be the child, not the parent: {presentation_json}"
        );

        let check_nonce =
            serde_json::from_str::<serde_json::Value>(http_body(&exchange_one_http_request(
                &kernel,
                &http_post_request(
                    "/challenge",
                    &serde_json::json!({ "instance_id": child_instance_id }).to_string(),
                ),
            )))
            .expect("POST /challenge must return JSON")["challenge_nonce"]
                .as_str()
                .expect("POST /challenge must return challenge_nonce")
                .to_string();
        let check_body = serde_json::json!({
            "presentation_json": presentation_json,
            "certificate_pem": certificate_pem,
            "intent": "read",
            "audience": "internal/prod",
            "holder_secret_path": child_holder_secret_path,
            "challenge_nonce": check_nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let allow_response =
            exchange_one_http_request(&kernel, &http_post_request("/check-svid", &check_body));
        assert!(
            allow_response.starts_with("HTTP/1.1 200"),
            "GET / POST /check-svid of the child must allow: {allow_response}"
        );
        let allow_payload = http_body(&allow_response);
        let allow_value: serde_json::Value =
            serde_json::from_str(allow_payload).expect("POST /check-svid must return JSON");
        assert_eq!(
            allow_value["result"].as_str(),
            Some("allowed"),
            "GET / check of the child must allow: {allow_payload}"
        );
        assert_eq!(
            allow_value["instance_id"].as_str(),
            Some(child_instance_id.as_str()),
            "GET / check must name the child: {allow_payload}"
        );

        let kill_body = serde_json::json!({
            "instance_id": child_instance_id,
            "confirm": child_instance_id,
        })
        .to_string();
        let kill_response =
            exchange_one_http_request(&kernel, &http_post_request("/kill", &kill_body));
        assert!(
            kill_response.starts_with("HTTP/1.1 200"),
            "GET / POST /kill of the child must return 200: {kill_response}"
        );
        let kill_value: serde_json::Value =
            serde_json::from_str(http_body(&kill_response)).expect("POST /kill must return JSON");
        assert_eq!(kill_value["status"].as_str(), Some("revoked"));
        assert_eq!(
            kill_value["instance_id"].as_str(),
            Some(child_instance_id.as_str()),
            "GET / kill must revoke the child: {}",
            http_body(&kill_response)
        );

        let refuse_response =
            exchange_one_http_request(&kernel, &http_post_request("/check-svid", &check_body));
        assert!(
            refuse_response.contains("HTTP/1.1 403"),
            "GET / check of the child historical present must refuse after child kill: {refuse_response}"
        );
        let refuse_payload = http_body(&refuse_response);
        let refuse_value: serde_json::Value =
            serde_json::from_str(refuse_payload).expect("POST /check-svid must return JSON");
        assert_eq!(
            refuse_value["result"].as_str(),
            Some("refused"),
            "GET / check must refuse after child death: {refuse_payload}"
        );
        let refuse_reason = refuse_value["reason"].as_str().unwrap_or("");
        assert!(
            refuse_reason.contains("local kill"),
            "GET / check must refuse from child death, not from expiry: {refuse_reason}"
        );
        assert!(
            !refuse_reason.contains("expired") && !refuse_reason.contains("expiry"),
            "short certificate life is not kill: {refuse_reason}"
        );

        let instances_after_kill: serde_json::Value =
            serde_json::from_str(http_body(&exchange_one_http_request(
                &kernel,
                "GET /instances HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            )))
            .expect("GET /instances must return JSON");
        let listings_after = instances_after_kill["instances"]
            .as_array()
            .expect("GET /instances must return an instances array");
        let child_after = listings_after
            .iter()
            .find(|listing| listing["instance_id"].as_str() == Some(child_instance_id.as_str()))
            .expect("GET /instances must still list the killed child");
        assert_eq!(
            child_after["status"].as_str(),
            Some("revoked"),
            "the killed child must appear revoked: {child_after}"
        );
        assert_eq!(
            child_after["parent_instance_id"].as_str(),
            Some(parent_instance_id.as_str()),
            "parent_instance_id stays on the child listing after kill: {child_after}"
        );
        let parent_after = listings_after
            .iter()
            .find(|listing| listing["instance_id"].as_str() == Some(parent_instance_id.as_str()))
            .expect("GET /instances must still list the parent");
        assert_eq!(
            parent_after["status"].as_str(),
            Some("live"),
            "killing the child must not kill the parent: {parent_after}"
        );

        assert_body_has_no_secrets(
            &kernel,
            page_body,
            Some(&parent_instance_id),
            "GET / spawn walk page parent",
        );
        assert_body_has_no_secrets(
            &kernel,
            page_body,
            Some(&child_instance_id),
            "GET / spawn walk page child",
        );
        assert_body_has_no_secrets(
            &kernel,
            http_body(&spawn_response),
            Some(&child_instance_id),
            "POST /spawn child",
        );
        assert_body_has_no_secrets(
            &kernel,
            allow_payload,
            Some(&child_instance_id),
            "child allow",
        );
        assert_body_has_no_secrets(
            &kernel,
            refuse_payload,
            Some(&child_instance_id),
            "child refuse",
        );
        assert_body_has_no_secrets(
            &kernel,
            wider_payload,
            Some(&parent_instance_id),
            "wider spawn refuse",
        );
    }

    #[test]
    fn the_laboratory_operator_page_remains_reachable() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let response = exchange_one_http_request(
            &kernel,
            "GET /laboratory HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "GET /laboratory must return 200: {response}"
        );
        let body = http_body(&response);
        assert!(
            body.contains("Prometheus loopback operator page"),
            "GET /laboratory must serve the laboratory operator page"
        );
        let root = exchange_one_http_request(
            &kernel,
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        let root_body = http_body(&root);
        assert!(
            root_body.contains("Prometheus later user interface"),
            "GET / must remain the later user interface while /laboratory stays reachable"
        );
        assert!(
            !root_body.contains("Prometheus loopback operator page"),
            "GET / must not serve the laboratory form dump"
        );
    }

    fn http_post_request(path: &str, body: &str) -> String {
        format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    #[test]
    fn the_host_instances_path_lists_live_and_revoked_without_secrets() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let live_birth = laboratory_host_birth(&kernel);
        let revoked_birth = kernel
            .birth_write(
                &live_birth.instance.agent_type_id,
                "laboratory".to_string(),
                std::collections::BTreeMap::new(),
                "read",
                "internal",
                None,
            )
            .expect("birth a second instance");
        kernel
            .kill_instance(&revoked_birth.instance.id)
            .expect("revoke the second instance");

        let response = exchange_one_http_request(
            &kernel,
            "GET /instances HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "GET /instances must return 200: {response}"
        );
        assert!(
            response.contains("application/json"),
            "GET /instances must return JSON: {response}"
        );
        let body = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(body).expect("GET /instances must return JSON");
        let listings = value["instances"]
            .as_array()
            .expect("GET /instances must return an instances array");
        assert_eq!(
            listings.len(),
            2,
            "GET /instances must list live and revoked"
        );

        let mut by_id = std::collections::BTreeMap::new();
        for listing in listings {
            let instance_id = listing["instance_id"]
                .as_str()
                .expect("each listing must have instance_id")
                .to_string();
            let status = listing["status"]
                .as_str()
                .expect("each listing must have status")
                .to_string();
            let object = listing.as_object().expect("each listing must be an object");
            assert!(
                object.contains_key("capability_ids"),
                "each listing must include capability identifiers: {listing}"
            );
            assert!(
                !object.contains_key("biscuit"),
                "each listing must omit capability tokens: {listing}"
            );
            assert!(
                !object.contains_key("holder_public_key"),
                "each listing must omit holder public keys: {listing}"
            );
            assert!(
                !object.contains_key("holder_secret_path"),
                "each listing must omit holder secret paths: {listing}"
            );
            let expected_len = if object.contains_key("agent_type_id") {
                4
            } else {
                3
            };
            assert_eq!(
                object.len(),
                expected_len,
                "each listing must have instance identifier, status, capability identifiers, and optional agent_type_id: {listing}"
            );
            by_id.insert(instance_id, status);
        }
        assert_eq!(
            by_id.get(&live_birth.instance.id).map(String::as_str),
            Some("live")
        );
        assert_eq!(
            by_id.get(&revoked_birth.instance.id).map(String::as_str),
            Some("revoked")
        );

        let holder_public_key = live_birth.instance.holder_public_key.clone();
        assert!(
            !holder_public_key.is_empty(),
            "the live instance must have a holder public key on the record"
        );
        assert!(
            !body.contains(&holder_public_key),
            "GET /instances must not include holder public keys"
        );
        let capability_token = live_birth.capability.biscuit.clone();
        assert!(
            !capability_token.is_empty(),
            "the live capability must have a token"
        );
        assert!(
            !body.contains(&capability_token),
            "GET /instances must not include capability tokens"
        );

        let issuer_secret = kernel.store().load_secret().expect("load issuer secret");
        let biscuit_secret = kernel
            .store()
            .load_biscuit_secret()
            .expect("load biscuit secret");
        let holder_secret =
            std::fs::read_to_string(kernel.store().holder_secret_path(&live_birth.instance.id))
                .expect("load holder secret");
        assert!(
            !body.contains(&issuer_secret),
            "the instances path must not include issuer secret material"
        );
        assert!(
            !body.contains(&biscuit_secret),
            "the instances path must not include biscuit secret material"
        );
        assert!(
            !body.contains(&holder_secret),
            "the instances path must not include holder secret material"
        );
        assert!(
            !body.contains("issuer.secret"),
            "the instances path must not name issuer.secret"
        );
        assert!(
            !body.contains("biscuit.secret"),
            "the instances path must not name biscuit.secret"
        );
        assert!(
            !body.contains("member-two.secret"),
            "the instances path must not name member-two.secret"
        );
    }

    #[test]
    fn the_host_instances_path_includes_capability_identifiers_without_tokens() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let live_birth = laboratory_host_birth(&kernel);
        let revoked_birth = kernel
            .birth_write(
                &live_birth.instance.agent_type_id,
                "laboratory".to_string(),
                std::collections::BTreeMap::new(),
                "read",
                "internal",
                None,
            )
            .expect("birth a second instance");
        kernel
            .kill_instance(&revoked_birth.instance.id)
            .expect("revoke the second instance");

        let response = exchange_one_http_request(
            &kernel,
            "GET /instances HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "GET /instances must return 200: {response}"
        );
        let body = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(body).expect("GET /instances must return JSON");
        let listings = value["instances"]
            .as_array()
            .expect("GET /instances must return an instances array");
        assert_eq!(
            listings.len(),
            2,
            "GET /instances must list live and revoked"
        );

        let mut by_id = std::collections::BTreeMap::new();
        for listing in listings {
            let instance_id = listing["instance_id"]
                .as_str()
                .expect("each listing must have instance_id")
                .to_string();
            let capability_ids = listing["capability_ids"]
                .as_array()
                .expect("each listing must have capability_ids");
            let identifiers: Vec<String> = capability_ids
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .expect("capability_ids must be identifier strings")
                        .to_string()
                })
                .collect();
            let object = listing.as_object().expect("each listing must be an object");
            assert!(
                !object.contains_key("biscuit"),
                "capability_ids must not include token bytes: {listing}"
            );
            assert!(
                !object.contains_key("holder_public_key"),
                "GET /instances must not include holder_public_key: {listing}"
            );
            assert!(
                !object.contains_key("holder_secret_path"),
                "GET /instances must not include holder_secret_path: {listing}"
            );
            if let Some(agent_type_id) = object.get("agent_type_id") {
                assert!(
                    agent_type_id.as_str().is_some(),
                    "agent_type_id must be a string when present: {listing}"
                );
            }
            by_id.insert(instance_id, identifiers);
        }

        assert_eq!(
            by_id.get(&live_birth.instance.id),
            Some(&vec![live_birth.capability.id.clone()]),
            "the live instance must list its capability identifier"
        );
        assert_eq!(
            by_id.get(&revoked_birth.instance.id),
            Some(&vec![revoked_birth.capability.id.clone()]),
            "the revoked instance must list its capability identifier"
        );
        assert_eq!(
            listings
                .iter()
                .find(|listing| listing["instance_id"].as_str()
                    == Some(live_birth.instance.id.as_str()))
                .and_then(|listing| listing["agent_type_id"].as_str()),
            Some(live_birth.instance.agent_type_id.as_str()),
            "agent_type_id must come from the instance record"
        );

        let capability_token = live_birth.capability.biscuit.clone();
        assert!(
            !capability_token.is_empty(),
            "the live capability must have a token so the absence check is real"
        );
        assert!(
            !body.contains(&capability_token),
            "GET /instances must not include capability tokens"
        );
        let holder_public_key = live_birth.instance.holder_public_key.clone();
        assert!(
            !holder_public_key.is_empty(),
            "the live instance must have a holder public key so the absence check is real"
        );
        assert!(
            !body.contains(&holder_public_key),
            "GET /instances must not include holder public keys"
        );
        let holder_secret_path = kernel
            .store()
            .holder_secret_path(&live_birth.instance.id)
            .display()
            .to_string();
        assert!(
            !holder_secret_path.is_empty(),
            "the live instance must have a holder secret path so the absence check is real"
        );
        assert!(
            !body.contains(&holder_secret_path),
            "GET /instances must not include holder secret paths"
        );
    }

    #[test]
    fn the_host_instances_path_includes_parent_instance_id_for_a_spawn_child() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let parent = laboratory_host_birth(&kernel);
        let child = laboratory_host_spawn_child(&kernel, &parent);

        let response = exchange_one_http_request(
            &kernel,
            "GET /instances HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "GET /instances must return 200: {response}"
        );
        let body = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(body).expect("GET /instances must return JSON");
        let listings = value["instances"]
            .as_array()
            .expect("GET /instances must return an instances array");
        assert_eq!(
            listings.len(),
            2,
            "GET /instances must list the parent and the spawn child"
        );

        let parent_listing = listings
            .iter()
            .find(|listing| listing["instance_id"].as_str() == Some(parent.instance.id.as_str()))
            .expect("the parent instance must appear in GET /instances");
        let parent_object = parent_listing
            .as_object()
            .expect("the parent listing must be an object");
        assert!(
            !parent_object.contains_key("parent_instance_id"),
            "birth with no parent must omit parent_instance_id: {parent_listing}"
        );

        let child_listing = listings
            .iter()
            .find(|listing| listing["instance_id"].as_str() == Some(child.instance.id.as_str()))
            .expect("the child instance must appear in GET /instances");
        let child_object = child_listing
            .as_object()
            .expect("the child listing must be an object");
        assert_eq!(
            child_listing["parent_instance_id"].as_str(),
            Some(parent.instance.id.as_str()),
            "a spawn child must include parent_instance_id: {child_listing}"
        );
        assert_eq!(
            child_listing["status"].as_str(),
            Some("live"),
            "a spawn child must appear live: {child_listing}"
        );
        assert!(
            !child_object.contains_key("biscuit"),
            "the child listing must omit capability tokens: {child_listing}"
        );
        assert!(
            !child_object.contains_key("holder_public_key"),
            "the child listing must omit holder public keys: {child_listing}"
        );
        assert!(
            !child_object.contains_key("holder_secret_path"),
            "the child listing must omit holder secret paths: {child_listing}"
        );

        let holder_public_key = child.instance.holder_public_key.clone();
        assert!(
            !holder_public_key.is_empty(),
            "the child instance must have a holder public key so the absence check is real"
        );
        assert!(
            !body.contains(&holder_public_key),
            "GET /instances must not include holder public keys"
        );
        let capability_token = child.capability.biscuit.clone();
        assert!(
            !capability_token.is_empty(),
            "the child capability must have a token so the absence check is real"
        );
        assert!(
            !body.contains(&capability_token),
            "GET /instances must not include capability tokens"
        );
        assert_body_has_no_secrets(
            &kernel,
            body,
            Some(&child.instance.id),
            "GET /instances spawn child",
        );
        assert_body_has_no_secrets(
            &kernel,
            body,
            Some(&parent.instance.id),
            "GET /instances spawn parent",
        );
    }

    #[test]
    fn the_host_challenge_path_returns_a_nonce_for_a_live_instance() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let body = serde_json::json!({
            "instance_id": birth.instance.id,
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/challenge", &body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /challenge must return 200 for a live instance: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /challenge must return JSON");
        let object = value
            .as_object()
            .expect("POST /challenge must return a JSON object");
        assert_eq!(
            object.len(),
            1,
            "POST /challenge must return challenge_nonce only: {payload}"
        );
        let nonce = value["challenge_nonce"]
            .as_str()
            .expect("POST /challenge must return challenge_nonce");
        assert!(
            !nonce.is_empty(),
            "POST /challenge must return a non-empty challenge_nonce"
        );

        let unknown = serde_json::json!({
            "instance_id": "unknown-instance",
        })
        .to_string();
        let unknown_response =
            exchange_one_http_request(&kernel, &http_post_request("/challenge", &unknown));
        assert!(
            unknown_response.contains("HTTP/1.1 403") || unknown_response.contains("HTTP/1.1 400"),
            "POST /challenge must fail closed for an unknown instance: {unknown_response}"
        );
        kernel
            .kill_instance(&birth.instance.id)
            .expect("revoke the live instance");
        let revoked_response =
            exchange_one_http_request(&kernel, &http_post_request("/challenge", &body));
        assert!(
            revoked_response.contains("HTTP/1.1 403"),
            "POST /challenge must fail closed for a revoked instance: {revoked_response}"
        );
        let revoked_body = http_body(&revoked_response);
        assert!(
            revoked_body.contains("revoked") || revoked_body.contains("does not exist"),
            "POST /challenge must name the revoke refuse: {revoked_body}"
        );
    }

    #[test]
    fn the_host_challenge_path_refuses_after_issuer_seal() {
        use crate::kernel::Kernel;
        use chrono::Duration;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let start = chrono::Utc::now();
        kernel.set_now_for_test(start);
        let birth = laboratory_host_birth(&kernel);
        kernel.seal_issuer(60).expect("seal the issuer");
        kernel.set_now_for_test(start + Duration::seconds(60));
        let log_before = kernel
            .store()
            .read_log()
            .expect("read the issuance log before the refused challenge");
        let challenge_lines_before = log_before
            .iter()
            .filter(|event| event.operation == "challenge")
            .count();
        let body = serde_json::json!({
            "instance_id": birth.instance.id,
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/challenge", &body));
        assert!(
            response.contains("HTTP/1.1 403") || response.contains("HTTP/1.1 400"),
            "POST /challenge must refuse after issuer seal: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("issuer seal") || payload.contains("kill_date has been reached"),
            "POST /challenge must name the issuer seal refuse: {payload}"
        );
        assert!(
            payload.contains("\"result\":\"refused\"")
                || payload.contains("\"result\": \"refused\""),
            "POST /challenge must return refused after issuer seal: {payload}"
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
            "POST /challenge after issuer seal must not append a challenge issuance.log line"
        );
        let instances_response = exchange_one_http_request(
            &kernel,
            "GET /instances HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            instances_response.starts_with("HTTP/1.1 200"),
            "GET /instances after issuer seal must still return 200: {instances_response}"
        );
        let verifier_response =
            exchange_one_http_request(&kernel, &http_post_request("/verifier-challenge", "{}"));
        assert!(
            verifier_response.starts_with("HTTP/1.1 200"),
            "POST /verifier-challenge after issuer seal must still return 200: {verifier_response}"
        );
        let log_after_verifier = kernel
            .store()
            .read_log()
            .expect("read the issuance log after verifier-challenge");
        assert_eq!(
            log_after_verifier.len(),
            log_after.len(),
            "POST /verifier-challenge after issuer seal must not append an issuance.log line"
        );
        assert_body_has_no_secrets(
            &kernel,
            payload,
            Some(&birth.instance.id),
            "POST /challenge after issuer seal",
        );
    }

    #[test]
    fn the_host_present_svid_path_emits_a_wrap_that_check_svid_allows() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let secret = kernel
            .store()
            .holder_secret_path(&birth.instance.id)
            .display()
            .to_string();
        let challenge_body = serde_json::json!({
            "instance_id": birth.instance.id,
        })
        .to_string();
        let challenge_response =
            exchange_one_http_request(&kernel, &http_post_request("/challenge", &challenge_body));
        let challenge_value: serde_json::Value =
            serde_json::from_str(http_body(&challenge_response))
                .expect("POST /challenge must return JSON");
        let present_nonce = challenge_value["challenge_nonce"]
            .as_str()
            .expect("POST /challenge must return challenge_nonce");
        let present_body = serde_json::json!({
            "instance_id": birth.instance.id,
            "capability_id": birth.capability.id,
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": secret,
            "challenge_nonce": present_nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let present_response =
            exchange_one_http_request(&kernel, &http_post_request("/present-svid", &present_body));
        assert!(
            present_response.starts_with("HTTP/1.1 200"),
            "POST /present-svid must return 200: {present_response}"
        );
        let present_payload = http_body(&present_response);
        let present_value: serde_json::Value =
            serde_json::from_str(present_payload).expect("POST /present-svid must return JSON");
        let presentation_json = present_value["presentation_json"]
            .as_str()
            .expect("POST /present-svid must return presentation_json");
        let certificate_pem = present_value["certificate_pem"]
            .as_str()
            .expect("POST /present-svid must return certificate_pem");
        assert!(
            presentation_json.contains(&birth.instance.id),
            "the presentation JSON must name the instance"
        );
        assert!(
            certificate_pem.contains("BEGIN CERTIFICATE"),
            "the certificate PEM must be a certificate artifact"
        );

        let issuer_secret = kernel.store().load_secret().expect("load issuer secret");
        let biscuit_secret = kernel
            .store()
            .load_biscuit_secret()
            .expect("load biscuit secret");
        let holder_secret =
            std::fs::read_to_string(kernel.store().holder_secret_path(&birth.instance.id))
                .expect("load holder secret");
        assert!(
            !present_payload.contains(&issuer_secret),
            "POST /present-svid must not include issuer secret material"
        );
        assert!(
            !present_payload.contains(&biscuit_secret),
            "POST /present-svid must not include biscuit secret material"
        );
        assert!(
            !present_payload.contains(&holder_secret),
            "POST /present-svid must not include holder secret material"
        );

        let check_challenge =
            exchange_one_http_request(&kernel, &http_post_request("/challenge", &challenge_body));
        let check_nonce = serde_json::from_str::<serde_json::Value>(http_body(&check_challenge))
            .expect("the second challenge must return JSON")["challenge_nonce"]
            .as_str()
            .expect("the second challenge must return a nonce")
            .to_string();
        let check_body = serde_json::json!({
            "presentation_json": presentation_json,
            "certificate_pem": certificate_pem,
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": secret,
            "challenge_nonce": check_nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let decision = super::check_svid_request_from_json(&kernel, check_body.as_bytes())
            .expect("the host check-svid path must return a decision");
        assert_eq!(decision.result, "allowed");
        assert_eq!(decision.instance_id, birth.instance.id);
    }

    #[test]
    fn the_host_present_svid_path_refuses_after_local_kill() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let secret = kernel
            .store()
            .holder_secret_path(&birth.instance.id)
            .display()
            .to_string();
        let challenge_body = serde_json::json!({
            "instance_id": birth.instance.id,
        })
        .to_string();
        let challenge_response =
            exchange_one_http_request(&kernel, &http_post_request("/challenge", &challenge_body));
        let present_nonce =
            serde_json::from_str::<serde_json::Value>(http_body(&challenge_response))
                .expect("POST /challenge must return JSON")["challenge_nonce"]
                .as_str()
                .expect("POST /challenge must return challenge_nonce")
                .to_string();
        kernel
            .kill_instance(&birth.instance.id)
            .expect("same store must persist local kill");
        let present_body = serde_json::json!({
            "instance_id": birth.instance.id,
            "capability_id": birth.capability.id,
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": secret,
            "challenge_nonce": present_nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let present_response =
            exchange_one_http_request(&kernel, &http_post_request("/present-svid", &present_body));
        assert!(
            present_response.contains("HTTP/1.1 403"),
            "POST /present-svid must refuse after local kill: {present_response}"
        );
        let present_payload = http_body(&present_response);
        assert!(
            present_payload.contains("revoked") || present_payload.contains("local kill"),
            "POST /present-svid must refuse after local kill on the wrap: {present_payload}"
        );
        assert!(
            !present_payload.contains("BEGIN CERTIFICATE"),
            "a refused present must not emit a certificate PEM"
        );
    }

    fn laboratory_agent_type(kernel: &crate::kernel::Kernel) -> crate::records::AgentType {
        kernel
            .add_agent_type(
                "laboratory".to_string(),
                vec!["read".to_string()],
                "internal".to_string(),
                2,
                crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE.to_string(),
                3600,
            )
            .expect("add a laboratory agent type")
    }

    fn assert_body_has_no_secrets(
        kernel: &crate::kernel::Kernel,
        body: &str,
        instance_id: Option<&str>,
        label: &str,
    ) {
        let issuer_secret = kernel.store().load_secret().expect("load issuer secret");
        let biscuit_secret = kernel
            .store()
            .load_biscuit_secret()
            .expect("load biscuit secret");
        assert!(
            !body.contains(&issuer_secret),
            "{label} must not include issuer secret material"
        );
        assert!(
            !body.contains(&biscuit_secret),
            "{label} must not include biscuit secret material"
        );
        if let Some(instance_id) = instance_id {
            let holder_secret =
                std::fs::read_to_string(kernel.store().holder_secret_path(instance_id))
                    .expect("load holder secret");
            assert!(
                !body.contains(&holder_secret),
                "{label} must not include holder secret material"
            );
        }
        assert!(
            !body.contains("issuer.secret"),
            "{label} must not name issuer.secret"
        );
        assert!(
            !body.contains("biscuit.secret"),
            "{label} must not name biscuit.secret"
        );
        assert!(
            !body.contains("member-two.secret"),
            "{label} must not name member-two.secret"
        );
    }

    #[test]
    fn the_host_agent_types_path_lists_identifiers_without_secrets() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let agent_type = laboratory_agent_type(&kernel);

        let response = exchange_one_http_request(
            &kernel,
            "GET /agent-types HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "GET /agent-types must return 200: {response}"
        );
        assert!(
            response.contains("application/json"),
            "GET /agent-types must return JSON: {response}"
        );
        let body = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(body).expect("GET /agent-types must return JSON");
        let listings = value["agent_types"]
            .as_array()
            .expect("GET /agent-types must return an agent_types array");
        assert_eq!(
            listings.len(),
            1,
            "GET /agent-types must list the stored agent type"
        );
        let listing = listings[0]
            .as_object()
            .expect("each listing must be an object");
        assert_eq!(
            listing.len(),
            2,
            "each listing must have agent type identifier and allowed intents only: {listing:?}"
        );
        assert_eq!(
            listing["agent_type_id"].as_str(),
            Some(agent_type.id.as_str())
        );
        let intents = listing["allowed_intents"]
            .as_array()
            .expect("allowed_intents must be an array");
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].as_str(), Some("read"));

        let issuer = kernel.store().load_issuer().expect("load issuer");
        let issuer_public_key = issuer.current_public_key_hex();
        assert!(
            !issuer_public_key.is_empty(),
            "the issuer public key must exist so the absence check is real"
        );
        assert!(
            !body.contains(&issuer_public_key),
            "GET /agent-types must not include issuer public keys"
        );
        if !agent_type.issuer_signature_hex.is_empty() {
            assert!(
                !body.contains(&agent_type.issuer_signature_hex),
                "GET /agent-types must not include agent type issuer signatures"
            );
        }
        assert_body_has_no_secrets(&kernel, body, None, "the agent-types path");
    }

    #[test]
    fn the_host_birth_path_writes_instance_and_first_capability() {
        use crate::kernel::Kernel;
        use crate::records::InstanceStatus;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let agent_type = laboratory_agent_type(&kernel);
        let body = serde_json::json!({
            "agent_type_id": agent_type.id,
            "owner": "laboratory",
            "intent": "read",
            "audience": "internal",
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/birth", &body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /birth must return 200: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /birth must return JSON");
        let object = value
            .as_object()
            .expect("POST /birth must return a JSON object");
        assert_eq!(
            object.len(),
            4,
            "POST /birth must return instance_id, capability_id, holder_secret_path, and revoke_identifier only: {payload}"
        );
        let instance_id = value["instance_id"]
            .as_str()
            .expect("POST /birth must return instance_id");
        let capability_id = value["capability_id"]
            .as_str()
            .expect("POST /birth must return capability_id");
        let holder_secret_path = value["holder_secret_path"]
            .as_str()
            .expect("POST /birth must return holder_secret_path");
        let revoke_identifier = value["revoke_identifier"]
            .as_str()
            .expect("POST /birth must return revoke_identifier");
        assert!(!instance_id.is_empty(), "instance_id must not be empty");
        assert!(!capability_id.is_empty(), "capability_id must not be empty");
        assert!(
            !holder_secret_path.is_empty(),
            "holder_secret_path must not be empty"
        );
        assert!(
            !revoke_identifier.is_empty(),
            "revoke_identifier must not be empty"
        );

        let instance = kernel
            .store()
            .load_instance(instance_id)
            .expect("POST /birth must persist the instance");
        assert_eq!(instance.status, InstanceStatus::Live);
        assert_eq!(instance.agent_type_id, agent_type.id);
        let capability = kernel
            .store()
            .load_capability(capability_id)
            .expect("POST /birth must persist the first capability");
        assert_eq!(capability.instance_id, instance.id);
        assert_eq!(capability.intent, "read");
        assert_eq!(capability.audience, "internal");
        assert_eq!(capability.revoke_identifier, revoke_identifier);
        assert_eq!(
            holder_secret_path,
            kernel
                .store()
                .holder_secret_path(instance_id)
                .display()
                .to_string()
        );
        assert!(
            std::path::Path::new(holder_secret_path).exists(),
            "the holder secret path returned by birth must exist on this host"
        );

        let holder_public_key = instance.holder_public_key.clone();
        assert!(
            !holder_public_key.is_empty(),
            "birth must write the first binder on the instance record"
        );
        assert!(
            !payload.contains(&holder_public_key),
            "POST /birth must not include the holder public key"
        );
        assert!(
            !capability.biscuit.is_empty(),
            "the first capability must have a token"
        );
        assert!(
            !payload.contains(&capability.biscuit),
            "POST /birth must not include capability token bytes"
        );
        if !instance.issuer_public_key_hex.is_empty() {
            assert!(
                !payload.contains(&instance.issuer_public_key_hex),
                "POST /birth must not include issuer public keys"
            );
        }
        assert_body_has_no_secrets(&kernel, payload, Some(instance_id), "POST /birth");

        let instances_response = exchange_one_http_request(
            &kernel,
            "GET /instances HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            instances_response.starts_with("HTTP/1.1 200"),
            "GET /instances after birth must return 200: {instances_response}"
        );
        let instances_body = http_body(&instances_response);
        let instances_value: serde_json::Value =
            serde_json::from_str(instances_body).expect("GET /instances must return JSON");
        let listings = instances_value["instances"]
            .as_array()
            .expect("GET /instances must return an instances array");
        let found = listings.iter().any(|listing| {
            listing["instance_id"].as_str() == Some(instance_id)
                && listing["status"].as_str() == Some("live")
        });
        assert!(
            found,
            "the born instance must appear live in GET /instances: {instances_body}"
        );
    }

    #[test]
    fn the_host_birth_path_refuses_an_unknown_agent_type() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let body = serde_json::json!({
            "agent_type_id": "unknown-agent-type",
            "owner": "laboratory",
            "intent": "read",
            "audience": "internal",
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/birth", &body));
        assert!(
            response.contains("HTTP/1.1 403") || response.contains("HTTP/1.1 400"),
            "POST /birth must fail closed for an unknown agent type: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("does not exist") || payload.contains("unknown"),
            "POST /birth must name the unknown agent type refuse: {payload}"
        );
        let instances = kernel
            .store()
            .list_instances()
            .expect("list instances after a refused birth");
        assert!(
            instances.is_empty(),
            "a refused unknown-type birth must not write an instance"
        );
        assert_body_has_no_secrets(&kernel, payload, None, "a refused unknown-type birth");
    }

    #[test]
    fn the_host_birth_path_refuses_an_intent_that_is_not_allowed() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let agent_type = laboratory_agent_type(&kernel);
        let body = serde_json::json!({
            "agent_type_id": agent_type.id,
            "owner": "laboratory",
            "intent": "write",
            "audience": "internal",
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/birth", &body));
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /birth must fail closed for an intent that is not allowed: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("allowed intents"),
            "POST /birth must name the intent refuse: {payload}"
        );
        let instances = kernel
            .store()
            .list_instances()
            .expect("list instances after a refused birth");
        assert!(
            instances.is_empty(),
            "a refused intent birth must not write an instance"
        );
    }

    #[test]
    fn the_host_birth_path_refuses_missing_required_fields() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let agent_type = laboratory_agent_type(&kernel);
        let body = serde_json::json!({
            "agent_type_id": agent_type.id,
            "intent": "read",
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/birth", &body));
        assert!(
            response.contains("HTTP/1.1 403") || response.contains("HTTP/1.1 400"),
            "POST /birth must fail closed when audience is missing: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("audience"),
            "POST /birth must name the missing audience: {payload}"
        );
        let instances = kernel
            .store()
            .list_instances()
            .expect("list instances after a refused birth");
        assert!(
            instances.is_empty(),
            "a refused missing-field birth must not write an instance"
        );
    }

    #[test]
    fn the_host_kill_path_revokes_a_live_instance() {
        use crate::kernel::Kernel;
        use crate::records::InstanceStatus;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let body = serde_json::json!({
            "instance_id": birth.instance.id,
            "confirm": birth.instance.id,
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/kill", &body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /kill must return 200 for a live instance: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /kill must return JSON");
        let object = value
            .as_object()
            .expect("POST /kill must return a JSON object");
        assert_eq!(
            object.len(),
            2,
            "POST /kill must return instance_id and status only: {payload}"
        );
        assert_eq!(
            value["instance_id"].as_str(),
            Some(birth.instance.id.as_str())
        );
        assert_eq!(value["status"].as_str(), Some("revoked"));

        let stored = kernel
            .store()
            .load_instance(&birth.instance.id)
            .expect("POST /kill must persist the instance");
        assert_eq!(stored.status, InstanceStatus::Revoked);

        let instances_response = exchange_one_http_request(
            &kernel,
            "GET /instances HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        let instances_body = http_body(&instances_response);
        let instances_value: serde_json::Value =
            serde_json::from_str(instances_body).expect("GET /instances must return JSON");
        let listings = instances_value["instances"]
            .as_array()
            .expect("GET /instances must return an instances array");
        let found = listings.iter().any(|listing| {
            listing["instance_id"].as_str() == Some(birth.instance.id.as_str())
                && listing["status"].as_str() == Some("revoked")
        });
        assert!(
            found,
            "the killed instance must appear revoked in GET /instances: {instances_body}"
        );
        assert_body_has_no_secrets(&kernel, payload, Some(&birth.instance.id), "POST /kill");

        let second = exchange_one_http_request(&kernel, &http_post_request("/kill", &body));
        assert!(
            second.contains("HTTP/1.1 403"),
            "POST /kill must fail closed for an already revoked instance: {second}"
        );
        let second_body = http_body(&second);
        assert!(
            second_body.contains("already revoked") || second_body.contains("revoked"),
            "POST /kill must name the already revoked refuse: {second_body}"
        );

        let unknown = serde_json::json!({
            "instance_id": "unknown-instance",
            "confirm": "unknown-instance",
        })
        .to_string();
        let unknown_response =
            exchange_one_http_request(&kernel, &http_post_request("/kill", &unknown));
        assert!(
            unknown_response.contains("HTTP/1.1 403") || unknown_response.contains("HTTP/1.1 400"),
            "POST /kill must fail closed for an unknown instance: {unknown_response}"
        );
        let unknown_body = http_body(&unknown_response);
        assert!(
            unknown_body.contains("does not exist") || unknown_body.contains("unknown"),
            "POST /kill must name the unknown instance refuse: {unknown_body}"
        );
    }

    #[test]
    fn the_host_kill_path_refuses_a_confirm_mismatch() {
        use crate::kernel::Kernel;
        use crate::records::InstanceStatus;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let mismatch = serde_json::json!({
            "instance_id": birth.instance.id,
            "confirm": "not-the-instance-identifier",
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/kill", &mismatch));
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /kill must fail closed for a confirm mismatch: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("confirm"),
            "POST /kill must name the confirm mismatch: {payload}"
        );
        let stored = kernel
            .store()
            .load_instance(&birth.instance.id)
            .expect("a refused kill must leave the instance");
        assert_eq!(stored.status, InstanceStatus::Live);

        let missing = serde_json::json!({
            "instance_id": birth.instance.id,
        })
        .to_string();
        let missing_response =
            exchange_one_http_request(&kernel, &http_post_request("/kill", &missing));
        assert!(
            missing_response.contains("HTTP/1.1 403"),
            "POST /kill must fail closed when confirm is missing: {missing_response}"
        );
        let missing_body = http_body(&missing_response);
        assert!(
            missing_body.contains("confirm"),
            "POST /kill must name the missing confirm refuse: {missing_body}"
        );
        let still_live = kernel
            .store()
            .load_instance(&birth.instance.id)
            .expect("a missing confirm must leave the instance");
        assert_eq!(still_live.status, InstanceStatus::Live);
        assert_body_has_no_secrets(
            &kernel,
            payload,
            Some(&birth.instance.id),
            "a refused confirm-mismatch kill",
        );
    }

    #[test]
    fn the_host_seal_path_refuses_a_confirm_mismatch() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let mismatch = serde_json::json!({
            "confirm": "not-seal",
            "after_seconds": 60,
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/seal", &mismatch));
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /seal must fail closed for a confirm mismatch: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("confirm"),
            "POST /seal must name the confirm mismatch: {payload}"
        );
        let issuer = kernel
            .store()
            .load_issuer()
            .expect("a refused seal must leave the issuer");
        assert!(
            issuer.kill_date.is_none(),
            "a confirm mismatch must not write issuer.kill_date"
        );
        assert_body_has_no_secrets(&kernel, payload, None, "a refused confirm-mismatch seal");

        let missing = serde_json::json!({
            "after_seconds": 60,
        })
        .to_string();
        let missing_response =
            exchange_one_http_request(&kernel, &http_post_request("/seal", &missing));
        assert!(
            missing_response.contains("HTTP/1.1 403"),
            "POST /seal must fail closed when confirm is missing: {missing_response}"
        );
        let missing_body = http_body(&missing_response);
        assert!(
            missing_body.contains("confirm"),
            "POST /seal must name the missing confirm refuse: {missing_body}"
        );
        let still_open = kernel
            .store()
            .load_issuer()
            .expect("a missing confirm must leave the issuer");
        assert!(
            still_open.kill_date.is_none(),
            "a missing confirm must not write issuer.kill_date"
        );
        assert_body_has_no_secrets(
            &kernel,
            missing_body,
            None,
            "a refused missing-confirm seal",
        );
    }

    #[test]
    fn the_host_rotate_path_rotates_and_keeps_the_previous_key_with_a_kill_date() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let before = kernel
            .store()
            .load_issuer()
            .expect("load the issuer before rotate");
        let old_public_key = before.current_public_key_hex();
        let public_response = exchange_one_http_request(
            &kernel,
            "GET /issuer-public HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            public_response.starts_with("HTTP/1.1 200"),
            "GET /issuer-public before rotate must return 200: {public_response}"
        );
        let public_before: serde_json::Value = serde_json::from_str(http_body(&public_response))
            .expect("GET /issuer-public must return JSON");
        assert_eq!(
            public_before["current_issuer_public_key_hex"].as_str(),
            Some(old_public_key.as_str())
        );

        let rotate_body = serde_json::json!({
            "confirm": "rotate",
            "kill_after_seconds": 60,
        })
        .to_string();
        let response =
            exchange_one_http_request(&kernel, &http_post_request("/rotate", &rotate_body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /rotate must return 200: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /rotate must return JSON");
        let object = value
            .as_object()
            .expect("POST /rotate must return a JSON object");
        assert_eq!(
            object.len(),
            3,
            "POST /rotate must return the new current public key and the previous key plus kill date only: {payload}"
        );
        let new_public_key = value["current_issuer_public_key_hex"]
            .as_str()
            .expect("POST /rotate must return current_issuer_public_key_hex");
        let previous_public_key = value["previous_public_key_hex"]
            .as_str()
            .expect("POST /rotate must return previous_public_key_hex");
        let previous_kill_date = value["previous_kill_date"]
            .as_str()
            .expect("POST /rotate must return previous_kill_date");
        assert_eq!(
            previous_public_key, old_public_key,
            "POST /rotate must keep the previous public key"
        );
        assert_ne!(
            new_public_key, old_public_key,
            "POST /rotate must write a new current issuer public key"
        );
        assert!(
            !previous_kill_date.is_empty(),
            "POST /rotate must keep a kill date on the previous key: {payload}"
        );
        assert_body_has_no_secrets(&kernel, payload, None, "POST /rotate");

        let after = kernel
            .store()
            .load_issuer()
            .expect("load the issuer after rotate");
        assert_eq!(after.current_public_key_hex(), new_public_key);
        assert_eq!(after.previous_issuer_keys.len(), 1);
        assert_eq!(after.previous_issuer_keys[0].public_key_hex, old_public_key);
        assert_eq!(
            after.previous_issuer_keys[0].kill_date.to_rfc3339(),
            previous_kill_date
        );

        let public_after_response = exchange_one_http_request(
            &kernel,
            "GET /issuer-public HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            public_after_response.starts_with("HTTP/1.1 200"),
            "GET /issuer-public after rotate must return 200: {public_after_response}"
        );
        let public_after: serde_json::Value =
            serde_json::from_str(http_body(&public_after_response))
                .expect("GET /issuer-public after rotate must return JSON");
        assert_eq!(
            public_after["current_issuer_public_key_hex"].as_str(),
            Some(new_public_key),
            "GET /issuer-public after rotate must return the new current key"
        );

        let export_response =
            exchange_one_http_request(&kernel, &http_post_request("/previous-key-export", "{}"));
        assert!(
            export_response.starts_with("HTTP/1.1 200"),
            "POST /previous-key-export must work after host rotate: {export_response}"
        );
        let export_payload = http_body(&export_response);
        let export_value: serde_json::Value = serde_json::from_str(export_payload)
            .expect("POST /previous-key-export must return JSON");
        assert_eq!(
            export_value["public_key_hex"].as_str(),
            Some(old_public_key.as_str()),
            "POST /previous-key-export must return the previous public key: {export_payload}"
        );
        assert_eq!(
            export_value["kill_date"].as_str(),
            Some(previous_kill_date),
            "POST /previous-key-export must return the previous-key kill date: {export_payload}"
        );
        assert_body_has_no_secrets(
            &kernel,
            export_payload,
            None,
            "POST /previous-key-export after host rotate",
        );
    }

    #[test]
    fn the_host_rotate_path_refuses_confirm_mismatch() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let before = kernel
            .store()
            .load_issuer()
            .expect("load the issuer before a refused rotate");
        let old_public_key = before.current_public_key_hex();
        let mismatch = serde_json::json!({
            "confirm": "not-rotate",
            "kill_after_seconds": 60,
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/rotate", &mismatch));
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /rotate must fail closed for a confirm mismatch: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("confirm"),
            "POST /rotate must name the confirm mismatch: {payload}"
        );
        let issuer = kernel
            .store()
            .load_issuer()
            .expect("a refused rotate must leave the issuer");
        assert_eq!(issuer.current_public_key_hex(), old_public_key);
        assert!(
            issuer.previous_issuer_keys.is_empty(),
            "a confirm mismatch must not write a previous issuer key"
        );
        assert_body_has_no_secrets(&kernel, payload, None, "a refused confirm-mismatch rotate");

        let missing = serde_json::json!({
            "kill_after_seconds": 60,
        })
        .to_string();
        let missing_response =
            exchange_one_http_request(&kernel, &http_post_request("/rotate", &missing));
        assert!(
            missing_response.contains("HTTP/1.1 403"),
            "POST /rotate must fail closed when confirm is missing: {missing_response}"
        );
        let missing_body = http_body(&missing_response);
        assert!(
            missing_body.contains("confirm"),
            "POST /rotate must name the missing confirm refuse: {missing_body}"
        );
        let still = kernel
            .store()
            .load_issuer()
            .expect("a missing confirm must leave the issuer");
        assert_eq!(still.current_public_key_hex(), old_public_key);
        assert!(
            still.previous_issuer_keys.is_empty(),
            "a missing confirm must not write a previous issuer key"
        );
        assert_body_has_no_secrets(
            &kernel,
            missing_body,
            None,
            "a refused missing-confirm rotate",
        );
    }

    #[test]
    fn the_host_rotate_path_refuses_after_issuer_seal() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let before = kernel
            .store()
            .load_issuer()
            .expect("load the issuer before seal");
        let old_public_key = before.current_public_key_hex();
        let seal_body = serde_json::json!({
            "confirm": "seal",
            "after_seconds": 60,
        })
        .to_string();
        let seal_response =
            exchange_one_http_request(&kernel, &http_post_request("/seal", &seal_body));
        assert!(
            seal_response.starts_with("HTTP/1.1 200"),
            "POST /seal must return 200: {seal_response}"
        );

        let rotate_body = serde_json::json!({
            "confirm": "rotate",
            "kill_after_seconds": 60,
        })
        .to_string();
        let response =
            exchange_one_http_request(&kernel, &http_post_request("/rotate", &rotate_body));
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /rotate must refuse after issuer seal: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("issuer seal") || payload.contains("already sealed"),
            "POST /rotate must name the issuer seal refuse: {payload}"
        );
        let after = kernel
            .store()
            .load_issuer()
            .expect("a refused rotate after seal must leave the issuer");
        assert_eq!(after.current_public_key_hex(), old_public_key);
        assert!(
            after.previous_issuer_keys.is_empty(),
            "rotate after seal must not write a previous issuer key"
        );
        assert!(after.kill_date.is_some(), "seal must still hold");
        assert_body_has_no_secrets(&kernel, payload, None, "POST /rotate after issuer seal");
    }

    #[test]
    fn the_host_member_two_path_registers_an_outside_member_and_does_not_return_secrets() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let store_directory = tempdir().expect("create a store directory");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        let before = kernel
            .store()
            .load_issuer()
            .expect("load the issuer before member two");
        assert_eq!(before.signing_member_count(), 1);
        assert_eq!(before.verify_threshold_n.max(1), 1);

        let body = serde_json::json!({
            "member_secret_path": outside.to_string_lossy(),
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/member-two", &body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /member-two must return 200: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /member-two must return JSON");
        let object = value
            .as_object()
            .expect("POST /member-two must return a JSON object");
        assert_eq!(
            object.len(),
            1,
            "POST /member-two must return the new member public key hexadecimal only: {payload}"
        );
        let public_key_hex = value["public_key_hex"]
            .as_str()
            .expect("POST /member-two must return public_key_hex");
        assert!(
            !public_key_hex.is_empty(),
            "POST /member-two must return a member public key: {payload}"
        );
        assert_ne!(
            public_key_hex,
            before.current_public_key_hex(),
            "POST /member-two must not copy issuer.secret as member two"
        );
        assert!(
            outside.exists(),
            "POST /member-two must write the member secret outside the data directory"
        );
        assert!(
            !kernel.store().path_is_inside_data_directory(&outside),
            "member two must live outside the data directory"
        );
        let member_secret =
            std::fs::read_to_string(&outside).expect("read the outside member secret");
        assert!(
            !payload.contains(member_secret.trim()),
            "POST /member-two must not return member-two secret bytes: {payload}"
        );
        assert_body_has_no_secrets(&kernel, payload, None, "POST /member-two");

        let after = kernel
            .store()
            .load_issuer()
            .expect("load the issuer after member two");
        assert_eq!(
            after.signing_member_count(),
            2,
            "POST /member-two must persist the second member public key"
        );
        assert!(
            after
                .trusted_signing_member_public_keys()
                .iter()
                .any(|key| key == public_key_hex),
            "the returned public key must be a persisted signing member"
        );

        let raise_body = serde_json::json!({
            "confirm": "verify-threshold",
            "n": 2,
        })
        .to_string();
        let raise_response = exchange_one_http_request(
            &kernel,
            &http_post_request("/set-verify-threshold", &raise_body),
        );
        assert!(
            raise_response.starts_with("HTTP/1.1 200"),
            "POST /set-verify-threshold must succeed after member two exists: {raise_response}"
        );
        let raise_payload = http_body(&raise_response);
        let raise_value: serde_json::Value = serde_json::from_str(raise_payload)
            .expect("POST /set-verify-threshold must return JSON");
        assert_eq!(
            raise_value["verify_threshold_n"].as_u64(),
            Some(2),
            "POST /set-verify-threshold must raise verify_threshold_n to 2: {raise_payload}"
        );
        assert_body_has_no_secrets(
            &kernel,
            raise_payload,
            None,
            "POST /set-verify-threshold after member two",
        );
        let raised = kernel
            .store()
            .load_issuer()
            .expect("load the issuer after verify threshold");
        assert_eq!(raised.verify_threshold_n, 2);
    }

    #[test]
    fn the_host_set_verify_threshold_refuses_before_member_two_exists() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let before = kernel
            .store()
            .load_issuer()
            .expect("load the issuer before a refused verify-threshold");
        assert_eq!(before.signing_member_count(), 1);
        assert_eq!(before.verify_threshold_n.max(1), 1);

        let body = serde_json::json!({
            "confirm": "verify-threshold",
            "n": 2,
        })
        .to_string();
        let response =
            exchange_one_http_request(&kernel, &http_post_request("/set-verify-threshold", &body));
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /set-verify-threshold must refuse before member two exists: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("member two") || payload.contains("persisted"),
            "POST /set-verify-threshold must name the persist-before-member-two refuse: {payload}"
        );
        let after = kernel
            .store()
            .load_issuer()
            .expect("a refused verify-threshold must leave the issuer");
        assert_eq!(
            after.verify_threshold_n.max(1),
            1,
            "a refused set-verify-threshold must not change verify_threshold_n"
        );
        assert_eq!(after.signing_member_count(), 1);
        assert_body_has_no_secrets(
            &kernel,
            payload,
            None,
            "a refused set-verify-threshold before member two",
        );
    }

    #[test]
    fn the_host_set_verify_threshold_at_issuance_n2_refuses_without_member_secret_path() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let store_directory = tempdir().expect("create a store directory");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        raise_live_host_issuance_threshold_two(&kernel, &outside);
        let before = kernel
            .store()
            .load_issuer()
            .expect("load the issuer after issuance threshold_n 2");
        assert_eq!(before.threshold_n, 2);
        assert_eq!(
            before.verify_threshold_n.max(1),
            1,
            "verify_threshold_n must still be 1 after issuance threshold_n 2"
        );
        let log_before = kernel
            .store()
            .read_log()
            .expect("read the issuance log before a refused verify-threshold");

        let body = serde_json::json!({
            "confirm": "verify-threshold",
            "n": 2,
        })
        .to_string();
        assert_live_host_write_refuses_without_member_secret_path(
            &kernel,
            "/set-verify-threshold",
            &body,
            "POST /set-verify-threshold after issuance n=2 without the outside member on the live host",
        );
        let after = kernel
            .store()
            .load_issuer()
            .expect("a refused set-verify-threshold must leave the issuer");
        assert_eq!(
            after.verify_threshold_n.max(1),
            1,
            "a refused set-verify-threshold must not change verify_threshold_n"
        );
        let log_after = kernel
            .store()
            .read_log()
            .expect("read the issuance log after a refused verify-threshold");
        assert_eq!(
            log_after.len(),
            log_before.len(),
            "a refused set-verify-threshold must not append a signed issuance.log line"
        );
    }

    #[test]
    fn the_host_set_verify_threshold_at_issuance_n2_succeeds_with_member_secret_path() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let store_directory = tempdir().expect("create a store directory");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        raise_live_host_issuance_threshold_two(&kernel, &outside);
        let log_before = kernel
            .store()
            .read_log()
            .expect("read the issuance log before verify-threshold");

        let body = serde_json::json!({
            "confirm": "verify-threshold",
            "n": 2,
            "member_secret_path": outside.to_string_lossy(),
        })
        .to_string();
        let response =
            exchange_one_http_request(&kernel, &http_post_request("/set-verify-threshold", &body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "after issuance threshold_n 2, POST /set-verify-threshold with the outside member must return 200: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /set-verify-threshold must return JSON");
        assert_eq!(
            value["verify_threshold_n"].as_u64(),
            Some(2),
            "POST /set-verify-threshold with the outside member must raise verify_threshold_n to 2: {payload}"
        );
        let raised = kernel
            .store()
            .load_issuer()
            .expect("load the issuer after verify-threshold");
        assert_eq!(raised.verify_threshold_n, 2);
        let log_after = kernel
            .store()
            .read_log()
            .expect("read the issuance log after verify-threshold");
        assert!(
            log_after.len() > log_before.len(),
            "POST /set-verify-threshold at issuance n=2 must append a signed issuance.log line"
        );
        assert_body_has_no_secrets(
            &kernel,
            payload,
            None,
            "POST /set-verify-threshold after issuance n=2 with the outside member",
        );
        let member_secret =
            std::fs::read_to_string(&outside).expect("read the outside member secret");
        assert!(
            !payload.contains(member_secret.trim()),
            "POST /set-verify-threshold must not return member-two secret bytes: {payload}"
        );
    }

    #[test]
    fn the_host_set_issuer_threshold_at_issuance_n2_is_same_n_noop_without_a_signed_line() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let store_directory = tempdir().expect("create a store directory");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        raise_live_host_issuance_threshold_two(&kernel, &outside);
        let log_before = kernel
            .store()
            .read_log()
            .expect("read the issuance log after issuance threshold_n 2");

        let body = serde_json::json!({
            "confirm": "issuer-threshold",
            "n": 2,
        })
        .to_string();
        let response =
            exchange_one_http_request(&kernel, &http_post_request("/set-issuer-threshold", &body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /set-issuer-threshold after n=2 is a same-n no-op: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /set-issuer-threshold must return JSON");
        assert_eq!(
            value["threshold_n"].as_u64(),
            Some(2),
            "POST /set-issuer-threshold same-n must still return threshold_n 2: {payload}"
        );
        let after = kernel
            .store()
            .load_issuer()
            .expect("load the issuer after same-n issuer-threshold");
        assert_eq!(after.threshold_n, 2);
        let log_after = kernel
            .store()
            .read_log()
            .expect("read the issuance log after same-n issuer-threshold");
        assert_eq!(
            log_after.len(),
            log_before.len(),
            "POST /set-issuer-threshold after n=2 must not append a signed issuance.log line"
        );
        assert_body_has_no_secrets(
            &kernel,
            payload,
            None,
            "POST /set-issuer-threshold same-n after issuance n=2",
        );
    }

    #[test]
    fn the_host_set_issuer_threshold_refuses_before_member_two_exists() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let before = kernel
            .store()
            .load_issuer()
            .expect("load the issuer before a refused issuer-threshold");
        assert_eq!(before.signing_member_count(), 1);
        assert_eq!(before.threshold_n.max(1), 1);

        let body = serde_json::json!({
            "confirm": "issuer-threshold",
            "n": 2,
        })
        .to_string();
        let response =
            exchange_one_http_request(&kernel, &http_post_request("/set-issuer-threshold", &body));
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /set-issuer-threshold must refuse before member two exists: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("member two") || payload.contains("persisted"),
            "POST /set-issuer-threshold must name the persist-before-member-two refuse: {payload}"
        );
        let after = kernel
            .store()
            .load_issuer()
            .expect("a refused issuer-threshold must leave the issuer");
        assert_eq!(
            after.threshold_n.max(1),
            1,
            "a refused set-issuer-threshold must not change threshold_n"
        );
        assert_eq!(after.signing_member_count(), 1);
        assert_body_has_no_secrets(
            &kernel,
            payload,
            None,
            "a refused set-issuer-threshold before member two",
        );
    }

    #[test]
    fn the_host_set_issuer_threshold_sets_two_after_member_two() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let store_directory = tempdir().expect("create a store directory");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        let before = kernel
            .store()
            .load_issuer()
            .expect("load the issuer before member two");
        assert_eq!(before.signing_member_count(), 1);
        assert_eq!(before.threshold_n.max(1), 1);
        assert_eq!(before.verify_threshold_n.max(1), 1);

        let member_body = serde_json::json!({
            "member_secret_path": outside.to_string_lossy(),
        })
        .to_string();
        let member_response =
            exchange_one_http_request(&kernel, &http_post_request("/member-two", &member_body));
        assert!(
            member_response.starts_with("HTTP/1.1 200"),
            "POST /member-two must return 200: {member_response}"
        );

        let body = serde_json::json!({
            "confirm": "issuer-threshold",
            "n": 2,
        })
        .to_string();
        let response =
            exchange_one_http_request(&kernel, &http_post_request("/set-issuer-threshold", &body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /set-issuer-threshold must succeed after member two exists: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /set-issuer-threshold must return JSON");
        let object = value
            .as_object()
            .expect("POST /set-issuer-threshold must return a JSON object");
        assert_eq!(
            object.len(),
            1,
            "POST /set-issuer-threshold must return threshold_n only: {payload}"
        );
        assert_eq!(
            value["threshold_n"].as_u64(),
            Some(2),
            "POST /set-issuer-threshold must raise threshold_n to 2: {payload}"
        );
        assert!(
            value.get("verify_threshold_n").is_none(),
            "POST /set-issuer-threshold must not rewrite verify_threshold_n: {payload}"
        );
        assert_body_has_no_secrets(
            &kernel,
            payload,
            None,
            "POST /set-issuer-threshold after member two",
        );

        let raised = kernel
            .store()
            .load_issuer()
            .expect("load the issuer after issuer threshold");
        assert_eq!(raised.threshold_n, 2);
        assert_eq!(
            raised.verify_threshold_n.max(1),
            1,
            "raising issuance threshold_n must not raise verify_threshold_n"
        );

        kernel
            .verify_log_chain()
            .expect("old one-signature lines must still verify after issuance threshold_n 2");
        let events = kernel
            .store()
            .read_log()
            .expect("read the issuance log after issuer threshold");
        let mut saw_one = false;
        let mut saw_two = false;
        for event in &events {
            let line_threshold = event.threshold_n.max(1);
            if line_threshold == 1 {
                saw_one = true;
            }
            if line_threshold >= 2 {
                saw_two = true;
            }
        }
        assert!(
            saw_one,
            "raising issuance threshold_n must not rewrite historical threshold_n 1 lines"
        );
        assert!(
            saw_two,
            "the issuer_threshold line must carry threshold_n 2"
        );

        let stolen = Kernel::open(store_directory.path());
        let seal_body = serde_json::json!({
            "confirm": "seal",
            "after_seconds": 60,
        })
        .to_string();
        let stolen_response =
            exchange_one_http_request(&stolen, &http_post_request("/seal", &seal_body));
        assert!(
            stolen_response.contains("HTTP/1.1 403"),
            "after issuance threshold_n 2, POST /seal without the outside member must refuse: {stolen_response}"
        );
        let stolen_payload = http_body(&stolen_response);
        assert!(
            stolen_payload.contains("secret")
                || stolen_payload.contains("threshold")
                || stolen_payload.contains("member"),
            "POST /seal after issuance n=2 must still require the outside member: {stolen_payload}"
        );
        let after_stolen = stolen
            .store()
            .load_issuer()
            .expect("a refused seal without member two must leave the issuer");
        assert!(
            after_stolen.kill_date.is_none(),
            "a refused seal without the outside member must not write kill_date"
        );
        assert_eq!(after_stolen.threshold_n, 2);
        assert_body_has_no_secrets(
            &stolen,
            stolen_payload,
            None,
            "POST /seal after issuance n=2 without the outside member",
        );
    }

    #[test]
    fn the_host_set_issuer_threshold_raise_refuses_without_the_outside_member_secret() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let store_directory = tempdir().expect("create a store directory");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        kernel
            .add_issuer_member_with_secret_path(Some(&outside))
            .expect("add member two outside the data directory");
        let log_before = kernel
            .store()
            .read_log()
            .expect("read the issuance log before the refused raise");
        assert_eq!(
            kernel
                .store()
                .load_issuer()
                .expect("load the issuer before the refused raise")
                .threshold_n
                .max(1),
            1
        );

        let stolen = Kernel::open(store_directory.path());
        let body = serde_json::json!({
            "confirm": "issuer-threshold",
            "n": 2,
        })
        .to_string();
        let response =
            exchange_one_http_request(&stolen, &http_post_request("/set-issuer-threshold", &body));
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /set-issuer-threshold raise without the outside member must refuse: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("secret")
                || payload.contains("member")
                || payload.contains("threshold"),
            "POST /set-issuer-threshold raise without the outside member must name the refuse: {payload}"
        );
        let after = stolen
            .store()
            .load_issuer()
            .expect("load the issuer after the refused raise");
        assert_eq!(
            after.threshold_n.max(1),
            1,
            "a refused POST /set-issuer-threshold raise must not persist the new threshold_n"
        );
        let log_after = stolen
            .store()
            .read_log()
            .expect("read the issuance log after the refused raise");
        assert_eq!(
            log_after.len(),
            log_before.len(),
            "a refused POST /set-issuer-threshold raise must not append an issuance.log line"
        );
        assert_body_has_no_secrets(
            &stolen,
            payload,
            None,
            "POST /set-issuer-threshold raise without the outside member",
        );
    }

    #[test]
    fn the_host_birth_path_at_issuance_threshold_two_refuses_without_the_outside_member_on_the_live_host(
    ) {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let store_directory = tempdir().expect("create a store directory");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");

        let member_body = serde_json::json!({
            "member_secret_path": outside.to_string_lossy(),
        })
        .to_string();
        let member_response =
            exchange_one_http_request(&kernel, &http_post_request("/member-two", &member_body));
        assert!(
            member_response.starts_with("HTTP/1.1 200"),
            "POST /member-two must return 200: {member_response}"
        );

        let threshold_body = serde_json::json!({
            "confirm": "issuer-threshold",
            "n": 2,
        })
        .to_string();
        let threshold_response = exchange_one_http_request(
            &kernel,
            &http_post_request("/set-issuer-threshold", &threshold_body),
        );
        assert!(
            threshold_response.starts_with("HTTP/1.1 200"),
            "POST /set-issuer-threshold must return 200: {threshold_response}"
        );
        let agent_type = laboratory_agent_type(&kernel);

        let birth_body = serde_json::json!({
            "agent_type_id": agent_type.id,
            "owner": "laboratory",
            "intent": "read",
            "audience": "internal",
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let response =
            exchange_one_http_request(&kernel, &http_post_request("/birth", &birth_body));
        assert!(
            response.contains("HTTP/1.1 403"),
            "after issuance threshold_n 2, POST /birth without member_secret_path on the live host must refuse: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("member_secret_path")
                || payload.contains("member secret")
                || payload.contains("outside"),
            "POST /birth without the outside member must name the required member path: {payload}"
        );
        let instances = kernel
            .store()
            .list_instances()
            .expect("a refused birth must leave the instance list");
        assert!(
            instances.is_empty(),
            "a refused birth without the outside member must not persist an instance"
        );
        assert_body_has_no_secrets(
            &kernel,
            payload,
            None,
            "POST /birth after issuance n=2 without the outside member on the live host",
        );
    }

    #[test]
    fn the_host_birth_path_at_issuance_threshold_two_succeeds_with_the_outside_member() {
        use crate::kernel::Kernel;
        use crate::records::InstanceStatus;
        use tempfile::tempdir;

        let store_directory = tempdir().expect("create a store directory");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");

        let member_body = serde_json::json!({
            "member_secret_path": outside.to_string_lossy(),
        })
        .to_string();
        let member_response =
            exchange_one_http_request(&kernel, &http_post_request("/member-two", &member_body));
        assert!(
            member_response.starts_with("HTTP/1.1 200"),
            "POST /member-two must return 200: {member_response}"
        );

        let threshold_body = serde_json::json!({
            "confirm": "issuer-threshold",
            "n": 2,
        })
        .to_string();
        let threshold_response = exchange_one_http_request(
            &kernel,
            &http_post_request("/set-issuer-threshold", &threshold_body),
        );
        assert!(
            threshold_response.starts_with("HTTP/1.1 200"),
            "POST /set-issuer-threshold must return 200: {threshold_response}"
        );
        let agent_type = laboratory_agent_type(&kernel);

        let stolen = Kernel::open(store_directory.path());
        let stolen_body = serde_json::json!({
            "agent_type_id": agent_type.id,
            "owner": "laboratory",
            "intent": "read",
            "audience": "internal",
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let stolen_response =
            exchange_one_http_request(&stolen, &http_post_request("/birth", &stolen_body));
        assert!(
            stolen_response.contains("HTTP/1.1 403"),
            "a new process with only the data directory must refuse birth at n=2: {stolen_response}"
        );

        let birth_body = serde_json::json!({
            "agent_type_id": agent_type.id,
            "owner": "laboratory",
            "intent": "read",
            "audience": "internal",
            "on_behalf_of": "autonomous",
            "member_secret_path": outside.to_string_lossy(),
        })
        .to_string();
        let response =
            exchange_one_http_request(&kernel, &http_post_request("/birth", &birth_body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "after issuance threshold_n 2, POST /birth with the outside member must return 200: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /birth must return JSON");
        let instance_id = value["instance_id"]
            .as_str()
            .expect("POST /birth must return instance_id");
        let instance = kernel
            .store()
            .load_instance(instance_id)
            .expect("POST /birth with the outside member must persist the instance");
        assert_eq!(instance.status, InstanceStatus::Live);
        assert!(
            instance.issuer_signatures.len() >= 2,
            "n=2 birth must persist two member signatures"
        );
        assert_body_has_no_secrets(
            &kernel,
            payload,
            Some(instance_id),
            "POST /birth after issuance n=2 with the outside member",
        );
        let member_secret =
            std::fs::read_to_string(&outside).expect("read the outside member secret");
        assert!(
            !payload.contains(member_secret.trim()),
            "POST /birth must not return member-two secret bytes: {payload}"
        );
    }

    #[test]
    fn the_host_sibling_writes_at_issuance_threshold_two_refuse_without_the_outside_member_on_the_live_host(
    ) {
        use crate::kernel::Kernel;
        use crate::records::InstanceStatus;
        use tempfile::tempdir;

        let store_directory = tempdir().expect("create a store directory");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let live = laboratory_host_birth(&kernel);
        let receipt = host_allowed_check_receipt(
            &kernel,
            &birth.instance.id,
            &birth.capability.id,
            "read",
            "internal",
        );
        kernel.kill_instance(&birth.instance.id).expect(
            "kill one instance before issuance threshold_n 2 so kill-export can hunt the live host",
        );
        raise_live_host_issuance_threshold_two(&kernel, &outside);

        let types_before = kernel
            .store()
            .list_agent_types()
            .expect("list agent types before a refused agent-type write")
            .len();
        assert_live_host_write_refuses_without_member_secret_path(
            &kernel,
            "/agent-type",
            &serde_json::json!({
                "allowed_intents": ["read"],
                "authorization_limit": "internal",
                "owner": "laboratory",
            })
            .to_string(),
            "POST /agent-type after issuance n=2 without the outside member on the live host",
        );
        let types_after = kernel
            .store()
            .list_agent_types()
            .expect("a refused agent-type write must leave the type list");
        assert_eq!(
            types_after.len(),
            types_before,
            "a refused agent-type write without the outside member must not persist a class"
        );

        let holder_secret_path = kernel
            .store()
            .holder_secret_path(&live.instance.id)
            .display()
            .to_string();
        let spawn_nonce = kernel
            .issue_holder_challenge(&live.instance.id)
            .expect("issue a holder challenge for spawn")
            .nonce;
        let instances_before = kernel
            .store()
            .list_instances()
            .expect("list instances before a refused spawn")
            .len();
        assert_live_host_write_refuses_without_member_secret_path(
            &kernel,
            "/spawn",
            &serde_json::json!({
                "parent_instance_id": live.instance.id,
                "parent_capability_id": live.capability.id,
                "owner": "child",
                "intent": "read",
                "audience": "internal/prod",
                "holder_secret_path": holder_secret_path,
                "challenge_nonce": spawn_nonce,
                "on_behalf_of": "autonomous",
            })
            .to_string(),
            "POST /spawn after issuance n=2 without the outside member on the live host",
        );
        let instances_after_spawn = kernel
            .store()
            .list_instances()
            .expect("a refused spawn must leave the instance list");
        assert_eq!(
            instances_after_spawn.len(),
            instances_before,
            "a refused spawn without the outside member must not persist a child"
        );

        let present_svid_nonce = kernel
            .issue_holder_challenge(&live.instance.id)
            .expect("issue a holder challenge for present-svid")
            .nonce;
        assert_live_host_write_refuses_without_member_secret_path(
            &kernel,
            "/present-svid",
            &serde_json::json!({
                "instance_id": live.instance.id,
                "capability_id": live.capability.id,
                "holder_secret_path": holder_secret_path,
                "challenge_nonce": present_svid_nonce,
            })
            .to_string(),
            "POST /present-svid after issuance n=2 without the outside member on the live host",
        );

        let present_wimse_nonce = kernel
            .issue_holder_challenge(&live.instance.id)
            .expect("issue a holder challenge for present-wimse")
            .nonce;
        assert_live_host_write_refuses_without_member_secret_path(
            &kernel,
            "/present-wimse",
            &serde_json::json!({
                "instance_id": live.instance.id,
                "capability_id": live.capability.id,
                "holder_secret_path": holder_secret_path,
                "challenge_nonce": present_wimse_nonce,
            })
            .to_string(),
            "POST /present-wimse after issuance n=2 without the outside member on the live host",
        );

        assert_live_host_write_refuses_without_member_secret_path(
            &kernel,
            "/act-export",
            &serde_json::json!({ "receipt": receipt }).to_string(),
            "POST /act-export after issuance n=2 without the outside member on the live host",
        );

        let issuer_before_rotate = kernel
            .store()
            .load_issuer()
            .expect("load the issuer before a refused rotate");
        let rotate_key = issuer_before_rotate.current_public_key_hex();
        assert_live_host_write_refuses_without_member_secret_path(
            &kernel,
            "/rotate",
            &serde_json::json!({
                "confirm": "rotate",
                "kill_after_seconds": 60,
            })
            .to_string(),
            "POST /rotate after issuance n=2 without the outside member on the live host",
        );
        let issuer_after_rotate = kernel
            .store()
            .load_issuer()
            .expect("a refused rotate must leave the issuer");
        assert_eq!(
            issuer_after_rotate.current_public_key_hex(),
            rotate_key,
            "a refused rotate without the outside member must not replace the current key"
        );
        assert!(
            issuer_after_rotate.previous_issuer_keys.is_empty(),
            "a refused rotate without the outside member must not write a previous key"
        );

        assert_live_host_write_refuses_without_member_secret_path(
            &kernel,
            "/seal",
            &serde_json::json!({
                "confirm": "seal",
                "after_seconds": 60,
            })
            .to_string(),
            "POST /seal after issuance n=2 without the outside member on the live host",
        );
        let issuer_after_seal = kernel
            .store()
            .load_issuer()
            .expect("a refused seal must leave the issuer");
        assert!(
            issuer_after_seal.kill_date.is_none(),
            "a refused seal without the outside member must not write kill_date"
        );

        assert_live_host_write_refuses_without_member_secret_path(
            &kernel,
            "/kill",
            &serde_json::json!({
                "instance_id": live.instance.id,
                "confirm": live.instance.id,
            })
            .to_string(),
            "POST /kill after issuance n=2 without the outside member on the live host",
        );
        let still_live = kernel
            .store()
            .load_instance(&live.instance.id)
            .expect("a refused kill must leave the instance");
        assert_eq!(
            still_live.status,
            InstanceStatus::Live,
            "a refused kill without the outside member must not revoke the instance"
        );

        assert_live_host_write_refuses_without_member_secret_path(
            &kernel,
            "/kill-export",
            &serde_json::json!({
                "instance_id": birth.instance.id,
                "confirm": birth.instance.id,
            })
            .to_string(),
            "POST /kill-export after issuance n=2 without the outside member on the live host",
        );
    }

    #[test]
    fn the_host_check_challenge_and_seal_export_at_issuance_threshold_two_refuse_without_the_outside_member_on_the_live_host(
    ) {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let store_directory = tempdir().expect("create a store directory");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        raise_live_host_issuance_threshold_two(&kernel, &outside);
        let agent_type = laboratory_agent_type(&kernel);
        let birth_body = serde_json::json!({
            "agent_type_id": agent_type.id,
            "owner": "laboratory",
            "intent": "read",
            "audience": "internal",
            "on_behalf_of": "autonomous",
            "member_secret_path": outside.to_string_lossy(),
        })
        .to_string();
        let birth_response =
            exchange_one_http_request(&kernel, &http_post_request("/birth", &birth_body));
        assert!(
            birth_response.starts_with("HTTP/1.1 200"),
            "POST /birth with the outside member must return 200 so leftover check paths can hunt the live host: {birth_response}"
        );
        let birth_value: serde_json::Value =
            serde_json::from_str(http_body(&birth_response)).expect("POST /birth must return JSON");
        let live = crate::kernel::BirthWrite {
            instance: kernel
                .store()
                .load_instance(
                    birth_value["instance_id"]
                        .as_str()
                        .expect("POST /birth must return instance_id"),
                )
                .expect("load the n=2 instance"),
            capability: kernel
                .store()
                .load_capability(
                    birth_value["capability_id"]
                        .as_str()
                        .expect("POST /birth must return capability_id"),
                )
                .expect("load the n=2 capability"),
            holder_secret_path: birth_value["holder_secret_path"]
                .as_str()
                .expect("POST /birth must return holder_secret_path")
                .to_string(),
        };
        let svid = laboratory_svid_wrap(&kernel, &live);
        let wimse = laboratory_wimse_artifact(&kernel, &live);

        let holder_secret_path = kernel
            .store()
            .holder_secret_path(&live.instance.id)
            .display()
            .to_string();
        let check_nonce = kernel
            .issue_holder_challenge(&live.instance.id)
            .expect("issue a holder challenge for check")
            .nonce;
        assert_live_host_write_refuses_without_member_secret_path(
            &kernel,
            "/check",
            &serde_json::json!({
                "instance_id": live.instance.id,
                "capability_id": live.capability.id,
                "intent": "read",
                "audience": "internal",
                "holder_secret_path": holder_secret_path,
                "challenge_nonce": check_nonce,
                "on_behalf_of": "autonomous",
            })
            .to_string(),
            "POST /check after issuance n=2 without the outside member on the live host",
        );

        assert_live_host_write_refuses_without_member_secret_path(
            &kernel,
            "/challenge",
            &serde_json::json!({
                "instance_id": live.instance.id,
            })
            .to_string(),
            "POST /challenge after issuance n=2 without the outside member on the live host",
        );

        let check_svid_body = check_svid_body(&kernel, &live, &svid, &svid.certificate_pem);
        assert_live_host_write_refuses_without_member_secret_path(
            &kernel,
            "/check-svid",
            &check_svid_body,
            "POST /check-svid after issuance n=2 without the outside member on the live issuing host",
        );

        let check_wimse_body = check_wimse_body(
            &kernel,
            &live,
            &wimse.presentation_json,
            &wimse.workload_identity_token,
            &wimse.content_digest,
        );
        assert_live_host_write_refuses_without_member_secret_path(
            &kernel,
            "/check-wimse",
            &check_wimse_body,
            "POST /check-wimse after issuance n=2 without the outside member on the live issuing host",
        );

        let seal_body = serde_json::json!({
            "confirm": "seal",
            "after_seconds": 60,
            "member_secret_path": outside.to_string_lossy(),
        })
        .to_string();
        let seal_response =
            exchange_one_http_request(&kernel, &http_post_request("/seal", &seal_body));
        assert!(
            seal_response.starts_with("HTTP/1.1 200"),
            "POST /seal with the outside member must return 200 so seal-export can hunt the live host: {seal_response}"
        );
        assert_live_host_write_refuses_without_member_secret_path(
            &kernel,
            "/seal-export",
            "{}",
            "POST /seal-export after issuance n=2 without the outside member on the live host",
        );

        let allowed_nonce = kernel
            .issue_holder_challenge(&live.instance.id)
            .expect("issue a holder challenge for an allowed check")
            .nonce;
        let allowed_body = serde_json::json!({
            "instance_id": live.instance.id,
            "capability_id": live.capability.id,
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": holder_secret_path,
            "challenge_nonce": allowed_nonce,
            "on_behalf_of": "autonomous",
            "member_secret_path": outside.to_string_lossy(),
        })
        .to_string();
        let allowed_response =
            exchange_one_http_request(&kernel, &http_post_request("/check", &allowed_body));
        assert!(
            allowed_response.starts_with("HTTP/1.1 200"),
            "after issuance threshold_n 2, POST /check with the outside member must return 200: {allowed_response}"
        );
        let allowed_payload = http_body(&allowed_response);
        let allowed_value: serde_json::Value =
            serde_json::from_str(allowed_payload).expect("POST /check must return JSON");
        assert_eq!(
            allowed_value["result"].as_str(),
            Some("allowed"),
            "POST /check with the outside member must allow: {allowed_payload}"
        );
        let receipt = allowed_value
            .get("receipt")
            .expect("an allowed check on the issuing store must sign a receipt");
        assert!(
            receipt["issuer_signatures"]
                .as_array()
                .map(|signatures| signatures.len() >= 2)
                .unwrap_or(false),
            "n=2 check must persist two member signatures on the receipt: {allowed_payload}"
        );
        assert_body_has_no_secrets(
            &kernel,
            allowed_payload,
            Some(&live.instance.id),
            "POST /check after issuance n=2 with the outside member",
        );
        let member_secret =
            std::fs::read_to_string(&outside).expect("read the outside member secret");
        assert!(
            !allowed_payload.contains(member_secret.trim()),
            "POST /check must not return member-two secret bytes: {allowed_payload}"
        );
    }

    #[test]
    fn store_b_check_svid_and_check_wimse_stay_free_of_issuer_member_secrets_after_store_a_issuance_threshold_two(
    ) {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let store_directory = tempdir().expect("create store A");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let store_a = Kernel::open(store_directory.path());
        store_a.initialize().expect("initialize store A");
        let birth = laboratory_host_birth(&store_a);
        let svid = laboratory_svid_wrap(&store_a, &birth);
        let wimse = laboratory_wimse_artifact(&store_a, &birth);
        raise_live_host_issuance_threshold_two(&store_a, &outside);
        let (_directory_b, store_b) = laboratory_verifier_kernel();
        pin_store_b_to_store_a(&store_a, &store_b);

        let (nonce, holder_proof) =
            store_b_verifier_signature(&store_a, &store_b, &birth.instance.id);
        let check_svid_body = serde_json::json!({
            "presentation_json": svid.presentation_json,
            "certificate_pem": svid.certificate_pem,
            "intent": "read",
            "audience": "internal",
            "holder_proof": holder_proof,
            "challenge_nonce": nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let svid_response = exchange_one_http_request(
            &store_b,
            &http_post_request("/check-svid", &check_svid_body),
        );
        assert!(
            svid_response.starts_with("HTTP/1.1 200"),
            "POST /check-svid on store B must allow without issuer member material after store A n=2: {svid_response}"
        );
        let svid_payload = http_body(&svid_response);
        let svid_value: serde_json::Value =
            serde_json::from_str(svid_payload).expect("POST /check-svid must return JSON");
        assert_eq!(
            svid_value["result"].as_str(),
            Some("allowed"),
            "POST /check-svid on store B must allow: {svid_payload}"
        );
        assert!(
            svid_value.get("receipt").is_none() || svid_value["receipt"].is_null(),
            "store B check-svid must not sign an issuing receipt: {svid_payload}"
        );
        assert_body_has_no_secrets(
            &store_a,
            svid_payload,
            Some(&birth.instance.id),
            "store B check-svid after A n=2",
        );
        assert_body_has_no_secrets(
            &store_b,
            svid_payload,
            None,
            "store B check-svid secrets after A n=2",
        );

        let (wimse_nonce, wimse_proof) =
            store_b_verifier_signature(&store_a, &store_b, &birth.instance.id);
        let envelope_secret = store_a
            .store()
            .load_biscuit_secret()
            .expect("load the issuing laboratory Ed25519 envelope secret");
        let (signature_input, signature) = crate::wimse::sign_laboratory_wimse_http_message(
            crate::wimse::LABORATORY_WIMSE_CHECK_METHOD,
            crate::wimse::LABORATORY_WIMSE_CHECK_PATH,
            &wimse.content_digest,
            &envelope_secret,
        )
        .expect("sign POST /check-wimse with the issuing envelope key");
        let check_wimse_body = serde_json::json!({
            "presentation_json": wimse.presentation_json,
            "workload_identity_token": wimse.workload_identity_token,
            "content_digest": wimse.content_digest,
            "intent": "read",
            "audience": "internal",
            "holder_proof": wimse_proof,
            "challenge_nonce": wimse_nonce,
            "on_behalf_of": "autonomous",
            "signature_input": signature_input,
            "signature": signature,
        })
        .to_string();
        let wimse_response = exchange_one_http_request(
            &store_b,
            &http_post_request_with_signature(
                "/check-wimse",
                &check_wimse_body,
                &signature_input,
                &signature,
            ),
        );
        assert!(
            wimse_response.starts_with("HTTP/1.1 200"),
            "POST /check-wimse on store B must allow without issuer member material after store A n=2: {wimse_response}"
        );
        let wimse_payload = http_body(&wimse_response);
        let wimse_value: serde_json::Value =
            serde_json::from_str(wimse_payload).expect("POST /check-wimse must return JSON");
        assert_eq!(
            wimse_value["result"].as_str(),
            Some("allowed"),
            "POST /check-wimse on store B must allow: {wimse_payload}"
        );
        assert!(
            wimse_value.get("receipt").is_none() || wimse_value["receipt"].is_null(),
            "store B check-wimse must not sign an issuing receipt: {wimse_payload}"
        );
        assert_body_has_no_secrets(
            &store_a,
            wimse_payload,
            Some(&birth.instance.id),
            "store B check-wimse after A n=2",
        );
        assert_body_has_no_secrets(
            &store_b,
            wimse_payload,
            None,
            "store B check-wimse secrets after A n=2",
        );
    }

    #[test]
    fn the_host_set_issuer_threshold_sets_three_after_three_members() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let store_directory = tempdir().expect("create a store directory");
        let two_directory = tempdir().expect("create a member-two custody directory");
        let three_directory = tempdir().expect("create a member-three custody directory");
        let outside = two_directory.path().join("member-two.secret");
        let third = three_directory.path().join("member-three.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        kernel
            .add_issuer_member_with_secret_path(Some(&outside))
            .expect("add member two outside the data directory");
        kernel
            .add_issuer_member_with_secret_path(Some(&third))
            .expect("add a third member outside the data directory");
        let before = kernel
            .store()
            .load_issuer()
            .expect("load the issuer before n=3");
        assert!(
            before.signing_member_count() >= 3,
            "n=3 requires three members"
        );
        assert_eq!(before.threshold_n.max(1), 1);

        let body = serde_json::json!({
            "confirm": "issuer-threshold",
            "n": 3,
        })
        .to_string();
        let response =
            exchange_one_http_request(&kernel, &http_post_request("/set-issuer-threshold", &body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /set-issuer-threshold must set n=3 after three members: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /set-issuer-threshold must return JSON");
        assert_eq!(
            value["threshold_n"].as_u64(),
            Some(3),
            "POST /set-issuer-threshold must raise threshold_n to 3: {payload}"
        );
        let after = kernel
            .store()
            .load_issuer()
            .expect("load the issuer after n=3");
        assert_eq!(after.threshold_n, 3);
        assert_eq!(after.signing_member_count(), before.signing_member_count());
        assert_body_has_no_secrets(&kernel, payload, None, "POST /set-issuer-threshold n=3");
    }

    #[test]
    fn the_host_member_two_path_registers_a_third_outside_member() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let store_directory = tempdir().expect("create a store directory");
        let two_directory = tempdir().expect("create a member-two custody directory");
        let three_directory = tempdir().expect("create a member-three custody directory");
        let two = two_directory.path().join("member-two.secret");
        let three = three_directory.path().join("member-three.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        let two_body = serde_json::json!({
            "member_secret_path": two.to_string_lossy(),
        })
        .to_string();
        let two_response =
            exchange_one_http_request(&kernel, &http_post_request("/member-two", &two_body));
        assert!(
            two_response.starts_with("HTTP/1.1 200"),
            "POST /member-two must register member two: {two_response}"
        );
        let three_body = serde_json::json!({
            "member_secret_path": three.to_string_lossy(),
        })
        .to_string();
        let response =
            exchange_one_http_request(&kernel, &http_post_request("/member-two", &three_body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /member-two must register a third outside member: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /member-two third member must return JSON");
        let public_key_hex = value["public_key_hex"]
            .as_str()
            .expect("POST /member-two must return public_key_hex");
        assert!(three.exists(), "member three must be written outside");
        assert!(
            !kernel.store().path_is_inside_data_directory(&three),
            "member three must live outside the data directory"
        );
        assert_ne!(
            two_directory.path(),
            three_directory.path(),
            "member three must not use the member-two custody path"
        );
        let after = kernel
            .store()
            .load_issuer()
            .expect("load the issuer after a third member");
        assert_eq!(
            after.signing_member_count(),
            3,
            "POST /member-two must persist a third member public key"
        );
        assert!(
            after
                .trusted_signing_member_public_keys()
                .iter()
                .any(|key| key == public_key_hex),
            "the returned public key must be the new third member"
        );
        assert_body_has_no_secrets(&kernel, payload, None, "POST /member-two third member");
    }

    #[test]
    fn the_host_set_issuer_threshold_refuses_after_issuer_seal() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let store_directory = tempdir().expect("create a store directory");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        kernel
            .add_issuer_member_with_secret_path(Some(&outside))
            .expect("add member two before seal");
        let seal_body = serde_json::json!({
            "confirm": "seal",
            "after_seconds": 60,
        })
        .to_string();
        let seal_response =
            exchange_one_http_request(&kernel, &http_post_request("/seal", &seal_body));
        assert!(
            seal_response.starts_with("HTTP/1.1 200"),
            "POST /seal must return 200: {seal_response}"
        );

        let body = serde_json::json!({
            "confirm": "issuer-threshold",
            "n": 2,
        })
        .to_string();
        let response =
            exchange_one_http_request(&kernel, &http_post_request("/set-issuer-threshold", &body));
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /set-issuer-threshold must refuse after issuer seal: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("issuer seal") || payload.contains("already sealed"),
            "POST /set-issuer-threshold must name the issuer seal refuse: {payload}"
        );
        let after = kernel
            .store()
            .load_issuer()
            .expect("a refused issuer-threshold after seal must leave the issuer");
        assert_eq!(
            after.threshold_n.max(1),
            1,
            "issuer-threshold after seal must not raise threshold_n"
        );
        assert!(after.kill_date.is_some(), "seal must still hold");
        assert_body_has_no_secrets(
            &kernel,
            payload,
            None,
            "POST /set-issuer-threshold after issuer seal",
        );
    }

    #[test]
    fn the_host_set_verify_threshold_refuses_after_issuer_seal() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let store_directory = tempdir().expect("create a store directory");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        kernel
            .add_issuer_member_with_secret_path(Some(&outside))
            .expect("add member two before seal");
        let seal_body = serde_json::json!({
            "confirm": "seal",
            "after_seconds": 60,
        })
        .to_string();
        let seal_response =
            exchange_one_http_request(&kernel, &http_post_request("/seal", &seal_body));
        assert!(
            seal_response.starts_with("HTTP/1.1 200"),
            "POST /seal must return 200: {seal_response}"
        );

        let body = serde_json::json!({
            "confirm": "verify-threshold",
            "n": 2,
            "member_secret_path": outside.to_string_lossy(),
        })
        .to_string();
        let response =
            exchange_one_http_request(&kernel, &http_post_request("/set-verify-threshold", &body));
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /set-verify-threshold must refuse after issuer seal: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("issuer seal") || payload.contains("already sealed"),
            "POST /set-verify-threshold must name the issuer seal refuse: {payload}"
        );
        let after = kernel
            .store()
            .load_issuer()
            .expect("a refused verify-threshold after seal must leave the issuer");
        assert_eq!(
            after.verify_threshold_n.max(1),
            1,
            "verify-threshold after seal must not raise verify_threshold_n"
        );
        assert!(after.kill_date.is_some(), "seal must still hold");
        assert_body_has_no_secrets(
            &kernel,
            payload,
            None,
            "POST /set-verify-threshold after issuer seal",
        );
    }

    #[test]
    fn the_host_member_two_path_refuses_after_issuer_seal() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let store_directory = tempdir().expect("create a store directory");
        let custody_directory = tempdir().expect("create a custody directory");
        let outside = custody_directory.path().join("member-two.secret");
        let kernel = Kernel::open(store_directory.path());
        kernel.initialize().expect("initialize the issuer");
        let seal_body = serde_json::json!({
            "confirm": "seal",
            "after_seconds": 60,
        })
        .to_string();
        let seal_response =
            exchange_one_http_request(&kernel, &http_post_request("/seal", &seal_body));
        assert!(
            seal_response.starts_with("HTTP/1.1 200"),
            "POST /seal must return 200: {seal_response}"
        );

        let body = serde_json::json!({
            "member_secret_path": outside.to_string_lossy(),
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/member-two", &body));
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /member-two must refuse after issuer seal: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("issuer seal") || payload.contains("already sealed"),
            "POST /member-two must name the issuer seal refuse: {payload}"
        );
        let after = kernel
            .store()
            .load_issuer()
            .expect("a refused member-two after seal must leave the issuer");
        assert_eq!(
            after.signing_member_count(),
            1,
            "member-two after seal must not grow the member list"
        );
        assert!(
            !outside.exists(),
            "member-two after seal must not write a member secret"
        );
        assert!(after.kill_date.is_some(), "seal must still hold");
        assert_body_has_no_secrets(&kernel, payload, None, "POST /member-two after issuer seal");
    }

    #[test]
    fn the_host_rotate_path_does_not_return_issuer_secret_material() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let rotate_body = serde_json::json!({
            "confirm": "rotate",
            "kill_after_seconds": 60,
        })
        .to_string();
        let response =
            exchange_one_http_request(&kernel, &http_post_request("/rotate", &rotate_body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /rotate must return 200: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /rotate must return JSON");
        let object = value
            .as_object()
            .expect("POST /rotate must return a JSON object");
        assert_eq!(
            object.len(),
            3,
            "POST /rotate must not grow past the public keys and the previous-key kill date: {payload}"
        );
        assert!(
            !object.contains_key("holder_secret_path"),
            "POST /rotate must not return holder_secret_path: {payload}"
        );
        assert!(
            !object.contains_key("issuer_secret_path"),
            "POST /rotate must not return issuer_secret_path: {payload}"
        );
        assert!(
            !object.contains_key("secret_path"),
            "POST /rotate must not return secret_path: {payload}"
        );
        assert_body_has_no_secrets(&kernel, payload, None, "POST /rotate secret material");
        assert_body_has_no_secrets(
            &kernel,
            &response,
            None,
            "POST /rotate full response secret material",
        );
        let secret_path = kernel.store().secret_path().display().to_string();
        assert!(
            !payload.contains(&secret_path),
            "POST /rotate must not return the issuer.secret path: {payload}"
        );
    }

    #[test]
    fn the_host_birth_path_refuses_after_host_seal() {
        use crate::kernel::Kernel;
        use chrono::Duration;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let start = chrono::Utc::now();
        kernel.set_now_for_test(start);
        let agent_type = laboratory_agent_type(&kernel);
        let seal_body = serde_json::json!({
            "confirm": "seal",
            "after_seconds": 60,
        })
        .to_string();
        let seal_response =
            exchange_one_http_request(&kernel, &http_post_request("/seal", &seal_body));
        assert!(
            seal_response.starts_with("HTTP/1.1 200"),
            "POST /seal must return 200: {seal_response}"
        );
        let seal_payload = http_body(&seal_response);
        let seal_value: serde_json::Value =
            serde_json::from_str(seal_payload).expect("POST /seal must return JSON");
        let seal_object = seal_value
            .as_object()
            .expect("POST /seal must return a JSON object");
        assert_eq!(
            seal_object.len(),
            2,
            "POST /seal must return status and kill_date only: {seal_payload}"
        );
        assert_eq!(seal_value["status"].as_str(), Some("sealed"));
        assert!(
            seal_value["kill_date"].as_str().is_some(),
            "POST /seal must return kill_date: {seal_payload}"
        );
        assert_body_has_no_secrets(&kernel, seal_payload, None, "POST /seal");

        kernel.set_now_for_test(start + Duration::seconds(60));
        let status_response = exchange_one_http_request(
            &kernel,
            "GET /status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            status_response.starts_with("HTTP/1.1 200"),
            "GET /status after host seal must return 200: {status_response}"
        );
        let status_body = http_body(&status_response);
        let status_value: serde_json::Value =
            serde_json::from_str(status_body).expect("GET /status must return JSON");
        assert_eq!(
            status_value["sealed"].as_bool(),
            Some(true),
            "GET /status after remaining life must show sealed: {status_body}"
        );

        let birth_body = serde_json::json!({
            "agent_type_id": agent_type.id,
            "owner": "laboratory",
            "intent": "read",
            "audience": "internal",
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let birth_response =
            exchange_one_http_request(&kernel, &http_post_request("/birth", &birth_body));
        assert!(
            birth_response.contains("HTTP/1.1 403"),
            "POST /birth must refuse after host seal: {birth_response}"
        );
        let birth_payload = http_body(&birth_response);
        assert!(
            birth_payload.contains("issuer seal")
                || birth_payload.contains("kill_date has been reached"),
            "POST /birth must name the issuer seal refuse: {birth_payload}"
        );
        let instances = kernel
            .store()
            .list_instances()
            .expect("list instances after a refused birth");
        assert!(
            instances.is_empty(),
            "a refused birth after host seal must not write an instance"
        );
        assert_body_has_no_secrets(&kernel, birth_payload, None, "POST /birth after host seal");
    }

    #[test]
    fn the_host_kill_path_still_revokes_after_host_seal() {
        use crate::kernel::Kernel;
        use crate::records::InstanceStatus;
        use chrono::Duration;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let start = chrono::Utc::now();
        kernel.set_now_for_test(start);
        let birth = laboratory_host_birth(&kernel);
        let seal_body = serde_json::json!({
            "confirm": "seal",
            "after_seconds": 60,
        })
        .to_string();
        let seal_response =
            exchange_one_http_request(&kernel, &http_post_request("/seal", &seal_body));
        assert!(
            seal_response.starts_with("HTTP/1.1 200"),
            "POST /seal must return 200: {seal_response}"
        );
        kernel.set_now_for_test(start + Duration::seconds(60));
        let kill_body = serde_json::json!({
            "instance_id": birth.instance.id,
            "confirm": birth.instance.id,
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/kill", &kill_body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /kill must still revoke after host seal: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /kill must return JSON");
        assert_eq!(
            value["instance_id"].as_str(),
            Some(birth.instance.id.as_str())
        );
        assert_eq!(value["status"].as_str(), Some("revoked"));
        let stored = kernel
            .store()
            .load_instance(&birth.instance.id)
            .expect("POST /kill after host seal must persist the instance");
        assert_eq!(stored.status, InstanceStatus::Revoked);
        assert_body_has_no_secrets(
            &kernel,
            payload,
            Some(&birth.instance.id),
            "POST /kill after host seal",
        );
    }

    #[test]
    fn the_host_kill_export_path_returns_event_proof_and_tree_head_after_kill() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let kill_body = serde_json::json!({
            "instance_id": birth.instance.id,
            "confirm": birth.instance.id,
        })
        .to_string();
        let kill_response =
            exchange_one_http_request(&kernel, &http_post_request("/kill", &kill_body));
        assert!(
            kill_response.starts_with("HTTP/1.1 200"),
            "POST /kill must revoke the live instance before export: {kill_response}"
        );
        let export_body = serde_json::json!({
            "instance_id": birth.instance.id,
            "confirm": birth.instance.id,
        })
        .to_string();
        let response =
            exchange_one_http_request(&kernel, &http_post_request("/kill-export", &export_body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /kill-export must return 200 after local kill: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /kill-export must return JSON");
        let object = value
            .as_object()
            .expect("POST /kill-export must return a JSON object");
        assert!(
            object.contains_key("event"),
            "POST /kill-export must return event: {payload}"
        );
        assert!(
            object.contains_key("proof"),
            "POST /kill-export must return proof: {payload}"
        );
        assert!(
            object.contains_key("tree_head"),
            "POST /kill-export must return tree_head: {payload}"
        );
        let event = &value["event"];
        assert!(
            event.is_object() || event.is_string(),
            "event must be a JSON object or string: {payload}"
        );
        let event_text = if event.is_string() {
            event.as_str().unwrap().to_string()
        } else {
            event.to_string()
        };
        assert!(
            event_text.contains("kill_instance") || event_text.contains("issuance_log_line"),
            "event must carry the public kill artifact: {payload}"
        );
        let proof = &value["proof"];
        assert!(
            proof.is_object() || proof.is_string(),
            "proof must be a JSON object or string: {payload}"
        );
        let proof_text = if proof.is_string() {
            proof.as_str().unwrap().to_string()
        } else {
            proof.to_string()
        };
        assert!(
            proof_text.contains("line_hash") && proof_text.contains("root"),
            "proof must carry line_hash and root: {payload}"
        );
        let tree_head = &value["tree_head"];
        assert!(
            tree_head.is_object() || tree_head.is_string(),
            "tree_head must be a JSON object or string: {payload}"
        );
        let tree_head_text = if tree_head.is_string() {
            tree_head.as_str().unwrap().to_string()
        } else {
            tree_head.to_string()
        };
        assert!(
            tree_head_text.contains("merkle_root"),
            "tree_head must carry merkle_root: {payload}"
        );
        assert_body_has_no_secrets(
            &kernel,
            payload,
            Some(&birth.instance.id),
            "POST /kill-export",
        );
    }

    #[test]
    fn the_host_kill_export_path_returns_event_proof_and_tree_head_after_remaining_life() {
        use crate::kernel::Kernel;
        use crate::records::InstanceStatus;
        use chrono::Duration;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let start = chrono::Utc::now();
        kernel.set_now_for_test(start);
        let birth = laboratory_host_birth(&kernel);
        let seal_body = serde_json::json!({
            "confirm": "seal",
            "after_seconds": 1,
        })
        .to_string();
        let seal_response =
            exchange_one_http_request(&kernel, &http_post_request("/seal", &seal_body));
        assert!(
            seal_response.starts_with("HTTP/1.1 200"),
            "POST /seal must return 200: {seal_response}"
        );
        kernel.set_now_for_test(start + Duration::seconds(2));
        let kill_body = serde_json::json!({
            "instance_id": birth.instance.id,
            "confirm": birth.instance.id,
        })
        .to_string();
        let kill_response =
            exchange_one_http_request(&kernel, &http_post_request("/kill", &kill_body));
        assert!(
            kill_response.starts_with("HTTP/1.1 200"),
            "POST /kill after remaining life must still revoke: {kill_response}"
        );
        let stored = kernel
            .store()
            .load_instance(&birth.instance.id)
            .expect("POST /kill after remaining life must persist the instance");
        assert_eq!(stored.status, InstanceStatus::Revoked);
        let export_body = serde_json::json!({
            "instance_id": birth.instance.id,
            "confirm": birth.instance.id,
        })
        .to_string();
        let response =
            exchange_one_http_request(&kernel, &http_post_request("/kill-export", &export_body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /kill-export after remaining life must return 200: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /kill-export must return JSON");
        let object = value
            .as_object()
            .expect("POST /kill-export must return a JSON object");
        assert!(
            object.contains_key("event"),
            "POST /kill-export after remaining life must return event: {payload}"
        );
        assert!(
            object.contains_key("proof"),
            "POST /kill-export after remaining life must return proof: {payload}"
        );
        assert!(
            object.contains_key("tree_head"),
            "POST /kill-export after remaining life must return tree_head: {payload}"
        );
        assert_body_has_no_secrets(
            &kernel,
            payload,
            Some(&birth.instance.id),
            "POST /kill-export after remaining life",
        );
    }

    #[test]
    fn the_host_kill_export_path_refuses_while_the_instance_is_live() {
        use crate::kernel::Kernel;
        use crate::records::InstanceStatus;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let body = serde_json::json!({
            "instance_id": birth.instance.id,
            "confirm": birth.instance.id,
        })
        .to_string();
        let response =
            exchange_one_http_request(&kernel, &http_post_request("/kill-export", &body));
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /kill-export must fail closed while the instance is live: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("live") || payload.contains("still live"),
            "POST /kill-export must name the live refuse: {payload}"
        );
        let stored = kernel
            .store()
            .load_instance(&birth.instance.id)
            .expect("a refused live export must leave the instance");
        assert_eq!(stored.status, InstanceStatus::Live);
        assert_body_has_no_secrets(
            &kernel,
            payload,
            Some(&birth.instance.id),
            "a refused live kill-export",
        );
    }

    #[test]
    fn the_host_kill_export_path_does_not_return_secrets() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        kernel
            .kill_instance(&birth.instance.id)
            .expect("revoke the instance before export");
        let body = serde_json::json!({
            "instance_id": birth.instance.id,
            "confirm": birth.instance.id,
        })
        .to_string();
        let response =
            exchange_one_http_request(&kernel, &http_post_request("/kill-export", &body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /kill-export must return 200 after local kill: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /kill-export must return JSON");
        assert!(
            value.get("event").is_some(),
            "POST /kill-export must return event: {payload}"
        );
        assert!(
            value.get("proof").is_some(),
            "POST /kill-export must return proof: {payload}"
        );
        assert!(
            value.get("tree_head").is_some(),
            "POST /kill-export must return tree_head: {payload}"
        );
        assert_body_has_no_secrets(
            &kernel,
            payload,
            Some(&birth.instance.id),
            "POST /kill-export secrets lock",
        );
    }

    #[test]
    fn the_host_check_svid_path_refuses_after_host_kill() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let artifact = laboratory_svid_wrap(&kernel, &birth);
        kernel
            .verify_x509_svid(
                &artifact.certificate_pem,
                artifact.presentation_json.as_bytes(),
            )
            .expect("the live wrap must verify before host kill");
        let kill_body = serde_json::json!({
            "instance_id": birth.instance.id,
            "confirm": birth.instance.id,
        })
        .to_string();
        let body = check_svid_body(&kernel, &birth, &artifact, &artifact.certificate_pem);
        let kill_response =
            exchange_one_http_request(&kernel, &http_post_request("/kill", &kill_body));
        assert!(
            kill_response.starts_with("HTTP/1.1 200"),
            "POST /kill must revoke the live instance: {kill_response}"
        );
        let decision = super::check_svid_request_from_json(&kernel, body.as_bytes())
            .expect("the host check-svid path must return a decision");
        assert_eq!(decision.result, "refused");
        let reason = decision.reason.unwrap_or_default();
        assert!(
            reason.contains("local kill"),
            "the host check-svid path must refuse after host kill on the wrap: {reason}"
        );
        assert!(
            decision.receipt.is_none(),
            "a refused wrap must not sign a new decision receipt"
        );
    }

    #[test]
    fn the_host_agent_type_path_refuses_after_issuer_seal() {
        use crate::kernel::Kernel;
        use chrono::Duration;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let start = chrono::Utc::now();
        kernel.set_now_for_test(start);
        kernel.seal_issuer(60).expect("seal the issuer");
        kernel.set_now_for_test(start + Duration::seconds(60));
        let types_before = kernel
            .store()
            .list_agent_types()
            .expect("list agent types before the host write")
            .len();
        let body = serde_json::json!({
            "allowed_intents": ["read"],
            "authorization_limit": "internal",
            "owner": "laboratory",
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/agent-type", &body));
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "POST /agent-type must refuse after the issuer seal kill_date: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("issuer seal") || payload.contains("kill_date has been reached"),
            "POST /agent-type must name the issuer seal refuse: {payload}"
        );
        assert!(
            payload.contains("\"result\":\"refused\"")
                || payload.contains("\"result\": \"refused\""),
            "POST /agent-type must return refused: {payload}"
        );
        let types_after = kernel
            .store()
            .list_agent_types()
            .expect("list agent types after the refused write")
            .len();
        assert_eq!(
            types_after, types_before,
            "POST /agent-type must not persist a class after the issuer seal"
        );
        assert_body_has_no_secrets(&kernel, payload, None, "POST /agent-type after seal");
    }

    #[test]
    fn the_host_agent_type_path_writes_a_class() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let body = serde_json::json!({
            "allowed_intents": ["read"],
            "authorization_limit": "internal",
            "owner": "laboratory",
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/agent-type", &body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /agent-type must return 200: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /agent-type must return JSON");
        let object = value
            .as_object()
            .expect("POST /agent-type must return a JSON object");
        assert_eq!(
            object.len(),
            2,
            "POST /agent-type must return agent_type_id and allowed_intents only: {payload}"
        );
        let agent_type_id = value["agent_type_id"]
            .as_str()
            .expect("POST /agent-type must return agent_type_id");
        assert!(!agent_type_id.is_empty(), "agent_type_id must not be empty");
        let intents = value["allowed_intents"]
            .as_array()
            .expect("POST /agent-type must return allowed_intents");
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].as_str(), Some("read"));

        let stored = kernel
            .store()
            .load_agent_type(agent_type_id)
            .expect("POST /agent-type must persist the agent type");
        assert_eq!(stored.allowed_intents, vec!["read".to_string()]);
        assert_eq!(stored.authorization_limit, "internal");
        assert_eq!(stored.owner, "laboratory");

        let issuer = kernel.store().load_issuer().expect("load issuer");
        let issuer_public_key = issuer.current_public_key_hex();
        assert!(
            !issuer_public_key.is_empty(),
            "the issuer public key must exist so the absence check is real"
        );
        assert!(
            !payload.contains(&issuer_public_key),
            "POST /agent-type must not include issuer public keys"
        );
        if !stored.issuer_signature_hex.is_empty() {
            assert!(
                !payload.contains(&stored.issuer_signature_hex),
                "POST /agent-type must not include agent type issuer signatures"
            );
        }
        assert_body_has_no_secrets(&kernel, payload, None, "POST /agent-type");

        let listing_response = exchange_one_http_request(
            &kernel,
            "GET /agent-types HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            listing_response.starts_with("HTTP/1.1 200"),
            "GET /agent-types after the class write must return 200: {listing_response}"
        );
        let listing_body = http_body(&listing_response);
        let listing_value: serde_json::Value =
            serde_json::from_str(listing_body).expect("GET /agent-types must return JSON");
        let listings = listing_value["agent_types"]
            .as_array()
            .expect("GET /agent-types must return an agent_types array");
        let found = listings.iter().any(|listing| {
            listing["agent_type_id"].as_str() == Some(agent_type_id)
                && listing["allowed_intents"]
                    .as_array()
                    .map(|values| values.iter().any(|value| value.as_str() == Some("read")))
                    == Some(true)
        });
        assert!(
            found,
            "the written class must appear in GET /agent-types: {listing_body}"
        );

        let empty = serde_json::json!({
            "allowed_intents": [],
            "authorization_limit": "internal",
        })
        .to_string();
        let empty_response =
            exchange_one_http_request(&kernel, &http_post_request("/agent-type", &empty));
        assert!(
            empty_response.starts_with("HTTP/1.1 403"),
            "POST /agent-type must fail closed for empty intents: {empty_response}"
        );
        let empty_body = http_body(&empty_response);
        assert!(
            empty_body.contains("intent"),
            "POST /agent-type must name the empty intent refuse: {empty_body}"
        );

        let missing = serde_json::json!({
            "allowed_intents": ["read"],
        })
        .to_string();
        let missing_response =
            exchange_one_http_request(&kernel, &http_post_request("/agent-type", &missing));
        assert!(
            missing_response.starts_with("HTTP/1.1 403"),
            "POST /agent-type must fail closed when authorization_limit is missing: {missing_response}"
        );
        let missing_body = http_body(&missing_response);
        assert!(
            missing_body.contains("authorization_limit")
                || missing_body.contains("authorization limit"),
            "POST /agent-type must name the missing authorization limit: {missing_body}"
        );
    }

    #[test]
    fn the_host_agent_type_path_refuses_adding_intents_after_first_write() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let first_body = serde_json::json!({
            "allowed_intents": ["read"],
            "authorization_limit": "internal",
        })
        .to_string();
        let first =
            exchange_one_http_request(&kernel, &http_post_request("/agent-type", &first_body));
        assert!(
            first.starts_with("HTTP/1.1 200"),
            "the first class write must succeed: {first}"
        );
        let first_payload = http_body(&first);
        let first_value: serde_json::Value =
            serde_json::from_str(first_payload).expect("the first class write must return JSON");
        let agent_type_id = first_value["agent_type_id"]
            .as_str()
            .expect("the first class write must return agent_type_id")
            .to_string();

        let later_body = serde_json::json!({
            "agent_type_id": agent_type_id,
            "allowed_intents": ["read", "write"],
            "authorization_limit": "internal",
        })
        .to_string();
        let later =
            exchange_one_http_request(&kernel, &http_post_request("/agent-type", &later_body));
        assert!(
            later.starts_with("HTTP/1.1 403"),
            "POST /agent-type must refuse adding intents after the first write: {later}"
        );
        let later_payload = http_body(&later);
        assert!(
            later_payload.contains("frozen") || later_payload.contains("adds an intent"),
            "POST /agent-type must name the frozen intents refuse: {later_payload}"
        );
        let stored = kernel
            .store()
            .load_agent_type(&agent_type_id)
            .expect("load the agent type after the refused later write");
        assert_eq!(
            stored.allowed_intents,
            vec!["read".to_string()],
            "a later add of intents must not persist"
        );
        assert_body_has_no_secrets(&kernel, later_payload, None, "POST /agent-type later write");

        let duplicate_body = serde_json::json!({
            "agent_type_id": agent_type_id,
            "allowed_intents": ["read"],
            "authorization_limit": "internal",
        })
        .to_string();
        let duplicate =
            exchange_one_http_request(&kernel, &http_post_request("/agent-type", &duplicate_body));
        assert!(
            duplicate.starts_with("HTTP/1.1 403"),
            "POST /agent-type must fail closed for a duplicate agent type identifier: {duplicate}"
        );
    }

    #[test]
    fn the_host_spawn_path_writes_a_narrower_child() {
        use crate::kernel::Kernel;
        use crate::records::InstanceStatus;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let nonce = kernel
            .issue_holder_challenge(&birth.instance.id)
            .expect("issue a holder challenge for spawn")
            .nonce;
        let holder_secret_path = kernel
            .store()
            .holder_secret_path(&birth.instance.id)
            .display()
            .to_string();
        let body = serde_json::json!({
            "parent_instance_id": birth.instance.id,
            "parent_capability_id": birth.capability.id,
            "owner": "child",
            "intent": "read",
            "audience": "internal/prod",
            "holder_secret_path": holder_secret_path,
            "challenge_nonce": nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/spawn", &body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /spawn must return 200 for a narrower child: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /spawn must return JSON");
        let object = value
            .as_object()
            .expect("POST /spawn must return a JSON object");
        assert_eq!(
            object.len(),
            3,
            "POST /spawn must return instance_id, capability_id, and holder_secret_path only: {payload}"
        );
        let instance_id = value["instance_id"]
            .as_str()
            .expect("POST /spawn must return instance_id");
        let capability_id = value["capability_id"]
            .as_str()
            .expect("POST /spawn must return capability_id");
        let child_holder_secret_path = value["holder_secret_path"]
            .as_str()
            .expect("POST /spawn must return holder_secret_path");
        assert!(
            !instance_id.is_empty(),
            "child instance_id must not be empty"
        );
        assert!(
            !capability_id.is_empty(),
            "child capability_id must not be empty"
        );
        assert!(
            !child_holder_secret_path.is_empty(),
            "child holder_secret_path must not be empty"
        );
        assert_ne!(
            instance_id, birth.instance.id,
            "the child instance identifier must differ from the parent"
        );

        let child = kernel
            .store()
            .load_instance(instance_id)
            .expect("POST /spawn must persist the child instance");
        assert_eq!(child.status, InstanceStatus::Live);
        assert_eq!(
            child.parent_instance_id.as_deref(),
            Some(birth.instance.id.as_str())
        );
        let capability = kernel
            .store()
            .load_capability(capability_id)
            .expect("POST /spawn must persist the child capability");
        assert_eq!(capability.instance_id, child.id);
        assert_eq!(capability.intent, "read");
        assert_eq!(capability.audience, "internal/prod");
        assert_eq!(
            child_holder_secret_path,
            kernel
                .store()
                .holder_secret_path(instance_id)
                .display()
                .to_string()
        );
        assert!(
            std::path::Path::new(child_holder_secret_path).exists(),
            "the holder secret path returned by spawn must exist on this host"
        );

        let holder_public_key = child.holder_public_key.clone();
        assert!(
            !holder_public_key.is_empty(),
            "spawn must write the first binder on the child instance record"
        );
        assert!(
            !payload.contains(&holder_public_key),
            "POST /spawn must not include the holder public key"
        );
        assert!(
            !capability.biscuit.is_empty(),
            "the child capability must have a token"
        );
        assert!(
            !payload.contains(&capability.biscuit),
            "POST /spawn must not include capability token bytes"
        );
        if !child.issuer_public_key_hex.is_empty() {
            assert!(
                !payload.contains(&child.issuer_public_key_hex),
                "POST /spawn must not include issuer public keys"
            );
        }
        assert_body_has_no_secrets(&kernel, payload, Some(instance_id), "POST /spawn");
        assert_body_has_no_secrets(
            &kernel,
            payload,
            Some(&birth.instance.id),
            "POST /spawn parent",
        );

        let instances_response = exchange_one_http_request(
            &kernel,
            "GET /instances HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            instances_response.starts_with("HTTP/1.1 200"),
            "GET /instances after spawn must return 200: {instances_response}"
        );
        let instances_body = http_body(&instances_response);
        let instances_value: serde_json::Value =
            serde_json::from_str(instances_body).expect("GET /instances must return JSON");
        let listings = instances_value["instances"]
            .as_array()
            .expect("GET /instances must return an instances array");
        let found = listings.iter().any(|listing| {
            listing["instance_id"].as_str() == Some(instance_id)
                && listing["status"].as_str() == Some("live")
        });
        assert!(
            found,
            "the child instance must appear live in GET /instances: {instances_body}"
        );
        let events = kernel.store().read_log().expect("read the issuance log");
        assert_eq!(
            events
                .iter()
                .filter(|event| event.operation == "spawn")
                .count(),
            1,
            "POST /spawn must reuse the kernel spawn write"
        );
    }

    #[test]
    fn the_host_spawn_path_refuses_a_child_that_exceeds_the_parent() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let agent_type = laboratory_agent_type(&kernel);
        let birth = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                std::collections::BTreeMap::new(),
                "read",
                "internal/prod",
                None,
            )
            .expect("birth a parent whose audience is already narrower than the type limit");
        let nonce = kernel
            .issue_holder_challenge(&birth.instance.id)
            .expect("issue a holder challenge for a refused spawn")
            .nonce;
        let holder_secret_path = kernel
            .store()
            .holder_secret_path(&birth.instance.id)
            .display()
            .to_string();
        let body = serde_json::json!({
            "parent_instance_id": birth.instance.id,
            "parent_capability_id": birth.capability.id,
            "owner": "wider",
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": holder_secret_path,
            "challenge_nonce": nonce,
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/spawn", &body));
        assert!(
            response.contains("HTTP/1.1 403") || response.contains("HTTP/1.1 400"),
            "POST /spawn must fail closed for a child that exceeds the parent: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("exceeds") || payload.contains("cannot gain rights"),
            "POST /spawn must name the wider-child refuse: {payload}"
        );
        let instances = kernel
            .store()
            .list_instances()
            .expect("list instances after a refused spawn");
        assert_eq!(
            instances.len(),
            1,
            "a refused wider spawn must not write a child instance"
        );
        assert_eq!(instances[0].id, birth.instance.id);
        let events = kernel.store().read_log().expect("read the issuance log");
        assert_eq!(
            events
                .iter()
                .filter(|event| event.operation == "spawn")
                .count(),
            0,
            "a refused wider spawn must not write a spawn issuance line"
        );
        assert_body_has_no_secrets(
            &kernel,
            payload,
            Some(&birth.instance.id),
            "a refused wider spawn",
        );
    }

    #[test]
    fn the_host_spawn_path_refuses_a_child_whose_intent_exceeds_the_parent() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let agent_type = kernel
            .add_agent_type(
                "laboratory".to_string(),
                vec!["read".to_string(), "write".to_string()],
                "internal".to_string(),
                2,
                crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE.to_string(),
                3600,
            )
            .expect("add an agent type that allows read and write");
        let birth = kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                std::collections::BTreeMap::new(),
                "read",
                "internal",
                None,
            )
            .expect("birth a parent whose intent is read");
        let nonce = kernel
            .issue_holder_challenge(&birth.instance.id)
            .expect("issue a holder challenge for a refused wider-intent spawn")
            .nonce;
        let holder_secret_path = kernel
            .store()
            .holder_secret_path(&birth.instance.id)
            .display()
            .to_string();
        let body = serde_json::json!({
            "parent_instance_id": birth.instance.id,
            "parent_capability_id": birth.capability.id,
            "owner": "wider-intent",
            "intent": "write",
            "audience": "internal",
            "holder_secret_path": holder_secret_path,
            "challenge_nonce": nonce,
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/spawn", &body));
        assert!(
            response.contains("HTTP/1.1 403") || response.contains("HTTP/1.1 400"),
            "POST /spawn must fail closed for a child whose intent exceeds the parent: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("exceeds") || payload.contains("cannot gain rights"),
            "POST /spawn must name the wider-intent refuse: {payload}"
        );
        let instances = kernel
            .store()
            .list_instances()
            .expect("list instances after a refused wider-intent spawn");
        assert_eq!(
            instances.len(),
            1,
            "a refused wider-intent spawn must not write a child instance"
        );
        assert_eq!(instances[0].id, birth.instance.id);
        let events = kernel.store().read_log().expect("read the issuance log");
        assert_eq!(
            events
                .iter()
                .filter(|event| event.operation == "spawn")
                .count(),
            0,
            "a refused wider-intent spawn must not write a spawn issuance line"
        );
        assert_body_has_no_secrets(
            &kernel,
            payload,
            Some(&birth.instance.id),
            "a refused wider-intent spawn",
        );
    }

    #[test]
    fn the_host_spawn_path_refuses_an_unknown_parent() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let body = serde_json::json!({
            "parent_instance_id": "unknown-parent",
            "parent_capability_id": "unknown-capability",
            "intent": "read",
            "audience": "internal/prod",
            "holder_secret_path": "/tmp/missing-holder.secret",
            "challenge_nonce": "unused-nonce",
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/spawn", &body));
        assert!(
            response.contains("HTTP/1.1 403") || response.contains("HTTP/1.1 400"),
            "POST /spawn must fail closed for an unknown parent: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("does not exist") || payload.contains("unknown"),
            "POST /spawn must name the unknown parent refuse: {payload}"
        );
        let instances = kernel
            .store()
            .list_instances()
            .expect("list instances after an unknown-parent spawn");
        assert!(
            instances.is_empty(),
            "an unknown-parent spawn must not write a child instance"
        );
        assert_body_has_no_secrets(&kernel, payload, None, "an unknown-parent spawn");
    }

    #[test]
    fn the_host_spawn_path_refuses_a_revoked_parent() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        kernel
            .kill_instance(&birth.instance.id)
            .expect("revoke the parent");
        let body = serde_json::json!({
            "parent_instance_id": birth.instance.id,
            "parent_capability_id": birth.capability.id,
            "intent": "read",
            "audience": "internal/prod",
            "holder_secret_path": kernel
                .store()
                .holder_secret_path(&birth.instance.id)
                .display()
                .to_string(),
            "challenge_nonce": "unused-nonce",
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/spawn", &body));
        assert!(
            response.contains("HTTP/1.1 403") || response.contains("HTTP/1.1 400"),
            "POST /spawn must fail closed for a revoked parent: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("revoked"),
            "POST /spawn must name the revoked parent refuse: {payload}"
        );
        let instances = kernel
            .store()
            .list_instances()
            .expect("list instances after a revoked-parent spawn");
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].id, birth.instance.id);
        let events = kernel.store().read_log().expect("read the issuance log");
        assert_eq!(
            events
                .iter()
                .filter(|event| event.operation == "spawn")
                .count(),
            0,
            "a revoked-parent spawn must not write a spawn issuance line"
        );
        assert_body_has_no_secrets(
            &kernel,
            payload,
            Some(&birth.instance.id),
            "a revoked-parent spawn",
        );
    }

    #[test]
    fn the_host_spawn_path_refuses_a_missing_holder_proof() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let nonce = kernel
            .issue_holder_challenge(&birth.instance.id)
            .expect("issue a holder challenge")
            .nonce;
        let body = serde_json::json!({
            "parent_instance_id": birth.instance.id,
            "parent_capability_id": birth.capability.id,
            "intent": "read",
            "audience": "internal/prod",
            "challenge_nonce": nonce,
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/spawn", &body));
        assert!(
            response.contains("HTTP/1.1 403") || response.contains("HTTP/1.1 400"),
            "POST /spawn must fail closed when the holder proof is missing: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("holder proof"),
            "POST /spawn must name the missing holder proof refuse: {payload}"
        );
        let instances = kernel
            .store()
            .list_instances()
            .expect("list instances after a missing-proof spawn");
        assert_eq!(instances.len(), 1);
        assert_body_has_no_secrets(
            &kernel,
            payload,
            Some(&birth.instance.id),
            "a missing-proof spawn",
        );
    }

    #[test]
    fn the_host_spawn_path_refuses_a_missing_challenge_nonce() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let holder_secret_path = kernel
            .store()
            .holder_secret_path(&birth.instance.id)
            .display()
            .to_string();
        let body = serde_json::json!({
            "parent_instance_id": birth.instance.id,
            "parent_capability_id": birth.capability.id,
            "intent": "read",
            "audience": "internal/prod",
            "holder_secret_path": holder_secret_path,
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/spawn", &body));
        assert!(
            response.contains("HTTP/1.1 403") || response.contains("HTTP/1.1 400"),
            "POST /spawn must fail closed when the challenge nonce is missing: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("challenge nonce"),
            "POST /spawn must name the missing nonce refuse: {payload}"
        );
        let instances = kernel
            .store()
            .list_instances()
            .expect("list instances after a missing-nonce spawn");
        assert_eq!(instances.len(), 1);
        assert_body_has_no_secrets(
            &kernel,
            payload,
            Some(&birth.instance.id),
            "a missing-nonce spawn",
        );
    }

    #[test]
    fn the_host_spawn_path_refuses_an_empty_parent() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let nonce = kernel
            .issue_holder_challenge(&birth.instance.id)
            .expect("issue a holder challenge for an empty-parent spawn")
            .nonce;
        let holder_secret_path = kernel
            .store()
            .holder_secret_path(&birth.instance.id)
            .display()
            .to_string();
        for parent_instance_id in ["", "   "] {
            let body = serde_json::json!({
                "parent_instance_id": parent_instance_id,
                "parent_capability_id": birth.capability.id,
                "owner": "child",
                "intent": "read",
                "audience": "internal/prod",
                "holder_secret_path": holder_secret_path,
                "challenge_nonce": nonce,
                "on_behalf_of": "autonomous",
            })
            .to_string();
            let response = exchange_one_http_request(&kernel, &http_post_request("/spawn", &body));
            assert!(
                response.contains("HTTP/1.1 403") || response.contains("HTTP/1.1 400"),
                "POST /spawn must fail closed for an empty parent: {response}"
            );
            let payload = http_body(&response);
            assert!(
                payload.contains("parent_instance_id"),
                "POST /spawn must name the empty parent refuse: {payload}"
            );
            assert!(
                payload.contains("\"result\":\"refused\"")
                    || payload.contains("\"result\": \"refused\""),
                "POST /spawn must return refused for an empty parent: {payload}"
            );
            assert_body_has_no_secrets(
                &kernel,
                payload,
                Some(&birth.instance.id),
                "an empty-parent spawn",
            );
        }
        let instances = kernel
            .store()
            .list_instances()
            .expect("list instances after an empty-parent spawn");
        assert_eq!(
            instances.len(),
            1,
            "an empty-parent spawn must not write a child instance"
        );
        assert_eq!(instances[0].id, birth.instance.id);
        let events = kernel.store().read_log().expect("read the issuance log");
        assert_eq!(
            events
                .iter()
                .filter(|event| event.operation == "spawn")
                .count(),
            0,
            "an empty-parent spawn must not write a spawn issuance line"
        );
    }

    #[test]
    fn the_host_spawn_path_refuses_after_issuer_seal() {
        use crate::kernel::Kernel;
        use chrono::Duration;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let start = chrono::Utc::now();
        kernel.set_now_for_test(start);
        let birth = laboratory_host_birth(&kernel);
        let nonce = kernel
            .issue_holder_challenge(&birth.instance.id)
            .expect("issue a holder challenge before remaining life")
            .nonce;
        kernel.seal_issuer(60).expect("seal the issuer");
        kernel.set_now_for_test(start + Duration::seconds(60));
        let holder_secret_path = kernel
            .store()
            .holder_secret_path(&birth.instance.id)
            .display()
            .to_string();
        let body = serde_json::json!({
            "parent_instance_id": birth.instance.id,
            "parent_capability_id": birth.capability.id,
            "owner": "child",
            "intent": "read",
            "audience": "internal/prod",
            "holder_secret_path": holder_secret_path,
            "challenge_nonce": nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/spawn", &body));
        assert!(
            response.contains("HTTP/1.1 403") || response.contains("HTTP/1.1 400"),
            "POST /spawn must refuse after issuer seal: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("issuer seal") || payload.contains("kill_date has been reached"),
            "POST /spawn must name the issuer seal refuse: {payload}"
        );
        assert!(
            payload.contains("\"result\":\"refused\"")
                || payload.contains("\"result\": \"refused\""),
            "POST /spawn must return refused after issuer seal: {payload}"
        );
        let instances = kernel
            .store()
            .list_instances()
            .expect("list instances after a refused spawn after issuer seal");
        assert_eq!(
            instances.len(),
            1,
            "POST /spawn after issuer seal must not write a child instance"
        );
        assert_eq!(instances[0].id, birth.instance.id);
        let events = kernel.store().read_log().expect("read the issuance log");
        assert_eq!(
            events
                .iter()
                .filter(|event| event.operation == "spawn")
                .count(),
            0,
            "POST /spawn after issuer seal must not write a spawn issuance line"
        );
        assert_body_has_no_secrets(
            &kernel,
            payload,
            Some(&birth.instance.id),
            "POST /spawn after issuer seal",
        );
    }

    fn laboratory_verifier_kernel() -> (tempfile::TempDir, crate::kernel::Kernel) {
        let directory = tempfile::tempdir().expect("create a temporary verifier directory");
        let kernel = crate::kernel::Kernel::open(directory.path());
        kernel.initialize().expect("initialize the verifier issuer");
        (directory, kernel)
    }

    fn host_kill_export_bundle(
        kernel: &crate::kernel::Kernel,
        instance_id: &str,
    ) -> serde_json::Value {
        let body = serde_json::json!({
            "instance_id": instance_id,
            "confirm": instance_id,
        })
        .to_string();
        let response = exchange_one_http_request(kernel, &http_post_request("/kill-export", &body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /kill-export must return the three public artifacts: {response}"
        );
        serde_json::from_str(http_body(&response)).expect("POST /kill-export must return JSON")
    }

    fn host_seal_export_bundle(kernel: &crate::kernel::Kernel) -> serde_json::Value {
        let response = exchange_one_http_request(kernel, &http_post_request("/seal-export", "{}"));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /seal-export must return the three public artifacts: {response}"
        );
        serde_json::from_str(http_body(&response)).expect("POST /seal-export must return JSON")
    }

    #[test]
    fn the_host_seal_export_path_is_refused_before_seal() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let response = exchange_one_http_request(&kernel, &http_post_request("/seal-export", "{}"));
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /seal-export must refuse a live issuer: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("still live")
                || payload.contains("after local seal")
                || payload.contains("kill_date"),
            "POST /seal-export must name the live refuse: {payload}"
        );
        assert_body_has_no_secrets(&kernel, payload, None, "a refused live seal-export");
    }

    #[test]
    fn the_host_seal_export_path_returns_event_proof_and_tree_head_after_seal() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        kernel.seal_issuer(60).expect("seal the issuer");
        let response = exchange_one_http_request(&kernel, &http_post_request("/seal-export", "{}"));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /seal-export must return 200 after local seal: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /seal-export must return JSON");
        let object = value
            .as_object()
            .expect("POST /seal-export must return a JSON object");
        assert!(
            object.contains_key("event"),
            "POST /seal-export must return event: {payload}"
        );
        assert!(
            object.contains_key("proof"),
            "POST /seal-export must return proof: {payload}"
        );
        assert!(
            object.contains_key("tree_head"),
            "POST /seal-export must return tree_head: {payload}"
        );
        assert_eq!(value["event"]["event"].as_str(), Some("issuer_seal"));
        assert_body_has_no_secrets(&kernel, payload, None, "POST /seal-export");
    }

    #[test]
    fn the_host_seal_export_path_returns_event_proof_and_tree_head_after_remaining_life() {
        use crate::kernel::Kernel;
        use chrono::Duration;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let start = chrono::Utc::now();
        kernel.set_now_for_test(start);
        kernel.seal_issuer(1).expect("seal the issuer");
        kernel.set_now_for_test(start + Duration::seconds(2));
        let issuer = kernel
            .store()
            .load_issuer()
            .expect("load the sealed issuer");
        assert!(
            issuer.is_sealed_at(start + Duration::seconds(2)),
            "remaining life must have elapsed"
        );
        let response = exchange_one_http_request(&kernel, &http_post_request("/seal-export", "{}"));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /seal-export must return 200 after remaining life: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /seal-export must return JSON");
        let object = value
            .as_object()
            .expect("POST /seal-export must return a JSON object");
        assert!(
            object.contains_key("event"),
            "POST /seal-export after remaining life must return event: {payload}"
        );
        assert!(
            object.contains_key("proof"),
            "POST /seal-export after remaining life must return proof: {payload}"
        );
        assert!(
            object.contains_key("tree_head"),
            "POST /seal-export after remaining life must return tree_head: {payload}"
        );
        assert_eq!(value["event"]["event"].as_str(), Some("issuer_seal"));
        assert_body_has_no_secrets(
            &kernel,
            payload,
            None,
            "POST /seal-export after remaining life",
        );
        let birth_response = exchange_one_http_request(
            &kernel,
            &http_post_request(
                "/agent-type",
                &serde_json::json!({
                    "owner": "laboratory",
                    "allowed_intents": ["read"],
                    "authorization_limit": "internal",
                    "max_delegation_depth": 2,
                    "crypto_profile": crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE,
                    "lifetime_seconds": 3600
                })
                .to_string(),
            ),
        );
        assert!(
            birth_response.contains("HTTP/1.1 403"),
            "POST /agent-type after remaining life must stay refused: {birth_response}"
        );
    }

    #[test]
    fn the_host_act_export_path_returns_receipt_proof_and_tree_head_after_remaining_life() {
        use crate::kernel::Kernel;
        use chrono::Duration;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let start = chrono::Utc::now();
        kernel.set_now_for_test(start);
        let birth = laboratory_host_birth(&kernel);
        let receipt = host_allowed_check_receipt(
            &kernel,
            &birth.instance.id,
            &birth.capability.id,
            "read",
            "internal",
        );
        kernel.seal_issuer(1).expect("seal the issuer");
        kernel.set_now_for_test(start + Duration::seconds(2));
        let issuer = kernel
            .store()
            .load_issuer()
            .expect("load the sealed issuer");
        assert!(
            issuer.is_sealed_at(start + Duration::seconds(2)),
            "remaining life must have elapsed"
        );
        let body = serde_json::json!({ "receipt": receipt }).to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/act-export", &body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /act-export after remaining life must return 200: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /act-export must return JSON");
        let object = value
            .as_object()
            .expect("POST /act-export must return a JSON object");
        assert!(
            object.contains_key("receipt"),
            "POST /act-export after remaining life must return receipt: {payload}"
        );
        assert!(
            object.contains_key("proof"),
            "POST /act-export after remaining life must return proof: {payload}"
        );
        assert!(
            object.contains_key("tree_head"),
            "POST /act-export after remaining life must return tree_head: {payload}"
        );
        assert_body_has_no_secrets(
            &kernel,
            payload,
            Some(&birth.instance.id),
            "POST /act-export after remaining life",
        );
        let birth_response = exchange_one_http_request(
            &kernel,
            &http_post_request(
                "/agent-type",
                &serde_json::json!({
                    "owner": "laboratory",
                    "allowed_intents": ["read"],
                    "authorization_limit": "internal",
                    "max_delegation_depth": 2,
                    "crypto_profile": crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE,
                    "lifetime_seconds": 3600
                })
                .to_string(),
            ),
        );
        assert!(
            birth_response.contains("HTTP/1.1 403"),
            "POST /agent-type after remaining life must stay refused: {birth_response}"
        );
    }

    #[test]
    fn the_host_previous_key_export_path_returns_public_artifacts_after_remaining_life() {
        use crate::kernel::Kernel;
        use chrono::Duration;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let start = chrono::Utc::now();
        kernel.set_now_for_test(start);
        let old_public_key = kernel
            .store()
            .load_issuer()
            .expect("load the issuer")
            .current_public_key_hex();
        kernel
            .rotate_issuer_key(60)
            .expect("rotate must write a previous key with a kill date");
        kernel.seal_issuer(1).expect("seal the issuer");
        kernel.set_now_for_test(start + Duration::seconds(2));
        let issuer = kernel
            .store()
            .load_issuer()
            .expect("load the sealed issuer");
        assert!(
            issuer.is_sealed_at(start + Duration::seconds(2)),
            "remaining life must have elapsed"
        );
        let response =
            exchange_one_http_request(&kernel, &http_post_request("/previous-key-export", "{}"));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /previous-key-export after remaining life must return 200: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /previous-key-export must return JSON");
        assert_eq!(
            value["public_key_hex"].as_str(),
            Some(old_public_key.as_str()),
            "POST /previous-key-export after remaining life must return the previous public key: {payload}"
        );
        assert!(
            value["kill_date"].as_str().is_some(),
            "POST /previous-key-export after remaining life must return kill_date: {payload}"
        );
        assert_body_has_no_secrets(
            &kernel,
            payload,
            None,
            "POST /previous-key-export after remaining life",
        );
    }

    #[test]
    fn the_host_issuer_public_path_returns_the_current_key_after_remaining_life() {
        use crate::kernel::Kernel;
        use chrono::Duration;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let expected = kernel
            .store()
            .load_issuer()
            .expect("load the issuer")
            .current_public_key_hex();
        let start = chrono::Utc::now();
        kernel.set_now_for_test(start);
        kernel.seal_issuer(1).expect("seal the issuer");
        kernel.set_now_for_test(start + Duration::seconds(2));
        let issuer = kernel
            .store()
            .load_issuer()
            .expect("load the sealed issuer");
        assert!(
            issuer.is_sealed_at(start + Duration::seconds(2)),
            "remaining life must have elapsed"
        );
        let response = exchange_one_http_request(
            &kernel,
            "GET /issuer-public HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "GET /issuer-public after remaining life must return 200: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("GET /issuer-public must return JSON");
        assert_eq!(
            value["current_issuer_public_key_hex"].as_str(),
            Some(expected.as_str()),
            "GET /issuer-public after remaining life must return the current issuer public key: {payload}"
        );
        assert_body_has_no_secrets(
            &kernel,
            payload,
            None,
            "GET /issuer-public after remaining life",
        );
    }

    #[test]
    fn store_b_check_wimse_allows_before_seal_accept_and_refuses_after() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let birth = laboratory_host_birth(&store_a);
        let artifact = laboratory_wimse_artifact(&store_a, &birth);
        let public_key_hex = store_a
            .store()
            .load_issuer()
            .expect("load store A issuer")
            .current_public_key_hex();

        let (_directory_b, store_b) = laboratory_verifier_kernel();
        let issuer_secret_a = store_a
            .store()
            .load_secret()
            .expect("load store A issuer.secret");
        let issuer_secret_b = store_b
            .store()
            .load_secret()
            .expect("load store B issuer.secret");
        assert_ne!(
            issuer_secret_a, issuer_secret_b,
            "store B must start with its own issuer.secret"
        );
        let pin_body = serde_json::json!({
            "public_key_hex": public_key_hex,
        })
        .to_string();
        let pin_response =
            exchange_one_http_request(&store_b, &http_post_request("/issuer-accept", &pin_body));
        assert!(
            pin_response.starts_with("HTTP/1.1 200"),
            "POST /issuer-accept must pin the foreign public key: {pin_response}"
        );

        let (check_body, signature_input, signature) = check_wimse_body_signed_by_issuer(
            &store_a,
            &store_b,
            &artifact.presentation_json,
            &artifact.workload_identity_token,
            &artifact.content_digest,
        );
        let allow_response = exchange_one_http_request(
            &store_b,
            &http_post_request_with_signature(
                "/check-wimse",
                &check_body,
                &signature_input,
                &signature,
            ),
        );
        assert!(
            allow_response.starts_with("HTTP/1.1 200"),
            "POST /check-wimse on store B must allow an honest present before seal accept: {allow_response}"
        );
        let allow_payload = http_body(&allow_response);
        let allow_value: serde_json::Value =
            serde_json::from_str(allow_payload).expect("POST /check-wimse must return JSON");
        assert_eq!(
            allow_value["result"].as_str(),
            Some("allowed"),
            "store B must allow the honest WIMSE present before seal accept: {allow_payload}"
        );

        store_a
            .seal_issuer(60)
            .expect("store A must persist local seal");
        let bundle = host_seal_export_bundle(&store_a);
        let export_body = serde_json::to_string(&bundle).expect("serialize the seal export bundle");
        let accept_response =
            exchange_one_http_request(&store_b, &http_post_request("/seal-accept", &export_body));
        assert!(
            accept_response.starts_with("HTTP/1.1 200"),
            "POST /seal-accept must accept the signed seal bundle: {accept_response}"
        );
        let accept_payload = http_body(&accept_response);
        let accept_value: serde_json::Value =
            serde_json::from_str(accept_payload).expect("POST /seal-accept must return JSON");
        assert_eq!(
            accept_value["public_key_hex"].as_str(),
            Some(public_key_hex.as_str())
        );
        assert_body_has_no_secrets(&store_a, accept_payload, None, "POST /seal-accept");
        assert_body_has_no_secrets(
            &store_b,
            accept_payload,
            None,
            "POST /seal-accept secrets on store B",
        );
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "store B must write no instance record after seal accept"
        );
        assert_ne!(
            store_b
                .store()
                .load_secret()
                .expect("reload store B issuer.secret"),
            issuer_secret_a,
            "store B must not copy issuer.secret"
        );

        let refuse_response = exchange_one_http_request(
            &store_b,
            &http_post_request_with_signature(
                "/check-wimse",
                &check_body,
                &signature_input,
                &signature,
            ),
        );
        assert!(
            refuse_response.contains("HTTP/1.1 403"),
            "POST /check-wimse on store B must refuse after seal accept: {refuse_response}"
        );
        let refuse_payload = http_body(&refuse_response);
        let refuse_value: serde_json::Value =
            serde_json::from_str(refuse_payload).expect("POST /check-wimse must return JSON");
        assert_eq!(
            refuse_value["result"].as_str(),
            Some("refused"),
            "POST /check-wimse on store B must refuse: {refuse_payload}"
        );
        let reason = refuse_value["reason"].as_str().unwrap_or("");
        assert!(
            reason.contains("seal accept") || reason.contains("issuer death"),
            "store B must refuse from accepted seal, not from an inode lookup: {reason}"
        );
        assert!(
            store_b
                .store()
                .list_instances()
                .expect("list store B instances")
                .is_empty(),
            "store B must write no instance record after the refused present"
        );
    }

    #[test]
    fn previous_key_export_is_refused_without_a_kill_date() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let response =
            exchange_one_http_request(&kernel, &http_post_request("/previous-key-export", "{}"));
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /previous-key-export must refuse without a previous-key kill date: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("kill date") || payload.contains("kill_date"),
            "POST /previous-key-export must name the missing kill date: {payload}"
        );
        assert_body_has_no_secrets(&kernel, payload, None, "a refused previous-key-export");
    }

    #[test]
    fn store_b_allows_a_present_on_the_old_key_before_previous_key_accept_and_refuses_after() {
        use crate::kernel::Kernel;
        use chrono::{Duration, Utc};
        use tempfile::tempdir;

        let start = Utc::now();
        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        store_a.set_now_for_test(start);
        let birth = laboratory_host_birth(&store_a);
        let artifact = laboratory_svid_wrap(&store_a, &birth);
        let old_public_key = store_a
            .store()
            .load_issuer()
            .expect("load store A issuer")
            .current_public_key_hex();
        let issuer_secret_a = store_a
            .store()
            .load_secret()
            .expect("load store A issuer.secret");

        let (_directory_b, store_b) = laboratory_verifier_kernel();
        store_b.set_now_for_test(start);
        let pin_body = serde_json::json!({
            "public_key_hex": old_public_key,
        })
        .to_string();
        let pin_response =
            exchange_one_http_request(&store_b, &http_post_request("/issuer-accept", &pin_body));
        assert!(
            pin_response.starts_with("HTTP/1.1 200"),
            "POST /issuer-accept must pin the foreign public key: {pin_response}"
        );

        let challenge = store_b
            .issue_verifier_challenge()
            .expect("issue a verifier challenge on store B");
        let holder_proof = store_a
            .sign_holder_nonce(
                &challenge.challenge_message,
                store_a.store().holder_secret_path(&birth.instance.id),
            )
            .expect("sign the verifier nonce on the issuing store");
        let check_body = serde_json::json!({
            "presentation_json": artifact.presentation_json,
            "certificate_pem": artifact.certificate_pem,
            "intent": "read",
            "audience": "internal",
            "holder_proof": holder_proof,
            "challenge_nonce": challenge.nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let allow_response =
            exchange_one_http_request(&store_b, &http_post_request("/check-svid", &check_body));
        assert!(
            allow_response.starts_with("HTTP/1.1 200"),
            "POST /check-svid on store B must allow a present on the old key before previous-key accept: {allow_response}"
        );
        let allow_payload = http_body(&allow_response);
        let allow_value: serde_json::Value =
            serde_json::from_str(allow_payload).expect("POST /check-svid must return JSON");
        assert_eq!(
            allow_value["result"].as_str(),
            Some("allowed"),
            "store B must allow the honest present on the old key before previous-key accept: {allow_payload}"
        );

        store_a
            .rotate_issuer_key(10)
            .expect("store A rotate must write a previous key with a kill date");
        let export_response =
            exchange_one_http_request(&store_a, &http_post_request("/previous-key-export", "{}"));
        assert!(
            export_response.starts_with("HTTP/1.1 200"),
            "POST /previous-key-export must return the public previous-key artifacts: {export_response}"
        );
        let export_payload = http_body(&export_response);
        let export_value: serde_json::Value = serde_json::from_str(export_payload)
            .expect("POST /previous-key-export must return JSON");
        assert_eq!(
            export_value["public_key_hex"].as_str(),
            Some(old_public_key.as_str()),
            "POST /previous-key-export must return the previous public key: {export_payload}"
        );
        assert!(
            export_value["kill_date"].as_str().is_some(),
            "POST /previous-key-export must return kill_date: {export_payload}"
        );
        assert_body_has_no_secrets(&store_a, export_payload, None, "POST /previous-key-export");

        let still_allow_challenge = store_b
            .issue_verifier_challenge()
            .expect("issue a second verifier challenge on store B");
        let still_allow_proof = store_a
            .sign_holder_nonce(
                &still_allow_challenge.challenge_message,
                store_a.store().holder_secret_path(&birth.instance.id),
            )
            .expect("sign the second verifier nonce on the issuing store");
        let still_allow_body = serde_json::json!({
            "presentation_json": artifact.presentation_json,
            "certificate_pem": artifact.certificate_pem,
            "intent": "read",
            "audience": "internal",
            "holder_proof": still_allow_proof,
            "challenge_nonce": still_allow_challenge.nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let still_allow_response = exchange_one_http_request(
            &store_b,
            &http_post_request("/check-svid", &still_allow_body),
        );
        assert!(
            still_allow_response.starts_with("HTTP/1.1 200"),
            "POST /check-svid on store B must still allow the old-key present before previous-key accept: {still_allow_response}"
        );

        let export_body =
            serde_json::to_string(&export_value).expect("serialize the previous-key export");
        let accept_response = exchange_one_http_request(
            &store_b,
            &http_post_request("/previous-key-accept", &export_body),
        );
        assert!(
            accept_response.starts_with("HTTP/1.1 200"),
            "POST /previous-key-accept must pin the previous key and kill date: {accept_response}"
        );
        let accept_payload = http_body(&accept_response);
        let accept_value: serde_json::Value = serde_json::from_str(accept_payload)
            .expect("POST /previous-key-accept must return JSON");
        assert_eq!(
            accept_value["public_key_hex"].as_str(),
            Some(old_public_key.as_str())
        );
        assert_body_has_no_secrets(&store_a, accept_payload, None, "POST /previous-key-accept");
        assert_body_has_no_secrets(
            &store_b,
            accept_payload,
            None,
            "POST /previous-key-accept secrets on store B",
        );
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "store B must write no instance record after previous-key accept"
        );
        assert_ne!(
            store_b
                .store()
                .load_secret()
                .expect("reload store B issuer.secret"),
            issuer_secret_a,
            "store B must not copy issuer.secret"
        );

        let after_kill = start + Duration::seconds(11);
        store_a.set_now_for_test(after_kill);
        store_b.set_now_for_test(after_kill);
        let refuse_challenge = store_b
            .issue_verifier_challenge()
            .expect("issue a third verifier challenge on store B");
        let refuse_proof = store_a
            .sign_holder_nonce(
                &refuse_challenge.challenge_message,
                store_a.store().holder_secret_path(&birth.instance.id),
            )
            .expect("sign the third verifier nonce on the issuing store");
        let refuse_body = serde_json::json!({
            "presentation_json": artifact.presentation_json,
            "certificate_pem": artifact.certificate_pem,
            "intent": "read",
            "audience": "internal",
            "holder_proof": refuse_proof,
            "challenge_nonce": refuse_challenge.nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let refuse_response =
            exchange_one_http_request(&store_b, &http_post_request("/check-svid", &refuse_body));
        assert!(
            refuse_response.contains("HTTP/1.1 403"),
            "POST /check-svid on store B must refuse after previous-key accept past kill date: {refuse_response}"
        );
        let refuse_payload = http_body(&refuse_response);
        let refuse_value: serde_json::Value =
            serde_json::from_str(refuse_payload).expect("POST /check-svid must return JSON");
        assert_eq!(
            refuse_value["result"].as_str(),
            Some("refused"),
            "POST /check-svid on store B must refuse: {refuse_payload}"
        );
        let reason = refuse_value["reason"].as_str().unwrap_or("");
        assert!(
            reason.contains("past its kill date") || reason.contains("previous issuer key"),
            "store B must refuse from accepted previous-key kill, not from an inode lookup: {reason}"
        );
        assert!(
            store_b
                .store()
                .list_instances()
                .expect("list store B instances")
                .is_empty(),
            "store B must write no instance record after the refused present"
        );
    }

    #[test]
    fn the_host_kill_accept_path_refuses_before_issuer_accept() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let birth = laboratory_host_birth(&store_a);
        store_a
            .kill_instance(&birth.instance.id)
            .expect("store A must persist local kill");
        let bundle = host_kill_export_bundle(&store_a, &birth.instance.id);
        let export_body = serde_json::to_string(&bundle).expect("serialize the export bundle");

        let (_directory_b, store_b) = laboratory_verifier_kernel();
        let instances_before = store_b
            .store()
            .list_instances()
            .expect("list store B instances before a refused accept");
        let log_before = store_b
            .store()
            .log_text()
            .expect("read store B log before a refused accept");
        let response =
            exchange_one_http_request(&store_b, &http_post_request("/kill-accept", &export_body));
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /kill-accept must fail closed before issuer accept: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("unknown issuer key") || payload.contains("accept list"),
            "POST /kill-accept must name the unknown issuer key refuse: {payload}"
        );
        let instances_after = store_b
            .store()
            .list_instances()
            .expect("list store B instances after a refused accept");
        assert_eq!(
            instances_before.len(),
            instances_after.len(),
            "a refused kill accept must write no instance record"
        );
        let log_after = store_b
            .store()
            .log_text()
            .expect("read store B log after a refused accept");
        assert_eq!(
            log_before, log_after,
            "a refused kill accept must not write a second issuance.log line"
        );
        assert_body_has_no_secrets(
            &store_a,
            payload,
            Some(&birth.instance.id),
            "a refused kill-accept",
        );
        assert_body_has_no_secrets(&store_b, payload, None, "a refused kill-accept on store B");
    }

    #[test]
    fn the_host_kill_accept_path_accepts_a_bundle_and_writes_no_instance_record() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let birth = laboratory_host_birth(&store_a);
        store_a
            .kill_instance(&birth.instance.id)
            .expect("store A must persist local kill");
        let bundle = host_kill_export_bundle(&store_a, &birth.instance.id);
        let export_body = serde_json::to_string(&bundle).expect("serialize the export bundle");
        let issuer_a = store_a.store().load_issuer().expect("load store A issuer");
        let public_key_hex = issuer_a.current_public_key_hex();

        let (_directory_b, store_b) = laboratory_verifier_kernel();
        let pin_body = serde_json::json!({
            "public_key_hex": public_key_hex,
        })
        .to_string();
        let pin_response =
            exchange_one_http_request(&store_b, &http_post_request("/issuer-accept", &pin_body));
        assert!(
            pin_response.starts_with("HTTP/1.1 200"),
            "POST /issuer-accept must pin the foreign public key: {pin_response}"
        );
        let pin_payload = http_body(&pin_response);
        let pin_value: serde_json::Value =
            serde_json::from_str(pin_payload).expect("POST /issuer-accept must return JSON");
        assert_eq!(
            pin_value["public_key_hex"].as_str(),
            Some(public_key_hex.as_str()),
            "POST /issuer-accept must return the public key hex only: {pin_payload}"
        );
        assert!(
            pin_value.as_object().map(|object| object.len()) == Some(1),
            "POST /issuer-accept must return public_key_hex only: {pin_payload}"
        );
        assert_body_has_no_secrets(
            &store_a,
            pin_payload,
            Some(&birth.instance.id),
            "POST /issuer-accept",
        );
        assert_body_has_no_secrets(
            &store_b,
            pin_payload,
            None,
            "POST /issuer-accept on store B",
        );

        let instances_before = store_b
            .store()
            .list_instances()
            .expect("list store B instances before kill accept");
        let log_before = store_b
            .store()
            .log_text()
            .expect("read store B log before kill accept");
        let response =
            exchange_one_http_request(&store_b, &http_post_request("/kill-accept", &export_body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /kill-accept must accept the signed death bundle: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /kill-accept must return JSON");
        let object = value
            .as_object()
            .expect("POST /kill-accept must return a JSON object");
        assert!(
            object.contains_key("accepted_killed_instance_ids"),
            "POST /kill-accept must return accepted instance identifiers: {payload}"
        );
        assert!(
            object.contains_key("accepted_killed_capability_ids"),
            "POST /kill-accept must return accepted capability identifiers: {payload}"
        );
        assert!(
            object.contains_key("accepted_revoke_identifiers"),
            "POST /kill-accept must return accepted revoke identifiers: {payload}"
        );
        let accepted_instances = value["accepted_killed_instance_ids"]
            .as_array()
            .expect("accepted_killed_instance_ids must be an array");
        let found = accepted_instances
            .iter()
            .any(|value| value.as_str() == Some(birth.instance.id.as_str()));
        assert!(
            found,
            "POST /kill-accept must store the killed instance identifier: {payload}"
        );
        let instances_after = store_b
            .store()
            .list_instances()
            .expect("list store B instances after kill accept");
        assert_eq!(
            instances_before.len(),
            instances_after.len(),
            "kill accept must write no instance record"
        );
        assert!(
            instances_after.is_empty(),
            "store B must remain without instance records"
        );
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "store B must not copy the issuing inode"
        );
        let log_after = store_b
            .store()
            .log_text()
            .expect("read store B log after kill accept");
        assert_eq!(
            log_before, log_after,
            "kill accept must not write a second issuance.log line"
        );
        assert_body_has_no_secrets(
            &store_a,
            payload,
            Some(&birth.instance.id),
            "POST /kill-accept",
        );
        assert_body_has_no_secrets(&store_b, payload, None, "POST /kill-accept on store B");
    }

    #[test]
    fn the_host_check_svid_path_on_store_b_refuses_after_kill_accept() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let birth = laboratory_host_birth(&store_a);
        let artifact = laboratory_svid_wrap(&store_a, &birth);
        store_a
            .verify_x509_svid(
                &artifact.certificate_pem,
                artifact.presentation_json.as_bytes(),
            )
            .expect("the live wrap must verify on the issuing store before kill");
        store_a
            .kill_instance(&birth.instance.id)
            .expect("store A must persist local kill");
        let bundle = host_kill_export_bundle(&store_a, &birth.instance.id);
        let export_body = serde_json::to_string(&bundle).expect("serialize the export bundle");
        let issuer_a = store_a.store().load_issuer().expect("load store A issuer");
        let public_key_hex = issuer_a.current_public_key_hex();

        let (_directory_b, store_b) = laboratory_verifier_kernel();
        let pin_body = serde_json::json!({
            "public_key_hex": public_key_hex,
        })
        .to_string();
        let pin_response =
            exchange_one_http_request(&store_b, &http_post_request("/issuer-accept", &pin_body));
        assert!(
            pin_response.starts_with("HTTP/1.1 200"),
            "POST /issuer-accept must pin the foreign public key: {pin_response}"
        );
        let accept_response =
            exchange_one_http_request(&store_b, &http_post_request("/kill-accept", &export_body));
        assert!(
            accept_response.starts_with("HTTP/1.1 200"),
            "POST /kill-accept must accept the signed death bundle: {accept_response}"
        );

        let check_body = serde_json::json!({
            "presentation_json": artifact.presentation_json,
            "certificate_pem": artifact.certificate_pem,
            "intent": "read",
            "audience": "internal",
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let response =
            exchange_one_http_request(&store_b, &http_post_request("/check-svid", &check_body));
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /check-svid on store B must refuse after kill accept: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /check-svid must return JSON");
        assert_eq!(
            value["result"].as_str(),
            Some("refused"),
            "POST /check-svid on store B must refuse: {payload}"
        );
        let reason = value["reason"].as_str().unwrap_or("");
        assert!(
            reason.contains("kill accept"),
            "store B must refuse from accepted death, not from an inode lookup: {reason}"
        );
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "store B must not copy the issuing inode after check"
        );
        let instances = store_b
            .store()
            .list_instances()
            .expect("list store B instances after check");
        assert!(
            instances.is_empty(),
            "store B must still write no instance record"
        );
        assert_body_has_no_secrets(
            &store_a,
            payload,
            Some(&birth.instance.id),
            "POST /check-svid on store B",
        );
        assert_body_has_no_secrets(
            &store_b,
            payload,
            None,
            "POST /check-svid secrets on store B",
        );
    }

    #[test]
    fn the_host_check_svid_path_on_store_b_allows_an_honest_wrap_and_refuses_without_holder_proof()
    {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let birth = laboratory_host_birth(&store_a);
        let artifact = laboratory_svid_wrap(&store_a, &birth);
        let public_key_hex = store_a
            .store()
            .load_issuer()
            .expect("load store A issuer")
            .current_public_key_hex();

        let (_directory_b, store_b) = laboratory_verifier_kernel();
        let pin_body = serde_json::json!({
            "public_key_hex": public_key_hex,
        })
        .to_string();
        let pin_response =
            exchange_one_http_request(&store_b, &http_post_request("/issuer-accept", &pin_body));
        assert!(
            pin_response.starts_with("HTTP/1.1 200"),
            "POST /issuer-accept must pin the foreign public key: {pin_response}"
        );

        let missing_body = serde_json::json!({
            "presentation_json": artifact.presentation_json,
            "certificate_pem": artifact.certificate_pem,
            "intent": "read",
            "audience": "internal",
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let missing_response =
            exchange_one_http_request(&store_b, &http_post_request("/check-svid", &missing_body));
        assert!(
            missing_response.contains("HTTP/1.1 403"),
            "POST /check-svid on store B must refuse a missing holder proof: {missing_response}"
        );
        let missing_payload = http_body(&missing_response);
        let missing_value: serde_json::Value =
            serde_json::from_str(missing_payload).expect("POST /check-svid must return JSON");
        assert_eq!(
            missing_value["result"].as_str(),
            Some("refused"),
            "POST /check-svid on store B must refuse without holder proof: {missing_payload}"
        );
        let missing_reason = missing_value["reason"].as_str().unwrap_or("");
        assert!(
            missing_reason.contains("holder proof"),
            "store B must refuse from missing holder proof, not from an inode lookup: {missing_reason}"
        );
        assert!(
            !missing_reason.contains("does not exist"),
            "store B must not look up the issuing inode: {missing_reason}"
        );

        let challenge = store_b
            .issue_verifier_challenge()
            .expect("issue a verifier challenge on store B");
        let holder_proof = store_a
            .sign_holder_nonce(
                &challenge.challenge_message,
                store_a.store().holder_secret_path(&birth.instance.id),
            )
            .expect("sign the verifier nonce on the issuing store");
        let honest_body = serde_json::json!({
            "presentation_json": artifact.presentation_json,
            "certificate_pem": artifact.certificate_pem,
            "intent": "read",
            "audience": "internal",
            "holder_proof": holder_proof,
            "challenge_nonce": challenge.nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let honest_response =
            exchange_one_http_request(&store_b, &http_post_request("/check-svid", &honest_body));
        assert!(
            honest_response.starts_with("HTTP/1.1 200"),
            "POST /check-svid on store B must allow an honest wrap with holder proof: {honest_response}"
        );
        let honest_payload = http_body(&honest_response);
        let honest_value: serde_json::Value =
            serde_json::from_str(honest_payload).expect("POST /check-svid must return JSON");
        assert_eq!(
            honest_value["result"].as_str(),
            Some("allowed"),
            "store B must allow the honest SVID wrap from the verified present: {honest_payload}"
        );
        assert!(
            honest_value.get("receipt").is_none() || honest_value["receipt"].is_null(),
            "a verifier allow must not mint a check receipt: {honest_payload}"
        );
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "store B must not copy the issuing inode after the honest allow"
        );
        let instances = store_b
            .store()
            .list_instances()
            .expect("list store B instances after honest allow");
        assert!(
            instances.is_empty(),
            "store B must write no instance record after honest allow"
        );
        assert_body_has_no_secrets(
            &store_a,
            honest_payload,
            Some(&birth.instance.id),
            "honest POST /check-svid on store B",
        );
        assert_body_has_no_secrets(
            &store_b,
            honest_payload,
            None,
            "honest POST /check-svid secrets on store B",
        );
    }

    fn check_wimse_body_signed_by_issuer(
        issuing_kernel: &crate::kernel::Kernel,
        verifier_kernel: &crate::kernel::Kernel,
        presentation_json: &str,
        workload_identity_token: &str,
        content_digest: &str,
    ) -> (String, String, String) {
        let envelope_secret = issuing_kernel
            .store()
            .load_biscuit_secret()
            .expect("load the issuing laboratory Ed25519 envelope secret");
        let (signature_input, signature) = crate::wimse::sign_laboratory_wimse_http_message(
            crate::wimse::LABORATORY_WIMSE_CHECK_METHOD,
            crate::wimse::LABORATORY_WIMSE_CHECK_PATH,
            content_digest,
            &envelope_secret,
        )
        .expect("sign POST /check-wimse with the issuing envelope key");
        let presentation = crate::presentation::parse_presentation_json(presentation_json)
            .expect("parse present for holder signature");
        let challenge = verifier_kernel
            .issue_verifier_challenge()
            .expect("issue a verifier challenge on store B");
        let holder_proof = issuing_kernel
            .sign_holder_nonce(
                &challenge.challenge_message,
                issuing_kernel
                    .store()
                    .holder_secret_path(&presentation.instance_id),
            )
            .expect("sign the verifier nonce on the issuing store");
        let body = serde_json::json!({
            "presentation_json": presentation_json,
            "workload_identity_token": workload_identity_token,
            "content_digest": content_digest,
            "intent": "read",
            "audience": "internal",
            "holder_proof": holder_proof,
            "challenge_nonce": challenge.nonce,
            "on_behalf_of": "autonomous",
            "signature_input": signature_input,
            "signature": signature,
        })
        .to_string();
        (body, signature_input, signature)
    }

    #[test]
    fn the_host_check_wimse_path_on_store_b_allows_then_refuses_after_kill_accept() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let birth = laboratory_host_birth(&store_a);
        let artifact = laboratory_wimse_artifact(&store_a, &birth);
        store_a
            .verify_wimse(
                &artifact.workload_identity_token,
                &artifact.content_digest,
                artifact.presentation_json.as_bytes(),
            )
            .expect("the live token must verify on the issuing store before the two-store walk");

        let public_response = exchange_one_http_request(
            &store_a,
            "GET /issuer-public HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(
            public_response.starts_with("HTTP/1.1 200"),
            "GET /issuer-public on store A must return the full public key: {public_response}"
        );
        let public_value: serde_json::Value = serde_json::from_str(http_body(&public_response))
            .expect("GET /issuer-public must return JSON");
        let public_key_hex = public_value["current_issuer_public_key_hex"]
            .as_str()
            .expect("GET /issuer-public must return current_issuer_public_key_hex");
        assert!(
            public_key_hex.len() > 64,
            "GET /issuer-public must return the full hex, not a truncated status key"
        );
        assert!(
            !public_value
                .as_object()
                .expect("object")
                .contains_key("biscuit_public_key_hex"),
            "GET /issuer-public must not return the envelope key"
        );

        let (_directory_b, store_b) = laboratory_verifier_kernel();
        let issuer_secret_b_before = store_b
            .store()
            .load_secret()
            .expect("load store B issuer.secret before the walk");
        let issuer_secret_a = store_a
            .store()
            .load_secret()
            .expect("load store A issuer.secret");
        assert_ne!(
            issuer_secret_a, issuer_secret_b_before,
            "store B must start with its own issuer.secret"
        );
        let log_before = store_b
            .store()
            .log_text()
            .expect("read store B log before the walk");
        let pin_body = serde_json::json!({
            "public_key_hex": public_key_hex,
        })
        .to_string();
        let pin_response =
            exchange_one_http_request(&store_b, &http_post_request("/issuer-accept", &pin_body));
        assert!(
            pin_response.starts_with("HTTP/1.1 200"),
            "POST /issuer-accept must pin the foreign public key: {pin_response}"
        );

        let (check_body, signature_input, signature) = check_wimse_body_signed_by_issuer(
            &store_a,
            &store_b,
            &artifact.presentation_json,
            &artifact.workload_identity_token,
            &artifact.content_digest,
        );
        let allow_response = exchange_one_http_request(
            &store_b,
            &http_post_request_with_signature(
                "/check-wimse",
                &check_body,
                &signature_input,
                &signature,
            ),
        );
        assert!(
            allow_response.starts_with("HTTP/1.1 200"),
            "POST /check-wimse on store B must allow an honest present before kill accept: {allow_response}"
        );
        let allow_payload = http_body(&allow_response);
        let allow_value: serde_json::Value =
            serde_json::from_str(allow_payload).expect("POST /check-wimse must return JSON");
        assert_eq!(
            allow_value["result"].as_str(),
            Some("allowed"),
            "store B must allow the honest WIMSE present without an inode copy: {allow_payload}"
        );
        assert_eq!(
            allow_value["instance_id"].as_str(),
            Some(birth.instance.id.as_str())
        );
        assert!(
            allow_value.get("receipt").is_none() || allow_value["receipt"].is_null(),
            "a verifier allow must not mint a check receipt: {allow_payload}"
        );
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "store B must not copy the issuing inode after the honest allow"
        );
        let instances_after_allow = store_b
            .store()
            .list_instances()
            .expect("list store B instances after honest allow");
        assert!(
            instances_after_allow.is_empty(),
            "store B must write no instance record after honest allow"
        );
        let log_after_allow = store_b
            .store()
            .log_text()
            .expect("read store B log after honest allow");
        assert_eq!(
            log_before, log_after_allow,
            "an honest verifier allow must not append an issuance.log line"
        );
        assert_body_has_no_secrets(
            &store_a,
            allow_payload,
            Some(&birth.instance.id),
            "honest POST /check-wimse on store B",
        );
        assert_body_has_no_secrets(
            &store_b,
            allow_payload,
            None,
            "honest POST /check-wimse secrets on store B",
        );

        store_a
            .kill_instance(&birth.instance.id)
            .expect("store A must persist local kill");
        let bundle = host_kill_export_bundle(&store_a, &birth.instance.id);
        let export_body = serde_json::to_string(&bundle).expect("serialize the export bundle");
        let accept_response =
            exchange_one_http_request(&store_b, &http_post_request("/kill-accept", &export_body));
        assert!(
            accept_response.starts_with("HTTP/1.1 200"),
            "POST /kill-accept must accept the signed death bundle: {accept_response}"
        );

        let refuse_response = exchange_one_http_request(
            &store_b,
            &http_post_request_with_signature(
                "/check-wimse",
                &check_body,
                &signature_input,
                &signature,
            ),
        );
        assert!(
            refuse_response.contains("HTTP/1.1 403"),
            "POST /check-wimse on store B must refuse after kill accept: {refuse_response}"
        );
        let refuse_payload = http_body(&refuse_response);
        let refuse_value: serde_json::Value =
            serde_json::from_str(refuse_payload).expect("POST /check-wimse must return JSON");
        assert_eq!(
            refuse_value["result"].as_str(),
            Some("refused"),
            "POST /check-wimse on store B must refuse: {refuse_payload}"
        );
        let reason = refuse_value["reason"].as_str().unwrap_or("");
        assert!(
            reason.contains("kill accept"),
            "store B must refuse from accepted death, not from an inode lookup: {reason}"
        );
        assert!(
            refuse_value.get("receipt").is_none() || refuse_value["receipt"].is_null(),
            "a refused present must not sign a new decision receipt"
        );
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "store B must not copy the issuing inode after kill accept"
        );
        let instances_after_kill = store_b
            .store()
            .list_instances()
            .expect("list store B instances after kill accept");
        assert!(
            instances_after_kill.is_empty(),
            "store B must still write no instance record"
        );
        let issuer_secret_b_after = store_b
            .store()
            .load_secret()
            .expect("load store B issuer.secret after the walk");
        assert_eq!(
            issuer_secret_b_before, issuer_secret_b_after,
            "store B must not copy issuer.secret"
        );
        assert_ne!(
            issuer_secret_a, issuer_secret_b_after,
            "store B must keep a different issuer.secret from store A"
        );
        assert_body_has_no_secrets(
            &store_a,
            refuse_payload,
            Some(&birth.instance.id),
            "refused POST /check-wimse on store B",
        );
        assert_body_has_no_secrets(
            &store_b,
            refuse_payload,
            None,
            "refused POST /check-wimse secrets on store B",
        );
    }

    fn pin_store_b_to_store_a(store_a: &crate::kernel::Kernel, store_b: &crate::kernel::Kernel) {
        let public_key_hex = store_a
            .store()
            .load_issuer()
            .expect("load store A issuer")
            .current_public_key_hex();
        let pin_body = serde_json::json!({
            "public_key_hex": public_key_hex,
        })
        .to_string();
        let pin_response =
            exchange_one_http_request(store_b, &http_post_request("/issuer-accept", &pin_body));
        assert!(
            pin_response.starts_with("HTTP/1.1 200"),
            "POST /issuer-accept must pin the foreign public key: {pin_response}"
        );
    }

    fn store_b_verifier_signature(
        store_a: &crate::kernel::Kernel,
        store_b: &crate::kernel::Kernel,
        instance_id: &str,
    ) -> (String, String) {
        let challenge_response =
            exchange_one_http_request(store_b, &http_post_request("/verifier-challenge", "{}"));
        assert!(
            challenge_response.starts_with("HTTP/1.1 200"),
            "POST /verifier-challenge must return a nonce: {challenge_response}"
        );
        let challenge_value: serde_json::Value =
            serde_json::from_str(http_body(&challenge_response))
                .expect("POST /verifier-challenge must return JSON");
        let nonce = challenge_value["challenge_nonce"]
            .as_str()
            .expect("POST /verifier-challenge must return challenge_nonce")
            .to_string();
        let message = challenge_value["challenge_message"]
            .as_str()
            .expect("POST /verifier-challenge must return challenge_message")
            .to_string();
        let sign_body = serde_json::json!({
            "challenge_message": message,
            "holder_secret_path": store_a
                .store()
                .holder_secret_path(instance_id)
                .display()
                .to_string(),
        })
        .to_string();
        let sign_response = exchange_one_http_request(
            store_a,
            &http_post_request("/sign-holder-nonce", &sign_body),
        );
        assert!(
            sign_response.starts_with("HTTP/1.1 200"),
            "POST /sign-holder-nonce on the issuing host must return a signature: {sign_response}"
        );
        let sign_payload = http_body(&sign_response);
        let sign_value: serde_json::Value =
            serde_json::from_str(sign_payload).expect("POST /sign-holder-nonce must return JSON");
        let holder_proof = sign_value["holder_proof"]
            .as_str()
            .expect("POST /sign-holder-nonce must return holder_proof")
            .to_string();
        assert_body_has_no_secrets(
            store_a,
            sign_payload,
            Some(instance_id),
            "POST /sign-holder-nonce",
        );
        (nonce, holder_proof)
    }

    #[test]
    fn store_b_check_wimse_allows_with_verifier_challenge_and_holder_signature() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let birth = laboratory_host_birth(&store_a);
        let artifact = laboratory_wimse_artifact(&store_a, &birth);
        let (_directory_b, store_b) = laboratory_verifier_kernel();
        pin_store_b_to_store_a(&store_a, &store_b);
        let instances_before = store_b
            .store()
            .list_instances()
            .expect("list store B instances before check");
        let (nonce, holder_proof) =
            store_b_verifier_signature(&store_a, &store_b, &birth.instance.id);
        let (check_body, signature_input, signature) = {
            let envelope_secret = store_a
                .store()
                .load_biscuit_secret()
                .expect("load the issuing laboratory Ed25519 envelope secret");
            let (signature_input, signature) = crate::wimse::sign_laboratory_wimse_http_message(
                crate::wimse::LABORATORY_WIMSE_CHECK_METHOD,
                crate::wimse::LABORATORY_WIMSE_CHECK_PATH,
                &artifact.content_digest,
                &envelope_secret,
            )
            .expect("sign POST /check-wimse with the issuing envelope key");
            let body = serde_json::json!({
                "presentation_json": artifact.presentation_json,
                "workload_identity_token": artifact.workload_identity_token,
                "content_digest": artifact.content_digest,
                "intent": "read",
                "audience": "internal",
                "holder_proof": holder_proof,
                "challenge_nonce": nonce,
                "on_behalf_of": "autonomous",
                "signature_input": signature_input,
                "signature": signature,
            })
            .to_string();
            (body, signature_input, signature)
        };
        let response = exchange_one_http_request(
            &store_b,
            &http_post_request_with_signature(
                "/check-wimse",
                &check_body,
                &signature_input,
                &signature,
            ),
        );
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /check-wimse on store B must allow with a verifier challenge and holder signature: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /check-wimse must return JSON");
        assert_eq!(
            value["result"].as_str(),
            Some("allowed"),
            "store B must allow from the present holder public key: {payload}"
        );
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "store B must not copy the issuing inode"
        );
        let instances_after = store_b
            .store()
            .list_instances()
            .expect("list store B instances after check");
        assert_eq!(
            instances_before.len(),
            instances_after.len(),
            "store B must write no instance record"
        );
        assert_body_has_no_secrets(
            &store_a,
            payload,
            Some(&birth.instance.id),
            "store B WIMSE allow",
        );
        assert_body_has_no_secrets(&store_b, payload, None, "store B WIMSE allow secrets");
    }

    #[test]
    fn store_b_check_wimse_refuses_without_holder_signature() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let birth = laboratory_host_birth(&store_a);
        let artifact = laboratory_wimse_artifact(&store_a, &birth);
        let (_directory_b, store_b) = laboratory_verifier_kernel();
        pin_store_b_to_store_a(&store_a, &store_b);
        let envelope_secret = store_a
            .store()
            .load_biscuit_secret()
            .expect("load the issuing laboratory Ed25519 envelope secret");
        let (signature_input, signature) = crate::wimse::sign_laboratory_wimse_http_message(
            crate::wimse::LABORATORY_WIMSE_CHECK_METHOD,
            crate::wimse::LABORATORY_WIMSE_CHECK_PATH,
            &artifact.content_digest,
            &envelope_secret,
        )
        .expect("sign POST /check-wimse with the issuing envelope key");
        let body = serde_json::json!({
            "presentation_json": artifact.presentation_json,
            "workload_identity_token": artifact.workload_identity_token,
            "content_digest": artifact.content_digest,
            "intent": "read",
            "audience": "internal",
            "on_behalf_of": "autonomous",
            "signature_input": signature_input,
            "signature": signature,
        })
        .to_string();
        let response = exchange_one_http_request(
            &store_b,
            &http_post_request_with_signature("/check-wimse", &body, &signature_input, &signature),
        );
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /check-wimse on store B must refuse without a holder signature: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /check-wimse must return JSON");
        assert_eq!(value["result"].as_str(), Some("refused"));
        let reason = value["reason"].as_str().unwrap_or("");
        assert!(
            reason.contains("holder proof") || reason.contains("holder signature"),
            "store B must name the missing holder signature refuse: {reason}"
        );
        assert!(
            !reason.contains("does not exist"),
            "store B must not look up the issuing inode: {reason}"
        );
    }

    #[test]
    fn store_b_check_wimse_refuses_when_only_a_holder_secret_path_is_offered() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let birth = laboratory_host_birth(&store_a);
        let artifact = laboratory_wimse_artifact(&store_a, &birth);
        let (_directory_b, store_b) = laboratory_verifier_kernel();
        pin_store_b_to_store_a(&store_a, &store_b);
        let envelope_secret = store_a
            .store()
            .load_biscuit_secret()
            .expect("load the issuing laboratory Ed25519 envelope secret");
        let (signature_input, signature) = crate::wimse::sign_laboratory_wimse_http_message(
            crate::wimse::LABORATORY_WIMSE_CHECK_METHOD,
            crate::wimse::LABORATORY_WIMSE_CHECK_PATH,
            &artifact.content_digest,
            &envelope_secret,
        )
        .expect("sign POST /check-wimse with the issuing envelope key");
        let secret = store_a
            .store()
            .holder_secret_path(&birth.instance.id)
            .display()
            .to_string();
        let body = serde_json::json!({
            "presentation_json": artifact.presentation_json,
            "workload_identity_token": artifact.workload_identity_token,
            "content_digest": artifact.content_digest,
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": secret,
            "on_behalf_of": "autonomous",
            "signature_input": signature_input,
            "signature": signature,
        })
        .to_string();
        let response = exchange_one_http_request(
            &store_b,
            &http_post_request_with_signature("/check-wimse", &body, &signature_input, &signature),
        );
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /check-wimse on store B must refuse a holder secret path: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /check-wimse must return JSON");
        assert_eq!(value["result"].as_str(), Some("refused"));
        let reason = value["reason"].as_str().unwrap_or("");
        assert!(
            reason.contains("holder secret file is not accepted"),
            "store B must refuse a holder secret path without opening it: {reason}"
        );
        assert!(
            store_b
                .store()
                .holder_secret_path(&birth.instance.id)
                .exists()
                == false,
            "store B must not write a holder secret file"
        );
    }

    #[test]
    fn store_b_check_svid_allows_with_verifier_challenge_and_holder_signature() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let birth = laboratory_host_birth(&store_a);
        let artifact = laboratory_svid_wrap(&store_a, &birth);
        let (_directory_b, store_b) = laboratory_verifier_kernel();
        pin_store_b_to_store_a(&store_a, &store_b);
        let (nonce, holder_proof) =
            store_b_verifier_signature(&store_a, &store_b, &birth.instance.id);
        let body = serde_json::json!({
            "presentation_json": artifact.presentation_json,
            "certificate_pem": artifact.certificate_pem,
            "intent": "read",
            "audience": "internal",
            "holder_proof": holder_proof,
            "challenge_nonce": nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let response =
            exchange_one_http_request(&store_b, &http_post_request("/check-svid", &body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /check-svid on store B must allow with a verifier challenge and holder signature: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /check-svid must return JSON");
        assert_eq!(
            value["result"].as_str(),
            Some("allowed"),
            "store B must allow the honest SVID wrap from the verified present: {payload}"
        );
        assert!(
            value.get("receipt").is_none() || value["receipt"].is_null(),
            "a verifier allow must not mint a check receipt: {payload}"
        );
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "store B must not copy the issuing inode"
        );
        assert_body_has_no_secrets(
            &store_a,
            payload,
            Some(&birth.instance.id),
            "store B SVID allow",
        );
        assert_body_has_no_secrets(&store_b, payload, None, "store B SVID allow secrets");
    }

    #[test]
    fn store_b_verifier_challenge_does_not_write_an_instance() {
        let (_directory_b, store_b) = laboratory_verifier_kernel();
        let instances_before = store_b
            .store()
            .list_instances()
            .expect("list store B instances before verifier challenge");
        let log_before = store_b
            .store()
            .log_text()
            .expect("read store B log before verifier challenge");
        let response =
            exchange_one_http_request(&store_b, &http_post_request("/verifier-challenge", "{}"));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /verifier-challenge must return 200: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /verifier-challenge must return JSON");
        let object = value
            .as_object()
            .expect("POST /verifier-challenge must return a JSON object");
        assert!(
            object.contains_key("challenge_nonce"),
            "POST /verifier-challenge must return challenge_nonce: {payload}"
        );
        assert!(
            object.contains_key("challenge_message"),
            "POST /verifier-challenge must return challenge_message: {payload}"
        );
        assert!(
            !object.contains_key("instance_id"),
            "POST /verifier-challenge must not return an instance identifier: {payload}"
        );
        assert!(
            !object.contains_key("holder_secret_path"),
            "POST /verifier-challenge must not return a holder secret path: {payload}"
        );
        let nonce = value["challenge_nonce"]
            .as_str()
            .expect("challenge_nonce must be a string");
        assert!(!nonce.is_empty(), "challenge_nonce must not be empty");
        let instances_after = store_b
            .store()
            .list_instances()
            .expect("list store B instances after verifier challenge");
        assert_eq!(
            instances_before.len(),
            instances_after.len(),
            "POST /verifier-challenge must write no instance record"
        );
        assert!(
            instances_after.is_empty(),
            "store B must remain without instance records"
        );
        let log_after = store_b
            .store()
            .log_text()
            .expect("read store B log after verifier challenge");
        assert_eq!(
            log_before, log_after,
            "POST /verifier-challenge must not append an issuance.log line"
        );
        assert_body_has_no_secrets(&store_b, payload, None, "POST /verifier-challenge");
    }

    #[test]
    fn store_b_sign_holder_nonce_is_refused_when_this_store_has_no_instance() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let birth = laboratory_host_birth(&store_a);
        let (_directory_b, store_b) = laboratory_verifier_kernel();
        let challenge_response =
            exchange_one_http_request(&store_b, &http_post_request("/verifier-challenge", "{}"));
        assert!(
            challenge_response.starts_with("HTTP/1.1 200"),
            "POST /verifier-challenge must return a nonce: {challenge_response}"
        );
        let challenge_value: serde_json::Value =
            serde_json::from_str(http_body(&challenge_response))
                .expect("POST /verifier-challenge must return JSON");
        let message = challenge_value["challenge_message"]
            .as_str()
            .expect("POST /verifier-challenge must return challenge_message");
        let sign_body = serde_json::json!({
            "challenge_message": message,
            "holder_secret_path": store_a
                .store()
                .holder_secret_path(&birth.instance.id)
                .display()
                .to_string(),
        })
        .to_string();
        let sign_response = exchange_one_http_request(
            &store_b,
            &http_post_request("/sign-holder-nonce", &sign_body),
        );
        assert!(
            sign_response.contains("HTTP/1.1 403"),
            "POST /sign-holder-nonce on store B must refuse: {sign_response}"
        );
        let payload = http_body(&sign_response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /sign-holder-nonce must return JSON");
        assert_eq!(value["result"].as_str(), Some("refused"));
        let reason = value["reason"].as_str().unwrap_or("");
        assert!(
            reason.contains("no matching local instance"),
            "store B must refuse sign-holder-nonce when this store has no instance: {reason}"
        );
        assert!(
            store_b
                .store()
                .list_instances()
                .expect("list store B instances")
                .is_empty(),
            "store B must write no instance"
        );
        assert!(
            store_b
                .store()
                .holder_secret_path(&birth.instance.id)
                .exists()
                == false,
            "store B must not write a holder secret file"
        );
        assert_body_has_no_secrets(
            &store_a,
            payload,
            Some(&birth.instance.id),
            "POST /sign-holder-nonce on store B",
        );
        assert_body_has_no_secrets(
            &store_b,
            payload,
            None,
            "POST /sign-holder-nonce secrets on store B",
        );
    }

    fn host_allowed_check_receipt(
        kernel: &crate::kernel::Kernel,
        instance_id: &str,
        capability_id: &str,
        intent: &str,
        audience: &str,
    ) -> serde_json::Value {
        let nonce = kernel
            .issue_holder_challenge(instance_id)
            .expect("issue a holder challenge for check")
            .nonce;
        let secret = kernel
            .store()
            .holder_secret_path(instance_id)
            .display()
            .to_string();
        let body = serde_json::json!({
            "instance_id": instance_id,
            "capability_id": capability_id,
            "intent": intent,
            "audience": audience,
            "holder_secret_path": secret,
            "challenge_nonce": nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let response = exchange_one_http_request(kernel, &http_post_request("/check", &body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /check must allow the honest act: {response}"
        );
        let value: serde_json::Value =
            serde_json::from_str(http_body(&response)).expect("POST /check must return JSON");
        assert_eq!(
            value["result"].as_str(),
            Some("allowed"),
            "POST /check must allow: {value}"
        );
        value
            .get("receipt")
            .cloned()
            .expect("an allowed check must return a signed receipt")
    }

    fn host_act_export_bundle(
        kernel: &crate::kernel::Kernel,
        receipt: &serde_json::Value,
    ) -> serde_json::Value {
        let body = serde_json::json!({ "receipt": receipt }).to_string();
        let response = exchange_one_http_request(kernel, &http_post_request("/act-export", &body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /act-export must return the three public artifacts: {response}"
        );
        serde_json::from_str(http_body(&response)).expect("POST /act-export must return JSON")
    }

    fn laboratory_host_spawn_child(
        kernel: &crate::kernel::Kernel,
        parent: &crate::kernel::BirthWrite,
    ) -> crate::kernel::SpawnWrite {
        use crate::kernel::HolderProof;
        use std::collections::BTreeMap;

        let nonce = kernel
            .issue_holder_challenge(&parent.instance.id)
            .expect("issue a holder challenge for spawn")
            .nonce;
        let secret = kernel.store().holder_secret_path(&parent.instance.id);
        kernel
            .spawn_child(
                &parent.instance.id,
                &parent.capability.id,
                "child".to_string(),
                BTreeMap::new(),
                "read",
                "internal/prod",
                Some("autonomous".to_string()),
                Some(&HolderProof::SecretPath(secret)),
                Some(&nonce),
            )
            .expect("spawn a narrower child")
    }

    #[test]
    fn the_host_act_export_path_returns_public_artifacts_without_secrets() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let receipt = host_allowed_check_receipt(
            &kernel,
            &birth.instance.id,
            &birth.capability.id,
            "read",
            "internal",
        );
        let body = serde_json::json!({ "receipt": receipt }).to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/act-export", &body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /act-export must return 200 after a successful check: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /act-export must return JSON");
        let object = value
            .as_object()
            .expect("POST /act-export must return a JSON object");
        assert!(
            object.contains_key("receipt"),
            "POST /act-export must return receipt: {payload}"
        );
        assert!(
            object.contains_key("proof"),
            "POST /act-export must return proof: {payload}"
        );
        assert!(
            object.contains_key("tree_head"),
            "POST /act-export must return tree_head: {payload}"
        );
        assert!(
            !object.contains_key("presentation"),
            "POST /act-export must not invent a presentation artifact: {payload}"
        );
        let receipt_value = &value["receipt"];
        assert!(
            receipt_value.is_object(),
            "receipt must be a JSON object: {payload}"
        );
        assert_eq!(
            receipt_value["instance_id"].as_str(),
            Some(birth.instance.id.as_str()),
            "receipt must bind the checked instance: {payload}"
        );
        assert_eq!(
            receipt_value["result"].as_str(),
            Some("allowed"),
            "receipt must be the successful check receipt: {payload}"
        );
        let proof_text = value["proof"].to_string();
        assert!(
            proof_text.contains("line_hash") && proof_text.contains("root"),
            "proof must carry line_hash and root: {payload}"
        );
        let tree_head_text = value["tree_head"].to_string();
        assert!(
            tree_head_text.contains("merkle_root"),
            "tree_head must carry merkle_root: {payload}"
        );
        assert_body_has_no_secrets(
            &kernel,
            payload,
            Some(&birth.instance.id),
            "POST /act-export",
        );
    }

    #[test]
    fn the_host_act_export_path_refuses_a_failed_check_receipt() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        let birth = laboratory_host_birth(&kernel);
        let nonce = kernel
            .issue_holder_challenge(&birth.instance.id)
            .expect("issue a holder challenge for a refused check")
            .nonce;
        let secret = kernel
            .store()
            .holder_secret_path(&birth.instance.id)
            .display()
            .to_string();
        let check_body = serde_json::json!({
            "instance_id": birth.instance.id,
            "capability_id": birth.capability.id,
            "intent": "read",
            "audience": "public",
            "holder_secret_path": secret,
            "challenge_nonce": nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let check_response =
            exchange_one_http_request(&kernel, &http_post_request("/check", &check_body));
        assert!(
            check_response.contains("HTTP/1.1 403"),
            "POST /check must refuse a destination outside the authorization limit: {check_response}"
        );
        let check_value: serde_json::Value =
            serde_json::from_str(http_body(&check_response)).expect("POST /check must return JSON");
        assert_eq!(
            check_value["result"].as_str(),
            Some("refused"),
            "POST /check must refuse: {check_value}"
        );
        let receipt = check_value
            .get("receipt")
            .cloned()
            .expect("a refused check must return a signed receipt");
        assert_eq!(
            receipt["result"].as_str(),
            Some("refused"),
            "the receipt must name the refused check: {receipt}"
        );
        let body = serde_json::json!({ "receipt": receipt }).to_string();
        let response = exchange_one_http_request(&kernel, &http_post_request("/act-export", &body));
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /act-export must fail closed for a refused check: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("successful check"),
            "POST /act-export must name the failed-check refuse: {payload}"
        );
        assert!(
            !payload.contains("\"proof\""),
            "a refused act-export must not return a proof: {payload}"
        );
        assert_body_has_no_secrets(
            &kernel,
            payload,
            Some(&birth.instance.id),
            "a refused failed-check act-export",
        );
    }

    #[test]
    fn the_host_act_accept_path_refuses_before_issuer_accept() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let birth = laboratory_host_birth(&store_a);
        let receipt = host_allowed_check_receipt(
            &store_a,
            &birth.instance.id,
            &birth.capability.id,
            "read",
            "internal",
        );
        let bundle = host_act_export_bundle(&store_a, &receipt);
        let export_body = serde_json::to_string(&bundle).expect("serialize the export bundle");

        let (_directory_b, store_b) = laboratory_verifier_kernel();
        let instances_before = store_b
            .store()
            .list_instances()
            .expect("list store B instances before a refused accept");
        let log_before = store_b
            .store()
            .log_text()
            .expect("read store B log before a refused accept");
        let response =
            exchange_one_http_request(&store_b, &http_post_request("/act-accept", &export_body));
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /act-accept must fail closed before issuer accept: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("unknown issuer key") || payload.contains("accept list"),
            "POST /act-accept must name the unknown issuer key refuse: {payload}"
        );
        let instances_after = store_b
            .store()
            .list_instances()
            .expect("list store B instances after a refused accept");
        assert_eq!(
            instances_before.len(),
            instances_after.len(),
            "a refused act accept must write no instance record"
        );
        let log_after = store_b
            .store()
            .log_text()
            .expect("read store B log after a refused accept");
        assert_eq!(
            log_before, log_after,
            "a refused act accept must not write a second issuance.log line"
        );
        assert_body_has_no_secrets(
            &store_a,
            payload,
            Some(&birth.instance.id),
            "a refused act-accept",
        );
        assert_body_has_no_secrets(&store_b, payload, None, "a refused act-accept on store B");
    }

    #[test]
    fn the_host_act_accept_path_accepts_and_writes_no_instance_record() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let birth = laboratory_host_birth(&store_a);
        let receipt = host_allowed_check_receipt(
            &store_a,
            &birth.instance.id,
            &birth.capability.id,
            "read",
            "internal",
        );
        let bundle = host_act_export_bundle(&store_a, &receipt);
        let export_body = serde_json::to_string(&bundle).expect("serialize the export bundle");
        let issuer_a = store_a.store().load_issuer().expect("load store A issuer");
        let public_key_hex = issuer_a.current_public_key_hex();

        let (_directory_b, store_b) = laboratory_verifier_kernel();
        let pin_body = serde_json::json!({
            "public_key_hex": public_key_hex,
        })
        .to_string();
        let pin_response =
            exchange_one_http_request(&store_b, &http_post_request("/issuer-accept", &pin_body));
        assert!(
            pin_response.starts_with("HTTP/1.1 200"),
            "POST /issuer-accept must pin the foreign public key: {pin_response}"
        );

        let instances_before = store_b
            .store()
            .list_instances()
            .expect("list store B instances before act accept");
        let log_before = store_b
            .store()
            .log_text()
            .expect("read store B log before act accept");
        let response =
            exchange_one_http_request(&store_b, &http_post_request("/act-accept", &export_body));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST /act-accept must accept the signed act bundle: {response}"
        );
        let payload = http_body(&response);
        let value: serde_json::Value =
            serde_json::from_str(payload).expect("POST /act-accept must return JSON");
        assert_eq!(
            value["result"].as_str(),
            Some("accepted"),
            "POST /act-accept must return result accepted: {payload}"
        );
        let instances_after = store_b
            .store()
            .list_instances()
            .expect("list store B instances after act accept");
        assert_eq!(
            instances_before.len(),
            instances_after.len(),
            "act accept must write no instance record"
        );
        assert!(
            instances_after.is_empty(),
            "store B must remain without instance records"
        );
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "store B must not copy the issuing inode"
        );
        let log_after = store_b
            .store()
            .log_text()
            .expect("read store B log after act accept");
        assert_eq!(
            log_before, log_after,
            "act accept must not write a second issuance.log line"
        );
        assert_body_has_no_secrets(
            &store_a,
            payload,
            Some(&birth.instance.id),
            "POST /act-accept",
        );
        assert_body_has_no_secrets(&store_b, payload, None, "POST /act-accept on store B");
    }

    #[test]
    fn the_host_act_accept_path_refuses_after_kill_accept_of_an_ancestor() {
        use crate::kernel::Kernel;
        use tempfile::tempdir;

        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let parent = laboratory_host_birth(&store_a);
        let child = laboratory_host_spawn_child(&store_a, &parent);
        let receipt = host_allowed_check_receipt(
            &store_a,
            &child.instance.id,
            &child.capability.id,
            "read",
            "internal/prod",
        );
        let ancestors = receipt["ancestor_instance_ids"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let parent_in_ancestors = ancestors
            .iter()
            .any(|value| value.as_str() == Some(parent.instance.id.as_str()));
        assert!(
            parent_in_ancestors,
            "the child check receipt must sign the parent as an ancestor: {receipt}"
        );
        let bundle = host_act_export_bundle(&store_a, &receipt);
        let export_body = serde_json::to_string(&bundle).expect("serialize the child act bundle");

        store_a
            .kill_instance(&parent.instance.id)
            .expect("store A must persist parent kill");
        let kill_bundle = host_kill_export_bundle(&store_a, &parent.instance.id);
        let kill_body =
            serde_json::to_string(&kill_bundle).expect("serialize the parent kill bundle");
        let issuer_a = store_a.store().load_issuer().expect("load store A issuer");
        let public_key_hex = issuer_a.current_public_key_hex();

        let (_directory_b, store_b) = laboratory_verifier_kernel();
        let pin_body = serde_json::json!({
            "public_key_hex": public_key_hex,
        })
        .to_string();
        let pin_response =
            exchange_one_http_request(&store_b, &http_post_request("/issuer-accept", &pin_body));
        assert!(
            pin_response.starts_with("HTTP/1.1 200"),
            "POST /issuer-accept must pin the foreign public key: {pin_response}"
        );
        let kill_accept =
            exchange_one_http_request(&store_b, &http_post_request("/kill-accept", &kill_body));
        assert!(
            kill_accept.starts_with("HTTP/1.1 200"),
            "POST /kill-accept must accept the parent death bundle: {kill_accept}"
        );

        let instances_before = store_b
            .store()
            .list_instances()
            .expect("list store B instances before a refused act accept");
        let log_before = store_b
            .store()
            .log_text()
            .expect("read store B log before a refused act accept");
        let response =
            exchange_one_http_request(&store_b, &http_post_request("/act-accept", &export_body));
        assert!(
            response.contains("HTTP/1.1 403"),
            "POST /act-accept must fail closed after kill accept of an ancestor: {response}"
        );
        let payload = http_body(&response);
        assert!(
            payload.contains("kill accept") || payload.contains("ancestor"),
            "POST /act-accept must name the accepted ancestor death refuse: {payload}"
        );
        let instances_after = store_b
            .store()
            .list_instances()
            .expect("list store B instances after a refused act accept");
        assert_eq!(
            instances_before.len(),
            instances_after.len(),
            "a refused act accept must write no instance record"
        );
        assert!(
            store_b.store().load_instance(&child.instance.id).is_err(),
            "store B must not copy the child inode"
        );
        let log_after = store_b
            .store()
            .log_text()
            .expect("read store B log after a refused act accept");
        assert_eq!(
            log_before, log_after,
            "a refused act accept must not write a second issuance.log line"
        );
        assert_body_has_no_secrets(
            &store_a,
            payload,
            Some(&parent.instance.id),
            "refused act-accept after ancestor kill",
        );
        assert_body_has_no_secrets(
            &store_a,
            payload,
            Some(&child.instance.id),
            "refused act-accept child secrets",
        );
        assert_body_has_no_secrets(&store_b, payload, None, "refused act-accept on store B");
    }
}
