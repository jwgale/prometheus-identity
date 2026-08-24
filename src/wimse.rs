//! Laboratory Workload Identity Token wrap of a signed presentation document.
//!
//! This wrap is an artifact. This wrap is not a sixth identity record.
//! Present stays a document. WIMSE is a second on-ramp. X.509 is still
//! presentation. This module does not replace the laboratory X.509-SVID wrap.
//!
//! The token `sub` claim is the only WIMSE identity. The subject is a
//! present-hash Uniform Resource Identifier:
//! `wimse://prometheus.laboratory/present/<sha256 hex of the present bytes>`.
//! The instance Unique Lexicographically Sortable Identifier stays inside the
//! present JSON only. Do not put that identifier in `sub`, in a Uniform
//! Resource Identifier path, or in a distinguished name.
//!
//! The token is a typed JSON Web Token. Header `typ` is `wit+jwt`. Header
//! `alg` is `EdDSA`. The token is signed with the laboratory Ed25519 envelope
//! key. Confirmation `cnf.jwk` is that same envelope public key. Do not mint
//! a second identity key. The token is not a bearer token. Short token life
//! is not kill.
//!
//! The present bytes are the request body. `Content-Digest` (sha-256) binds
//! those bytes. Verify refuses a swapped body. This slice verifies the token,
//! the digest, and existing present-verify. The loopback host binds POST
//! /check-wimse with HTTP Message Signatures over `@method`,
//! `@request-target`, and `content-digest`. This slice does not sign every
//! HTTP header. This is still not a full header-coverage stack.
//!
//! Do not start mutual Transport Layer Security, the Workload Identity
//! Certificate, the Workload Proof Token, a DID, SPIRE, or a sixth inode.
//! Soft-fail is forbidden.

use crate::error::{Error, Result};
use crate::presentation::Presentation;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Trust domain for the laboratory Workload Identity Token.
/// This is not a global name system.
pub const LABORATORY_WIMSE_TRUST_DOMAIN: &str = "prometheus.laboratory";

/// Path prefix that names a presentation document, not an instance.
pub const LABORATORY_PRESENT_WIMSE_PATH_PREFIX: &str = "/present/";

/// Laboratory Workload Identity Token lifetime in seconds.
/// This bounds a missed kill for a relying party that only checks expiry.
/// This is not kill. Short token life is not kill.
pub const LABORATORY_WIT_LIFETIME_SECONDS: u64 = 300;

/// HTTP field that carries the Workload Identity Token.
pub const WORKLOAD_IDENTITY_TOKEN_HEADER: &str = "Workload-Identity-Token";

/// HTTP field that carries the Content-Digest of the present bytes.
pub const CONTENT_DIGEST_HEADER: &str = "Content-Digest";

/// HTTP field that carries the RFC 9421 signature input.
pub const SIGNATURE_INPUT_HEADER: &str = "Signature-Input";

/// HTTP field that carries the RFC 9421 signature.
pub const SIGNATURE_HEADER: &str = "Signature";

/// Laboratory HTTP Message Signatures label for the loopback WIMSE check bind.
pub const LABORATORY_WIMSE_HTTP_SIGNATURE_LABEL: &str = "sig";

/// Bound HTTP method for POST /check-wimse.
pub const LABORATORY_WIMSE_CHECK_METHOD: &str = "POST";

/// Bound request-target for POST /check-wimse.
pub const LABORATORY_WIMSE_CHECK_PATH: &str = "/check-wimse";

/// Typed JSON Web Token header type for a Workload Identity Token.
pub const LABORATORY_WIT_TYP: &str = "wit+jwt";

/// Bound Uniform Resource Identifier for the token subject.
pub fn bound_wimse_uri(presentation_document_bytes: &[u8]) -> String {
    format!(
        "wimse://{LABORATORY_WIMSE_TRUST_DOMAIN}{LABORATORY_PRESENT_WIMSE_PATH_PREFIX}{}",
        presentation_document_sha256_hex(presentation_document_bytes)
    )
}

/// SHA-256 hexadecimal of the present document bytes that were shown.
pub fn presentation_document_sha256_hex(presentation_document_bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(presentation_document_bytes))
}

/// RFC 9530 Content-Digest field value for SHA-256 of the present bytes.
pub fn content_digest_sha256(presentation_document_bytes: &[u8]) -> String {
    let digest = Sha256::digest(presentation_document_bytes);
    format!("sha-256=:{}:", STANDARD.encode(digest))
}

/// Cap Workload Identity Token expiry to the earlier of presentation
/// expires_at and now plus laboratory_wit_lifetime. Expiry must never exceed
/// presentation expires_at. Short token life is not kill.
pub fn laboratory_wit_not_after(
    presentation_expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> DateTime<Utc> {
    presentation_expires_at.min(now + Duration::seconds(LABORATORY_WIT_LIFETIME_SECONDS as i64))
}

/// Laboratory WIMSE on-ramp artifact. This is not a sixth identity record.
#[derive(Debug, Clone)]
pub struct WimseArtifact {
    pub presentation: Presentation,
    /// Exact present document bytes that were hashed into `sub` and Content-Digest.
    pub presentation_json: String,
    pub workload_identity_token: String,
    pub content_digest: String,
    pub wimse_uri: String,
}

/// Emit a laboratory Workload Identity Token and the Content-Digest of the
/// present bytes. Sign with the laboratory Ed25519 envelope key.
pub fn emit_laboratory_wit(
    presentation_document_bytes: &[u8],
    envelope_secret_hex: &str,
    laboratory_envelope_public_key_hex: &str,
    presented_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<(String, String, String)> {
    let not_after = require_emit_window(presented_at, expires_at)?;
    let sub = bound_wimse_uri(presentation_document_bytes);
    let token = sign_workload_identity_token(SignSpec {
        envelope_secret_hex,
        laboratory_envelope_public_key_hex,
        sub: &sub,
        presented_at,
        not_after,
    })?;
    Ok((
        token,
        content_digest_sha256(presentation_document_bytes),
        sub,
    ))
}

/// Parse the token, refuse a forbidden subject, check expiry, check the
/// envelope signature and confirmation key, then check Content-Digest.
/// The kernel adds present-verify. A swapped body fails closed.
pub fn require_laboratory_wimse(
    workload_identity_token: &str,
    content_digest: &str,
    presentation_document_bytes: &[u8],
    presentation: &Presentation,
    now: DateTime<Utc>,
    laboratory_envelope_public_key_hex: &str,
) -> Result<()> {
    require_content_digest(content_digest, presentation_document_bytes)?;
    let claims = require_workload_identity_token(
        workload_identity_token,
        laboratory_envelope_public_key_hex,
        now,
        presentation.expires_at,
    )?;
    require_bound_wimse_sub(
        &claims.sub,
        presentation_document_bytes,
        &presentation.instance_id,
    )?;
    require_confirmation_matches_envelope(&claims, laboratory_envelope_public_key_hex)?;
    Ok(())
}

/// RFC 9421 signature-params inner list for the laboratory WIMSE check bind.
pub fn laboratory_wimse_signature_params() -> &'static str {
    r#"("@method" "@request-target" "content-digest")"#
}

/// RFC 9421 Signature-Input field value for the laboratory WIMSE check bind.
pub fn laboratory_wimse_signature_input() -> String {
    format!(
        "{LABORATORY_WIMSE_HTTP_SIGNATURE_LABEL}={}",
        laboratory_wimse_signature_params()
    )
}

/// RFC 9421 signature base over method, request-target, and Content-Digest.
pub fn laboratory_wimse_signature_base(
    method: &str,
    request_target: &str,
    content_digest: &str,
    params: &str,
) -> String {
    format!(
        "\"@method\": {method}\n\"@request-target\": {request_target}\n\"content-digest\": {content_digest}\n\"@signature-params\": {params}"
    )
}

fn sign_envelope_over_http_base(
    params: &str,
    base: &str,
    envelope_secret_hex: &str,
) -> Result<(String, String)> {
    let seed =
        bytes_32_from_hexadecimal(envelope_secret_hex, "laboratory Ed25519 envelope secret")?;
    let signing_key = SigningKey::from_bytes(&seed);
    let signature = signing_key.sign(base.as_bytes());
    let encoded = STANDARD.encode(signature.to_bytes());
    Ok((
        format!("{LABORATORY_WIMSE_HTTP_SIGNATURE_LABEL}={params}"),
        format!("{LABORATORY_WIMSE_HTTP_SIGNATURE_LABEL}=:{encoded}:"),
    ))
}

/// Sign `@method`, `@request-target`, and `content-digest` with the laboratory
/// Ed25519 envelope key. Returns the Signature-Input field value and the
/// Signature field value.
pub fn sign_laboratory_wimse_http_message(
    method: &str,
    request_target: &str,
    content_digest: &str,
    envelope_secret_hex: &str,
) -> Result<(String, String)> {
    let params = laboratory_wimse_signature_params();
    let base = laboratory_wimse_signature_base(method, request_target, content_digest, params);
    sign_envelope_over_http_base(params, &base, envelope_secret_hex)
}

/// Sign `@method` and `@request-target` only. Tests use this to prove that
/// a check refuses a signature that omits content-digest.
pub fn sign_laboratory_wimse_http_message_omitting_content_digest(
    method: &str,
    request_target: &str,
    envelope_secret_hex: &str,
) -> Result<(String, String)> {
    let params = r#"("@method" "@request-target")"#;
    let base = format!(
        "\"@method\": {method}\n\"@request-target\": {request_target}\n\"@signature-params\": {params}"
    );
    sign_envelope_over_http_base(params, &base, envelope_secret_hex)
}

/// Verify the laboratory HTTP Message Signature over the actual method,
/// request-target, and Content-Digest. Covered components are `@method`,
/// `@request-target`, and `content-digest`. POST /check-wimse is required.
/// The signed digest must be the same digest the body verify requires.
/// A missing signature, a missing digest, a signature that omits
/// content-digest, a signature over a different digest, a different method,
/// a different path, and a signature that is not the envelope key fail closed.
/// This is still not a full header-coverage stack.
pub fn require_laboratory_wimse_http_message_signature(
    method: &str,
    request_target: &str,
    content_digest: &str,
    signature_input: &str,
    signature: &str,
    laboratory_envelope_public_key_hex: &str,
) -> Result<()> {
    if signature_input.trim().is_empty() || signature.trim().is_empty() {
        return Err(Error::denied(
            "The HTTP Message Signature is missing. POST /check-wimse requires a signature over @method, @request-target, and content-digest. The check fails closed.",
        ));
    }
    if content_digest.trim().is_empty() {
        return Err(Error::denied(
            "The Content-Digest is missing. POST /check-wimse requires a signature over content-digest. The check fails closed.",
        ));
    }
    let params = require_laboratory_wimse_signature_input(signature_input)?;
    let signature_bytes = parse_laboratory_wimse_signature(signature)?;
    if method != LABORATORY_WIMSE_CHECK_METHOD {
        return Err(Error::denied(
            "POST /check-wimse binds HTTP @method POST and @request-target /check-wimse. A different method is refused. The check fails closed.",
        ));
    }
    if request_target != LABORATORY_WIMSE_CHECK_PATH {
        return Err(Error::denied(
            "POST /check-wimse binds HTTP @method POST and @request-target /check-wimse. A different request-target is refused. The check fails closed.",
        ));
    }
    let base = laboratory_wimse_signature_base(method, request_target, content_digest, &params);
    require_ed25519_http_signature(&base, &signature_bytes, laboratory_envelope_public_key_hex)
}

fn require_laboratory_wimse_signature_input(signature_input: &str) -> Result<String> {
    let trimmed = signature_input.trim();
    let rest = trimmed.strip_prefix("sig=").ok_or_else(|| {
        Error::denied(
            "The HTTP Message Signature-Input label must be sig. The covered components must be @method, @request-target, and content-digest. The check fails closed.",
        )
    })?;
    let inner = rest.trim();
    if inner.contains(';') {
        return Err(Error::denied(
            "The HTTP Message Signature-Input must cover @method, @request-target, and content-digest only. Extra signature parameters are refused. The check fails closed.",
        ));
    }
    if !laboratory_wimse_covers_required_components(inner) {
        return Err(Error::denied(
            "The HTTP Message Signature must cover @method, @request-target, and content-digest. A signature that omits content-digest is refused. The check fails closed.",
        ));
    }
    Ok(inner.to_string())
}

fn laboratory_wimse_covers_required_components(inner: &str) -> bool {
    let Some(list) = inner
        .strip_prefix('(')
        .and_then(|text| text.strip_suffix(')'))
    else {
        return false;
    };
    let mut parts: Vec<&str> = list.split_whitespace().collect();
    if parts.len() != 3 {
        return false;
    }
    parts.sort_unstable();
    parts
        == [
            r#""@method""#,
            r#""@request-target""#,
            r#""content-digest""#,
        ]
}

fn parse_laboratory_wimse_signature(signature: &str) -> Result<Vec<u8>> {
    let trimmed = signature.trim();
    let rest = trimmed.strip_prefix("sig=").ok_or_else(|| {
        Error::denied("The HTTP Message Signature label must be sig. The check fails closed.")
    })?;
    let rest = rest.trim();
    if rest.len() < 2 || !rest.starts_with(':') || !rest.ends_with(':') {
        return Err(Error::denied(
            "The HTTP Message Signature must be a structured-field byte sequence. The check fails closed.",
        ));
    }
    let encoded = &rest[1..rest.len() - 1];
    STANDARD.decode(encoded.trim()).map_err(|error| {
        Error::denied(format!(
            "The HTTP Message Signature value is not valid base64: {error}. The check fails closed."
        ))
    })
}

fn require_ed25519_http_signature(
    signing_input: &str,
    signature_bytes: &[u8],
    laboratory_envelope_public_key_hex: &str,
) -> Result<()> {
    if laboratory_envelope_public_key_hex.trim().is_empty() {
        return Err(Error::denied(
            "The laboratory Ed25519 envelope public key is empty. The HTTP Message Signature check fails closed.",
        ));
    }
    let public_bytes = bytes_32_from_hexadecimal(
        laboratory_envelope_public_key_hex,
        "laboratory Ed25519 envelope public key",
    )?;
    let verifying_key = VerifyingKey::from_bytes(&public_bytes).map_err(|error| {
        Error::denied(format!(
            "The laboratory Ed25519 envelope public key is not a valid Ed25519 key: {error}. The HTTP Message Signature check fails closed."
        ))
    })?;
    let signature_array: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        Error::denied("The HTTP Message Signature must decode to 64 bytes. The check fails closed.")
    })?;
    let signature = Signature::from_bytes(&signature_array);
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| {
            Error::denied(
                "The HTTP Message Signature is not valid for the laboratory Ed25519 envelope key. The covered components are @method, @request-target, and content-digest. A signature over a different method, request-target, or digest is refused. The check fails closed.",
            )
        })?;
    Ok(())
}

struct SignSpec<'a> {
    envelope_secret_hex: &'a str,
    laboratory_envelope_public_key_hex: &'a str,
    sub: &'a str,
    presented_at: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

struct WitClaims {
    sub: String,
    confirmation_public_key_hex: String,
}

fn require_emit_window(
    presented_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<DateTime<Utc>> {
    if expires_at <= presented_at {
        return Err(Error::denied(
            "The presentation window is empty. Token expiry must be after presented_at. Short token life is not kill. The check fails closed.",
        ));
    }
    let not_after = laboratory_wit_not_after(expires_at, presented_at);
    if not_after > expires_at {
        return Err(Error::denied(
            "The Workload Identity Token expiry is after the presentation expires_at. Short token life is not kill. Expiry must be the presentation expires_at or earlier. The check fails closed.",
        ));
    }
    if not_after <= presented_at {
        return Err(Error::denied(
            "The Workload Identity Token window is empty. Expiry must be after presented_at. Short token life is not kill. The check fails closed.",
        ));
    }
    Ok(not_after)
}

fn sign_workload_identity_token(spec: SignSpec<'_>) -> Result<String> {
    refuse_instance_shaped_identifier(spec.sub, "")?;
    let public_bytes = bytes_32_from_hexadecimal(
        spec.laboratory_envelope_public_key_hex,
        "laboratory Ed25519 envelope public key",
    )?;
    let header = json!({
        "alg": "EdDSA",
        "typ": LABORATORY_WIT_TYP,
    });
    let payload = json!({
        "sub": spec.sub,
        "iss": format!("wimse://{LABORATORY_WIMSE_TRUST_DOMAIN}"),
        "iat": spec.presented_at.timestamp(),
        "exp": spec.not_after.timestamp(),
        "cnf": {
            "jwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": URL_SAFE_NO_PAD.encode(public_bytes),
            }
        }
    });
    compact_jws(&header, &payload, spec.envelope_secret_hex)
}

fn compact_jws(header: &Value, payload: &Value, envelope_secret_hex: &str) -> Result<String> {
    let header_json = serde_json::to_string(header).map_err(|error| {
        Error::denied(format!(
            "The Workload Identity Token header could not be written: {error}. The check fails closed."
        ))
    })?;
    let payload_json = serde_json::to_string(payload).map_err(|error| {
        Error::denied(format!(
            "The Workload Identity Token claims could not be written: {error}. The check fails closed."
        ))
    })?;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let seed =
        bytes_32_from_hexadecimal(envelope_secret_hex, "laboratory Ed25519 envelope secret")?;
    let signing_key = SigningKey::from_bytes(&seed);
    let signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    Ok(format!("{signing_input}.{signature_b64}"))
}

fn require_content_digest(content_digest: &str, presentation_document_bytes: &[u8]) -> Result<()> {
    let expected = content_digest_sha256(presentation_document_bytes);
    if content_digest.trim() != expected {
        return Err(Error::denied(
            "The Content-Digest does not match the present bytes. A swapped body is refused. The receiver must verify Content-Digest. The check fails closed.",
        ));
    }
    Ok(())
}

fn require_workload_identity_token(
    token: &str,
    laboratory_envelope_public_key_hex: &str,
    now: DateTime<Utc>,
    presentation_expires_at: DateTime<Utc>,
) -> Result<WitClaims> {
    if token.trim().is_empty() {
        return Err(Error::denied(
            "The Workload Identity Token is empty. The check fails closed.",
        ));
    }
    let mut parts = token.trim().split('.');
    let header_b64 = parts.next().ok_or_else(|| {
        Error::denied(
            "The Workload Identity Token is not a compact JSON Web Token. The check fails closed.",
        )
    })?;
    let payload_b64 = parts.next().ok_or_else(|| {
        Error::denied(
            "The Workload Identity Token is not a compact JSON Web Token. The check fails closed.",
        )
    })?;
    let signature_b64 = parts.next().ok_or_else(|| {
        Error::denied(
            "The Workload Identity Token is not a compact JSON Web Token. The check fails closed.",
        )
    })?;
    if parts.next().is_some() {
        return Err(Error::denied(
            "The Workload Identity Token has extra compact segments. The check fails closed.",
        ));
    }
    let header_bytes = decode_base64url(header_b64, "Workload Identity Token header")?;
    let payload_bytes = decode_base64url(payload_b64, "Workload Identity Token claims")?;
    let signature_bytes = decode_base64url(signature_b64, "Workload Identity Token signature")?;
    let header: Value = serde_json::from_slice(&header_bytes).map_err(|error| {
        Error::denied(format!(
            "The Workload Identity Token header did not parse: {error}. The check fails closed."
        ))
    })?;
    let payload: Value = serde_json::from_slice(&payload_bytes).map_err(|error| {
        Error::denied(format!(
            "The Workload Identity Token claims did not parse: {error}. The check fails closed."
        ))
    })?;
    require_typed_header(&header)?;
    require_ed25519_compact_signature(
        &format!("{header_b64}.{payload_b64}"),
        &signature_bytes,
        laboratory_envelope_public_key_hex,
    )?;
    require_token_time(&payload, now, presentation_expires_at)?;
    let sub = json_string_field(&payload, "sub")?;
    refuse_instance_shaped_identifier(&sub, "")?;
    let confirmation_public_key_hex = confirmation_public_key_hex_from_claims(&payload)?;
    Ok(WitClaims {
        sub,
        confirmation_public_key_hex,
    })
}

fn require_typed_header(header: &Value) -> Result<()> {
    let typ = json_string_field(header, "typ")?;
    if typ != LABORATORY_WIT_TYP {
        return Err(Error::denied(
            "The Workload Identity Token typ must be wit+jwt. The check fails closed.",
        ));
    }
    let alg = json_string_field(header, "alg")?;
    if alg == "none" {
        return Err(Error::denied(
            "The Workload Identity Token algorithm none is refused. The check fails closed.",
        ));
    }
    if alg != "EdDSA" {
        return Err(Error::denied(
            "The Workload Identity Token algorithm must be EdDSA. The token is signed with the laboratory Ed25519 envelope key. The check fails closed.",
        ));
    }
    Ok(())
}

fn require_ed25519_compact_signature(
    signing_input: &str,
    signature_bytes: &[u8],
    laboratory_envelope_public_key_hex: &str,
) -> Result<()> {
    let public_bytes = bytes_32_from_hexadecimal(
        laboratory_envelope_public_key_hex,
        "laboratory Ed25519 envelope public key",
    )?;
    let verifying_key = VerifyingKey::from_bytes(&public_bytes).map_err(|error| {
        Error::denied(format!(
            "The laboratory Ed25519 envelope public key is not a valid Ed25519 key: {error}. The check fails closed."
        ))
    })?;
    let signature_array: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        Error::denied(
            "The Workload Identity Token signature must decode to 64 bytes. The check fails closed.",
        )
    })?;
    let signature = Signature::from_bytes(&signature_array);
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| {
            Error::denied(
                "The Workload Identity Token signature is not valid for the laboratory Ed25519 envelope key. The check fails closed.",
            )
        })?;
    Ok(())
}

fn require_token_time(
    payload: &Value,
    now: DateTime<Utc>,
    presentation_expires_at: DateTime<Utc>,
) -> Result<()> {
    let exp = json_unix_field(payload, "exp")?;
    let not_after = DateTime::<Utc>::from_timestamp(exp, 0).ok_or_else(|| {
        Error::denied(
            "The Workload Identity Token exp value is not a valid time. The check fails closed.",
        )
    })?;
    if not_after > presentation_expires_at {
        return Err(Error::denied(
            "The Workload Identity Token exp is after the presentation expires_at. Short token life is not kill. Expiry must be the presentation expires_at or earlier. The check fails closed.",
        ));
    }
    if now >= not_after {
        return Err(Error::denied(
            "The Workload Identity Token has expired. Now is at or after exp. Short token life is not kill. The check fails closed.",
        ));
    }
    Ok(())
}

fn confirmation_public_key_hex_from_claims(payload: &Value) -> Result<String> {
    let cnf = payload.get("cnf").ok_or_else(|| {
        Error::denied(
            "The Workload Identity Token is missing cnf. The token is not a bearer token. The check fails closed.",
        )
    })?;
    let jwk = cnf.get("jwk").ok_or_else(|| {
        Error::denied(
            "The Workload Identity Token is missing cnf.jwk. Proof of possession uses the laboratory envelope public key. The check fails closed.",
        )
    })?;
    let kty = json_string_field(jwk, "kty")?;
    if kty != "OKP" {
        return Err(Error::denied(
            "The Workload Identity Token confirmation key type must be OKP. The check fails closed.",
        ));
    }
    let crv = json_string_field(jwk, "crv")?;
    if crv != "Ed25519" {
        return Err(Error::denied(
            "The Workload Identity Token confirmation curve must be Ed25519. The check fails closed.",
        ));
    }
    let alg = json_string_field(jwk, "alg")?;
    if alg == "none" {
        return Err(Error::denied(
            "The Workload Identity Token confirmation algorithm none is refused. The check fails closed.",
        ));
    }
    if alg != "EdDSA" {
        return Err(Error::denied(
            "The Workload Identity Token confirmation algorithm must be EdDSA. The check fails closed.",
        ));
    }
    let x = json_string_field(jwk, "x")?;
    let public_bytes = decode_base64url(&x, "Workload Identity Token confirmation key")?;
    if public_bytes.len() != 32 {
        return Err(Error::denied(
            "The Workload Identity Token confirmation key must decode to 32 bytes. The check fails closed.",
        ));
    }
    Ok(hex::encode(public_bytes))
}

fn require_confirmation_matches_envelope(
    claims: &WitClaims,
    laboratory_envelope_public_key_hex: &str,
) -> Result<()> {
    let expected = laboratory_envelope_public_key_hex.trim();
    if expected.is_empty() {
        return Err(Error::denied(
            "The laboratory Ed25519 envelope public key is empty. The check fails closed.",
        ));
    }
    if !claims
        .confirmation_public_key_hex
        .eq_ignore_ascii_case(expected)
    {
        return Err(Error::denied(
            "The Workload Identity Token confirmation key does not match the laboratory Ed25519 envelope public key in the signed present. A resigned token fails closed. The check fails closed.",
        ));
    }
    Ok(())
}

fn require_bound_wimse_sub(
    sub: &str,
    presentation_document_bytes: &[u8],
    instance_id: &str,
) -> Result<()> {
    refuse_instance_shaped_identifier(sub, instance_id)?;
    let expected = bound_wimse_uri(presentation_document_bytes);
    if sub != expected {
        return Err(Error::denied(
            "The Workload Identity Token subject is not the bound presentation Uniform Resource Identifier. The relying party hashes the present document bytes it was shown and requires that path. The scheme must be wimse. The path must be a non-root /present/<sha256hex> path. The instance identifier must not appear in the subject. The check fails closed.",
        ));
    }
    Ok(())
}

fn refuse_instance_shaped_identifier(identifier: &str, instance_id: &str) -> Result<()> {
    if !instance_id.trim().is_empty() && identifier.contains(instance_id) {
        return Err(Error::denied(
            "The Workload Identity Token subject contains the instance identifier. Do not put the instance Unique Lexicographically Sortable Identifier in the subject. The subject names the presentation, not the instance. The check fails closed.",
        ));
    }
    if identifier.contains('?') || identifier.contains('#') || identifier.contains('@') {
        return Err(Error::denied(
            "The Workload Identity Token subject must not contain a query, a fragment, or user information. The check fails closed.",
        ));
    }
    if identifier.contains("spiffe://") {
        return Err(Error::denied(
            "The Workload Identity Token subject must use the wimse scheme. The instance identifier must not become a distinguished name or a DID. The check fails closed.",
        ));
    }
    if identifier.contains("did:") {
        return Err(Error::denied(
            "The Workload Identity Token subject must not be a DID. The drafts do not define a DID. The check fails closed.",
        ));
    }
    Ok(())
}

fn json_string_field(value: &Value, field_name: &str) -> Result<String> {
    match value.get(field_name) {
        None => Err(Error::denied(format!(
            "The Workload Identity Token is missing {field_name}. The check fails closed."
        ))),
        Some(Value::String(text)) => {
            if text.trim().is_empty() {
                return Err(Error::denied(format!(
                    "The Workload Identity Token {field_name} is empty. The check fails closed."
                )));
            }
            Ok(text.clone())
        }
        Some(other) => Err(Error::denied(format!(
            "The Workload Identity Token {field_name} must be a string. Found {other}. The check fails closed."
        ))),
    }
}

fn json_unix_field(value: &Value, field_name: &str) -> Result<i64> {
    match value.get(field_name) {
        None => Err(Error::denied(format!(
            "The Workload Identity Token is missing {field_name}. The check fails closed."
        ))),
        Some(Value::Number(number)) => number.as_i64().ok_or_else(|| {
            Error::denied(format!(
                "The Workload Identity Token {field_name} is not a valid NumericDate. The check fails closed."
            ))
        }),
        Some(other) => Err(Error::denied(format!(
            "The Workload Identity Token {field_name} must be a number. Found {other}. The check fails closed."
        ))),
    }
}

fn decode_base64url(value: &str, field_name: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value.trim().as_bytes())
        .map_err(|error| {
            Error::denied(format!(
                "The {field_name} value is not valid base64url: {error}. The check fails closed."
            ))
        })
}

fn bytes_32_from_hexadecimal(hexadecimal: &str, field_name: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hexadecimal.trim()).map_err(|error| {
        Error::Crypto(format!(
            "The {field_name} value is not valid hexadecimal: {error}"
        ))
    })?;
    let seed = if bytes.len() == 32 {
        bytes
    } else if bytes.len() == 64 {
        bytes[..32].to_vec()
    } else {
        return Err(Error::Crypto(format!(
            "The {field_name} value must decode to 32 bytes or 64 bytes. Found {} bytes.",
            bytes.len()
        )));
    };
    let mut array = [0u8; 32];
    array.copy_from_slice(&seed);
    Ok(array)
}

#[cfg(test)]
pub(crate) fn emit_illegal_laboratory_wit(
    _presentation_document_bytes: &[u8],
    envelope_secret_hex: &str,
    laboratory_envelope_public_key_hex: &str,
    presented_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    sub: &str,
) -> Result<String> {
    let not_after = require_emit_window(presented_at, expires_at)?;
    sign_workload_identity_token(SignSpec {
        envelope_secret_hex,
        laboratory_envelope_public_key_hex,
        sub,
        presented_at,
        not_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::{HolderProof, Kernel};
    use crate::records::{Capability, Instance};
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    fn laboratory_kernel() -> (tempfile::TempDir, Kernel) {
        let directory = tempdir().expect("create a temporary directory");
        let kernel = Kernel::open(directory.path());
        kernel.initialize().expect("initialize the issuer");
        (directory, kernel)
    }

    fn laboratory_agent_type(kernel: &Kernel) -> crate::records::AgentType {
        kernel
            .add_agent_type(
                "laboratory".to_string(),
                vec!["read".to_string(), "read/limited".to_string()],
                "payments".to_string(),
                3,
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

    fn laboratory_capability(kernel: &Kernel) -> (Instance, Capability) {
        let agent_type = laboratory_agent_type(kernel);
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

    fn envelope_secret(kernel: &Kernel) -> String {
        kernel
            .store()
            .load_biscuit_secret()
            .expect("load the laboratory Ed25519 envelope secret")
    }

    fn envelope_public(kernel: &Kernel) -> String {
        kernel
            .store()
            .load_issuer()
            .expect("load the issuer")
            .biscuit_public_key_hex
    }

    #[test]
    fn a_wimse_wit_and_digest_verify_of_an_honest_present_succeeds() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let artifact = kernel
            .present_wimse(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
            )
            .expect("a live present must emit a Workload Identity Token");
        assert_eq!(
            artifact.wimse_uri,
            bound_wimse_uri(artifact.presentation_json.as_bytes()),
            "the subject must name the present-hash path"
        );
        assert!(
            artifact
                .wimse_uri
                .starts_with("wimse://prometheus.laboratory/present/"),
            "the Uniform Resource Identifier must name the presentation: {}",
            artifact.wimse_uri
        );
        assert!(
            !artifact.wimse_uri.contains(&instance.id),
            "the instance identifier must not appear in the subject"
        );
        assert!(
            !artifact.workload_identity_token.contains(&instance.id),
            "the instance identifier must not appear in the token"
        );
        assert_eq!(
            artifact.content_digest,
            content_digest_sha256(artifact.presentation_json.as_bytes())
        );
        kernel
            .verify_wimse(
                &artifact.workload_identity_token,
                &artifact.content_digest,
                artifact.presentation_json.as_bytes(),
            )
            .expect("an honest laboratory Workload Identity Token and digest must verify");
    }

    #[test]
    fn a_wimse_wit_with_instance_identifier_in_sub_is_refused() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let artifact = kernel
            .present_wimse(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
            )
            .expect("emit a live token");
        let illegal_sub = format!("wimse://prometheus.laboratory/present/{}", instance.id);
        let illegal = emit_illegal_laboratory_wit(
            artifact.presentation_json.as_bytes(),
            &envelope_secret(&kernel),
            &envelope_public(&kernel),
            artifact.presentation.presented_at,
            artifact.presentation.expires_at,
            &illegal_sub,
        )
        .expect("emit a token with a forbidden subject");
        let error = kernel
            .verify_wimse(
                &illegal,
                &artifact.content_digest,
                artifact.presentation_json.as_bytes(),
            )
            .expect_err("a subject that contains the instance identifier must fail closed");
        let text = error.to_string();
        assert!(
            text.contains("instance identifier") || text.contains("subject"),
            "unexpected instance-subject error: {error}"
        );
    }

    #[test]
    fn a_wimse_present_body_that_does_not_match_the_digest_is_refused() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let artifact = kernel
            .present_wimse(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
            )
            .expect("emit a live token");
        let swapped = artifact
            .presentation_json
            .replace("\"intent\": \"read\"", "\"intent\": \"write\"");
        assert_ne!(
            swapped, artifact.presentation_json,
            "the swapped body must differ from the bound present bytes"
        );
        let error = kernel
            .verify_wimse(
                &artifact.workload_identity_token,
                &artifact.content_digest,
                swapped.as_bytes(),
            )
            .expect_err("a present body that does not match Content-Digest must fail closed");
        assert!(
            error.to_string().contains("Content-Digest") || error.to_string().contains("swapped"),
            "unexpected swapped-body error: {error}"
        );
    }

    #[test]
    fn a_wimse_wit_verify_refuses_after_local_kill() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let artifact = kernel
            .present_wimse(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
            )
            .expect("emit a live token");
        kernel
            .verify_wimse(
                &artifact.workload_identity_token,
                &artifact.content_digest,
                artifact.presentation_json.as_bytes(),
            )
            .expect("the live token must verify before local kill");
        assert!(
            Utc::now() < artifact.presentation.expires_at,
            "token expiry must still be in the future at kill time"
        );
        kernel
            .kill_instance(&instance.id)
            .expect("same store must persist local kill");
        let error = kernel
            .verify_wimse(
                &artifact.workload_identity_token,
                &artifact.content_digest,
                artifact.presentation_json.as_bytes(),
            )
            .expect_err(
                "historical Workload Identity Token verify must refuse after same-store kill",
            );
        let text = error.to_string();
        assert!(
            text.contains("local kill") || text.contains("revoked instance"),
            "unexpected same-store-kill WIMSE error: {error}"
        );
        assert!(
            Utc::now() < artifact.presentation.expires_at,
            "token expiry must still be in the future after immediate post-kill verify"
        );
    }

    fn laboratory_digest() -> String {
        content_digest_sha256(b"{\"intent\":\"read\"}\n")
    }

    #[test]
    fn a_wimse_http_message_signature_over_method_and_target_verifies() {
        let (_directory, kernel) = laboratory_kernel();
        let digest = laboratory_digest();
        let (signature_input, signature) = sign_laboratory_wimse_http_message(
            LABORATORY_WIMSE_CHECK_METHOD,
            LABORATORY_WIMSE_CHECK_PATH,
            &digest,
            &envelope_secret(&kernel),
        )
        .expect("sign POST /check-wimse");
        assert!(
            signature_input.contains("content-digest"),
            "Signature-Input must cover content-digest: {signature_input}"
        );
        require_laboratory_wimse_http_message_signature(
            LABORATORY_WIMSE_CHECK_METHOD,
            LABORATORY_WIMSE_CHECK_PATH,
            &digest,
            &signature_input,
            &signature,
            &envelope_public(&kernel),
        )
        .expect("an honest method, request-target, and content-digest signature must verify");
    }

    #[test]
    fn a_wimse_http_message_signature_for_a_different_path_is_refused() {
        let (_directory, kernel) = laboratory_kernel();
        let digest = laboratory_digest();
        let (signature_input, signature) = sign_laboratory_wimse_http_message(
            LABORATORY_WIMSE_CHECK_METHOD,
            "/check-svid",
            &digest,
            &envelope_secret(&kernel),
        )
        .expect("sign a different path");
        let error = require_laboratory_wimse_http_message_signature(
            LABORATORY_WIMSE_CHECK_METHOD,
            LABORATORY_WIMSE_CHECK_PATH,
            &digest,
            &signature_input,
            &signature,
            &envelope_public(&kernel),
        )
        .expect_err("a signature over a different request-target must fail closed");
        let text = error.to_string();
        assert!(
            text.contains("request-target")
                || text.contains("different")
                || text.contains("envelope key"),
            "unexpected different-path signature error: {error}"
        );
    }

    #[test]
    fn a_wimse_http_message_signature_that_omits_content_digest_is_refused() {
        let (_directory, kernel) = laboratory_kernel();
        let digest = laboratory_digest();
        let (signature_input, signature) =
            sign_laboratory_wimse_http_message_omitting_content_digest(
                LABORATORY_WIMSE_CHECK_METHOD,
                LABORATORY_WIMSE_CHECK_PATH,
                &envelope_secret(&kernel),
            )
            .expect("sign without content-digest");
        let error = require_laboratory_wimse_http_message_signature(
            LABORATORY_WIMSE_CHECK_METHOD,
            LABORATORY_WIMSE_CHECK_PATH,
            &digest,
            &signature_input,
            &signature,
            &envelope_public(&kernel),
        )
        .expect_err("a signature that omits content-digest must fail closed");
        assert!(
            error.to_string().contains("content-digest"),
            "unexpected omit-content-digest error: {error}"
        );
    }

    #[test]
    fn a_wimse_http_message_signature_over_a_different_digest_is_refused() {
        let (_directory, kernel) = laboratory_kernel();
        let digest = laboratory_digest();
        let other = content_digest_sha256(b"other-present-bytes");
        assert_ne!(digest, other, "the other digest must differ");
        let (signature_input, signature) = sign_laboratory_wimse_http_message(
            LABORATORY_WIMSE_CHECK_METHOD,
            LABORATORY_WIMSE_CHECK_PATH,
            &other,
            &envelope_secret(&kernel),
        )
        .expect("sign a different digest");
        let error = require_laboratory_wimse_http_message_signature(
            LABORATORY_WIMSE_CHECK_METHOD,
            LABORATORY_WIMSE_CHECK_PATH,
            &digest,
            &signature_input,
            &signature,
            &envelope_public(&kernel),
        )
        .expect_err("a signature over a different digest must fail closed");
        let text = error.to_string();
        assert!(
            text.contains("digest")
                || text.contains("envelope key")
                || text.contains("content-digest"),
            "unexpected different-digest signature error: {error}"
        );
    }

    #[test]
    fn a_wimse_http_message_signature_that_is_missing_is_refused() {
        let error = require_laboratory_wimse_http_message_signature(
            LABORATORY_WIMSE_CHECK_METHOD,
            LABORATORY_WIMSE_CHECK_PATH,
            &laboratory_digest(),
            "",
            "",
            "00",
        )
        .expect_err("a missing HTTP Message Signature must fail closed");
        assert!(
            error.to_string().contains("missing"),
            "unexpected missing-signature error: {error}"
        );
    }
}
