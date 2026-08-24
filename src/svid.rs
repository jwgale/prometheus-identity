//! Laboratory X.509-SVID wrap of a signed presentation document.
//!
//! This wrap is an artifact. This wrap is not a sixth identity record.
//! Present stays a document. X.509 is presentation, not the inode.
//!
//! The Uniform Resource Identifier subject alternative name is the only identity.
//! The subject distinguished name is omitted. The subject alternative name is
//! marked critical (RFC 5280 section 4.1.2.6).
//!
//! URI = `spiffe://prometheus.laboratory/present/<sha256hex of the present document bytes>`.
//! A relying party hashes the bytes it was shown and requires that path.
//! The instance ULID stays inside the present JSON only.
//! Remint on every re-present.
//!
//! NotAfter is the earlier of presentation expires_at and now plus
//! laboratory_svid_lifetime. This bounds a missed kill for a relying party
//! that only checks expiry. This is not kill. Short life is not kill.
//! Verify still calls existing present-verify, including accepted kill lists,
//! local instance status, local kill log, and signed ancestor refuse.
//! Death on the issuing store refuses a historical wrap after local kill.
//! Soft-fail is forbidden.
//!
//! The certificate is signed with the laboratory Ed25519 envelope key
//! (the Biscuit envelope key on the issuer record). The signed present carries
//! that envelope public key. A foreign verifier binds the wrap to that signed
//! field. Module-Lattice Digital Signature Algorithm in X.509 is not used tonight.
//! The identity root stays Module-Lattice Digital Signature Algorithm. This is
//! not a classical-only issuer root. This is not SPIRE. This is not a SPIRE
//! Workload API. This is not WIMSE. This is not SPIRE issue 3341
//! x500UniqueIdentifier-as-identity.
//!
//! Refuse: instance ULID in CN or URI path; SPIFFE ID copied into DN;
//! identity from DN, DNS, or serial; a second URI SAN.

use crate::error::{Error, Result};
use crate::presentation::Presentation;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rcgen::{CertificateParams, CustomExtension, DistinguishedName, DnType, IsCa, KeyPair};
use sha2::{Digest, Sha256};
use x509_parser::extensions::GeneralName;
use x509_parser::pem::parse_x509_pem;

/// Trust domain for the laboratory wrap. This is not a global name system.
pub const LABORATORY_SPIFFE_TRUST_DOMAIN: &str = "prometheus.laboratory";

/// Path prefix that names a presentation document, not an instance.
pub const LABORATORY_PRESENT_SPIFFE_PATH_PREFIX: &str = "/present/";

/// Laboratory X.509-SVID lifetime in seconds.
/// This bounds a missed kill for a relying party that only checks expiry.
/// This is not kill.
pub const LABORATORY_SVID_LIFETIME_SECONDS: u64 = 300;

/// Cap X.509-SVID NotAfter to the earlier of presentation expires_at and now
/// plus laboratory_svid_lifetime. NotAfter must never exceed presentation expires_at.
pub fn laboratory_svid_not_after(
    presentation_expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> DateTime<Utc> {
    presentation_expires_at.min(now + Duration::seconds(LABORATORY_SVID_LIFETIME_SECONDS as i64))
}

/// Documented bound Uniform Resource Identifier for the wrap.
pub fn bound_spiffe_uri(presentation_document_bytes: &[u8]) -> String {
    format!(
        "spiffe://{LABORATORY_SPIFFE_TRUST_DOMAIN}{LABORATORY_PRESENT_SPIFFE_PATH_PREFIX}{}",
        presentation_document_sha256_hex(presentation_document_bytes)
    )
}

/// SHA-256 hexadecimal of the present document bytes that were shown.
pub fn presentation_document_sha256_hex(presentation_document_bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(presentation_document_bytes))
}

/// Laboratory wrap artifact. This is not a sixth identity record.
#[derive(Debug, Clone)]
pub struct X509SvidArtifact {
    pub presentation: Presentation,
    /// Exact present document bytes that were hashed into the Uniform Resource Identifier.
    pub presentation_json: String,
    pub certificate_pem: String,
    pub spiffe_uri: String,
}

/// Emit a laboratory X.509-SVID wrap. Subject distinguished name is omitted.
/// Exactly one critical Uniform Resource Identifier subject alternative name.
pub fn emit_laboratory_x509_svid(
    presentation_document_bytes: &[u8],
    envelope_secret_hex: &str,
    presented_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<String> {
    if expires_at <= presented_at {
        return Err(Error::denied(
            "The presentation window is empty. NotAfter must be after presented_at. Short life is not kill. The check fails closed.",
        ));
    }
    let not_after = laboratory_svid_not_after(expires_at, presented_at);
    if not_after > expires_at {
        return Err(Error::denied(
            "The X.509-SVID NotAfter is after the presentation expires_at. Short life is not kill. NotAfter must be the presentation expires_at or earlier. The check fails closed.",
        ));
    }
    if not_after <= presented_at {
        return Err(Error::denied(
            "The X.509-SVID window is empty. NotAfter must be after presented_at. Short life is not kill. The check fails closed.",
        ));
    }
    let uri = bound_spiffe_uri(presentation_document_bytes);
    emit_certificate_pem(EmitSpec {
        envelope_secret_hex,
        presented_at,
        not_after,
        uris: vec![uri],
        common_name: None,
        mark_san_critical: true,
    })
}

/// Parse the wrap, refuse a forbidden distinguished name or Uniform Resource Identifier,
/// check NotAfter, check the envelope signature, then stop. The kernel adds present-verify.
/// The subject public key must equal `laboratory_envelope_public_key_hex`.
/// That value is the laboratory Ed25519 envelope public key from the signed present.
/// A resigned wrap fails closed.
pub fn require_laboratory_x509_svid(
    certificate_pem: &str,
    presentation_document_bytes: &[u8],
    presentation: &Presentation,
    now: DateTime<Utc>,
    laboratory_envelope_public_key_hex: &str,
) -> Result<()> {
    if certificate_pem.trim().is_empty() {
        return Err(Error::denied(
            "The X.509-SVID is empty. The check fails closed.",
        ));
    }
    let (remainder, pem) = parse_x509_pem(certificate_pem.as_bytes()).map_err(|error| {
        Error::denied(format!(
            "The X.509-SVID PEM did not parse: {error}. The check fails closed."
        ))
    })?;
    if remainder.iter().any(|byte| !byte.is_ascii_whitespace()) {
        return Err(Error::denied(
            "The X.509-SVID PEM has extra data after the certificate. The check fails closed.",
        ));
    }
    if pem.label != "CERTIFICATE" {
        return Err(Error::denied(
            "The X.509-SVID PEM must be a CERTIFICATE block. The check fails closed.",
        ));
    }
    let certificate = pem.parse_x509().map_err(|error| {
        Error::denied(format!(
            "The X.509-SVID certificate did not parse: {error}. The check fails closed."
        ))
    })?;

    refuse_subject_distinguished_name(&certificate, &presentation.instance_id)?;
    let uri = require_exactly_one_critical_uri_san(&certificate)?;
    require_bound_spiffe_uri(&uri, presentation_document_bytes, &presentation.instance_id)?;
    require_not_after_not_past_expiry(&certificate, presentation, now)?;
    require_ed25519_self_signature(&certificate)?;
    require_laboratory_envelope_public_key(&certificate, laboratory_envelope_public_key_hex)?;
    Ok(())
}

struct EmitSpec<'a> {
    envelope_secret_hex: &'a str,
    presented_at: DateTime<Utc>,
    not_after: DateTime<Utc>,
    uris: Vec<String>,
    common_name: Option<String>,
    mark_san_critical: bool,
}

fn emit_certificate_pem(spec: EmitSpec<'_>) -> Result<String> {
    let key_pair = envelope_key_pair(spec.envelope_secret_hex)?;
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    if let Some(common_name) = spec.common_name {
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
    }
    params.subject_alt_names.clear();
    params.is_ca = IsCa::NoCa;
    params.key_usages.clear();
    params.extended_key_usages.clear();
    params.use_authority_key_identifier_extension = false;
    params.not_before = offset_date_time(spec.presented_at, "presented_at")?;
    params.not_after = offset_date_time(spec.not_after, "NotAfter")?;
    let uri_refs: Vec<&str> = spec.uris.iter().map(String::as_str).collect();
    let mut san = CustomExtension::from_oid_content(
        &[2, 5, 29, 17],
        encode_uri_san_extension_content(&uri_refs)?,
    );
    san.set_criticality(spec.mark_san_critical);
    params.custom_extensions.push(san);
    let certificate = params.self_signed(&key_pair).map_err(|error| {
        Error::denied(format!(
            "The laboratory X.509-SVID wrap could not be signed with the laboratory Ed25519 envelope key: {error}. Module-Lattice Digital Signature Algorithm in X.509 is not used tonight. The identity root stays Module-Lattice Digital Signature Algorithm. The check fails closed."
        ))
    })?;
    Ok(certificate.pem())
}

fn envelope_key_pair(envelope_secret_hex: &str) -> Result<KeyPair> {
    let seed =
        bytes_32_from_hexadecimal(envelope_secret_hex, "laboratory Ed25519 envelope secret")?;
    let pkcs8 = encode_ed25519_pkcs8_from_seed(&seed);
    KeyPair::try_from(pkcs8.as_slice()).map_err(|error| {
        Error::denied(format!(
            "The laboratory Ed25519 envelope secret is not a valid envelope key for the X.509-SVID wrap: {error}. The check fails closed."
        ))
    })
}

fn encode_ed25519_pkcs8_from_seed(seed: &[u8; 32]) -> Vec<u8> {
    let mut pkcs8 = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    pkcs8.extend_from_slice(seed);
    pkcs8
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

fn offset_date_time(instant: DateTime<Utc>, field_name: &str) -> Result<time::OffsetDateTime> {
    time::OffsetDateTime::from_unix_timestamp(instant.timestamp()).map_err(|error| {
        Error::denied(format!(
            "The {field_name} value is not a valid certificate time: {error}. The check fails closed."
        ))
    })
}

fn encode_uri_san_extension_content(uris: &[&str]) -> Result<Vec<u8>> {
    if uris.is_empty() {
        return Err(Error::denied(
            "The X.509-SVID must have exactly one Uniform Resource Identifier subject alternative name. The check fails closed.",
        ));
    }
    let mut names = Vec::new();
    for uri in uris {
        if !uri.is_ascii() {
            return Err(Error::denied(
                "The Uniform Resource Identifier subject alternative name must be ASCII. The check fails closed.",
            ));
        }
        names.push(0x86);
        write_der_length(&mut names, uri.len());
        names.extend_from_slice(uri.as_bytes());
    }
    let mut sequence = Vec::new();
    sequence.push(0x30);
    write_der_length(&mut sequence, names.len());
    sequence.extend(names);
    Ok(sequence)
}

fn write_der_length(output: &mut Vec<u8>, length: usize) {
    if length < 0x80 {
        output.push(length as u8);
        return;
    }
    let bytes = length.to_be_bytes();
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let significant = &bytes[start..];
    output.push(0x80 | significant.len() as u8);
    output.extend_from_slice(significant);
}

fn refuse_subject_distinguished_name(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
    instance_id: &str,
) -> Result<()> {
    let mut saw_attribute = false;
    for attribute in certificate.subject().iter_attributes() {
        saw_attribute = true;
        let value = attribute.as_str().unwrap_or("").to_string();
        let raw = String::from_utf8_lossy(attribute.attr_value().data);
        let combined = format!("{value}{raw}");
        if !instance_id.trim().is_empty()
            && (value.contains(instance_id) || raw.contains(instance_id))
        {
            return Err(Error::denied(
                "The X.509-SVID distinguished name contains the instance identifier. The instance identifier must not appear in CN, O, OU, or any distinguished name relative distinguished name. URI SAN is the only identity. The check fails closed.",
            ));
        }
        if combined.contains("spiffe://") {
            return Err(Error::denied(
                "The X.509-SVID distinguished name contains a SPIFFE identifier. Do not copy the SPIFFE identifier into the distinguished name. URI SAN is the only identity. The check fails closed.",
            ));
        }
    }
    if saw_attribute {
        return Err(Error::denied(
            "The X.509-SVID subject distinguished name must be omitted. URI SAN is the only identity. Identity from the distinguished name is refused. The check fails closed.",
        ));
    }
    Ok(())
}

fn require_exactly_one_critical_uri_san(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<String> {
    let extension = certificate
        .subject_alternative_name()
        .map_err(|error| {
            Error::denied(format!(
                "The X.509-SVID subject alternative name did not parse: {error}. The check fails closed."
            ))
        })?
        .ok_or_else(|| {
            Error::denied(
                "The X.509-SVID has no subject alternative name. URI SAN is the only identity. The check fails closed.",
            )
        })?;
    if !extension.critical {
        return Err(Error::denied(
            "The Uniform Resource Identifier subject alternative name must be marked critical because the subject distinguished name is omitted (RFC 5280 section 4.1.2.6). The check fails closed.",
        ));
    }
    let mut uri: Option<String> = None;
    let mut uri_count = 0usize;
    for name in &extension.value.general_names {
        match name {
            GeneralName::URI(value) => {
                uri_count += 1;
                if uri_count > 1 {
                    return Err(Error::denied(
                        "The X.509-SVID has a second Uniform Resource Identifier subject alternative name. Validators refuse a second URI SAN. URI SAN is the only identity. The check fails closed.",
                    ));
                }
                uri = Some((*value).to_string());
            }
            GeneralName::DNSName(_) => {
                return Err(Error::denied(
                    "The X.509-SVID has a DNS subject alternative name. Identity from DNS is refused. URI SAN is the only identity. The check fails closed.",
                ));
            }
            other => {
                return Err(Error::denied(format!(
                    "The X.509-SVID has a non-URI subject alternative name ({other}). Identity from DNS, serial, or distinguished name is refused. URI SAN is the only identity. The check fails closed."
                )));
            }
        }
    }
    if uri_count != 1 {
        return Err(Error::denied(
            "The X.509-SVID must have exactly one Uniform Resource Identifier subject alternative name. The check fails closed.",
        ));
    }
    uri.ok_or_else(|| {
        Error::denied(
            "The X.509-SVID must have exactly one Uniform Resource Identifier subject alternative name. The check fails closed.",
        )
    })
}

fn require_bound_spiffe_uri(
    uri: &str,
    presentation_document_bytes: &[u8],
    instance_id: &str,
) -> Result<()> {
    if uri.contains(instance_id) && !instance_id.trim().is_empty() {
        return Err(Error::denied(
            "The Uniform Resource Identifier path contains the instance identifier. Do not put the instance ULID in the SPIFFE identifier path as if it were a username. This Uniform Resource Identifier names the presentation, not the instance. The check fails closed.",
        ));
    }
    let expected = bound_spiffe_uri(presentation_document_bytes);
    if uri != expected {
        return Err(Error::denied(
            "The Uniform Resource Identifier subject alternative name is not the bound presentation Uniform Resource Identifier. The relying party hashes the present document bytes it was shown and requires that path. The scheme must be spiffe. The path must be a non-root /present/<sha256hex> path. The check fails closed.",
        ));
    }
    if !uri.starts_with("spiffe://") {
        return Err(Error::denied(
            "The Uniform Resource Identifier scheme must be spiffe. The check fails closed.",
        ));
    }
    Ok(())
}

fn require_not_after_not_past_expiry(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
    presentation: &Presentation,
    now: DateTime<Utc>,
) -> Result<()> {
    let not_after_timestamp = certificate.validity().not_after.timestamp();
    let not_after = DateTime::<Utc>::from_timestamp(not_after_timestamp, 0).ok_or_else(|| {
        Error::denied("The X.509-SVID NotAfter value is not a valid time. The check fails closed.")
    })?;
    if not_after > presentation.expires_at {
        return Err(Error::denied(
            "The X.509-SVID NotAfter is after the presentation expires_at. Short life is not kill. NotAfter must be the presentation expires_at or earlier. The check fails closed.",
        ));
    }
    if now >= not_after {
        return Err(Error::denied(
            "The X.509-SVID wrap has expired. Now is at or after NotAfter. Short life is not kill. The check fails closed.",
        ));
    }
    Ok(())
}

fn require_ed25519_self_signature(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<()> {
    let algorithm = certificate.signature_algorithm.algorithm.to_id_string();
    if algorithm != "1.3.101.112" {
        return Err(Error::denied(format!(
            "The X.509-SVID signature algorithm must be Ed25519. Found {algorithm}. The certificate is signed with the laboratory Ed25519 envelope key. Module-Lattice Digital Signature Algorithm in X.509 is not used tonight. The identity root stays Module-Lattice Digital Signature Algorithm. The check fails closed."
        )));
    }
    let public_key = certificate.public_key().subject_public_key.data.as_ref();
    let public_array: [u8; 32] = public_key.try_into().map_err(|_| {
        Error::denied(
            "The X.509-SVID subject public key must be a 32-byte Ed25519 key. The check fails closed.",
        )
    })?;
    let signature_bytes = certificate.signature_value.data.as_ref();
    let signature_array: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        Error::denied("The X.509-SVID signature must decode to 64 bytes. The check fails closed.")
    })?;
    let verifying_key = VerifyingKey::from_bytes(&public_array).map_err(|error| {
        Error::denied(format!(
            "The X.509-SVID subject public key is not a valid Ed25519 key: {error}. The check fails closed."
        ))
    })?;
    let signature = Signature::from_bytes(&signature_array);
    verifying_key
        .verify(certificate.tbs_certificate.as_ref(), &signature)
        .map_err(|_| {
            Error::denied(
                "The X.509-SVID signature is not valid for the laboratory Ed25519 envelope key. The check fails closed.",
            )
        })?;
    Ok(())
}

fn require_laboratory_envelope_public_key(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
    laboratory_envelope_public_key_hex: &str,
) -> Result<()> {
    let expected = laboratory_envelope_public_key_hex.trim();
    if expected.is_empty() {
        return Err(Error::denied(
            "The laboratory Ed25519 envelope public key is empty. The check fails closed.",
        ));
    }
    let public_key = certificate.public_key().subject_public_key.data.as_ref();
    let found = hex::encode(public_key);
    if !found.eq_ignore_ascii_case(expected) {
        return Err(Error::denied(
            "The X.509-SVID subject public key does not match the laboratory Ed25519 envelope public key in the signed present. A resigned wrap fails closed. The check fails closed.",
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn emit_illegal_laboratory_x509_svid(
    envelope_secret_hex: &str,
    presented_at: DateTime<Utc>,
    not_after: DateTime<Utc>,
    uris: Vec<String>,
    common_name: Option<String>,
) -> Result<String> {
    emit_certificate_pem(EmitSpec {
        envelope_secret_hex,
        presented_at,
        not_after,
        uris,
        common_name,
        mark_san_critical: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::{HolderProof, Kernel};
    use crate::records::{Capability, Instance};
    use chrono::Duration;
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

    fn first_issuer_public_key(kernel: &Kernel) -> String {
        kernel
            .store()
            .load_issuer()
            .expect("load the issuer")
            .current_public_key_hex()
    }

    #[test]
    fn emit_and_verify_succeeds_for_a_live_present() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let artifact = kernel
            .present_x509_svid(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
            )
            .expect("a live present must emit an X.509-SVID wrap");
        assert!(
            artifact
                .spiffe_uri
                .starts_with("spiffe://prometheus.laboratory/present/"),
            "the Uniform Resource Identifier must name the presentation: {}",
            artifact.spiffe_uri
        );
        assert!(
            !artifact.spiffe_uri.contains(&instance.id),
            "the instance identifier must not appear in the Uniform Resource Identifier"
        );
        assert!(
            !artifact.certificate_pem.contains(&instance.id),
            "the instance identifier must not appear in the certificate PEM"
        );
        kernel
            .verify_x509_svid(
                &artifact.certificate_pem,
                artifact.presentation_json.as_bytes(),
            )
            .expect("a live laboratory X.509-SVID wrap must verify");
    }

    #[test]
    fn a_distinguished_name_that_contains_the_instance_id_is_refused() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let artifact = kernel
            .present_x509_svid(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
            )
            .expect("emit a live wrap");
        let illegal = emit_illegal_laboratory_x509_svid(
            &envelope_secret(&kernel),
            artifact.presentation.presented_at,
            artifact.presentation.expires_at,
            vec![artifact.spiffe_uri.clone()],
            Some(instance.id.clone()),
        )
        .expect("emit a wrap with a forbidden distinguished name");
        let error = kernel
            .verify_x509_svid(&illegal, artifact.presentation_json.as_bytes())
            .expect_err(
                "a distinguished name that contains the instance identifier must fail closed",
            );
        let text = error.to_string();
        assert!(
            text.contains("instance identifier") || text.contains("distinguished name"),
            "unexpected distinguished-name error: {error}"
        );
    }

    #[test]
    fn a_uri_san_that_uses_the_instance_id_as_the_spiffe_path_is_refused() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let artifact = kernel
            .present_x509_svid(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
            )
            .expect("emit a live wrap");
        let illegal_uri = format!("spiffe://prometheus.laboratory/{}", instance.id);
        let illegal = emit_illegal_laboratory_x509_svid(
            &envelope_secret(&kernel),
            artifact.presentation.presented_at,
            artifact.presentation.expires_at,
            vec![illegal_uri],
            None,
        )
        .expect("emit a wrap with a forbidden Uniform Resource Identifier");
        let error = kernel
            .verify_x509_svid(&illegal, artifact.presentation_json.as_bytes())
            .expect_err("a Uniform Resource Identifier that uses the instance identifier as the path must fail closed");
        let text = error.to_string();
        assert!(
            text.contains("instance identifier")
                || text.contains("username")
                || text.contains("path"),
            "unexpected instance-path error: {error}"
        );
    }

    #[test]
    fn a_second_uri_san_is_refused() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let artifact = kernel
            .present_x509_svid(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
            )
            .expect("emit a live wrap");
        let illegal = emit_illegal_laboratory_x509_svid(
            &envelope_secret(&kernel),
            artifact.presentation.presented_at,
            artifact.presentation.expires_at,
            vec![
                artifact.spiffe_uri.clone(),
                format!("spiffe://prometheus.laboratory/{}", instance.id),
            ],
            None,
        )
        .expect("emit a wrap with a second Uniform Resource Identifier");
        let error = kernel
            .verify_x509_svid(&illegal, artifact.presentation_json.as_bytes())
            .expect_err(
                "a second Uniform Resource Identifier subject alternative name must fail closed",
            );
        assert!(
            error
                .to_string()
                .contains("second Uniform Resource Identifier"),
            "unexpected second-URI error: {error}"
        );
    }

    #[test]
    fn after_kill_accept_on_store_b_svid_verify_of_a_parent_or_child_present_refuses() {
        let (first_directory, first) = laboratory_kernel();
        let (parent, parent_capability) = laboratory_capability(&first);
        let parent_nonce = fresh_challenge(&first, &parent);
        let child = first
            .spawn_child(
                &parent.id,
                &parent_capability.id,
                "child".to_string(),
                BTreeMap::new(),
                "read",
                "payments/prod",
                None,
                Some(&holder_proof(&first, &parent)),
                Some(&parent_nonce),
            )
            .expect("a narrower child must succeed");
        let parent_artifact = first
            .present_x509_svid(
                &parent.id,
                &parent_capability.id,
                Some(&holder_proof(&first, &parent)),
                Some(&fresh_challenge(&first, &parent)),
            )
            .expect("emit a parent wrap");
        let child_artifact = first
            .present_x509_svid(
                &child.instance.id,
                &child.capability.id,
                Some(&holder_proof(&first, &child.instance)),
                Some(&fresh_challenge(&first, &child.instance)),
            )
            .expect("emit a child wrap");
        first
            .kill_instance(&parent.id)
            .expect("store A must persist parent kill");
        let kill_directory = first_directory.path().join("parent-kill-bundle");
        first
            .export_kill_bundle(Some(&parent.id), None, &kill_directory)
            .expect("export the parent kill bundle");
        let (_second_directory, second) = laboratory_kernel();
        second
            .accept_issuer_public_key(&first_issuer_public_key(&first))
            .expect("store B must accept the first public key");
        second
            .accept_kill_bundle(&kill_directory)
            .expect("store B must accept the parent kill bundle");
        let parent_error = second
            .verify_x509_svid(
                &parent_artifact.certificate_pem,
                parent_artifact.presentation_json.as_bytes(),
            )
            .expect_err("parent SVID verify must refuse after kill accept");
        assert!(
            parent_error.to_string().contains("kill accept"),
            "unexpected parent SVID-after-kill-accept error: {parent_error}"
        );
        let child_error = second
            .verify_x509_svid(
                &child_artifact.certificate_pem,
                child_artifact.presentation_json.as_bytes(),
            )
            .expect_err("child SVID verify must refuse after kill accept");
        assert!(
            child_error.to_string().contains("kill accept"),
            "unexpected child SVID-after-kill-accept error: {child_error}"
        );
    }

    #[test]
    fn expired_presentation_or_not_after_past_expires_at_refuses() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        let (instance, capability) = laboratory_capability(&kernel);
        let artifact = kernel
            .present_x509_svid(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
            )
            .expect("emit a live wrap");
        kernel
            .verify_x509_svid(
                &artifact.certificate_pem,
                artifact.presentation_json.as_bytes(),
            )
            .expect("a wrap inside its window must verify");
        let late_not_after = artifact.presentation.expires_at + Duration::seconds(30);
        let late = emit_illegal_laboratory_x509_svid(
            &envelope_secret(&kernel),
            artifact.presentation.presented_at,
            late_not_after,
            vec![artifact.spiffe_uri.clone()],
            None,
        )
        .expect("emit a wrap whose NotAfter is after expires_at");
        let late_error = kernel
            .verify_x509_svid(&late, artifact.presentation_json.as_bytes())
            .expect_err("NotAfter after expires_at must fail closed");
        assert!(
            late_error.to_string().contains("NotAfter")
                || late_error.to_string().contains("expires_at"),
            "unexpected late-NotAfter error: {late_error}"
        );
        kernel.set_now_for_test(artifact.presentation.expires_at);
        let expired_error = kernel
            .verify_x509_svid(
                &artifact.certificate_pem,
                artifact.presentation_json.as_bytes(),
            )
            .expect_err("an expired presentation wrap must fail closed");
        assert!(
            expired_error.to_string().contains("expired"),
            "unexpected expired-wrap error: {expired_error}"
        );
    }

    #[test]
    fn historical_present_json_path_still_works() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let nonce = fresh_challenge(&kernel, &instance);
        let presentation = kernel
            .present_capability(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&nonce),
            )
            .expect("write a historical presentation");
        let json = serde_json::to_string(&presentation).expect("serialize historical JSON");
        assert!(
            !json.contains("ancestor_instance_ids"),
            "empty ancestor lists must skip-if-empty so historical JSON stays the same"
        );
        let parsed = crate::presentation::parse_presentation_json(&json)
            .expect("historical JSON without ancestor fields must parse");
        kernel
            .verify_presentation(&parsed)
            .expect("the historical present JSON path must still verify");
    }

    fn certificate_not_after(pem: &str) -> DateTime<Utc> {
        let (_remainder, parsed) = parse_x509_pem(pem.as_bytes()).expect("parse PEM");
        let certificate = parsed.parse_x509().expect("parse certificate");
        DateTime::<Utc>::from_timestamp(certificate.validity().not_after.timestamp(), 0)
            .expect("NotAfter")
    }

    #[test]
    fn emit_caps_not_after_to_laboratory_lifetime_when_capability_lifetime_is_3600s() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        let (instance, capability) = laboratory_capability(&kernel);
        assert_eq!(
            capability.expires.timestamp() - instance.born.timestamp(),
            3600,
            "this lock uses a one-hour capability lifetime"
        );
        let presented_at = DateTime::<Utc>::from_timestamp(start.timestamp(), 0).unwrap();
        let pem = emit_laboratory_x509_svid(
            b"laboratory-present-document",
            &envelope_secret(&kernel),
            presented_at,
            capability.expires,
        )
        .expect("emit a wrap against a one-hour capability expiry");
        let not_after = certificate_not_after(&pem);
        let laboratory_bound =
            presented_at + Duration::seconds(LABORATORY_SVID_LIFETIME_SECONDS as i64);
        assert!(
            not_after <= laboratory_bound,
            "NotAfter must be at or before now plus 300 seconds: {not_after} > {laboratory_bound}"
        );
        assert!(
            not_after <= capability.expires,
            "NotAfter must never exceed presentation expires_at"
        );
        assert_eq!(
            not_after, laboratory_bound,
            "a one-hour capability must take the 300 second laboratory bound"
        );
    }

    #[test]
    fn emit_uses_the_60s_presentation_expiry_when_that_window_is_the_minimum() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        let (instance, capability) = laboratory_capability(&kernel);
        let artifact = kernel
            .present_x509_svid(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
            )
            .expect("a 60 second presentation must emit an X.509-SVID wrap");
        let not_after = certificate_not_after(&artifact.certificate_pem);
        assert_eq!(
            not_after, artifact.presentation.expires_at,
            "when presentation expires in 60 seconds, NotAfter is that 60 seconds"
        );
        assert_eq!(
            (artifact.presentation.expires_at - artifact.presentation.presented_at).num_seconds(),
            60
        );
        assert!(
            not_after
                <= artifact.presentation.presented_at
                    + Duration::seconds(LABORATORY_SVID_LIFETIME_SECONDS as i64)
        );
    }

    #[test]
    fn verify_refuses_when_now_is_past_not_after_even_if_presentation_expires_at_is_later() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        let (instance, capability) = laboratory_capability(&kernel);
        let artifact = kernel
            .present_x509_svid(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
            )
            .expect("emit a live wrap");
        let short_not_after = artifact.presentation.presented_at + Duration::seconds(30);
        assert!(
            short_not_after < artifact.presentation.expires_at,
            "this case needs presentation expires_at still later than NotAfter"
        );
        let short = emit_illegal_laboratory_x509_svid(
            &envelope_secret(&kernel),
            artifact.presentation.presented_at,
            short_not_after,
            vec![artifact.spiffe_uri.clone()],
            None,
        )
        .expect("emit a wrap whose NotAfter is before presentation expires_at");
        kernel.set_now_for_test(short_not_after);
        let error = kernel
            .verify_x509_svid(&short, artifact.presentation_json.as_bytes())
            .expect_err(
                "now at NotAfter must fail closed even when presentation expires_at is later",
            );
        let text = error.to_string();
        assert!(
            text.contains("expired") || text.contains("NotAfter"),
            "unexpected X.509-expiry error: {error}"
        );
        assert!(
            !text.contains("kill accept"),
            "this refuse is X.509 expiry, not kill accept: {error}"
        );
    }

    #[test]
    fn remint_on_every_present_produces_a_new_uri_hash() {
        let (_directory, kernel) = laboratory_kernel();
        let start = Utc::now();
        kernel.set_now_for_test(start);
        let (instance, capability) = laboratory_capability(&kernel);
        let first = kernel
            .present_x509_svid(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
            )
            .expect("emit the first wrap");
        kernel.set_now_for_test(start + Duration::seconds(1));
        let second = kernel
            .present_x509_svid(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
            )
            .expect("remint a second wrap");
        assert_ne!(
            first.spiffe_uri, second.spiffe_uri,
            "remint on every present must hash the new document bytes"
        );
    }

    #[test]
    fn same_store_kill_refuses_historical_svid_verify() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let artifact = kernel
            .present_x509_svid(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
            )
            .expect("emit a live wrap");
        kernel
            .verify_x509_svid(
                &artifact.certificate_pem,
                artifact.presentation_json.as_bytes(),
            )
            .expect("the live wrap must verify before local kill");
        assert!(
            Utc::now() < artifact.presentation.expires_at,
            "NotAfter must still be in the future at kill time"
        );
        kernel
            .kill_instance(&instance.id)
            .expect("same store must persist local kill");
        let error = kernel
            .verify_x509_svid(
                &artifact.certificate_pem,
                artifact.presentation_json.as_bytes(),
            )
            .expect_err("historical SVID verify must refuse after same-store kill");
        let text = error.to_string();
        assert!(
            text.contains("local kill") || text.contains("revoked instance"),
            "unexpected same-store-kill SVID error: {error}"
        );
        assert!(
            Utc::now() < artifact.presentation.expires_at,
            "NotAfter must still be in the future after immediate post-kill verify"
        );
    }

    #[test]
    fn a_pem_resigned_with_a_foreign_envelope_key_is_refused() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let artifact = kernel
            .present_x509_svid(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
            )
            .expect("emit a live wrap");
        kernel
            .verify_x509_svid(
                &artifact.certificate_pem,
                artifact.presentation_json.as_bytes(),
            )
            .expect("the live wrap signed with the laboratory envelope key must verify");
        let foreign = crate::tokens::generate_keypair();
        let foreign_secret = crate::tokens::private_key_hexadecimal(&foreign);
        let resigned = emit_illegal_laboratory_x509_svid(
            &foreign_secret,
            artifact.presentation.presented_at,
            artifact.presentation.expires_at,
            vec![artifact.spiffe_uri.clone()],
            None,
        )
        .expect("emit a wrap signed with a foreign envelope key");
        let error = kernel
            .verify_x509_svid(&resigned, artifact.presentation_json.as_bytes())
            .expect_err("a PEM resigned with a foreign envelope key must fail closed");
        let text = error.to_string();
        assert!(
            text.contains("envelope key") || text.contains("resigned"),
            "unexpected resigned-wrap error: {error}"
        );
    }

    #[test]
    fn store_b_refuses_a_pem_resigned_with_a_foreign_envelope_key() {
        let (_first_directory, first) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&first);
        let artifact = first
            .present_x509_svid(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&first, &instance)),
                Some(&fresh_challenge(&first, &instance)),
            )
            .expect("store A must emit an X.509-SVID wrap");
        let first_issuer = first.store().load_issuer().expect("load store A issuer");
        let (_second_directory, second) = laboratory_kernel();
        let second_issuer = second.store().load_issuer().expect("load store B issuer");
        assert_ne!(
            first_issuer.current_public_key_hex(),
            second_issuer.current_public_key_hex(),
            "store B must have its own Module-Lattice identity root"
        );
        assert_ne!(
            first_issuer.biscuit_public_key_hex, second_issuer.biscuit_public_key_hex,
            "store B must not hold store A laboratory envelope public key as its own envelope key"
        );
        second
            .accept_issuer_public_key(&first_issuer_public_key(&first))
            .expect("store B must accept store A issuer public key only");
        second
            .verify_x509_svid(
                &artifact.certificate_pem,
                artifact.presentation_json.as_bytes(),
            )
            .expect("the honest wrap must verify on store B after issuer accept");
        let foreign = crate::tokens::generate_keypair();
        let foreign_secret = crate::tokens::private_key_hexadecimal(&foreign);
        let resigned = emit_illegal_laboratory_x509_svid(
            &foreign_secret,
            artifact.presentation.presented_at,
            artifact.presentation.expires_at,
            vec![artifact.spiffe_uri.clone()],
            None,
        )
        .expect("emit a wrap signed with a foreign envelope key");
        let error = second
            .verify_x509_svid(&resigned, artifact.presentation_json.as_bytes())
            .expect_err("a PEM resigned with a foreign envelope key must fail closed on store B");
        let text = error.to_string();
        assert!(
            text.contains("envelope public key") && text.contains("does not match"),
            "store B must name the envelope key mismatch: {error}"
        );
        assert!(
            !text.contains("kill"),
            "this refuse is envelope key mismatch, not kill: {error}"
        );
    }

    #[test]
    fn x509_svid_verify_refuses_a_historical_present_without_the_signed_envelope_key() {
        let (_directory, kernel) = laboratory_kernel();
        let (instance, capability) = laboratory_capability(&kernel);
        let artifact = kernel
            .present_x509_svid(
                &instance.id,
                &capability.id,
                Some(&holder_proof(&kernel, &instance)),
                Some(&fresh_challenge(&kernel, &instance)),
            )
            .expect("emit a live wrap");
        let issuer_secret = kernel
            .store()
            .load_secret()
            .expect("load this store issuer secret for a historical-style re-sign");
        let mut historical = artifact.presentation.clone();
        historical.laboratory_envelope_public_key_hex.clear();
        historical.signature_hex =
            crate::tokens::sign_decision_receipt(&issuer_secret, &historical.canonical_message())
                .expect("sign historical present bytes without the envelope field");
        kernel.verify_presentation(&historical).expect(
            "ordinary present-verify of JSON without the envelope field must still succeed",
        );
        let historical_json =
            serde_json::to_string(&historical).expect("serialize historical present JSON");
        assert!(
            !historical_json.contains("laboratory_envelope_public_key_hex"),
            "empty envelope public key must skip-if-empty so historical JSON stays the same"
        );
        let error = kernel
            .verify_x509_svid(&artifact.certificate_pem, historical_json.as_bytes())
            .expect_err("X.509-SVID verify must refuse a missing envelope-key bind");
        let text = error.to_string();
        assert!(
            text.contains("envelope public key") || text.contains("bind"),
            "missing bind must fail closed: {error}"
        );
        assert!(
            !text.contains("kill"),
            "this refuse is a missing envelope-key bind, not kill: {error}"
        );
    }
}
