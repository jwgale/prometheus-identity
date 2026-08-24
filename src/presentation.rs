//! Signed presentation document derived from existing instance, capability, and issuer records.
//!
//! This is a signed presentation document. It is not a name.
//! A laboratory X.509-SVID wrap of this document lives in the svid module.
//! That wrap is an artifact. This is not a sixth identity record.
//! The instance identifier must not become a certificate subject.
//! Do not put the instance name in an X.509 distinguished name.
//! This is not a WIMSE token. This is not a Transaction Token.

use crate::error::{Error, Result};
use crate::tokens;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

/// Short laboratory presentation lifetime in seconds.
/// The written `expires_at` is the earlier of this window and the capability expiry.
pub const LABORATORY_PRESENTATION_WINDOW_SECONDS: u64 = 60;

/// Documented signed bytes for a presentation document.
///
/// The signature is Module-Lattice Digital Signature Algorithm over the UTF-8 bytes of this exact concatenation:
///
/// `prometheus-presentation|{instance_id}|{agent_type_id}|{capability_id}|{on_behalf_of}|{intent}|{audience}|{holder_public_key}|{issuer_public_key_hex}|{presented_at}|{expires_at}`
///
/// When laboratory_envelope_public_key_hex is empty, and ancestor_instance_ids and ancestor_capability_ids are both empty, stop here.
/// A historical present with empty ancestor lists and no envelope public key uses this same concatenation.
/// Historical present verify still succeeds.
///
/// When laboratory_envelope_public_key_hex is not empty, append these bytes:
///
/// `|laboratory_envelope_public_key_hex|{hex}`
///
/// When at least one ancestor list is not empty, append these bytes:
///
/// `|ancestor_instance_ids|{id},{id}|ancestor_capability_ids|{id},{id}`
///
/// - `presented_at` and `expires_at` are RFC3339 UTC with seconds precision and a `Z` suffix
/// - The pipe character is literal ASCII 0x7C
/// - Ancestor identifier lists are comma-separated in parent-walk order. Parent is first.
/// - An empty ancestor list is the empty string between the pipes.
/// - The presented instance and the presented capability stay in the existing fields.
/// - Do not copy those identifiers into the ancestor lists.
/// - Ancestor fields are signed. If the ancestor fields are present, they must be in the signature.
/// - The laboratory envelope public key is signed when present. X.509-SVID verify requires that bind.
/// - Soft-fail is forbidden. This is not Online Certificate Status Protocol soft-fail.
///
/// This is not JSON. Check reconstructs these bytes from the fields and never
/// signs the JSON object. Field reorder in the JSON container cannot change
/// the signed bytes. This is the same style as the signed tree head.
pub fn presentation_message(
    instance_id: &str,
    agent_type_id: &str,
    capability_id: &str,
    on_behalf_of: &str,
    intent: &str,
    audience: &str,
    holder_public_key: &str,
    issuer_public_key_hex: &str,
    presented_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    laboratory_envelope_public_key_hex: &str,
    ancestor_instance_ids: &[String],
    ancestor_capability_ids: &[String],
) -> String {
    let mut message = format!(
        "prometheus-presentation|{instance_id}|{agent_type_id}|{capability_id}|{on_behalf_of}|{intent}|{audience}|{holder_public_key}|{issuer_public_key_hex}|{}|{}",
        presented_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        expires_at.to_rfc3339_opts(SecondsFormat::Secs, true)
    );
    let envelope = laboratory_envelope_public_key_hex.trim();
    if !envelope.is_empty() {
        message.push_str("|laboratory_envelope_public_key_hex|");
        message.push_str(envelope);
    }
    if !ancestor_instance_ids.is_empty() || !ancestor_capability_ids.is_empty() {
        message.push_str("|ancestor_instance_ids|");
        message.push_str(&ancestor_instance_ids.join(","));
        message.push_str("|ancestor_capability_ids|");
        message.push_str(&ancestor_capability_ids.join(","));
    }
    message
}

/// Signed presentation document. This is a document, not a name.
/// This is not a sixth identity record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Presentation {
    pub instance_id: String,
    pub agent_type_id: String,
    pub capability_id: String,
    /// Signed ancestor instance identifiers. Walk order: parent first.
    /// Empty for a root present. The presented instance stays in instance_id.
    /// This is not a sixth identity record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ancestor_instance_ids: Vec<String>,
    /// Signed ancestor capability identifiers. Walk order: parent first.
    /// Empty for a root present. The presented capability stays in capability_id.
    /// This is not a sixth identity record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ancestor_capability_ids: Vec<String>,
    pub on_behalf_of: String,
    pub intent: String,
    pub audience: String,
    pub holder_public_key: String,
    pub issuer_public_key_hex: String,
    /// Laboratory Ed25519 envelope public key that issued the X.509-SVID wrap.
    /// This is biscuit_public_key_hex on the issuing store. This is not the identity root.
    /// Empty on historical JSON. Ordinary present-verify still succeeds.
    /// X.509-SVID verify refuses a missing bind.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub laboratory_envelope_public_key_hex: String,
    pub presented_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub signature_hex: String,
    /// Distinct trusted member signatures. Empty when threshold_n is 1.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuer_signatures: Vec<crate::records::IssuerMemberSignature>,
}

impl Presentation {
    pub fn canonical_message(&self) -> String {
        presentation_message(
            &self.instance_id,
            &self.agent_type_id,
            &self.capability_id,
            &self.on_behalf_of,
            &self.intent,
            &self.audience,
            &self.holder_public_key,
            &self.issuer_public_key_hex,
            self.presented_at,
            self.expires_at,
            &self.laboratory_envelope_public_key_hex,
            &self.ancestor_instance_ids,
            &self.ancestor_capability_ids,
        )
    }
}

/// Refuse empty or missing presentation fields after the JSON parses.
pub fn require_presentation_fields(presentation: &Presentation) -> Result<()> {
    for (field_name, value) in [
        ("instance_id", presentation.instance_id.as_str()),
        ("agent_type_id", presentation.agent_type_id.as_str()),
        ("capability_id", presentation.capability_id.as_str()),
        ("on_behalf_of", presentation.on_behalf_of.as_str()),
        ("intent", presentation.intent.as_str()),
        ("audience", presentation.audience.as_str()),
        ("holder_public_key", presentation.holder_public_key.as_str()),
        (
            "issuer_public_key_hex",
            presentation.issuer_public_key_hex.as_str(),
        ),
        ("signature_hex", presentation.signature_hex.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(Error::denied(format!(
                "The presentation is missing {field_name}. The check fails closed."
            )));
        }
    }
    if presentation.expires_at <= presentation.presented_at {
        return Err(Error::denied(
            "The presentation window is empty. expires_at must be after presented_at. The check fails closed.",
        ));
    }
    Ok(())
}

fn require_json_string_field(value: &serde_json::Value, field_name: &str) -> Result<String> {
    match value.get(field_name) {
        None => Err(Error::denied(format!(
            "The presentation is missing {field_name}. The check fails closed."
        ))),
        Some(serde_json::Value::Null) => Err(Error::denied(format!(
            "The presentation {field_name} is empty. The check fails closed."
        ))),
        Some(serde_json::Value::String(text)) => {
            if text.trim().is_empty() {
                return Err(Error::denied(format!(
                    "The presentation {field_name} is empty. The check fails closed."
                )));
            }
            Ok(text.clone())
        }
        Some(other) => Err(Error::denied(format!(
            "The presentation {field_name} must be a string. Found {other}. The check fails closed."
        ))),
    }
}

/// Parse a presentation JSON container. Missing or empty fields fail closed.
/// The JSON is a container only. The signed bytes are the documented concatenation.
pub fn parse_presentation_json(text: &str) -> Result<Presentation> {
    if text.trim().is_empty() {
        return Err(Error::denied(
            "The presentation is empty. The check fails closed.",
        ));
    }
    let value: serde_json::Value = serde_json::from_str(text).map_err(|error| {
        Error::denied(format!(
            "The presentation fields did not parse: {error}. The check fails closed."
        ))
    })?;
    if !value.is_object() {
        return Err(Error::denied(
            "The presentation must be a JSON object. The check fails closed.",
        ));
    }
    for field_name in [
        "instance_id",
        "agent_type_id",
        "capability_id",
        "on_behalf_of",
        "intent",
        "audience",
        "holder_public_key",
        "issuer_public_key_hex",
        "presented_at",
        "expires_at",
        "signature_hex",
    ] {
        require_json_string_field(&value, field_name)?;
    }
    let presentation: Presentation = serde_json::from_value(value).map_err(|error| {
        Error::denied(format!(
            "The presentation fields did not parse: {error}. The check fails closed."
        ))
    })?;
    require_presentation_fields(&presentation)?;
    Ok(presentation)
}

/// Verify the signature against the issuer public key named in the file.
/// This does not consult the accept list. The kernel adds that check.
pub fn verify_presentation_signature(presentation: &Presentation) -> Result<()> {
    require_presentation_fields(presentation)?;
    tokens::verify_decision_receipt_signature(
        presentation.issuer_public_key_hex.trim(),
        &presentation.canonical_message(),
        presentation.signature_hex.trim(),
    )
    .map_err(|error| {
        let text = error.to_string();
        if text.contains("not valid hexadecimal") || text.contains("must decode to 64 bytes") {
            Error::denied(format!(
                "The presentation signature is not valid: {text} The check fails closed."
            ))
        } else if text.contains("not a valid Module-Lattice")
            || text.contains("forged Ed25519-only")
        {
            Error::denied(
                "The presentation issuer public key is not a valid Module-Lattice Digital Signature Algorithm key. The check fails closed."
                    .to_string(),
            )
        } else {
            Error::denied(
                "The presentation signature is not valid for the issuer public key in the file. A tampered presentation fails closed."
                    .to_string(),
            )
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixture_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 19, 7, 51, 0).unwrap()
    }

    #[test]
    fn the_canonical_message_is_the_documented_concatenation() {
        let presented_at = fixture_time();
        let expires_at = presented_at + chrono::Duration::seconds(60);
        let message = presentation_message(
            "instance-one",
            "agent-type-one",
            "capability-one",
            "autonomous",
            "read",
            "payments",
            "holder-public-key",
            "issuer-public-key",
            presented_at,
            expires_at,
            "",
            &[],
            &[],
        );
        assert_eq!(
            message,
            "prometheus-presentation|instance-one|agent-type-one|capability-one|autonomous|read|payments|holder-public-key|issuer-public-key|2026-08-19T07:51:00Z|2026-08-19T07:52:00Z"
        );
    }

    #[test]
    fn an_empty_signature_fails_closed() {
        let presented_at = fixture_time();
        let presentation = Presentation {
            instance_id: "instance-one".to_string(),
            agent_type_id: "agent-type-one".to_string(),
            capability_id: "capability-one".to_string(),
            on_behalf_of: "autonomous".to_string(),
            intent: "read".to_string(),
            audience: "payments".to_string(),
            ancestor_instance_ids: Vec::new(),
            ancestor_capability_ids: Vec::new(),
            holder_public_key: "ab".repeat(32),
            issuer_public_key_hex: "cd".repeat(32),
            laboratory_envelope_public_key_hex: String::new(),
            presented_at,
            expires_at: presented_at + chrono::Duration::seconds(60),
            signature_hex: String::new(),
            issuer_signatures: Vec::new(),
        };
        let error = require_presentation_fields(&presentation)
            .expect_err("an empty signature must fail closed");
        assert!(
            error.to_string().contains("missing signature_hex"),
            "unexpected empty-signature error: {error}"
        );
    }

    #[test]
    fn a_missing_signature_in_json_fails_closed() {
        let error = parse_presentation_json(
            r#"{"instance_id":"i","agent_type_id":"a","capability_id":"c","on_behalf_of":"autonomous","intent":"read","audience":"payments","holder_public_key":"aa","issuer_public_key_hex":"bb","presented_at":"2026-08-19T07:51:00Z","expires_at":"2026-08-19T07:52:00Z"}"#,
        )
        .expect_err("a missing signature must fail closed");
        assert!(
            error.to_string().contains("signature_hex"),
            "unexpected missing-signature error: {error}"
        );
    }

    #[test]
    fn an_empty_presentation_document_fails_closed() {
        let error = parse_presentation_json(" \n").expect_err("an empty document must fail closed");
        assert!(
            error.to_string().contains("empty"),
            "unexpected empty-document error: {error}"
        );
    }

    #[test]
    fn empty_ancestor_lists_keep_the_historical_concatenation() {
        let presented_at = fixture_time();
        let expires_at = presented_at + chrono::Duration::seconds(60);
        let historical = "prometheus-presentation|instance-one|agent-type-one|capability-one|autonomous|read|payments|holder-public-key|issuer-public-key|2026-08-19T07:51:00Z|2026-08-19T07:52:00Z";
        let empty_lists = presentation_message(
            "instance-one",
            "agent-type-one",
            "capability-one",
            "autonomous",
            "read",
            "payments",
            "holder-public-key",
            "issuer-public-key",
            presented_at,
            expires_at,
            "",
            &[],
            &[],
        );
        assert_eq!(empty_lists, historical);
        let presentation = Presentation {
            instance_id: "instance-one".to_string(),
            agent_type_id: "agent-type-one".to_string(),
            capability_id: "capability-one".to_string(),
            ancestor_instance_ids: Vec::new(),
            ancestor_capability_ids: Vec::new(),
            on_behalf_of: "autonomous".to_string(),
            intent: "read".to_string(),
            audience: "payments".to_string(),
            holder_public_key: "holder-public-key".to_string(),
            issuer_public_key_hex: "issuer-public-key".to_string(),
            laboratory_envelope_public_key_hex: String::new(),
            presented_at,
            expires_at,
            signature_hex: "aa".to_string(),
            issuer_signatures: Vec::new(),
        };
        assert_eq!(presentation.canonical_message(), historical);
    }

    #[test]
    fn non_empty_ancestor_lists_append_signed_ancestor_bytes() {
        let presented_at = fixture_time();
        let expires_at = presented_at + chrono::Duration::seconds(60);
        let message = presentation_message(
            "instance-child",
            "agent-type-one",
            "capability-child",
            "autonomous",
            "read",
            "payments",
            "holder-public-key",
            "issuer-public-key",
            presented_at,
            expires_at,
            "",
            &["instance-parent".to_string()],
            &["capability-parent".to_string()],
        );
        assert_eq!(
            message,
            "prometheus-presentation|instance-child|agent-type-one|capability-child|autonomous|read|payments|holder-public-key|issuer-public-key|2026-08-19T07:51:00Z|2026-08-19T07:52:00Z|ancestor_instance_ids|instance-parent|ancestor_capability_ids|capability-parent"
        );
    }

    #[test]
    fn historical_json_without_ancestor_fields_parses_with_empty_lists() {
        let presentation = parse_presentation_json(
            r#"{"instance_id":"i","agent_type_id":"a","capability_id":"c","on_behalf_of":"autonomous","intent":"read","audience":"payments","holder_public_key":"aa","issuer_public_key_hex":"bb","presented_at":"2026-08-19T07:51:00Z","expires_at":"2026-08-19T07:52:00Z","signature_hex":"cc"}"#,
        )
        .expect("historical JSON without ancestor fields must parse");
        assert!(presentation.ancestor_instance_ids.is_empty());
        assert!(presentation.ancestor_capability_ids.is_empty());
        assert!(
            presentation.laboratory_envelope_public_key_hex.is_empty(),
            "historical JSON without the envelope public key must parse with an empty bind"
        );
        assert_eq!(
            presentation.canonical_message(),
            "prometheus-presentation|i|a|c|autonomous|read|payments|aa|bb|2026-08-19T07:51:00Z|2026-08-19T07:52:00Z"
        );
    }

    #[test]
    fn a_non_empty_envelope_public_key_appends_signed_bytes() {
        let presented_at = fixture_time();
        let expires_at = presented_at + chrono::Duration::seconds(60);
        let message = presentation_message(
            "instance-one",
            "agent-type-one",
            "capability-one",
            "autonomous",
            "read",
            "payments",
            "holder-public-key",
            "issuer-public-key",
            presented_at,
            expires_at,
            "envelope-public-key",
            &[],
            &[],
        );
        assert_eq!(
            message,
            "prometheus-presentation|instance-one|agent-type-one|capability-one|autonomous|read|payments|holder-public-key|issuer-public-key|2026-08-19T07:51:00Z|2026-08-19T07:52:00Z|laboratory_envelope_public_key_hex|envelope-public-key"
        );
        let with_ancestors = presentation_message(
            "instance-child",
            "agent-type-one",
            "capability-child",
            "autonomous",
            "read",
            "payments",
            "holder-public-key",
            "issuer-public-key",
            presented_at,
            expires_at,
            "envelope-public-key",
            &["instance-parent".to_string()],
            &["capability-parent".to_string()],
        );
        assert_eq!(
            with_ancestors,
            "prometheus-presentation|instance-child|agent-type-one|capability-child|autonomous|read|payments|holder-public-key|issuer-public-key|2026-08-19T07:51:00Z|2026-08-19T07:52:00Z|laboratory_envelope_public_key_hex|envelope-public-key|ancestor_instance_ids|instance-parent|ancestor_capability_ids|capability-parent"
        );
    }
}
