//! Laboratory helpers for capability tokens.
//! This package uses the biscuit-auth library (the Biscuit capability token format).
//! A production root key must not use only classical cryptography.
//! This file is a laboratory envelope.

use crate::error::{Error, Result};
use crate::records::{
    agent_type_issuer_signature_message, capability_issuer_signature_message,
    chain_issuer_signature_message, instance_issuer_signature_message, is_narrower_or_equal,
    AgentType, Capability, Chain, Instance, Issuer,
};
use biscuit_auth::builder_ext::{AuthorizerExt, BuilderExt};
use biscuit_auth::macros::{authorizer, biscuit, block};
use biscuit_auth::{
    Algorithm, AuthorizerBuilder, AuthorizerLimits, Biscuit, KeyPair, PrivateKey, PublicKey,
};
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::time::{Duration, SystemTime};

/// Laboratory Datalog budget for the Biscuit envelope.
/// biscuit-auth default max_time is one millisecond. Parallel Module-Lattice
/// work can deschedule a thread for longer than that. An honest token must not
/// fail closed as a Datalog timeout. Fact and iteration caps stay.
fn laboratory_authorizer_limits() -> AuthorizerLimits {
    AuthorizerLimits {
        max_facts: 1000,
        max_iterations: 100,
        max_time: Duration::from_secs(1),
    }
}

pub fn generate_keypair() -> KeyPair {
    KeyPair::new()
}

pub fn keypair_from_private_hexadecimal(hexadecimal: &str) -> Result<KeyPair> {
    let private_key = PrivateKey::from_bytes_hex(hexadecimal, Algorithm::Ed25519)
        .map_err(|error| Error::Crypto(error.to_string()))?;
    Ok(KeyPair::from(&private_key))
}

pub fn public_key_from_hexadecimal(hexadecimal: &str) -> Result<PublicKey> {
    PublicKey::from_bytes_hex(hexadecimal, Algorithm::Ed25519)
        .map_err(|error| Error::Crypto(error.to_string()))
}

pub fn public_key_hexadecimal(key_pair: &KeyPair) -> String {
    key_pair.public().to_bytes_hex()
}

pub fn private_key_hexadecimal(key_pair: &KeyPair) -> String {
    key_pair.private().to_bytes_hex()
}

/// Return true when the secret derives the given public key.
pub fn public_key_matches_secret(
    public_key_hexadecimal_value: &str,
    private_key_hexadecimal_value: &str,
) -> Result<bool> {
    let key_pair = keypair_from_private_hexadecimal(private_key_hexadecimal_value)?;
    Ok(public_key_hexadecimal(&key_pair) == public_key_hexadecimal_value)
}

/// One-time holder challenge string. The nonce and the time window bind the proof.
/// This is not a production proof of possession. The static laboratory challenge is removed.
pub fn holder_challenge_message(
    nonce: &str,
    instance_id: &str,
    issued: DateTime<Utc>,
    expires: DateTime<Utc>,
) -> String {
    format!(
        "prometheus-holder-challenge|{nonce}|{instance_id}|{}|{}",
        issued.to_rfc3339_opts(SecondsFormat::Secs, true),
        expires.to_rfc3339_opts(SecondsFormat::Secs, true)
    )
}

/// Signed bytes for a verifier-host holder challenge. The nonce is process memory.
/// This is an artifact. This is not an instance record. This is not a sixth identity record.
pub fn verifier_challenge_message(nonce: &str) -> String {
    format!("prometheus-verifier-challenge|{nonce}")
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

/// Sign the laboratory holder challenge with the holder secret. This is not a production proof of possession.
pub fn sign_holder_challenge(private_key_hexadecimal_value: &str, message: &str) -> Result<String> {
    let seed = bytes_32_from_hexadecimal(private_key_hexadecimal_value, "holder secret")?;
    let signing_key = SigningKey::from_bytes(&seed);
    let signature = signing_key.sign(message.as_bytes());
    Ok(hex::encode(signature.to_bytes()))
}

/// Verify a laboratory holder signature against the instance holder public key.
pub fn verify_holder_signature(
    public_key_hexadecimal_value: &str,
    message: &str,
    signature_hexadecimal: &str,
) -> Result<()> {
    let public_bytes =
        bytes_32_from_hexadecimal(public_key_hexadecimal_value, "holder public key")?;
    let verifying_key = VerifyingKey::from_bytes(&public_bytes).map_err(|error| {
        Error::Crypto(format!(
            "The holder public key is not a valid Ed25519 key: {error}"
        ))
    })?;
    let signature_bytes = hex::decode(signature_hexadecimal.trim()).map_err(|error| {
        Error::denied(format!(
            "The holder signature is not valid hexadecimal: {error}"
        ))
    })?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| Error::denied("The holder signature must decode to 64 bytes."))?;
    let signature = Signature::from_bytes(&signature_array);
    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| Error::denied("The holder signature is not valid for this instance."))
}

/// Documented signed bytes for a decision receipt.
///
/// The signature is Module-Lattice Digital Signature Algorithm over the UTF-8 bytes of this exact concatenation:
///
/// `prometheus-decision-receipt|{instance_id}|{capability_id}|{intent}|{audience}|{on_behalf_of}|{result}|{reason}|{challenge_nonce}|{issued}|{issuance_log_line}`
///
/// When ancestor_instance_ids and ancestor_capability_ids are both empty, stop here.
/// A historical receipt with empty ancestor lists uses this same concatenation.
/// Historical receipt verify still succeeds. Old act bundles still succeed.
///
/// When at least one ancestor list is not empty, append these bytes:
///
/// `|ancestor_instance_ids|{id},{id}|ancestor_capability_ids|{id},{id}`
///
/// - `issued` is RFC3339 UTC with seconds precision and a `Z` suffix
/// - The pipe character is literal ASCII 0x7C
/// - Ancestor identifier lists are comma-separated in parent-walk order. Parent is first.
/// - An empty ancestor list is the empty string between the pipes.
/// - The receipt instance and the receipt capability stay in the existing fields.
/// - Do not copy those identifiers into the ancestor lists.
/// - Ancestor fields are signed. If the ancestor fields are present, they must be in the signature.
/// - Soft-fail is forbidden. This is not Online Certificate Status Protocol soft-fail.
///
/// This is not JSON. Check reconstructs these bytes from the fields and never
/// signs the JSON object. Field reorder in the JSON container cannot change
/// the signed bytes. This is the same style as the signed presentation.
pub fn decision_receipt_message(
    instance_id: &str,
    capability_id: &str,
    intent: &str,
    audience: &str,
    on_behalf_of: &str,
    result: &str,
    reason: &str,
    challenge_nonce: &str,
    issued: DateTime<Utc>,
    issuance_log_line: &str,
    ancestor_instance_ids: &[String],
    ancestor_capability_ids: &[String],
) -> String {
    let mut message = format!(
        "prometheus-decision-receipt|{instance_id}|{capability_id}|{intent}|{audience}|{on_behalf_of}|{result}|{reason}|{challenge_nonce}|{}|{issuance_log_line}",
        issued.to_rfc3339_opts(SecondsFormat::Secs, true)
    );
    if !ancestor_instance_ids.is_empty() || !ancestor_capability_ids.is_empty() {
        message.push_str("|ancestor_instance_ids|");
        message.push_str(&ancestor_instance_ids.join(","));
        message.push_str("|ancestor_capability_ids|");
        message.push_str(&ancestor_capability_ids.join(","));
    }
    message
}

/// Sign a decision receipt with the issuer Module-Lattice secret.
/// This is a laboratory Module-Lattice Digital Signature Algorithm signature.
/// This is not a production FIPS module. The Biscuit envelope key must not be used here.
pub fn sign_decision_receipt(private_key_hexadecimal_value: &str, message: &str) -> Result<String> {
    crate::issuer_crypto::sign_with_module_lattice_secret(private_key_hexadecimal_value, message)
}

/// Verify a decision receipt signature against the issuer Module-Lattice public key.
pub fn verify_decision_receipt_signature(
    public_key_hexadecimal_value: &str,
    message: &str,
    signature_hexadecimal: &str,
) -> Result<()> {
    crate::issuer_crypto::verify_module_lattice_signature(
        public_key_hexadecimal_value,
        message,
        signature_hexadecimal,
    )
}

/// Return the accepted issuer public key that verifies this receipt signature.
/// An unknown key fails closed. This is an accept list. This is not a global name system.
pub fn matching_accepted_issuer_public_key(
    accepted_issuer_public_keys: &[String],
    message: &str,
    signature_hexadecimal: &str,
) -> Result<String> {
    if accepted_issuer_public_keys.is_empty() {
        return Err(Error::denied(
            "The issuer accept list is empty. The receipt check fails closed.",
        ));
    }
    let mut saw_valid_key = false;
    for public_key in accepted_issuer_public_keys {
        let trimmed = public_key.trim();
        if trimmed.is_empty() {
            continue;
        }
        saw_valid_key = true;
        if verify_decision_receipt_signature(trimmed, message, signature_hexadecimal).is_ok() {
            return Ok(trimmed.to_string());
        }
    }
    if !saw_valid_key {
        return Err(Error::denied(
            "The issuer accept list has no usable public key. The receipt check fails closed.",
        ));
    }
    Err(Error::denied(
        "The decision receipt signature is not valid for any accepted issuer public key. An unknown issuer key is refused. The check fails closed.",
    ))
}

/// Verify a decision receipt signature against the store accept list.
/// The signature must match one accepted issuer public key. An unknown key fails closed.
/// This is an accept list. This is not a global name system. This is not SPIFFE federation.
pub fn verify_decision_receipt_signature_against_accepted_keys(
    accepted_issuer_public_keys: &[String],
    message: &str,
    signature_hexadecimal: &str,
) -> Result<()> {
    matching_accepted_issuer_public_key(accepted_issuer_public_keys, message, signature_hexadecimal)
        .map(|_| ())
}

/// True when `public_key_hex` is this store current key, an additional member on
/// public_keys, or a previous key still before kill_date.
/// The Biscuit envelope key is never a threshold member.
/// A previous key past kill_date cannot sign a trusted record. A foreign accept-list key cannot
/// mint a local instance, capability, or agent type record. This is not allow-all.
pub fn issuer_key_trusted_for_record_signature(
    issuer: &Issuer,
    public_key_hex: &str,
    now: DateTime<Utc>,
) -> bool {
    let trimmed = public_key_hex.trim();
    if trimmed.is_empty() {
        return false;
    }
    if issuer.is_biscuit_envelope_key(trimmed) {
        return false;
    }
    if trimmed == issuer.current_public_key_hex() {
        return true;
    }
    if issuer.public_keys.iter().any(|key| key.trim() == trimmed)
        && !issuer.is_previous_issuer_key_past_kill_date(trimmed, now)
    {
        return true;
    }
    issuer
        .previous_issuer_keys
        .iter()
        .any(|previous| previous.public_key_hex.trim() == trimmed && now < previous.kill_date)
}

fn require_record_issuer_signature(
    issuer: &Issuer,
    now: DateTime<Utc>,
    public_key_hex: &str,
    signature_hex: &str,
    issuer_signatures: &[crate::records::IssuerMemberSignature],
    message: &str,
    record_name: &str,
) -> Result<()> {
    let trusted_keys = crate::threshold::trusted_keys_for_record_threshold(issuer, now);
    crate::threshold::require_threshold_signatures(
        issuer_signatures,
        public_key_hex,
        signature_hex,
        message,
        &trusted_keys,
        &issuer.biscuit_public_key_hex,
        issuer.threshold_n,
        record_name,
    )
}

/// Verify the laboratory issuer signature on an instance record.
/// Missing, wrong, or untrusted signatures fail closed. Recompute from the in-memory fields.
pub fn require_trusted_instance_issuer_signature(
    instance: &Instance,
    issuer: &Issuer,
    now: DateTime<Utc>,
) -> Result<()> {
    require_record_issuer_signature(
        issuer,
        now,
        &instance.issuer_public_key_hex,
        &instance.issuer_signature_hex,
        &instance.issuer_signatures,
        &instance_issuer_signature_message(instance),
        "instance",
    )
}

/// Verify the laboratory issuer signature on a capability record.
/// Missing, wrong, or untrusted signatures fail closed. Recompute from the in-memory fields.
pub fn require_trusted_capability_issuer_signature(
    capability: &Capability,
    issuer: &Issuer,
    now: DateTime<Utc>,
) -> Result<()> {
    require_record_issuer_signature(
        issuer,
        now,
        &capability.issuer_public_key_hex,
        &capability.issuer_signature_hex,
        &capability.issuer_signatures,
        &capability_issuer_signature_message(capability),
        "capability",
    )
}

/// Verify the laboratory issuer signature on an agent type record.
/// Missing, wrong, or untrusted signatures fail closed. Recompute from the in-memory fields.
pub fn require_trusted_agent_type_issuer_signature(
    agent_type: &AgentType,
    issuer: &Issuer,
    now: DateTime<Utc>,
) -> Result<()> {
    require_record_issuer_signature(
        issuer,
        now,
        &agent_type.issuer_public_key_hex,
        &agent_type.issuer_signature_hex,
        &agent_type.issuer_signatures,
        &agent_type_issuer_signature_message(agent_type),
        "agent type",
    )
}

/// Verify the laboratory issuer signature on a chain record.
/// Missing, wrong, or untrusted signatures fail closed. Recompute from the in-memory fields.
pub fn require_trusted_chain_issuer_signature(
    chain: &Chain,
    issuer: &Issuer,
    now: DateTime<Utc>,
) -> Result<()> {
    require_record_issuer_signature(
        issuer,
        now,
        &chain.issuer_public_key_hex,
        &chain.issuer_signature_hex,
        &chain.issuer_signatures,
        &chain_issuer_signature_message(chain),
        "chain",
    )
}

/// Return the first issuer public key that can parse this capability token.
/// After rotate, an old token still parses with a previous public key.
pub fn first_public_key_that_parses_token(
    public_key_hexadecimal_values: &[String],
    token_bytes: &[u8],
) -> Result<PublicKey> {
    let mut saw_valid_key = false;
    let mut last_error = None;
    for hexadecimal in public_key_hexadecimal_values {
        let trimmed = hexadecimal.trim();
        if trimmed.is_empty() {
            continue;
        }
        let public_key = match public_key_from_hexadecimal(trimmed) {
            Ok(key) => {
                saw_valid_key = true;
                key
            }
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        match Biscuit::from(token_bytes, public_key) {
            Ok(_) => return Ok(public_key),
            Err(error) => last_error = Some(Error::Biscuit(error.to_string())),
        }
    }
    if !saw_valid_key {
        return Err(Error::denied(
            "No usable issuer public key could parse this capability token. The check fails closed.",
        ));
    }
    Err(last_error.unwrap_or_else(|| {
        Error::denied(
            "The capability token did not match the current issuer key or any previous issuer key. The check fails closed.",
        )
    }))
}

fn last_revoke_identifier_hexadecimal(token: &Biscuit) -> String {
    token
        .revocation_identifiers()
        .last()
        .map(hex::encode)
        .unwrap_or_default()
}

pub fn mint_token(
    root: &KeyPair,
    capability_id: &str,
    instance_id: &str,
    intent: &str,
    audience: &str,
    on_behalf_of: &str,
    expires: SystemTime,
) -> Result<(Vec<u8>, String)> {
    let token = biscuit!(
        r#"
        capability({capability_id});
        instance({instance_id});
        intent({intent});
        audience_prefix({audience});
        on_behalf_of({on_behalf_of});
        check if requested_intent($i), $i.starts_with({intent});
        check if requested_audience($a), $a.starts_with({audience});
        check if requested_on_behalf_of($authority), on_behalf_of($authority);
        "#
    )
    .check_expiration_date(expires)
    .build(root)
    .map_err(|error| Error::Biscuit(error.to_string()))?;

    let bytes = token
        .to_vec()
        .map_err(|error| Error::Biscuit(error.to_string()))?;
    Ok((bytes, last_revoke_identifier_hexadecimal(&token)))
}

pub fn attenuate_token(
    root_public_key: PublicKey,
    parent_bytes: &[u8],
    new_audience: &str,
    new_intent: Option<&str>,
    expires: SystemTime,
) -> Result<(Vec<u8>, String)> {
    let parent = Biscuit::from(parent_bytes, root_public_key)
        .map_err(|error| Error::Biscuit(error.to_string()))?;
    let token = if let Some(new_intent) = new_intent {
        parent
            .append(
                block!(
                    r#"
                    check if requested_intent($i), $i.starts_with({new_intent});
                    check if requested_audience($a), $a.starts_with({new_audience});
                    "#
                )
                .check_expiration_date(expires),
            )
            .map_err(|error| Error::Biscuit(error.to_string()))?
    } else {
        parent
            .append(
                block!(
                    r#"
                    check if requested_audience($a), $a.starts_with({new_audience});
                    "#
                )
                .check_expiration_date(expires),
            )
            .map_err(|error| Error::Biscuit(error.to_string()))?
    };
    let bytes = token
        .to_vec()
        .map_err(|error| Error::Biscuit(error.to_string()))?;
    Ok((bytes, last_revoke_identifier_hexadecimal(&token)))
}

pub fn authorize_token(
    root_public_key: PublicKey,
    token_bytes: &[u8],
    intent: &str,
    audience: &str,
    on_behalf_of: &str,
) -> Result<()> {
    let token = Biscuit::from(token_bytes, root_public_key)
        .map_err(|error| Error::Biscuit(error.to_string()))?;
    let mut authorizer = authorizer!(
        r#"
        requested_intent({intent});
        requested_audience({audience});
        requested_on_behalf_of({on_behalf_of});
        "#
    )
    .time()
    .allow_all()
    .set_limits(laboratory_authorizer_limits())
    .build(&token)
    .map_err(|error| Error::Biscuit(error.to_string()))?;
    authorizer
        .authorize()
        .map_err(|error| Error::Denied(error.to_string()))?;
    Ok(())
}

/// Capability-token facts read from the authority block after the signature check.
/// The store record is the source for identity fields. The token must not exceed or contradict it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenFacts {
    pub instance_id: String,
    pub intent: String,
    pub audience: String,
    pub on_behalf_of: String,
}

fn query_one_string_fact(
    authorizer: &mut biscuit_auth::Authorizer,
    rule: &str,
    fact_name: &str,
) -> Result<String> {
    let (value,): (String,) = authorizer.query_exactly_one(rule).map_err(|error| {
        Error::denied(format!(
            "The capability token must contain exactly one {fact_name} fact. A missing or repeated fact fails closed. {error}"
        ))
    })?;
    if value.is_empty() {
        return Err(Error::denied(format!(
            "The capability token {fact_name} fact is empty. The check fails closed."
        )));
    }
    Ok(value)
}

/// Read intent, audience, on_behalf_of, and instance facts from a signed capability token.
/// This reuses the biscuit-auth authorizer query path. A missing fact fails closed.
pub fn extract_token_facts(root_public_key: PublicKey, token_bytes: &[u8]) -> Result<TokenFacts> {
    let token = Biscuit::from(token_bytes, root_public_key)
        .map_err(|error| Error::Biscuit(error.to_string()))?;
    let mut authorizer = AuthorizerBuilder::new()
        .set_limits(laboratory_authorizer_limits())
        .build(&token)
        .map_err(|error| {
            Error::denied(format!(
                "The capability token facts could not be read. The check fails closed. {error}"
            ))
        })?;
    Ok(TokenFacts {
        instance_id: query_one_string_fact(
            &mut authorizer,
            r#"data($value) <- instance($value)"#,
            "instance",
        )?,
        intent: query_one_string_fact(
            &mut authorizer,
            r#"data($value) <- intent($value)"#,
            "intent",
        )?,
        audience: query_one_string_fact(
            &mut authorizer,
            r#"data($value) <- audience_prefix($value)"#,
            "audience",
        )?,
        on_behalf_of: query_one_string_fact(
            &mut authorizer,
            r#"data($value) <- on_behalf_of($value)"#,
            "on_behalf_of",
        )?,
    })
}

fn token_effectively_grants(
    root_public_key: PublicKey,
    token_bytes: &[u8],
    intent: &str,
    audience: &str,
    on_behalf_of: &str,
) -> bool {
    authorize_token(root_public_key, token_bytes, intent, audience, on_behalf_of).is_ok()
}

/// After the token signature check, refuse a token that exceeds or contradicts the capability record.
///
/// The store record is the source for identity fields. This is not a new record type.
///
/// - `instance_id` and `on_behalf_of` must match the record exactly.
/// - Intent and audience use `is_narrower_or_equal`, the same helper mint, spawn, and
///   authorization_limit use. A token fact that is not within the record is a claimed exceed.
/// - Attenuation keeps the parent authority facts and adds narrower checks. A claimed exceed
///   is refused only when the token still authorizes at that wider fact. That is the smaller
///   fail-closed lock: an honest attenuated child still verifies.
pub fn require_token_facts_agree_with_record(
    root_public_key: PublicKey,
    token_bytes: &[u8],
    instance_id: &str,
    intent: &str,
    audience: &str,
    on_behalf_of: &str,
) -> Result<TokenFacts> {
    let facts = extract_token_facts(root_public_key, token_bytes)?;
    if facts.instance_id != instance_id {
        return Err(Error::denied(format!(
            "The capability token instance identifier '{}' does not match the capability record '{instance_id}'. The store record is the source for identity fields. A token that contradicts the record is a golden-ticket-class lie. The check fails closed.",
            facts.instance_id
        )));
    }
    if facts.on_behalf_of != on_behalf_of {
        return Err(Error::denied(format!(
            "The capability token on_behalf_of '{}' does not match the capability record '{on_behalf_of}'. The store record is the source for identity fields. A token that contradicts the record is a golden-ticket-class lie. The check fails closed.",
            facts.on_behalf_of
        )));
    }
    if !is_narrower_or_equal(&facts.intent, intent) {
        let grants_claimed = token_effectively_grants(
            root_public_key,
            token_bytes,
            &facts.intent,
            audience,
            on_behalf_of,
        ) || token_effectively_grants(
            root_public_key,
            token_bytes,
            &facts.intent,
            &facts.audience,
            on_behalf_of,
        );
        if grants_claimed {
            return Err(Error::denied(format!(
                "The capability token intent '{}' is wider than the capability record '{intent}'. The store record is the source for identity fields. A token that exceeds the record is a golden-ticket-class lie. The check fails closed.",
                facts.intent
            )));
        }
    }
    if !is_narrower_or_equal(&facts.audience, audience) {
        let grants_claimed = token_effectively_grants(
            root_public_key,
            token_bytes,
            intent,
            &facts.audience,
            on_behalf_of,
        ) || token_effectively_grants(
            root_public_key,
            token_bytes,
            &facts.intent,
            &facts.audience,
            on_behalf_of,
        );
        if grants_claimed {
            return Err(Error::denied(format!(
                "The capability token audience '{}' is wider than the capability record '{audience}'. The store record is the source for identity fields. A token that exceeds the record is a golden-ticket-class lie. The check fails closed.",
                facts.audience
            )));
        }
    }
    Ok(facts)
}

pub fn revocation_identifier_list(
    root_public_key: PublicKey,
    token_bytes: &[u8],
) -> Result<Vec<String>> {
    let token = Biscuit::from(token_bytes, root_public_key)
        .map_err(|error| Error::Biscuit(error.to_string()))?;
    Ok(token
        .revocation_identifiers()
        .into_iter()
        .map(hex::encode)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::time::{Duration, SystemTime};

    #[test]
    fn the_capability_token_refuses_a_wrong_act_authority() {
        let root = generate_keypair();
        let expires = SystemTime::now() + Duration::from_secs(3600);
        let (bytes, _revoke) = mint_token(
            &root,
            "capability-one",
            "instance-one",
            "read",
            "internal",
            "autonomous",
            expires,
        )
        .expect("mint a capability token");
        authorize_token(root.public(), &bytes, "read", "internal", "autonomous")
            .expect("the matching act authority must pass");
        let error = authorize_token(root.public(), &bytes, "read", "internal", "jordan")
            .expect_err("a wrong act authority must fail at the token");
        let error_text = error.to_string();
        assert!(
            error_text.contains("verification failed") || error_text.contains("check"),
            "unexpected error: {error_text}"
        );
        let empty = authorize_token(root.public(), &bytes, "read", "internal", "")
            .expect_err("an empty act authority must fail at the token");
        let empty_text = empty.to_string();
        assert!(
            empty_text.contains("verification failed") || empty_text.contains("check"),
            "unexpected error: {empty_text}"
        );
    }

    #[test]
    fn extract_token_facts_reads_the_authority_facts() {
        let root = generate_keypair();
        let expires = SystemTime::now() + Duration::from_secs(3600);
        let (bytes, _revoke) = mint_token(
            &root,
            "capability-one",
            "instance-one",
            "read",
            "internal",
            "autonomous",
            expires,
        )
        .expect("mint a capability token");
        let facts = extract_token_facts(root.public(), &bytes).expect("read the token facts");
        assert_eq!(facts.instance_id, "instance-one");
        assert_eq!(facts.intent, "read");
        assert_eq!(facts.audience, "internal");
        assert_eq!(facts.on_behalf_of, "autonomous");
        require_token_facts_agree_with_record(
            root.public(),
            &bytes,
            "instance-one",
            "read",
            "internal",
            "autonomous",
        )
        .expect("matching facts must agree with the record");
    }

    #[test]
    fn a_token_with_a_wider_audience_fact_is_refused_at_the_evaluate_boundary() {
        let root = generate_keypair();
        let expires = SystemTime::now() + Duration::from_secs(3600);
        let (wide_bytes, _revoke) = mint_token(
            &root,
            "capability-wide",
            "instance-one",
            "read",
            "payments",
            "autonomous",
            expires,
        )
        .expect("mint a wider capability token");
        let error = require_token_facts_agree_with_record(
            root.public(),
            &wide_bytes,
            "instance-one",
            "read",
            "payments/prod",
            "autonomous",
        )
        .expect_err("a token wider than the record must fail closed");
        let error_text = error.to_string();
        assert!(
            error_text.contains("wider than the capability record"),
            "unexpected error: {error_text}"
        );
    }

    #[test]
    fn a_token_with_a_wider_intent_fact_is_refused_at_the_evaluate_boundary() {
        let root = generate_keypair();
        let expires = SystemTime::now() + Duration::from_secs(3600);
        let (wide_bytes, _revoke) = mint_token(
            &root,
            "capability-wide",
            "instance-one",
            "read",
            "payments",
            "autonomous",
            expires,
        )
        .expect("mint a wider capability token");
        let error = require_token_facts_agree_with_record(
            root.public(),
            &wide_bytes,
            "instance-one",
            "read/limited",
            "payments",
            "autonomous",
        )
        .expect_err("a token wider than the record must fail closed");
        let error_text = error.to_string();
        assert!(
            error_text.contains("wider than the capability record"),
            "unexpected error: {error_text}"
        );
    }

    #[test]
    fn a_token_with_a_different_act_authority_is_refused_at_the_evaluate_boundary() {
        let root = generate_keypair();
        let expires = SystemTime::now() + Duration::from_secs(3600);
        let (bytes, _revoke) = mint_token(
            &root,
            "capability-one",
            "instance-one",
            "read",
            "internal",
            "jordan",
            expires,
        )
        .expect("mint a capability token");
        let error = require_token_facts_agree_with_record(
            root.public(),
            &bytes,
            "instance-one",
            "read",
            "internal",
            "autonomous",
        )
        .expect_err("a different on_behalf_of must fail closed");
        let error_text = error.to_string();
        assert!(
            error_text.contains("does not match the capability record"),
            "unexpected error: {error_text}"
        );
    }

    #[test]
    fn a_token_with_a_different_instance_identifier_is_refused_at_the_evaluate_boundary() {
        let root = generate_keypair();
        let expires = SystemTime::now() + Duration::from_secs(3600);
        let (bytes, _revoke) = mint_token(
            &root,
            "capability-one",
            "instance-two",
            "read",
            "internal",
            "autonomous",
            expires,
        )
        .expect("mint a capability token");
        let error = require_token_facts_agree_with_record(
            root.public(),
            &bytes,
            "instance-one",
            "read",
            "internal",
            "autonomous",
        )
        .expect_err("a different instance identifier must fail closed");
        let error_text = error.to_string();
        assert!(
            error_text.contains("instance identifier"),
            "unexpected error: {error_text}"
        );
    }

    #[test]
    fn an_attenuated_token_still_agrees_when_checks_constrain_the_parent_facts() {
        let root = generate_keypair();
        let expires = SystemTime::now() + Duration::from_secs(3600);
        let (parent_bytes, _revoke) = mint_token(
            &root,
            "capability-parent",
            "instance-one",
            "read",
            "payments",
            "autonomous",
            expires,
        )
        .expect("mint a parent capability token");
        let (child_bytes, _revoke) = attenuate_token(
            root.public(),
            &parent_bytes,
            "payments/prod",
            Some("read/limited"),
            expires,
        )
        .expect("attenuate to a child path");
        require_token_facts_agree_with_record(
            root.public(),
            &child_bytes,
            "instance-one",
            "read/limited",
            "payments/prod",
            "autonomous",
        )
        .expect("an honest attenuated child must still agree with the narrower record");
    }

    #[test]
    fn laboratory_authorizer_limits_raise_the_one_millisecond_clock() {
        let limits = laboratory_authorizer_limits();
        let biscuit_default = AuthorizerLimits::default();
        assert_eq!(limits.max_facts, biscuit_default.max_facts);
        assert_eq!(limits.max_iterations, biscuit_default.max_iterations);
        assert_eq!(
            biscuit_default.max_time,
            Duration::from_millis(1),
            "this lock tracks the biscuit-auth default of one millisecond"
        );
        assert!(
            limits.max_time >= Duration::from_millis(250),
            "the laboratory envelope must not use the biscuit-auth default of one millisecond. Parallel Module-Lattice work can deschedule a thread for more than one millisecond. An honest token must not fail closed as a Datalog timeout."
        );
    }

    #[test]
    fn an_honest_token_still_reads_four_facts_on_one_authorizer() {
        let root = generate_keypair();
        let expires = SystemTime::now() + Duration::from_secs(3600);
        let (bytes, _revoke) = mint_token(
            &root,
            "capability-one",
            "instance-one",
            "read",
            "internal",
            "autonomous",
            expires,
        )
        .expect("mint a capability token");
        for _ in 0..32 {
            let facts = extract_token_facts(root.public(), &bytes)
                .expect("an honest token must still yield exactly one fact per name");
            assert_eq!(facts.instance_id, "instance-one");
            assert_eq!(facts.intent, "read");
            assert_eq!(facts.audience, "internal");
            assert_eq!(facts.on_behalf_of, "autonomous");
            authorize_token(root.public(), &bytes, "read", "internal", "autonomous")
                .expect("an honest token must still authorize");
        }
    }

    #[test]
    fn empty_receipt_ancestor_lists_keep_the_historical_concatenation() {
        let issued = Utc.with_ymd_and_hms(2026, 8, 19, 7, 51, 0).unwrap();
        let historical = "prometheus-decision-receipt|instance-one|capability-one|read|payments|autonomous|allowed||nonce-one|2026-08-19T07:51:00Z|log-line";
        let empty_lists = decision_receipt_message(
            "instance-one",
            "capability-one",
            "read",
            "payments",
            "autonomous",
            "allowed",
            "",
            "nonce-one",
            issued,
            "log-line",
            &[],
            &[],
        );
        assert_eq!(empty_lists, historical);
    }

    #[test]
    fn non_empty_receipt_ancestor_lists_append_signed_ancestor_bytes() {
        let issued = Utc.with_ymd_and_hms(2026, 8, 19, 7, 51, 0).unwrap();
        let message = decision_receipt_message(
            "instance-child",
            "capability-child",
            "read",
            "payments",
            "autonomous",
            "allowed",
            "",
            "nonce-one",
            issued,
            "log-line",
            &["instance-parent".to_string()],
            &["capability-parent".to_string()],
        );
        assert_eq!(
            message,
            "prometheus-decision-receipt|instance-child|capability-child|read|payments|autonomous|allowed||nonce-one|2026-08-19T07:51:00Z|log-line|ancestor_instance_ids|instance-parent|ancestor_capability_ids|capability-parent"
        );
    }
}
