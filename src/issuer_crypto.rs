//! Laboratory Module-Lattice Digital Signature Algorithm (ML-DSA) for the issuer identity root.
//!
//! This module uses the `fips204` crate, Federal Information Processing Standard (FIPS) 204
//! parameter set ML-DSA-65. This is a laboratory issuer. This is not a production FIPS module.
//! This is not a post-quantum Biscuit. The Biscuit capability-envelope key stays laboratory
//! Edwards-curve Digital Signature Algorithm on Curve 25519 (Ed25519).

use crate::error::{Error, Result};
use crate::records::Issuer;
use fips204::ml_dsa_65::{self, PrivateKey, PublicKey, PK_LEN, SIG_LEN, SK_LEN};
use fips204::traits::{SerDes, Signer, Verifier};

/// Laboratory cryptographic profile name written on issuer init.
/// Identity root is Module-Lattice Digital Signature Algorithm 65.
/// Biscuit capability tokens stay laboratory Ed25519.
pub const LABORATORY_ISSUER_CRYPTO_PROFILE: &str = "lab-ml-dsa-65-hybrid-biscuit-ed25519";

/// Classical-only profile name that new issuer init must refuse.
pub const CLASSICAL_ONLY_ISSUER_CRYPTO_PROFILE: &str = "lab-ed25519";

/// A laboratory Module-Lattice Digital Signature Algorithm key pair.
#[derive(Debug, Clone)]
pub struct ModuleLatticeKeyPair {
    pub public_key_hexadecimal: String,
    pub secret_key_hexadecimal: String,
}

fn empty_context() -> &'static [u8] {
    &[]
}

fn bytes_from_hexadecimal(hexadecimal: &str, field_name: &str) -> Result<Vec<u8>> {
    hex::decode(hexadecimal.trim()).map_err(|error| {
        Error::Crypto(format!(
            "The {field_name} value is not valid hexadecimal: {error}"
        ))
    })
}

fn fixed_bytes<const LENGTH: usize>(bytes: &[u8], field_name: &str) -> Result<[u8; LENGTH]> {
    if bytes.len() != LENGTH {
        return Err(Error::Crypto(format!(
            "The {field_name} value must decode to {LENGTH} bytes. Found {} bytes. A classical-only key is not a Module-Lattice Digital Signature Algorithm key. The check fails closed.",
            bytes.len()
        )));
    }
    let mut array = [0u8; LENGTH];
    array.copy_from_slice(bytes);
    Ok(array)
}

fn public_key_from_hexadecimal(hexadecimal: &str) -> Result<PublicKey> {
    let bytes = bytes_from_hexadecimal(hexadecimal, "issuer public key")?;
    let array = fixed_bytes::<PK_LEN>(&bytes, "issuer public key")?;
    PublicKey::try_from_bytes(array).map_err(|error| {
        Error::Crypto(format!(
            "The issuer public key is not a valid Module-Lattice Digital Signature Algorithm public key: {error}"
        ))
    })
}

fn secret_key_from_hexadecimal(hexadecimal: &str) -> Result<PrivateKey> {
    let bytes = bytes_from_hexadecimal(hexadecimal, "issuer secret")?;
    let array = fixed_bytes::<SK_LEN>(&bytes, "issuer secret")?;
    PrivateKey::try_from_bytes(array).map_err(|error| {
        Error::Crypto(format!(
            "The issuer secret is not a valid Module-Lattice Digital Signature Algorithm secret key: {error}"
        ))
    })
}

/// Return true when the profile name is a classical-only issuer root.
/// New issuer init and birth refuse this profile.
pub fn is_classical_only_issuer_profile(crypto_profile: &str) -> bool {
    let trimmed = crypto_profile.trim();
    trimmed == CLASSICAL_ONLY_ISSUER_CRYPTO_PROFILE || trimmed.eq_ignore_ascii_case("ed25519")
}

/// Refuse a classical-only issuer profile name.
pub fn require_not_classical_only_issuer_profile(crypto_profile: &str) -> Result<()> {
    if crypto_profile.trim().is_empty() {
        return Err(Error::denied(
            "The crypto_profile value must not be empty. Issuer init refuses a classical-only root. The identity root must be Module-Lattice Digital Signature Algorithm. The check fails closed.",
        ));
    }
    if is_classical_only_issuer_profile(crypto_profile) {
        return Err(Error::denied(
            "Issuer init and birth refuse a classical-only root. Profile lab-ed25519 as the only issuer signature algorithm is refused. The identity root must be Module-Lattice Digital Signature Algorithm. The Biscuit envelope may stay laboratory Ed25519. This is not a production FIPS module. This is not a post-quantum Biscuit. The check fails closed.",
        ));
    }
    Ok(())
}

/// Refuse a public key that is not Module-Lattice Digital Signature Algorithm 65.
/// An Ed25519 32-byte key used as the current identity root fails closed.
pub fn require_module_lattice_public_key(public_key_hexadecimal: &str) -> Result<()> {
    if public_key_hexadecimal.trim().is_empty() {
        return Err(Error::denied(
            "The current issuer public key is empty. A classical-only root is refused. The identity root must be Module-Lattice Digital Signature Algorithm. The check fails closed.",
        ));
    }
    public_key_from_hexadecimal(public_key_hexadecimal).map(|_| ()).map_err(|error| {
        Error::denied(format!(
            "A forged Ed25519-only issuer used as the current root is refused. The identity root must be a Module-Lattice Digital Signature Algorithm public key. {error} The check fails closed."
        ))
    })
}

/// Refuse a classical-only issuer record. Birth, mint, spawn, and init use this gate.
pub fn require_issuer_identity_root_is_module_lattice(issuer: &Issuer) -> Result<()> {
    require_not_classical_only_issuer_profile(&issuer.crypto_profile)?;
    require_module_lattice_public_key(&issuer.current_public_key_hex())
}

/// Generate a laboratory Module-Lattice Digital Signature Algorithm 65 key pair.
pub fn generate_module_lattice_key_pair() -> Result<ModuleLatticeKeyPair> {
    let (public_key, secret_key) = ml_dsa_65::try_keygen().map_err(|error| {
        Error::Crypto(format!(
            "Module-Lattice Digital Signature Algorithm key generation failed: {error}"
        ))
    })?;
    Ok(ModuleLatticeKeyPair {
        public_key_hexadecimal: hex::encode(public_key.into_bytes()),
        secret_key_hexadecimal: hex::encode(secret_key.into_bytes()),
    })
}

/// Derive the public key hexadecimal from a Module-Lattice secret.
pub fn public_key_hexadecimal_from_secret(secret_key_hexadecimal: &str) -> Result<String> {
    let secret_key = secret_key_from_hexadecimal(secret_key_hexadecimal)?;
    Ok(hex::encode(secret_key.get_public_key().into_bytes()))
}

/// Return true when the secret derives the given Module-Lattice public key.
pub fn public_key_matches_secret(
    public_key_hexadecimal: &str,
    secret_key_hexadecimal: &str,
) -> Result<bool> {
    let derived = public_key_hexadecimal_from_secret(secret_key_hexadecimal)?;
    Ok(derived == public_key_hexadecimal.trim())
}

/// Sign documented concatenation bytes with the issuer Module-Lattice secret.
/// Context is empty so the signed bytes stay the documented concatenations.
pub fn sign_with_module_lattice_secret(
    secret_key_hexadecimal: &str,
    message: &str,
) -> Result<String> {
    let secret_key = secret_key_from_hexadecimal(secret_key_hexadecimal)?;
    let signature = secret_key
        .try_sign(message.as_bytes(), empty_context())
        .map_err(|error| {
            Error::Crypto(format!(
                "Module-Lattice Digital Signature Algorithm signing failed: {error}"
            ))
        })?;
    Ok(hex::encode(signature))
}

/// Verify a Module-Lattice signature against an issuer public key.
pub fn verify_module_lattice_signature(
    public_key_hexadecimal: &str,
    message: &str,
    signature_hexadecimal: &str,
) -> Result<()> {
    let public_key = public_key_from_hexadecimal(public_key_hexadecimal)?;
    let signature_bytes = bytes_from_hexadecimal(signature_hexadecimal, "issuer signature")?;
    if signature_bytes.len() != SIG_LEN {
        return Err(Error::denied(format!(
            "The issuer signature must decode to {SIG_LEN} bytes. Found {} bytes. The check fails closed.",
            signature_bytes.len()
        )));
    }
    let mut signature_array = [0u8; SIG_LEN];
    signature_array.copy_from_slice(&signature_bytes);
    if !public_key.verify(message.as_bytes(), &signature_array, empty_context()) {
        return Err(Error::denied(
            "The decision receipt signature is not valid for this issuer.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_lattice_sign_and_verify_round_trip() {
        let key_pair =
            generate_module_lattice_key_pair().expect("generate a module lattice key pair");
        let message = "prometheus-decision-receipt|test";
        let signature = sign_with_module_lattice_secret(&key_pair.secret_key_hexadecimal, message)
            .expect("sign with the module lattice secret");
        verify_module_lattice_signature(&key_pair.public_key_hexadecimal, message, &signature)
            .expect("the matching signature must verify");
        verify_module_lattice_signature(&key_pair.public_key_hexadecimal, "tampered", &signature)
            .expect_err("a tampered message must fail closed");
    }

    #[test]
    fn an_ed25519_public_key_is_not_a_module_lattice_root() {
        let error = require_module_lattice_public_key(&"ab".repeat(32))
            .expect_err("a 32-byte Ed25519 key must not be the identity root");
        let text = error.to_string();
        assert!(
            text.contains("forged Ed25519-only") || text.contains("Module-Lattice"),
            "unexpected classical-root error: {error}"
        );
    }

    #[test]
    fn classical_only_profile_is_refused() {
        let error = require_not_classical_only_issuer_profile(CLASSICAL_ONLY_ISSUER_CRYPTO_PROFILE)
            .expect_err("lab-ed25519 must be refused");
        assert!(
            error.to_string().contains("classical-only"),
            "unexpected profile error: {error}"
        );
    }
}
