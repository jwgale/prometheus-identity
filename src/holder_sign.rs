//! Agent holder-sign. This command is the agent. This command is not the check
//! host. This command is not LaboratoryRuntime. A live instance is not required.
//! This is holder-key use on the agent machine. This module does not open a
//! data directory. This module does not open an identity kernel.

use crate::error::{Error, Result};
use crate::tokens;
use std::path::Path;

/// Environment variable the laboratory runtime sets on a holder-proof command.
pub const CHALLENGE_MESSAGE_ENVIRONMENT: &str = "PROMETHEUS_CHALLENGE_MESSAGE";

/// Sign a verifier nonce with the holder key this agent holds.
///
/// `environment_message` is PROMETHEUS_CHALLENGE_MESSAGE when that variable is
/// set. `flag_message` is --challenge-message when the operator passes the
/// message. The environment value wins when it is set. An empty message is
/// refused. Secret bytes are not returned.
pub fn sign_holder_proof(
    holder_secret_path: impl AsRef<Path>,
    environment_message: Option<&str>,
    flag_message: Option<&str>,
) -> Result<String> {
    let message = resolve_challenge_message(environment_message, flag_message)?;
    let secret = read_holder_secret(holder_secret_path.as_ref())?;
    tokens::sign_holder_challenge(&secret, &message)
}

/// Read PROMETHEUS_CHALLENGE_MESSAGE. Absent is None. Invalid UTF-8 is refused.
pub fn environment_challenge_message() -> Result<Option<String>> {
    match std::env::var(CHALLENGE_MESSAGE_ENVIRONMENT) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(Error::denied(
            "PROMETHEUS_CHALLENGE_MESSAGE is not valid UTF-8. The sign fails closed.",
        )),
    }
}

fn resolve_challenge_message(
    environment_message: Option<&str>,
    flag_message: Option<&str>,
) -> Result<String> {
    let chosen = match environment_message {
        Some(_) => environment_message,
        None => flag_message,
    };
    let Some(message) = chosen else {
        return Err(Error::denied(
            "A challenge message is required. Set PROMETHEUS_CHALLENGE_MESSAGE or pass --challenge-message. The sign fails closed.",
        ));
    };
    let message = message.trim();
    if message.is_empty() {
        return Err(Error::denied(
            "The challenge message is empty. Set PROMETHEUS_CHALLENGE_MESSAGE or pass --challenge-message. The sign fails closed.",
        ));
    }
    Ok(message.to_string())
}

fn read_holder_secret(path: &Path) -> Result<String> {
    if !path.exists() {
        return Err(Error::denied(
            "The holder secret file does not exist. This command is the agent. Secret bytes are not printed. The sign fails closed.",
        ));
    }
    if path.is_dir() {
        return Err(Error::denied(
            "The holder secret path is not a file. Secret bytes are not printed. The sign fails closed.",
        ));
    }
    let secret = std::fs::read_to_string(path).map_err(|_| {
        Error::denied(
            "The holder secret file could not be read. Secret bytes are not printed. The sign fails closed.",
        )
    })?;
    let secret = secret.trim();
    if secret.is_empty() {
        return Err(Error::denied(
            "The holder secret file is empty. Secret bytes are not printed. The sign fails closed.",
        ));
    }
    Ok(secret.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_check::refuse_holder_secret_path;
    use crate::tokens::{
        generate_keypair, private_key_hexadecimal, public_key_hexadecimal, verify_holder_signature,
    };
    use std::fs;
    use tempfile::tempdir;

    fn write_holder_secret(secret: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempdir().expect("create a temporary directory");
        let path = directory.path().join("holder.secret");
        fs::write(&path, secret).expect("write a holder secret file");
        (directory, path)
    }

    #[test]
    fn holder_sign_output_verifies_with_the_holder_public_key() {
        let key_pair = generate_keypair();
        let secret = private_key_hexadecimal(&key_pair);
        let public_key = public_key_hexadecimal(&key_pair);
        let (_directory, path) = write_holder_secret(&secret);
        let message = "prometheus-verifier-challenge|laboratory-nonce";
        let proof = sign_holder_proof(&path, None, Some(message)).expect("sign the challenge");
        assert!(
            !proof.contains('{') && !proof.contains("holder_proof") && !proof.contains('\n'),
            "holder-sign must print only the holder proof hexadecimal: {proof}"
        );
        hex::decode(&proof).expect("the holder proof must be hexadecimal");
        verify_holder_signature(&public_key, message, &proof)
            .expect("tokens::verify_holder_signature must accept the holder-sign output");
        assert!(
            !proof.contains(&secret),
            "the holder proof must not contain secret bytes"
        );
    }

    #[test]
    fn holder_sign_refuses_a_missing_file() {
        let directory = tempdir().expect("create a temporary directory");
        let missing = directory.path().join("missing-holder.secret");
        let error = sign_holder_proof(&missing, None, Some("prometheus-verifier-challenge|nonce"))
            .expect_err("a missing holder secret file must be refused");
        let text = error.to_string();
        assert!(
            text.contains("does not exist") && text.contains("fails closed"),
            "the refuse must name the missing file: {text}"
        );
        assert!(!text.contains('{'), "the refuse must not wrap JSON: {text}");
    }

    #[test]
    fn holder_sign_refuses_an_empty_message() {
        let key_pair = generate_keypair();
        let (_directory, path) = write_holder_secret(&private_key_hexadecimal(&key_pair));
        for (environment, flag) in [
            (None, None),
            (None, Some("")),
            (None, Some("   ")),
            (Some(""), Some("prometheus-verifier-challenge|nonce")),
            (Some("   "), Some("prometheus-verifier-challenge|nonce")),
        ] {
            let error = sign_holder_proof(&path, environment, flag)
                .expect_err("an empty challenge message must be refused");
            let text = error.to_string();
            assert!(
                text.contains("challenge message") && text.contains("fails closed"),
                "the refuse must name the empty message: {text}"
            );
        }
    }

    #[test]
    fn holder_sign_refuses_an_unreadable_secret() {
        let directory = tempdir().expect("create a temporary directory");
        let empty_path = directory.path().join("empty.secret");
        fs::write(&empty_path, "   ").expect("write an empty holder secret file");
        let empty_error = sign_holder_proof(
            &empty_path,
            None,
            Some("prometheus-verifier-challenge|nonce"),
        )
        .expect_err("an empty holder secret file must be refused");
        let empty_text = empty_error.to_string();
        assert!(
            empty_text.contains("empty") && empty_text.contains("Secret bytes are not printed"),
            "the refuse must name the empty secret: {empty_text}"
        );

        let marker = "MUST-NOT-PRINT-HOLDER-SECRET-BYTES";
        let bad_path = directory.path().join("bad.secret");
        fs::write(&bad_path, marker).expect("write an unreadable holder secret file");
        let bad_error =
            sign_holder_proof(&bad_path, None, Some("prometheus-verifier-challenge|nonce"))
                .expect_err("an unreadable holder secret must be refused");
        let bad_text = bad_error.to_string();
        assert!(
            !bad_text.contains(marker),
            "secret bytes must not be printed: {bad_text}"
        );
    }

    #[test]
    fn holder_sign_environment_message_wins_over_the_flag() {
        let key_pair = generate_keypair();
        let secret = private_key_hexadecimal(&key_pair);
        let public_key = public_key_hexadecimal(&key_pair);
        let (_directory, path) = write_holder_secret(&secret);
        let environment = "prometheus-verifier-challenge|from-environment";
        let flag = "prometheus-verifier-challenge|from-flag";
        let proof = sign_holder_proof(&path, Some(environment), Some(flag))
            .expect("sign the environment message");
        verify_holder_signature(&public_key, environment, &proof)
            .expect("the environment message must be the signed bytes");
        verify_holder_signature(&public_key, flag, &proof).expect_err(
            "the flag message must not be the signed bytes when the environment is set",
        );
    }

    #[test]
    fn holder_sign_uses_the_flag_when_the_environment_is_unset() {
        let key_pair = generate_keypair();
        let secret = private_key_hexadecimal(&key_pair);
        let public_key = public_key_hexadecimal(&key_pair);
        let (_directory, path) = write_holder_secret(&secret);
        let flag = "prometheus-verifier-challenge|from-flag";
        let proof = sign_holder_proof(&path, None, Some(flag)).expect("sign the flag message");
        verify_holder_signature(&public_key, flag, &proof)
            .expect("the flag message must be the signed bytes when the environment is unset");
    }

    #[test]
    fn holder_sign_does_not_open_a_data_directory_or_call_kernel_sign_holder_nonce() {
        let production = include_str!("holder_sign.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source sits before the test module");
        assert!(
            production.contains("tokens::sign_holder_challenge")
                && !production.contains("Kernel::")
                && !production.contains(".sign_holder_nonce")
                && !production.contains("data_directory")
                && !production.contains("force-allow")
                && !production.contains("force_allow"),
            "holder-sign must reuse tokens::sign_holder_challenge. A live instance is not required. No force-allow."
        );
        let main_source = include_str!("main.rs");
        assert!(
            main_source.contains("name = \"holder-sign\"") && main_source.contains("HolderSign {"),
            "the documented command prometheus holder-sign must exist"
        );
        let run_fn = main_source
            .split("fn run()")
            .nth(1)
            .expect("the command runner must exist");
        let holder_index = run_fn
            .find("Command::HolderSign")
            .expect("holder-sign must run in the command runner");
        let kernel_index = run_fn
            .find("Kernel::open_with_member_secrets")
            .expect("other commands still open a data directory");
        assert!(
            holder_index < kernel_index,
            "holder-sign must not open a data directory"
        );
        let holder_handler = &run_fn[..kernel_index];
        assert!(
            holder_handler.contains("sign_holder_proof")
                && holder_handler.contains("environment_challenge_message")
                && !holder_handler.contains("sign_holder_nonce")
                && !holder_handler.contains("print_json"),
            "holder-sign must print only the holder proof hexadecimal and must not call Kernel::sign_holder_nonce"
        );
    }

    #[test]
    fn laboratory_runtime_still_refuses_a_holder_secret_path() {
        refuse_holder_secret_path(None)
            .expect("an absent holder secret path argument is not a refuse of that argument");
        let directory = tempdir().expect("create a temporary directory");
        let secret_path = directory.path().join("holder.secret");
        fs::write(&secret_path, "MUST-NOT-BE-READ").expect("write a marker file");
        let error = refuse_holder_secret_path(Some(&secret_path))
            .expect_err("LaboratoryRuntime must still refuse a holder secret path");
        let text = error.to_string();
        assert!(
            text.contains("holder secret") && text.contains("Secret bytes are not opened"),
            "the runtime refuse must stay fail-closed: {text}"
        );
        let unread = fs::read_to_string(&secret_path).expect("the marker file must still exist");
        assert_eq!(
            unread, "MUST-NOT-BE-READ",
            "the runtime refuse must not rewrite holder secret bytes"
        );
        let runtime_production = include_str!("runtime_check.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source sits before the test module");
        assert!(
            runtime_production.contains("pub fn refuse_holder_secret_path")
                && !runtime_production.contains("holder_sign::")
                && !runtime_production.contains("sign_holder_proof"),
            "LaboratoryRuntime must still refuse --holder-secret-path and must not become holder-sign"
        );
    }
}
