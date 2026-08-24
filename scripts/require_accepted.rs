
    fn require_accepted_artifact_signatures(
        &self,
        issuer: &Issuer,
        issuer_signatures: &[crate::records::IssuerMemberSignature],
        fallback_public_key_hex: &str,
        fallback_signature_hex: &str,
        message: &str,
        artifact_name: &str,
    ) -> Result<()> {
        let required = issuer.verify_threshold_n.max(1);
        let accepted = issuer.accepted_issuer_public_keys_for_verify_at(self.now());
        if !issuer_signatures.is_empty() {
            return crate::threshold::require_threshold_signatures(
                issuer_signatures,
                fallback_public_key_hex,
                fallback_signature_hex,
                message,
                &accepted,
                &issuer.biscuit_public_key_hex,
                required,
                artifact_name,
            );
        }
        if required > 1 {
            return Err(Error::denied(format!(
                "The {artifact_name} has one signature. This store verify_threshold_n is {required}. A stolen single member secret is not enough. The check fails closed."
            )));
        }
        tokens::matching_accepted_issuer_public_key(
            &accepted,
            message,
            fallback_signature_hex,
        )?;
        Ok(())
    }
