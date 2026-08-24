
    /// Set verify_threshold_n for foreign act, receipt, presentation, and tree-head checks.
    /// This is not issuance threshold_n. Refuse K < 1. Refuse lowering.
    pub fn set_verify_threshold(&self, verify_threshold_n: u32) -> Result<Issuer> {
        if verify_threshold_n < 1 {
            return Err(Error::denied(
                "The verify_threshold_n value must be at least 1. A verify threshold of zero is refused. The check fails closed.",
            ));
        }
        let mut issuer = self.store.load_issuer()?;
        self.require_loaded_issuer_not_sealed(&issuer)?;
        crate::issuer_crypto::require_issuer_identity_root_is_module_lattice(&issuer)?;
        if verify_threshold_n < issuer.verify_threshold_n.max(1) {
            return Err(Error::denied(
                "The verify_threshold_n value cannot be lowered. Lowering the verify threshold is a persist-raise class. The check fails closed.",
            ));
        }
        if verify_threshold_n == issuer.verify_threshold_n {
            return Ok(issuer);
        }
        issuer.verify_threshold_n = verify_threshold_n;
        self.store.save_issuer(&issuer)?;
        self.store.append_log(&self.issuance_event(
            "issuer_verify_threshold",
            None,
            None,
            None,
            None,
            None,
            None,
            Some(format!(
                "Raised verify_threshold_n to {verify_threshold_n}. A foreign act, receipt, presentation, or tree head now needs {verify_threshold_n} distinct accepted issuer signatures. This is not issuance threshold_n. This is not a sixth identity record."
            )),
        ))?;
        Ok(issuer)
    }
