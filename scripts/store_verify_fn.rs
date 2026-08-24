
    /// verify_threshold_n cannot be lowered. Lowering is a persist-raise class.
    /// This is not issuance threshold_n.
    fn require_issuer_verify_threshold_not_lowered(&self, stored: &Issuer, issuer: &Issuer) -> Result<()> {
        let stored_n = if stored.verify_threshold_n < 1 { 1 } else { stored.verify_threshold_n };
        if issuer.verify_threshold_n < 1 {
            return Err(Error::denied(
                "The verify_threshold_n value must be at least 1. A verify threshold of zero is refused. The check fails closed.",
            ));
        }
        if issuer.verify_threshold_n < stored_n {
            return Err(Error::denied(
                "The verify_threshold_n value cannot be lowered. Lowering the verify threshold is a persist-raise class. A stolen single member secret must not verify a foreign act. The check fails closed.",
            ));
        }
        Ok(())
    }
