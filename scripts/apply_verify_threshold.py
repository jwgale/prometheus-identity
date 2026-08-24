#!/usr/bin/env python3
from pathlib import Path

ROOT = Path("/home/jason/Projects/Prometheus")

def replace_once(text, old, new, label):
    if old not in text:
        raise SystemExit(f"missing snippet: {label}")
    return text.replace(old, new, 1)

# ---- records.rs ----
records = ROOT / "src/records.rs"
text = records.read_text()
if "verify_threshold_n" not in text:
    text = replace_once(
        text,
        """    pub threshold_n: u32,
    pub issuance_log: String,
}
""",
        """    pub threshold_n: u32,
    /// How many distinct accepted issuer signatures a foreign act, receipt,
    /// presentation, or tree head needs. This is not issuance threshold_n.
    /// Init default is 1. Lowering is refused. This is not a sixth identity record.
    #[serde(default = "default_threshold_one")]
    pub verify_threshold_n: u32,
    pub issuance_log: String,
}

fn default_threshold_one() -> u32 {
    1
}
""",
        "Issuer.verify_threshold_n",
    )
    records.write_text(text)
    print("records.rs updated")
else:
    print("records.rs already has verify_threshold_n")

# ---- store.rs freeze ----
store = ROOT / "src/store.rs"
text = store.read_text()
if "require_issuer_verify_threshold_not_lowered" not in text:
    text = replace_once(
        text,
        "            self.require_issuer_threshold_not_lowered(&stored, issuer)?;\n",
        "            self.require_issuer_threshold_not_lowered(&stored, issuer)?;\n            self.require_issuer_verify_threshold_not_lowered(&stored, issuer)?;\n",
        "save_issuer call freeze",
    )
    text = replace_once(
        text,
        """        Ok(())
    }

    pub fn load_issuer(&self) -> Result<Issuer> {
""",
        """        Ok(())
    }

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

    pub fn load_issuer(&self) -> Result<Issuer> {
""",
        "verify threshold freeze fn",
    )
    text = replace_once(
        text,
        """        if issuer.threshold_n < 1 {
            return Err(Error::denied(
                "The threshold_n value must be at least 1. A threshold of zero is refused. The check fails closed.",
            ));
        }
        self.write_json(&path, issuer)
""",
        """        if issuer.threshold_n < 1 {
            return Err(Error::denied(
                "The threshold_n value must be at least 1. A threshold of zero is refused. The check fails closed.",
            ));
        }
        if issuer.verify_threshold_n < 1 {
            return Err(Error::denied(
                "The verify_threshold_n value must be at least 1. A verify threshold of zero is refused. The check fails closed.",
            ));
        }
        self.write_json(&path, issuer)
""",
        "save_issuer first-write verify_threshold_n",
    )
    store.write_text(text)
    print("store.rs updated")
else:
    print("store.rs already has verify freeze")

# ---- kernel.rs ----
kernel = ROOT / "src/kernel.rs"
text = kernel.read_text()
if "set_verify_threshold" not in text:
    text = replace_once(
        text,
        """            kill_date: None,
            threshold_n: 1,
            issuance_log: "issuance.log".to_string(),
""",
        """            kill_date: None,
            threshold_n: 1,
            verify_threshold_n: 1,
            issuance_log: "issuance.log".to_string(),
""",
        "init verify_threshold_n",
    )
    text = replace_once(
        text,
        """        Ok(issuer)
    }

    /// Pre-committed store-wide issuer death. Sets issuer.kill_date to now plus after_seconds.
""",
        """        Ok(issuer)
    }

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

    /// Pre-committed store-wide issuer death. Sets issuer.kill_date to now plus after_seconds.
""",
        "set_verify_threshold method",
    )
    # helper before require_child_act_authority or after store_status closing of impl
    text = replace_once(
        text,
        """            check_host_bind: "127.0.0.1 only".to_string(),
        })
    }

}
""",
        """            verify_threshold_n: issuer.verify_threshold_n.max(1),
            check_host_bind: "127.0.0.1 only".to_string(),
        })
    }

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
                "The {artifact_name} has an empty issuer_signatures list. This store verify_threshold_n is {required}. A second accepted issuer signature is missing. A stolen single member secret is not enough. The check fails closed."
            )));
        }
        Ok(())
    }

}
""",
        "helper + status field",
    )
    text = replace_once(
        text,
        """    pub threshold_n: u32,
    pub member_count: u32,
""",
        """    pub threshold_n: u32,
    pub verify_threshold_n: u32,
    pub member_count: u32,
""",
        "StoreStatus field",
    )
    text = replace_once(
        text,
        """threshold_n: {threshold_n}\\n\\
member_count: {member_count}\\n\\
""",
        """threshold_n: {threshold_n}\\n\\
verify_threshold_n: {verify_threshold_n}\\n\\
member_count: {member_count}\\n\\
""",
        "human status line",
    )
    text = replace_once(
        text,
        """            threshold_n = self.threshold_n,
            member_count = self.member_count,
""",
        """            threshold_n = self.threshold_n,
            verify_threshold_n = self.verify_threshold_n,
            member_count = self.member_count,
""",
        "human status args",
    )
    # foreign verify sites
    text = replace_once(
        text,
        """        if !receipt.issuer_signatures.is_empty() {
            crate::threshold::require_threshold_signatures(
                &receipt.issuer_signatures,
                "",
                "",
                &message,
                &accepted_issuer_public_keys,
                &issuer.biscuit_public_key_hex,
                issuer.threshold_n,
                "decision receipt",
            )?;
        }
""",
        """        self.require_accepted_artifact_signatures(
            &issuer,
            &receipt.issuer_signatures,
            "",
            &receipt.signature,
            &message,
            "decision receipt",
        )?;
""",
        "receipt verify signatures",
    )
    text = replace_once(
        text,
        """        let trusted_log_keys = match issuance_log_path {
            Some(_) => issuer.accepted_issuer_public_keys_for_verify_at(now),
            None => issuer.trusted_issuer_keys_for_issuance_log(),
        };
        crate::log_chain::verify_issuance_log_text_with_threshold(
            &log_text,
            &trusted_log_keys,
            issuer.threshold_n,
            &issuer.biscuit_public_key_hex,
        )?;
""",
        """        let trusted_log_keys = match issuance_log_path {
            Some(_) => issuer.accepted_issuer_public_keys_for_verify_at(now),
            None => issuer.trusted_issuer_keys_for_issuance_log(),
        };
        let log_threshold = if issuance_log_path.is_some() {
            issuer.verify_threshold_n.max(1)
        } else {
            issuer.threshold_n
        };
        crate::log_chain::verify_issuance_log_text_with_threshold(
            &log_text,
            &trusted_log_keys,
            log_threshold,
            &issuer.biscuit_public_key_hex,
        )?;
""",
        "foreign log threshold",
    )
    text = replace_once(
        text,
        """        crate::log_chain::require_bound_issuance_log_line_issuer_signature_with_threshold(
            receipt.issuance_log_line.trim(),
            &trusted_log_keys,
            issuer.threshold_n,
            &issuer.biscuit_public_key_hex,
        )?;
""",
        """        crate::log_chain::require_bound_issuance_log_line_issuer_signature_with_threshold(
            receipt.issuance_log_line.trim(),
            &trusted_log_keys,
            log_threshold,
            &issuer.biscuit_public_key_hex,
        )?;
""",
        "foreign bound line threshold",
    )
    text = replace_once(
        text,
        """        if !tree_head.issuer_signatures.is_empty() {
            let accepted = issuer.accepted_issuer_public_keys_for_verify_at(self.now());
            crate::threshold::require_threshold_signatures(
                &tree_head.issuer_signatures,
                &tree_head.issuer_public_key_hex,
                &tree_head.signature_hex,
                &tree_head.canonical_message(),
                &accepted,
                &issuer.biscuit_public_key_hex,
                issuer.threshold_n,
                "signed tree head",
            )?;
        }
""",
        """        self.require_accepted_artifact_signatures(
            &issuer,
            &tree_head.issuer_signatures,
            &tree_head.issuer_public_key_hex,
            &tree_head.signature_hex,
            &tree_head.canonical_message(),
            "signed tree head",
        )?;
""",
        "tree head foreign verify",
    )
    text = replace_once(
        text,
        """        if !receipt.issuer_signatures.is_empty() {
            crate::threshold::require_threshold_signatures(
                &receipt.issuer_signatures,
                "",
                "",
                &receipt.canonical_message(),
                &accepted_issuer_public_keys,
                &issuer.biscuit_public_key_hex,
                issuer.threshold_n,
                "decision receipt",
            )?;
            return Ok(());
        }
        tokens::matching_accepted_issuer_public_key(
            &accepted_issuer_public_keys,
            &receipt.canonical_message(),
            &receipt.signature,
        )?;
        Ok(())
""",
        """        self.require_accepted_artifact_signatures(
            &issuer,
            &receipt.issuer_signatures,
            "",
            &receipt.signature,
            &receipt.canonical_message(),
            "decision receipt",
        )?;
        if receipt.issuer_signatures.is_empty() {
            tokens::matching_accepted_issuer_public_key(
                &accepted_issuer_public_keys,
                &receipt.canonical_message(),
                &receipt.signature,
            )?;
        }
        Ok(())
""",
        "act-accept receipt signatures",
    )
    text = replace_once(
        text,
        """        if !presentation.issuer_signatures.is_empty() {
            let accepted = issuer.accepted_issuer_public_keys_for_verify_at(self.now());
            crate::threshold::require_threshold_signatures(
                &presentation.issuer_signatures,
                &presentation.issuer_public_key_hex,
                &presentation.signature_hex,
                &presentation.canonical_message(),
                &accepted,
                &issuer.biscuit_public_key_hex,
                issuer.threshold_n,
                "presentation",
            )?;
        }
""",
        """        self.require_accepted_artifact_signatures(
            &issuer,
            &presentation.issuer_signatures,
            &presentation.issuer_public_key_hex,
            &presentation.signature_hex,
            &presentation.canonical_message(),
            "presentation",
        )?;
""",
        "presentation foreign verify",
    )
    kernel.write_text(text)
    print("kernel.rs updated")
else:
    print("kernel.rs already has set_verify_threshold")

# ---- main.rs ----
main = ROOT / "src/main.rs"
text = main.read_text()
if "VerifyThreshold" not in text:
    text = replace_once(
        text,
        """    Threshold {
        /// Required number of distinct trusted Module-Lattice member signatures.
        #[arg(long = "n")]
        n: u32,
    },
    /// Add or show issuer members. The Biscuit envelope key is not a member.
""",
        """    Threshold {
        /// Required number of distinct trusted Module-Lattice member signatures.
        #[arg(long = "n")]
        n: u32,
    },
    /// Set verify_threshold_n for foreign act, receipt, presentation, and tree-head checks.
    /// This is not issuance threshold_n. Refuse K < 1. Refuse lowering.
    VerifyThreshold {
        /// Required number of distinct accepted issuer signatures on a foreign artifact.
        #[arg(long = "n")]
        n: u32,
    },
    /// Add or show issuer members. The Biscuit envelope key is not a member.
""",
        "CLI enum",
    )
    text = replace_once(
        text,
        """        Command::Issuer(IssuerCommand::Threshold { n }) => {
            let issuer = kernel.set_issuer_threshold(n)?;
            print_json(&issuer)?;
        }
""",
        """        Command::Issuer(IssuerCommand::Threshold { n }) => {
            let issuer = kernel.set_issuer_threshold(n)?;
            print_json(&issuer)?;
        }
        Command::Issuer(IssuerCommand::VerifyThreshold { n }) => {
            let issuer = kernel.set_verify_threshold(n)?;
            print_json(&issuer)?;
        }
""",
        "CLI dispatch",
    )
    main.write_text(text)
    print("main.rs updated")
else:
    print("main.rs already has VerifyThreshold")


# ---- ANATOMY.md ----
anatomy = ROOT / "ANATOMY.md"
atext = anatomy.read_text()
if "verify_threshold_n" not in atext:
    atext = replace_once(
        atext,
        """Threshold is a property of one issuer. Member two is a second Module-Lattice Digital Signature Algorithm key for that same issuer. Member two is not a second store. Copying `issuer.secret` to the second store is refused as an operator rule.
""",
        """Threshold is a property of one issuer. Member two is a second Module-Lattice Digital Signature Algorithm key for that same issuer. Member two is not a second store. Copying `issuer.secret` to the second store is refused as an operator rule.

Foreign act accept uses `verify_threshold_n` on the verifying store. The operator must accept each member public key. This is not issuance `threshold_n`. Binding `threshold_n` inside a receipt does not fix a stolen issuer secret. The verifying store counts distinct accepted signatures.
""",
        "ANATOMY foreign verify paragraph",
    )
    anatomy.write_text(atext)
    print("ANATOMY.md updated")
else:
    print("ANATOMY.md already has verify_threshold_n")

print("apply_verify_threshold complete")
