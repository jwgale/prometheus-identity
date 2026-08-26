use anyhow::Result;
use clap::{Parser, Subcommand};
use prometheus_identity::kernel::LABORATORY_ISSUER_ROTATE_KILL_AFTER_SECONDS;
use prometheus_identity::{DecisionReceipt, HolderProof, Kernel};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "prometheus",
    about = "Prometheus laboratory prototype for agent identity. This is not Sanctum product source of truth. This is not a Cyera product.",
    long_about = None
)]
struct Arguments {
    /// Directory that holds issuer.json, issuance.log, and the record folders.
    #[arg(long, default_value = "./data")]
    data_directory: PathBuf,
    /// Extra issuer member secret files. Repeatable. Operator custody. Not an identity record.
    #[arg(long = "member-secret", value_name = "PATH")]
    member_secret: Vec<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create the issuer Module-Lattice key pair, the laboratory Biscuit envelope key, and an empty store.
    Init {
        /// Cryptographic profile name. A classical-only profile is refused.
        #[arg(long, default_value = "lab-ml-dsa-65-hybrid-biscuit-ed25519")]
        crypto_profile: String,
    },
    /// Print a laboratory operator view of this store. Refuse if the issuer is missing. Secrets are not printed.
    Status,
    /// Create an instance and the first capability as one issuance. A name is not a key.
    Birth {
        /// Agent type identifier. This identifier is not a cryptographic key.
        #[arg(long = "agent-type")]
        agent_type: String,
        /// Owner name. This name is not a cryptographic key.
        #[arg(long)]
        owner: String,
        /// Intent of the first capability. The value must be in the allowed intents.
        #[arg(long)]
        intent: String,
        /// Audience of the first capability. The value must sit inside the authorization limit.
        #[arg(long)]
        audience: String,
        /// User identifier, or omit the option to use autonomous.
        #[arg(long)]
        on_behalf_of: Option<String>,
        /// Optional site attribute.
        #[arg(long)]
        site: Option<String>,
        /// Optional region attribute.
        #[arg(long)]
        region: Option<String>,
        /// Optional runtime attribute.
        #[arg(long)]
        runtime: Option<String>,
    },
    /// Birth a child instance with a narrower capability. The child cannot exceed the parent rights.
    Spawn {
        /// Parent instance identifier.
        #[arg(long = "parent-instance")]
        parent_instance: String,
        /// Parent capability identifier.
        #[arg(long = "parent-capability")]
        parent_capability: String,
        /// Owner name of the child instance.
        #[arg(long)]
        owner: String,
        /// Intent of the child capability. The value must not exceed the parent intent.
        #[arg(long)]
        intent: String,
        /// Audience of the child capability. The value must not exceed the parent audience.
        #[arg(long)]
        audience: String,
        /// User identifier, or omit the option to use autonomous.
        #[arg(long)]
        on_behalf_of: Option<String>,
        /// Path to the parent holder secret file. A holder proof is required.
        #[arg(long, global = true)]
        holder_secret_path: Option<PathBuf>,
        /// Hexadecimal Ed25519 signature of the one-time holder challenge.
        #[arg(long)]
        holder_proof: Option<String>,
        /// One-time challenge nonce. Issue the challenge first. A static challenge is not accepted.
        #[arg(long, global = true)]
        challenge_nonce: Option<String>,
    },
    /// Write a one-time holder challenge for an instance. The nonce is spent on the first valid proof.
    Challenge {
        /// Instance identifier.
        #[arg(long)]
        instance: String,
        /// Lifetime of the challenge in seconds. The default is 60.
        #[arg(long, default_value_t = 60)]
        lifetime_seconds: u64,
    },
    /// Allow or refuse a tool action for an instance. A host can call this before a tool action.
    Check {
        /// Instance identifier.
        #[arg(long)]
        instance: String,
        /// Capability identifier. A check that omits this field is refused. The kernel does not guess which capability.
        #[arg(long)]
        capability: Option<String>,
        /// Requested intent.
        #[arg(long)]
        intent: String,
        /// Requested audience.
        #[arg(long)]
        audience: String,
        /// Path to the holder secret file. A holder proof is required.
        #[arg(long)]
        holder_secret_path: Option<PathBuf>,
        /// Hexadecimal Ed25519 signature of the one-time holder challenge.
        #[arg(long)]
        holder_proof: Option<String>,
        /// One-time challenge nonce. Issue the challenge first. A static challenge is not accepted.
        #[arg(long)]
        challenge_nonce: Option<String>,
        /// Act authority. Required. Empty is not autonomous. The exact word autonomous is required. The value must match the capability token.
        #[arg(long)]
        on_behalf_of: Option<String>,
    },
    /// Listen on a loopback address and answer GET /, GET /laboratory, GET /health, GET /.well-known/prometheus-check, GET /status, GET /issuer-public, GET /instances, GET /agent-types, POST /check, POST /check-svid, POST /check-wimse, POST /challenge, POST /verifier-challenge, POST /sign-holder-nonce, POST /present-svid, POST /present-wimse, POST /birth, POST /kill, POST /seal, POST /rotate, POST /seal-export, POST /seal-accept, POST /previous-key-export, POST /previous-key-accept, POST /kill-export, POST /kill-accept, POST /issuer-accept, POST /act-export, POST /act-accept, POST /agent-type, POST /spawn, POST /member-two, POST /set-verify-threshold, and POST /set-issuer-threshold. GET /.well-known/prometheus-check is a laboratory discovery document. POST /check-wimse binds HTTP @method, @request-target, and content-digest. GET / serves the later user interface. GET /laboratory serves the laboratory operator page. Binding to all interfaces is not permitted. --check-only makes this host a verifier.
    Host {
        /// Loopback listen address. The default is 127.0.0.1:18765.
        #[arg(long, default_value = "127.0.0.1:18765")]
        listen_address: String,
        /// Verifier host. Refuse Create Agent Principal and mint paths. Loopback bind stays required.
        #[arg(long = "check-only", default_value_t = false)]
        check_only: bool,
        /// Public check name named in the well-known document. Only check.prestigeworldwide.digital is accepted. The process still binds loopback.
        #[arg(long = "public-check-name")]
        public_check_name: Option<String>,
    },
    /// Laboratory runtime check. This command is a thin wrapper over the runtime module.
    /// The runtime starts from GET /.well-known/prometheus-check and learns check paths from that document only.
    #[command(subcommand, name = "runtime-check")]
    RuntimeCheck(RuntimeCheckCommand),
    /// Sign a verifier nonce with the holder key this agent holds.
    /// This command is the agent. This command is not the check host. This command is not LaboratoryRuntime.
    /// This command does not open a data directory. A live instance is not required. Secret bytes are not printed.
    #[command(name = "holder-sign")]
    HolderSign {
        /// Path to the holder secret file. Secret bytes are not printed.
        #[arg(long)]
        holder_secret_path: PathBuf,
        /// Challenge message. The laboratory runtime sets PROMETHEUS_CHALLENGE_MESSAGE.
        #[arg(long)]
        challenge_message: Option<String>,
    },
    /// Add an agent type record, or refuse a forbidden authorization-limit raise.
    #[command(subcommand, name = "agent-type")]
    AgentType(AgentTypeCommand),
    /// Create or revoke an instance without the first capability.
    #[command(subcommand)]
    Instance(InstanceCommand),
    /// Mint, attenuate, verify, revoke, or refuse an expiry extension.
    #[command(subcommand)]
    Capability(CapabilityCommand),
    /// Show the issuance log and the tool-boundary check events.
    #[command(subcommand)]
    Log(LogCommand),
    /// Verify a signed decision receipt against the accepted issuer public keys.
    #[command(subcommand)]
    Receipt(ReceiptCommand),
    /// Accept a foreign issuer public key, rotate this store's laboratory issuer key, or seal the issuer.
    #[command(subcommand)]
    Issuer(IssuerCommand),
    /// Export or accept a local act bundle. A second store can check three existing artifacts without becoming a second identity kernel.
    #[command(subcommand)]
    Act(ActCommand),
    /// Export or accept a kill bundle. Death travels the way an act already travels.
    #[command(subcommand)]
    Kill(KillCommand),
    /// Write or verify a signed presentation document. This is a document, not a name.
    /// Optional laboratory X.509-SVID wrap of that document. This is not SPIRE.
    Present {
        #[command(subcommand)]
        action: Option<PresentAction>,
        /// Instance identifier.
        #[arg(long, global = true)]
        instance: Option<String>,
        /// Capability identifier. The capability must belong to the instance.
        #[arg(long, global = true)]
        capability: Option<String>,
        /// Write the presentation JSON to this file.
        #[arg(long, global = true)]
        output: Option<PathBuf>,
        /// Laboratory wrap format. json is the historical presentation document. x509-svid wraps that document.
        #[arg(long, global = true, default_value = "json")]
        format: String,
        /// Path to the holder secret file. A holder proof is required. Present is not a bearer document.
        #[arg(long, global = true)]
        holder_secret_path: Option<PathBuf>,
        /// Hexadecimal Ed25519 signature of the one-time holder challenge.
        #[arg(long, global = true)]
        holder_proof: Option<String>,
        /// One-time challenge nonce from prometheus challenge --instance. Required. Present is not bearer.
        #[arg(long, global = true)]
        challenge_nonce: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum RuntimeCheckCommand {
    /// Connect, request a verifier challenge, and post the documented check.
    /// This command is one process. Exit 0 only when the check is allowed.
    /// This command names one on-ramp. Do not mix an X.509-SVID wrap with a WIMSE present.
    /// Completing both checks is the durable agent-process path.
    /// The caller supplies the holder signature. This command does not read holder secrets.
    Act {
        /// Base URL of the check host. Must be http://127.0.0.1 or https://check.prestigeworldwide.digital.
        #[arg(long)]
        base_url: String,
        /// Path to the present JSON bytes.
        #[arg(long)]
        presentation_json: PathBuf,
        /// Path to the laboratory X.509-SVID PEM. This is the first on-ramp.
        #[arg(long)]
        certificate_pem: Option<PathBuf>,
        /// Path to the Workload Identity Token text. Same verb. Documented WIMSE check path.
        #[arg(long)]
        workload_identity_token: Option<PathBuf>,
        /// Content-Digest of the present bytes. Required with the WIMSE present.
        #[arg(long)]
        content_digest: Option<String>,
        /// HTTP Message Signature Input over the documented check method, path, and content-digest.
        #[arg(long)]
        signature_input: Option<String>,
        /// HTTP Message Signature over the documented check method, path, and content-digest.
        #[arg(long)]
        signature: Option<String>,
        /// Holder signature over the verifier nonce this process requests. Sign on the issuing store.
        #[arg(long, conflicts_with = "holder_proof_command")]
        holder_proof: Option<String>,
        /// Shell command that writes the holder signature to standard output.
        /// The laboratory runtime sets PROMETHEUS_CHALLENGE_MESSAGE.
        /// This command does not read holder secrets.
        /// An agent can run prometheus holder-sign --holder-secret-path PATH.
        #[arg(long, conflicts_with = "holder_proof")]
        holder_proof_command: Option<String>,
        /// Always refuse. The laboratory runtime does not read holder secrets. Secret bytes are not opened.
        #[arg(long)]
        holder_secret_path: Option<PathBuf>,
    },
    /// Reuse the act gate before a tool. Print ALLOWED or REFUSED. Exit 0 only when the tool may run.
    /// This command names one on-ramp. Do not mix an X.509-SVID wrap with a WIMSE present.
    /// Completing both checks is the durable agent-process path.
    /// The tool command does not run when the act is refused or when transport fails. Unknown is not live.
    /// This command does not override a refuse. This command does not read holder secrets.
    #[command(name = "before-tool")]
    BeforeTool {
        /// Base URL of the check host. Must be http://127.0.0.1 or https://check.prestigeworldwide.digital.
        #[arg(long)]
        base_url: String,
        /// Path to the present JSON bytes.
        #[arg(long)]
        presentation_json: PathBuf,
        /// Path to the laboratory X.509-SVID PEM. This is the first on-ramp.
        #[arg(long)]
        certificate_pem: Option<PathBuf>,
        /// Path to the Workload Identity Token text. Same verb. Documented WIMSE check path.
        #[arg(long)]
        workload_identity_token: Option<PathBuf>,
        /// Content-Digest of the present bytes. Required with the WIMSE present.
        #[arg(long)]
        content_digest: Option<String>,
        /// HTTP Message Signature Input over the documented check method, path, and content-digest.
        #[arg(long)]
        signature_input: Option<String>,
        /// HTTP Message Signature over the documented check method, path, and content-digest.
        #[arg(long)]
        signature: Option<String>,
        /// Holder signature over the verifier nonce this process requests. Sign on the issuing store.
        #[arg(long, conflicts_with = "holder_proof_command")]
        holder_proof: Option<String>,
        /// Shell command that writes the holder signature to standard output.
        /// The laboratory runtime sets PROMETHEUS_CHALLENGE_MESSAGE.
        /// This command does not read holder secrets.
        /// An agent can run prometheus holder-sign --holder-secret-path PATH.
        #[arg(long, conflicts_with = "holder_proof")]
        holder_proof_command: Option<String>,
        /// Always refuse. The laboratory runtime does not read holder secrets. Secret bytes are not opened.
        #[arg(long)]
        holder_secret_path: Option<PathBuf>,
        /// Shell command that runs only when the act is allowed. This command does not run when the act is refused or when transport fails.
        #[arg(long)]
        tool: Option<String>,
    },
    /// Durable agent process. Stay up after start. Re-check before each tool. Do not cache allow.
    /// Each non-empty stdin line is one tool command. An empty line is a check-only act.
    /// A line that begins with add-act adds one later Assertion Act without a restart.
    /// Name present files the same way start does. One on-ramp on that line.
    /// Do not mix an X.509-SVID wrap with a WIMSE present on the same add-act line.
    /// A line that is exactly the word stop ends the process. Print ALLOWED or REFUSED on its own line.
    /// A successful add-act prints ADDED. A refused act or a refused add stays up.
    /// A line that begins with act and a held act number checks only that act.
    /// An unnamed tool line still checks every held act.
    /// This process is not a public listener. This process is not a store.
    #[command(name = "agent-process")]
    AgentProcess {
        /// Base URL of the check host. Must be http://127.0.0.1 or https://check.prestigeworldwide.digital.
        #[arg(long)]
        base_url: String,
        /// Path to the present JSON bytes. Used by WIMSE. Also used by X.509-SVID unless --svid-presentation-json is set.
        #[arg(long)]
        presentation_json: PathBuf,
        /// Path to the laboratory X.509-SVID PEM. This is the first on-ramp.
        #[arg(long)]
        certificate_pem: Option<PathBuf>,
        /// Present JSON bytes for the X.509-SVID wrap when that wrap is a second Assertion Act.
        /// When omitted, the X.509-SVID wrap uses --presentation-json.
        #[arg(long)]
        svid_presentation_json: Option<PathBuf>,
        /// Path to the Workload Identity Token text. Same verb. Documented WIMSE check path.
        #[arg(long)]
        workload_identity_token: Option<PathBuf>,
        /// Content-Digest of the present bytes. Required with the WIMSE present.
        #[arg(long)]
        content_digest: Option<String>,
        /// HTTP Message Signature Input over the documented check method, path, and content-digest.
        #[arg(long)]
        signature_input: Option<String>,
        /// HTTP Message Signature over the documented check method, path, and content-digest.
        #[arg(long)]
        signature: Option<String>,
        /// Holder signature over the verifier nonce this process requests. Sign on the issuing store.
        #[arg(long, conflicts_with = "holder_proof_command")]
        holder_proof: Option<String>,
        /// Shell command that writes the holder signature to standard output.
        /// The laboratory runtime sets PROMETHEUS_CHALLENGE_MESSAGE.
        /// This command does not read holder secrets.
        /// An agent can run prometheus holder-sign --holder-secret-path PATH.
        #[arg(long, conflicts_with = "holder_proof")]
        holder_proof_command: Option<String>,
        /// Always refuse. The laboratory runtime does not read holder secrets. Secret bytes are not opened.
        #[arg(long)]
        holder_secret_path: Option<PathBuf>,
    },
    /// GET the well-known document and POST the named verifier-challenge path.
    Challenge {
        /// Base URL of the check host. Must be http://127.0.0.1 or https://check.prestigeworldwide.digital.
        #[arg(long)]
        base_url: String,
    },
    /// GET the well-known document and POST the named WIMSE check path.
    /// The caller supplies the holder signature. This command does not read holder secrets.
    Wimse {
        /// Base URL of the check host. Must be http://127.0.0.1 or https://check.prestigeworldwide.digital.
        #[arg(long)]
        base_url: String,
        /// Path to the present JSON bytes.
        #[arg(long)]
        presentation_json: PathBuf,
        /// Path to the Workload Identity Token text.
        #[arg(long)]
        workload_identity_token: PathBuf,
        /// Content-Digest of the present bytes.
        #[arg(long)]
        content_digest: String,
        /// HTTP Message Signature Input over the documented check method, path, and content-digest.
        #[arg(long)]
        signature_input: String,
        /// HTTP Message Signature over the documented check method, path, and content-digest.
        #[arg(long)]
        signature: String,
        /// Holder signature over the verifier nonce. Sign on the issuing store.
        #[arg(long)]
        holder_proof: String,
        /// Verifier nonce from prometheus runtime-check challenge.
        #[arg(long)]
        challenge_nonce: String,
    },
    /// GET the well-known document and POST the named X.509-SVID check path.
    /// The caller supplies the holder signature. This command does not read holder secrets.
    Svid {
        /// Base URL of the check host. Must be http://127.0.0.1 or https://check.prestigeworldwide.digital.
        #[arg(long)]
        base_url: String,
        /// Path to the present JSON bytes.
        #[arg(long)]
        presentation_json: PathBuf,
        /// Path to the laboratory X.509-SVID PEM.
        #[arg(long)]
        certificate_pem: PathBuf,
        /// Holder signature over the verifier nonce. Sign on the issuing store.
        #[arg(long)]
        holder_proof: String,
        /// Verifier nonce from prometheus runtime-check challenge.
        #[arg(long)]
        challenge_nonce: String,
    },
}

#[derive(Subcommand, Debug)]
enum AgentTypeCommand {
    /// Add an agent type record.
    Add {
        /// Owner name. This name is not a cryptographic key.
        #[arg(long)]
        owner: String,
        /// An allowed intent. Repeat this option to add more intents.
        #[arg(long = "intent")]
        intents: Vec<String>,
        /// Highest destination prefix this agent type may hold.
        #[arg(long, default_value = "laboratory")]
        authorization_limit: String,
        /// Maximum hop index after the first capability.
        #[arg(long, default_value_t = 2)]
        max_delegation_depth: u32,
        /// Cryptographic profile name. A later issuer may use a different profile, including a non-classical profile.
        #[arg(long, default_value = "lab-ml-dsa-65-hybrid-biscuit-ed25519")]
        crypto_profile: String,
        /// Lifetime of a new instance and of the first capability, in seconds.
        #[arg(long, default_value_t = 3600)]
        lifetime_seconds: u64,
    },
    /// Always refuse. The authorization limit is frozen after the first write. A raise is a golden-ticket-class raise.
    Raise {
        /// Agent type identifier.
        #[arg(long = "agent-type")]
        agent_type: String,
        /// Destination prefix that will not be written. The command always refuses.
        #[arg(long)]
        authorization_limit: String,
    },
    /// Always refuse. The allowed intents are frozen after the first write. Adding an intent is a golden-ticket-class raise.
    AddIntent {
        /// Agent type identifier.
        #[arg(long = "agent-type")]
        agent_type: String,
        /// Intent that will not be written. The command always refuses.
        #[arg(long)]
        intent: String,
    },
}

#[derive(Subcommand, Debug)]
enum InstanceCommand {
    /// Create a live instance from an agent type. Prefer the birth command for the first capability.
    Birth {
        /// Agent type identifier.
        #[arg(long = "agent-type")]
        agent_type: String,
        /// Owner name. This name is not a cryptographic key.
        #[arg(long)]
        owner: String,
        /// Optional site attribute.
        #[arg(long)]
        site: Option<String>,
        /// Optional region attribute.
        #[arg(long)]
        region: Option<String>,
        /// Optional runtime attribute.
        #[arg(long)]
        runtime: Option<String>,
    },
    /// Revoke a live instance.
    Kill {
        /// Instance identifier.
        #[arg(long)]
        instance: String,
    },
    /// Print an instance record, including the first-binder holder_public_key.
    Show {
        /// Instance identifier.
        #[arg(long)]
        instance: String,
    },
    /// Always refuse. The first binder is written once at birth. There is no holder-key rotate.
    Rebind {
        /// Instance identifier.
        #[arg(long)]
        instance: String,
        /// Hexadecimal public key that will not be written. The command always refuses.
        #[arg(long = "public-key-hex")]
        public_key_hex: String,
    },
}

#[derive(Subcommand, Debug)]
enum CapabilityCommand {
    /// Mint a capability token for an instance.
    Mint {
        /// Instance identifier.
        #[arg(long)]
        instance: String,
        /// Intent string. The value must be in the allowed intents of the agent type.
        #[arg(long)]
        intent: String,
        /// Audience string. The value must sit inside the authorization limit.
        #[arg(long)]
        audience: String,
        /// User identifier, or omit the option to use autonomous.
        #[arg(long)]
        on_behalf_of: Option<String>,
    },
    /// Reduce the audience or the intent of a capability. This command cannot widen rights.
    Attenuate {
        /// Capability identifier.
        #[arg(long)]
        capability: String,
        /// New audience. The value must equal the current audience or be a child path.
        #[arg(long)]
        audience: String,
        /// Optional new intent. The value must stay in the allowed intents and must not widen rights.
        #[arg(long)]
        intent: Option<String>,
    },
    /// Verify a capability token against an audience and an intent. A holder proof is required.
    Verify {
        /// Capability identifier.
        #[arg(long)]
        capability: String,
        /// Requested audience.
        #[arg(long)]
        audience: String,
        /// Requested intent.
        #[arg(long)]
        intent: String,
        /// Path to the holder secret file. A holder proof is required.
        #[arg(long)]
        holder_secret_path: Option<PathBuf>,
        /// Hexadecimal Ed25519 signature of the one-time holder challenge.
        #[arg(long)]
        holder_proof: Option<String>,
        /// One-time challenge nonce. Issue the challenge first. A static challenge is not accepted.
        #[arg(long)]
        challenge_nonce: Option<String>,
        /// Act authority. Required. Empty is not autonomous. The exact word autonomous is required. The value must match the capability token.
        #[arg(long)]
        on_behalf_of: Option<String>,
    },
    /// Revoke a capability. Record the revoke_identifier in the issuance log.
    Kill {
        /// Capability identifier.
        #[arg(long)]
        capability: String,
    },
    /// Always refuse. The capability expiry is frozen after the first write. An extension is a golden-ticket-class extension.
    Extend {
        /// Capability identifier.
        #[arg(long)]
        capability: String,
        /// Expiry time that will not be written. The command always refuses.
        #[arg(long = "expires-at")]
        expires_at: String,
    },
}

#[derive(Subcommand, Debug)]
enum LogCommand {
    /// Print the issuance log and the tool-boundary check events.
    Show,
    /// Walk the local SHA-256 hash chain. A missing field, a wrong previous_line_hash, or a wrong line_hash fails closed.
    Verify,
    /// Print the local Merkle root and the leaf count. This is not a public transparency log.
    Root,
    /// Write an inclusion proof for one line_hash. Fail closed if the line is not in this log.
    Prove {
        /// SHA-256 hexadecimal line_hash of the issuance-log line to prove.
        #[arg(long = "line-hash")]
        line_hash: String,
    },
    /// Recompute the Merkle root from an inclusion proof. Refuse a mismatch, an empty proof, or a truncated sibling list.
    CheckProof {
        /// Path to an inclusion proof JSON file.
        #[arg(long)]
        proof: PathBuf,
        /// Expected Merkle root hexadecimal. If omitted, this store's current root is used.
        #[arg(long)]
        root: Option<String>,
    },
    /// Sign the current local Merkle root with the current issuer secret only.
    /// This is a locally signed Merkle root. This is not Certificate Transparency.
    SignRoot {
        /// Write the signed tree head JSON to this file. If omitted, print to standard output.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Check a locally signed Merkle tree head. Default: signature plus accept list.
    CheckRoot {
        /// Path to a signed tree head JSON file.
        #[arg(long = "tree-head")]
        tree_head: PathBuf,
        /// Also require merkle_root and leaf_count to match this store's current Merkle root.
        #[arg(long = "require-current-root", default_value_t = false)]
        require_current_root: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ReceiptCommand {
    /// Verify a signed decision receipt. Tampered fields, a missing signature, an unknown issuer key, and a missing issuance-log line fail closed.
    Verify {
        /// Path to a decision receipt JSON file. Holder secrets must not appear in this file.
        #[arg(long)]
        receipt: PathBuf,
        /// Path to the issuance log that must contain the bound line.
        /// If omitted, this store's issuance.log is used.
        /// A foreign receipt needs the foreign issuance log. The log must hash-chain verify.
        #[arg(long = "issuance-log")]
        issuance_log: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum IssuerCommand {
    /// Add a hexadecimal public key to the accepted issuer list. Empty is refused.
    /// Optional kill-date pins that key as an accepted previous key.
    Accept {
        /// Hexadecimal Module-Lattice Digital Signature Algorithm public key this store will trust for receipt verify.
        #[arg(long = "public-key-hex")]
        public_key_hex: String,
        /// RFC3339 UTC kill date for a foreign previous issuer key. Omit for a current pin.
        #[arg(long = "kill-date")]
        kill_date: Option<String>,
    },
    /// Create a new laboratory issuer key pair. The old public key stays on the accept list until kill_date.
    /// issuer.secret becomes the new key only. This is laboratory single-key rotate. This is not threshold issuance.
    Rotate {
        /// Seconds until the old issuer key is past its kill date. The default is a short laboratory window.
        #[arg(long, default_value_t = LABORATORY_ISSUER_ROTATE_KILL_AFTER_SECONDS)]
        kill_after_seconds: u64,
    },
    /// Set a store-wide issuer death time. After that time this store refuses new mint, birth, and spawn, and refuses act.
    /// Historical receipt signature check may still succeed. This is not a previous-key kill_date.
    Seal {
        /// Seconds until the store-wide issuer death. Must be greater than zero. Cannot postpone an existing seal.
        #[arg(long)]
        after_seconds: u64,
    },
    /// Set multi-signature issuance threshold_n. Refuse K < 1. Refuse K greater than the member count. Refuse lowering.
    Threshold {
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
    #[command(subcommand)]
    Member(IssuerMemberCommand),
}

#[derive(Subcommand, Debug)]
enum IssuerMemberCommand {
    /// Install a second Module-Lattice Digital Signature Algorithm member key pair.
    Add {
        /// Write this member secret outside the data directory. A missing path is refused. A path inside the data directory is refused.
        #[arg(long = "secret-path")]
        secret_path: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum KillCommand {
    /// Write event.json, proof.json, and tree-head.json for one kill issuance-log line.
    /// The line must be a kill_instance or kill_capability event. This is an artifact, not a sixth record.
    Export {
        /// Instance identifier of a kill_instance issuance-log line.
        #[arg(long)]
        instance: Option<String>,
        /// Capability identifier of a kill_capability issuance-log line.
        #[arg(long)]
        capability: Option<String>,
        /// Directory that will receive event.json, proof.json, and tree-head.json.
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify a foreign kill bundle against this store accept list. Verify-only. Do not mint.
    /// Persist accepted death on the issuer as verifier state. This is not a sixth identity record.
    Accept {
        /// Directory that holds event.json, proof.json, and tree-head.json.
        #[arg(long)]
        bundle: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum ActCommand {
    /// Write receipt.json, proof.json, and tree-head.json from a signed decision receipt.
    /// Refuse if the receipt line is not in this store issuance log.
    Export {
        /// Path to a signed decision receipt JSON file.
        #[arg(long)]
        receipt: PathBuf,
        /// Directory that will receive receipt.json, proof.json, and tree-head.json.
        #[arg(long = "output-directory")]
        output_directory: PathBuf,
    },
    /// Verify a foreign act bundle against this store accept list. Verify-only. Do not mint.
    Accept {
        /// Directory that holds receipt.json, proof.json, and tree-head.json.
        #[arg(long = "bundle-directory")]
        bundle_directory: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum PresentAction {
    /// Verify a signed presentation document against this store accept list. Verify-only.
    Verify {
        /// Path to a presentation JSON file.
        #[arg(long)]
        presentation: PathBuf,
        /// Laboratory wrap format. json is the historical presentation document. x509-svid wraps that document.
        #[arg(long, default_value = "json")]
        format: String,
        /// Path to the laboratory X.509-SVID PEM when format is x509-svid.
        #[arg(long)]
        svid: Option<PathBuf>,
    },
    /// Verify a laboratory X.509-SVID wrap of a presentation. This is not SPIRE.
    #[command(name = "verify-svid")]
    VerifySvid {
        /// Path to the laboratory X.509-SVID PEM.
        #[arg(long)]
        svid: PathBuf,
        /// Path to the inner presentation JSON. The relying party hashes these bytes.
        #[arg(long)]
        presentation: PathBuf,
    },
    /// Write a laboratory X.509-SVID wrap. Alias for present --format x509-svid.
    Spiffe,
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn attributes_from_flags(
    site: Option<String>,
    region: Option<String>,
    runtime: Option<String>,
) -> BTreeMap<String, String> {
    let mut attributes = BTreeMap::new();
    if let Some(site) = site {
        attributes.insert("site".to_string(), site);
    }
    if let Some(region) = region {
        attributes.insert("region".to_string(), region);
    }
    if let Some(runtime) = runtime {
        attributes.insert("runtime".to_string(), runtime);
    }
    attributes
}

fn holder_proof_from_flags(
    holder_secret_path: Option<PathBuf>,
    holder_proof: Option<String>,
) -> Option<HolderProof> {
    if let Some(path) = holder_secret_path {
        Some(HolderProof::SecretPath(path))
    } else {
        holder_proof.map(HolderProof::SignatureHexadecimal)
    }
}

fn apply_agent_process_add_act(
    process: &mut prometheus_identity::runtime_check::AgentProcess,
    line: &str,
    start_holder_proof: &Option<String>,
    start_holder_proof_command: &Option<String>,
    act_holder_proofs: &mut Vec<Option<String>>,
    act_holder_commands: &mut Vec<Option<String>>,
) -> anyhow::Result<()> {
    let request = prometheus_identity::runtime_check::parse_agent_process_add_act_line(line)?;
    prometheus_identity::runtime_check::refuse_holder_secret_path(
        request
            .holder_secret_path
            .as_deref()
            .map(std::path::Path::new),
    )?;
    let presentation_json = std::fs::read_to_string(&request.presentation_json_path)?;
    let present = if let Some(pem_path) = request.certificate_pem_path {
        let svid_presentation = if let Some(svid_path) = request.svid_presentation_json_path {
            std::fs::read_to_string(&svid_path)?
        } else {
            presentation_json
        };
        prometheus_identity::runtime_check::RuntimePresent::Svid(
            prometheus_identity::runtime_check::SvidPresent {
                presentation_json: svid_presentation,
                certificate_pem: std::fs::read_to_string(&pem_path)?,
            },
        )
    } else if let (Some(token_path), Some(content_digest), Some(signature_input), Some(signature)) = (
        request.workload_identity_token_path,
        request.content_digest,
        request.signature_input,
        request.signature,
    ) {
        prometheus_identity::runtime_check::RuntimePresent::Wimse(
            prometheus_identity::runtime_check::WimsePresent {
                presentation_json,
                workload_identity_token: std::fs::read_to_string(&token_path)?.trim().to_string(),
                content_digest: prometheus_identity::runtime_check::add_act_field_value(
                    &content_digest,
                )?,
                signature_input: prometheus_identity::runtime_check::add_act_field_value(
                    &signature_input,
                )?,
                signature: prometheus_identity::runtime_check::add_act_field_value(&signature)?,
            },
        )
    } else {
        anyhow::bail!(
            "The add-act line needs one on-ramp. Pass --certificate-pem or the documented WIMSE fields. Do not mix an X.509-SVID wrap with a WIMSE present on the same add-act line."
        );
    };
    process.add_act(present)?;
    act_holder_proofs.push(
        request
            .holder_proof
            .filter(|proof| !proof.trim().is_empty())
            .or_else(|| start_holder_proof.clone()),
    );
    act_holder_commands.push(
        request
            .holder_proof_command
            .filter(|command| !command.trim().is_empty())
            .or_else(|| start_holder_proof_command.clone()),
    );
    Ok(())
}

fn caller_holder_signature(
    holder_proof: Option<String>,
    holder_proof_command: Option<String>,
    challenge: &prometheus_identity::runtime_check::RuntimeVerifierChallenge,
) -> prometheus_identity::Result<String> {
    if let Some(proof) = holder_proof {
        if !proof.trim().is_empty() {
            return Ok(proof);
        }
    }
    if let Some(command) = holder_proof_command {
        return holder_signature_from_command(&command, challenge);
    }
    Err(prometheus_identity::Error::denied(
        "A holder signature is required. The laboratory runtime does not read holder secrets. Sign the verifier nonce on the issuing store. The check fails closed.",
    ))
}

fn holder_signature_from_command(
    command: &str,
    challenge: &prometheus_identity::runtime_check::RuntimeVerifierChallenge,
) -> prometheus_identity::Result<String> {
    let mut child = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .env(
            "PROMETHEUS_CHALLENGE_NONCE",
            &challenge.challenge_nonce,
        )
        .env(
            "PROMETHEUS_CHALLENGE_MESSAGE",
            &challenge.challenge_message,
        )
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| {
            prometheus_identity::Error::denied(format!(
                "The holder proof command did not run. The laboratory runtime does not read holder secrets. {error}"
            ))
        })?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin
            .write_all(challenge.challenge_message.as_bytes())
            .map_err(|error| prometheus_identity::Error::kernel(error.to_string()))?;
    }
    let output = child.wait_with_output().map_err(|error| {
        prometheus_identity::Error::denied(format!(
            "The holder proof command did not write a holder signature. {error}"
        ))
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(prometheus_identity::Error::denied(format!(
            "The holder proof command did not write a holder signature. The check fails closed. {stderr}"
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&stdout) {
        if let Some(proof) = value["holder_proof"].as_str() {
            let proof = proof.trim();
            if !proof.is_empty() {
                return Ok(proof.to_string());
            }
        }
    }
    if stdout.is_empty() {
        return Err(prometheus_identity::Error::denied(
            "The holder proof command wrote an empty holder signature. The check fails closed.",
        ));
    }
    Ok(stdout)
}

fn print_check_decision(decision: &prometheus_identity::CheckDecision) -> ExitCode {
    println!(
        "{}",
        serde_json::to_string_pretty(decision).unwrap_or_else(|_| "{}".to_string())
    );
    if decision.result == "allowed" {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn run_authorized_tool(command: &str) -> Result<()> {
    let status = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .status()
        .map_err(|error| {
            anyhow::anyhow!("The tool command did not run. The check fails closed. {error}")
        })?;
    if !status.success() {
        anyhow::bail!(
            "The tool command failed after ALLOWED. This process does not override a refuse."
        );
    }
    Ok(())
}

fn run() -> Result<ExitCode> {
    let arguments = Arguments::parse();
    if let Command::HolderSign {
        holder_secret_path,
        challenge_message,
    } = &arguments.command
    {
        let environment_message =
            prometheus_identity::holder_sign::environment_challenge_message()?;
        let proof = prometheus_identity::holder_sign::sign_holder_proof(
            holder_secret_path,
            environment_message.as_deref(),
            challenge_message.as_deref(),
        )?;
        println!("{proof}");
        return Ok(ExitCode::SUCCESS);
    }
    let kernel = Kernel::open_with_member_secrets(
        &arguments.data_directory,
        arguments.member_secret.clone(),
    )?;

    match arguments.command {
        Command::HolderSign { .. } => {
            unreachable!("holder-sign does not open a data directory")
        }
        Command::Init { crypto_profile } => {
            let issuer = kernel.initialize_with_crypto_profile(&crypto_profile)?;
            print_json(&issuer)?;
        }
        Command::Status => {
            let status = kernel.store_status()?;
            print!("{}", status.format_human());
            println!();
            println!("JSON");
            print_json(&status)?;
        }
        Command::Birth {
            agent_type,
            owner,
            intent,
            audience,
            on_behalf_of,
            site,
            region,
            runtime,
        } => {
            let birth = kernel.birth_write(
                &agent_type,
                owner,
                attributes_from_flags(site, region, runtime),
                &intent,
                &audience,
                on_behalf_of,
            )?;
            print_json(&birth)?;
        }
        Command::Spawn {
            parent_instance,
            parent_capability,
            owner,
            intent,
            audience,
            on_behalf_of,
            holder_secret_path,
            holder_proof,
            challenge_nonce,
        } => {
            let proof = holder_proof_from_flags(holder_secret_path, holder_proof);
            let spawn = kernel.spawn_child(
                &parent_instance,
                &parent_capability,
                owner,
                BTreeMap::new(),
                &intent,
                &audience,
                on_behalf_of,
                proof.as_ref(),
                challenge_nonce.as_deref(),
            )?;
            print_json(&spawn)?;
        }
        Command::Challenge {
            instance,
            lifetime_seconds,
        } => {
            let challenge =
                kernel.issue_holder_challenge_with_lifetime(&instance, lifetime_seconds)?;
            print_json(&challenge)?;
        }
        Command::Check {
            instance,
            capability,
            intent,
            audience,
            holder_secret_path,
            holder_proof,
            challenge_nonce,
            on_behalf_of,
        } => {
            let proof = holder_proof_from_flags(holder_secret_path, holder_proof);
            let decision = kernel.check_tool_action(
                &instance,
                capability.as_deref(),
                &intent,
                &audience,
                proof.as_ref(),
                challenge_nonce.as_deref(),
                on_behalf_of.as_deref(),
            )?;
            return Ok(print_check_decision(&decision));
        }
        Command::Host {
            listen_address,
            check_only,
            public_check_name,
        } => {
            prometheus_identity::host::run_host_from_flags(
                &kernel,
                &listen_address,
                check_only,
                public_check_name.as_deref(),
            )?;
        }
        Command::RuntimeCheck(RuntimeCheckCommand::Act {
            base_url,
            presentation_json,
            certificate_pem,
            workload_identity_token,
            content_digest,
            signature_input,
            signature,
            holder_proof,
            holder_proof_command,
            holder_secret_path,
        }) => {
            prometheus_identity::runtime_check::refuse_holder_secret_path(
                holder_secret_path.as_deref(),
            )?;
            let on_ramp = prometheus_identity::runtime_check::one_shot_on_ramp(
                "act",
                certificate_pem.is_some(),
                workload_identity_token.is_some(),
                content_digest.is_some(),
                signature_input.is_some(),
                signature.is_some(),
            )?;
            let presentation_json = std::fs::read_to_string(&presentation_json)?;
            let present = match on_ramp {
                prometheus_identity::runtime_check::OneShotOnRamp::Svid => {
                    let pem_path = certificate_pem.ok_or_else(|| {
                        anyhow::anyhow!(
                            "The laboratory runtime act verb selected the X.509-SVID on-ramp. Pass --certificate-pem."
                        )
                    })?;
                    prometheus_identity::runtime_check::RuntimePresent::Svid(
                        prometheus_identity::runtime_check::SvidPresent {
                            presentation_json,
                            certificate_pem: std::fs::read_to_string(&pem_path)?,
                        },
                    )
                }
                prometheus_identity::runtime_check::OneShotOnRamp::Wimse => {
                    if let (
                        Some(token_path),
                        Some(content_digest),
                        Some(signature_input),
                        Some(signature),
                    ) = (
                        workload_identity_token,
                        content_digest,
                        signature_input,
                        signature,
                    ) {
                        prometheus_identity::runtime_check::RuntimePresent::Wimse(
                            prometheus_identity::runtime_check::WimsePresent {
                                presentation_json,
                                workload_identity_token: std::fs::read_to_string(&token_path)?
                                    .trim()
                                    .to_string(),
                                content_digest,
                                signature_input,
                                signature,
                            },
                        )
                    } else {
                        anyhow::bail!(
                            "The laboratory runtime act verb WIMSE present needs --workload-identity-token, --content-digest, --signature-input, and --signature. This command does not open a third presenter."
                        );
                    }
                }
            };
            let decision =
                prometheus_identity::runtime_check::act(&base_url, &present, move |challenge| {
                    caller_holder_signature(
                        holder_proof.clone(),
                        holder_proof_command.clone(),
                        challenge,
                    )
                })?;
            return Ok(print_check_decision(&decision));
        }
        Command::RuntimeCheck(RuntimeCheckCommand::Challenge { base_url }) => {
            let runtime =
                prometheus_identity::runtime_check::LaboratoryRuntime::connect(&base_url)?;
            let challenge = runtime.request_verifier_challenge()?;
            print_json(&serde_json::json!({
                "challenge_nonce": challenge.challenge_nonce,
                "challenge_message": challenge.challenge_message,
            }))?;
        }
        Command::RuntimeCheck(RuntimeCheckCommand::Wimse {
            base_url,
            presentation_json,
            workload_identity_token,
            content_digest,
            signature_input,
            signature,
            holder_proof,
            challenge_nonce,
        }) => {
            let runtime =
                prometheus_identity::runtime_check::LaboratoryRuntime::connect(&base_url)?;
            let present = prometheus_identity::runtime_check::WimsePresent {
                presentation_json: std::fs::read_to_string(&presentation_json)?,
                workload_identity_token: std::fs::read_to_string(&workload_identity_token)?
                    .trim()
                    .to_string(),
                content_digest,
                signature_input,
                signature,
            };
            let decision =
                runtime.post_named_wimse_check(&present, &challenge_nonce, &holder_proof)?;
            return Ok(print_check_decision(&decision));
        }
        Command::RuntimeCheck(RuntimeCheckCommand::Svid {
            base_url,
            presentation_json,
            certificate_pem,
            holder_proof,
            challenge_nonce,
        }) => {
            let runtime =
                prometheus_identity::runtime_check::LaboratoryRuntime::connect(&base_url)?;
            let present = prometheus_identity::runtime_check::SvidPresent {
                presentation_json: std::fs::read_to_string(&presentation_json)?,
                certificate_pem: std::fs::read_to_string(&certificate_pem)?,
            };
            let decision =
                runtime.post_named_svid_check(&present, &challenge_nonce, &holder_proof)?;
            return Ok(print_check_decision(&decision));
        }
        Command::RuntimeCheck(RuntimeCheckCommand::BeforeTool {
            base_url,
            presentation_json,
            certificate_pem,
            workload_identity_token,
            content_digest,
            signature_input,
            signature,
            holder_proof,
            holder_proof_command,
            holder_secret_path,
            tool,
        }) => {
            prometheus_identity::runtime_check::refuse_holder_secret_path(
                holder_secret_path.as_deref(),
            )?;
            let on_ramp = prometheus_identity::runtime_check::one_shot_on_ramp(
                "before-tool",
                certificate_pem.is_some(),
                workload_identity_token.is_some(),
                content_digest.is_some(),
                signature_input.is_some(),
                signature.is_some(),
            )?;
            let presentation_json = std::fs::read_to_string(&presentation_json)?;
            let present = match on_ramp {
                prometheus_identity::runtime_check::OneShotOnRamp::Svid => {
                    let pem_path = certificate_pem.ok_or_else(|| {
                        anyhow::anyhow!(
                            "The laboratory runtime before-tool verb selected the X.509-SVID on-ramp. Pass --certificate-pem."
                        )
                    })?;
                    prometheus_identity::runtime_check::RuntimePresent::Svid(
                        prometheus_identity::runtime_check::SvidPresent {
                            presentation_json,
                            certificate_pem: std::fs::read_to_string(&pem_path)?,
                        },
                    )
                }
                prometheus_identity::runtime_check::OneShotOnRamp::Wimse => {
                    if let (
                        Some(token_path),
                        Some(content_digest),
                        Some(signature_input),
                        Some(signature),
                    ) = (
                        workload_identity_token,
                        content_digest,
                        signature_input,
                        signature,
                    ) {
                        prometheus_identity::runtime_check::RuntimePresent::Wimse(
                            prometheus_identity::runtime_check::WimsePresent {
                                presentation_json,
                                workload_identity_token: std::fs::read_to_string(&token_path)?
                                    .trim()
                                    .to_string(),
                                content_digest,
                                signature_input,
                                signature,
                            },
                        )
                    } else {
                        anyhow::bail!(
                            "The laboratory runtime before-tool verb WIMSE present needs --workload-identity-token, --content-digest, --signature-input, and --signature. This command does not open a third presenter."
                        );
                    }
                }
            };
            let outcome = prometheus_identity::runtime_check::before_tool(
                &base_url,
                &present,
                move |challenge| {
                    caller_holder_signature(
                        holder_proof.clone(),
                        holder_proof_command.clone(),
                        challenge,
                    )
                },
                None::<fn()>,
            );
            if !outcome.tool_may_run() {
                println!("REFUSED");
                match &outcome.decision {
                    Ok(decision) => {
                        if let Some(reason) = &decision.reason {
                            eprintln!("{reason}");
                        }
                    }
                    Err(error) => eprintln!("{error}"),
                }
                return Ok(ExitCode::from(outcome.exit_code()));
            }
            println!("ALLOWED");
            if let Some(command) = tool {
                run_authorized_tool(&command)?;
            }
            return Ok(ExitCode::SUCCESS);
        }
        Command::RuntimeCheck(RuntimeCheckCommand::AgentProcess {
            base_url,
            presentation_json,
            certificate_pem,
            svid_presentation_json,
            workload_identity_token,
            content_digest,
            signature_input,
            signature,
            holder_proof,
            holder_proof_command,
            holder_secret_path,
        }) => {
            prometheus_identity::runtime_check::refuse_holder_secret_path(
                holder_secret_path.as_deref(),
            )?;
            let presentation_json = std::fs::read_to_string(&presentation_json)?;
            let mut presents = Vec::new();
            if let Some(pem_path) = certificate_pem {
                let svid_presentation = if let Some(svid_path) = svid_presentation_json {
                    std::fs::read_to_string(&svid_path)?
                } else {
                    presentation_json.clone()
                };
                presents.push(prometheus_identity::runtime_check::RuntimePresent::Svid(
                    prometheus_identity::runtime_check::SvidPresent {
                        presentation_json: svid_presentation,
                        certificate_pem: std::fs::read_to_string(&pem_path)?,
                    },
                ));
            }
            if let (
                Some(token_path),
                Some(content_digest),
                Some(signature_input),
                Some(signature),
            ) = (
                workload_identity_token,
                content_digest,
                signature_input,
                signature,
            ) {
                presents.push(prometheus_identity::runtime_check::RuntimePresent::Wimse(
                    prometheus_identity::runtime_check::WimsePresent {
                        presentation_json,
                        workload_identity_token: std::fs::read_to_string(&token_path)?
                            .trim()
                            .to_string(),
                        content_digest,
                        signature_input,
                        signature,
                    },
                ));
            }
            if presents.is_empty() {
                anyhow::bail!(
                    "The laboratory runtime agent-process verb needs a laboratory X.509-SVID wrap. Pass --certificate-pem. WIMSE uses the same verb with the documented check path. Both on-ramp Assertion Acts may sit on one process. This command does not open a third presenter."
                );
            }
            let start_act_count = presents.len();
            let mut process =
                prometheus_identity::runtime_check::AgentProcess::start_acts(&base_url, presents)?;
            let mut act_holder_proofs: Vec<Option<String>> =
                vec![holder_proof.clone(); start_act_count];
            let mut act_holder_commands: Vec<Option<String>> =
                vec![holder_proof_command.clone(); start_act_count];
            let stdin = std::io::stdin();
            for line in std::io::BufRead::lines(stdin.lock()) {
                let line = line?;
                if line == "stop" {
                    break;
                }
                if prometheus_identity::runtime_check::is_agent_process_add_act_line(&line) {
                    match apply_agent_process_add_act(
                        &mut process,
                        &line,
                        &holder_proof,
                        &holder_proof_command,
                        &mut act_holder_proofs,
                        &mut act_holder_commands,
                    ) {
                        Ok(()) => {
                            println!("ADDED");
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                        }
                        Err(error) => {
                            println!("REFUSED");
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                            eprintln!("{error}");
                        }
                    }
                    continue;
                }
                if prometheus_identity::runtime_check::is_agent_process_named_act_line(&line) {
                    match prometheus_identity::runtime_check::parse_agent_process_named_act_line(
                        &line,
                    ) {
                        Ok((act_number, tool_command)) => {
                            let holder_index = act_number.saturating_sub(1);
                            let outcome = process.before_named_act(
                                act_number,
                                |challenge| {
                                    caller_holder_signature(
                                        act_holder_proofs.get(holder_index).cloned().flatten(),
                                        act_holder_commands.get(holder_index).cloned().flatten(),
                                        challenge,
                                    )
                                },
                                None::<fn()>,
                            );
                            if !outcome.tool_may_run() {
                                println!("REFUSED");
                                let _ = std::io::Write::flush(&mut std::io::stdout());
                                match &outcome.decision {
                                    Ok(decision) => {
                                        if let Some(reason) = &decision.reason {
                                            eprintln!("{reason}");
                                        }
                                    }
                                    Err(error) => eprintln!("{error}"),
                                }
                                continue;
                            }
                            println!("ALLOWED");
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                            if !tool_command.is_empty() {
                                if let Err(error) = run_authorized_tool(&tool_command) {
                                    eprintln!("{error}");
                                }
                            }
                        }
                        Err(error) => {
                            println!("REFUSED");
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                            eprintln!("{error}");
                        }
                    }
                    continue;
                }
                let sign_index = std::cell::Cell::new(0);
                let outcome = process.before_next_tool(
                    |challenge| {
                        let index = sign_index.get();
                        sign_index.set(index + 1);
                        caller_holder_signature(
                            act_holder_proofs.get(index).cloned().flatten(),
                            act_holder_commands.get(index).cloned().flatten(),
                            challenge,
                        )
                    },
                    None::<fn()>,
                );
                if !outcome.tool_may_run() {
                    println!("REFUSED");
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                    match &outcome.decision {
                        Ok(decision) => {
                            if let Some(reason) = &decision.reason {
                                eprintln!("{reason}");
                            }
                        }
                        Err(error) => eprintln!("{error}"),
                    }
                    continue;
                }
                println!("ALLOWED");
                let _ = std::io::Write::flush(&mut std::io::stdout());
                if !line.is_empty() {
                    if let Err(error) = run_authorized_tool(&line) {
                        eprintln!("{error}");
                    }
                }
            }
            return Ok(ExitCode::SUCCESS);
        }
        Command::AgentType(AgentTypeCommand::Add {
            owner,
            mut intents,
            authorization_limit,
            max_delegation_depth,
            crypto_profile,
            lifetime_seconds,
        }) => {
            if intents.is_empty() {
                intents.push("read".to_string());
            }
            let agent_type = kernel.add_agent_type(
                owner,
                intents,
                authorization_limit,
                max_delegation_depth,
                crypto_profile,
                lifetime_seconds,
            )?;
            print_json(&agent_type)?;
        }
        Command::AgentType(AgentTypeCommand::Raise {
            agent_type,
            authorization_limit,
        }) => match kernel.raise_authorization_limit(&agent_type, &authorization_limit) {
            Ok(_) => {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "result": "refused",
                        "reason": "The authorization limit is frozen after the first write. A later write that raises authorization_limit is refused. If the new limit is not allowed by the stored limit, it is a raise. The type must not become more powerful than at birth. This is not a sixth identity record."
                    })
                );
                return Ok(ExitCode::from(1));
            }
            Err(error) => {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "result": "refused",
                        "reason": error.to_string()
                    })
                );
                return Ok(ExitCode::from(1));
            }
        },
        Command::AgentType(AgentTypeCommand::AddIntent { agent_type, intent }) => {
            match kernel.add_allowed_intent(&agent_type, &intent) {
                Ok(_) => {
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "result": "refused",
                            "reason": "The allowed intents are frozen after the first write. A later write that adds an intent is refused. Adding an intent is a golden-ticket-class raise. The type must not become more powerful than at birth. This is not a sixth identity record."
                        })
                    );
                    return Ok(ExitCode::from(1));
                }
                Err(error) => {
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "result": "refused",
                            "reason": error.to_string()
                        })
                    );
                    return Ok(ExitCode::from(1));
                }
            }
        }
        Command::Instance(InstanceCommand::Birth {
            agent_type,
            owner,
            site,
            region,
            runtime,
        }) => {
            let instance = kernel.birth_instance(
                &agent_type,
                owner,
                attributes_from_flags(site, region, runtime),
                None,
            )?;
            print_json(&instance)?;
        }
        Command::Instance(InstanceCommand::Kill { instance }) => {
            let instance = kernel.kill_instance(&instance)?;
            print_json(&instance)?;
        }
        Command::Instance(InstanceCommand::Show { instance }) => {
            let instance = kernel.show_instance(&instance)?;
            print_json(&instance)?;
        }
        Command::Instance(InstanceCommand::Rebind {
            instance,
            public_key_hex,
        }) => match kernel.rebind_holder_public_key(&instance, &public_key_hex) {
            Ok(_) => {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "result": "refused",
                        "reason": "The first binder is written once at birth. A later write that replaces holder_public_key is refused. Identity is not the key. The holder public key is not replaceable. This is not a remote proof-of-possession protocol. This is not SPIFFE."
                    })
                );
                return Ok(ExitCode::from(1));
            }
            Err(error) => {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "result": "refused",
                        "reason": error.to_string()
                    })
                );
                return Ok(ExitCode::from(1));
            }
        },
        Command::Capability(CapabilityCommand::Mint {
            instance,
            intent,
            audience,
            on_behalf_of,
        }) => {
            let capability = kernel.mint_capability(&instance, &intent, &audience, on_behalf_of)?;
            print_json(&capability)?;
        }
        Command::Capability(CapabilityCommand::Attenuate {
            capability,
            audience,
            intent,
        }) => {
            let capability =
                kernel.attenuate_capability(&capability, &audience, intent.as_deref())?;
            print_json(&capability)?;
        }
        Command::Capability(CapabilityCommand::Verify {
            capability,
            audience,
            intent,
            holder_secret_path,
            holder_proof,
            challenge_nonce,
            on_behalf_of,
        }) => {
            let proof = holder_proof_from_flags(holder_secret_path, holder_proof);
            let decision = kernel.verify_capability_decision(
                &capability,
                &audience,
                &intent,
                proof.as_ref(),
                challenge_nonce.as_deref(),
                on_behalf_of.as_deref(),
            )?;
            return Ok(print_check_decision(&decision));
        }
        Command::Capability(CapabilityCommand::Kill { capability }) => {
            let capability = kernel.kill_capability(&capability)?;
            print_json(&capability)?;
        }
        Command::Capability(CapabilityCommand::Extend {
            capability,
            expires_at,
        }) => match kernel.extend_capability_expiry(&capability, &expires_at) {
            Ok(_) => {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "result": "refused",
                        "reason": "The capability expiry is frozen after the first write. A later write that moves expires later is refused. An extension is a golden-ticket-class extension. The capability must not outlive the mint. This is not a sixth identity record."
                    })
                );
                return Ok(ExitCode::from(1));
            }
            Err(error) => {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "result": "refused",
                        "reason": error.to_string()
                    })
                );
                return Ok(ExitCode::from(1));
            }
        },
        Command::Log(LogCommand::Show) => {
            let text = kernel.show_log()?;
            if text.is_empty() {
                println!("The issuance log is empty.");
            } else {
                print!("{text}");
            }
        }
        Command::Log(LogCommand::Verify) => {
            kernel.verify_log_chain()?;
            println!(
                "{}",
                serde_json::json!({
                    "result": "accepted",
                    "message": "The issuance log hash chain is intact. This is a local hash chain. This is not a public append-only service."
                })
            );
        }
        Command::Log(LogCommand::Root) => {
            let root = kernel.issuance_log_merkle_root()?;
            println!(
                "{}",
                serde_json::json!({
                    "root": root.root,
                    "leaf_count": root.leaf_count,
                    "message": "This is a local Merkle tree over the hash-chained issuance log. This is not a public transparency log."
                })
            );
        }
        Command::Log(LogCommand::Prove { line_hash }) => {
            let proof = kernel.prove_issuance_log_inclusion(&line_hash)?;
            print_json(&proof)?;
        }
        Command::Log(LogCommand::CheckProof { proof, root }) => {
            let text = std::fs::read_to_string(&proof).map_err(|error| {
                anyhow::anyhow!("The inclusion proof file could not be read: {error}")
            })?;
            if text.trim().is_empty() {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "result": "refused",
                        "reason": "The inclusion proof is empty. The check fails closed."
                    })
                );
                return Ok(ExitCode::from(1));
            }
            let parsed: prometheus_identity::log_proof::IssuanceLogInclusionProof =
                serde_json::from_str(&text).map_err(|error| {
                    anyhow::anyhow!("The inclusion proof fields did not parse: {error}")
                })?;
            match kernel.check_issuance_log_inclusion_proof(&parsed, root.as_deref()) {
                Ok(()) => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "result": "accepted",
                            "message": "The inclusion proof recomputes to the expected Merkle root. This is a local Merkle tree over the hash-chained issuance log. This is not a public transparency log."
                        })
                    );
                }
                Err(error) => {
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "result": "refused",
                            "reason": error.to_string()
                        })
                    );
                    return Ok(ExitCode::from(1));
                }
            }
        }
        Command::Log(LogCommand::SignRoot { output }) => {
            let tree_head = kernel.sign_issuance_log_tree_head()?;
            let pretty = serde_json::to_string_pretty(&tree_head)?;
            if let Some(path) = output {
                std::fs::write(&path, format!("{pretty}\n")).map_err(|error| {
                    anyhow::anyhow!("The signed tree head file could not be written: {error}")
                })?;
            }
            println!("{pretty}");
        }
        Command::Log(LogCommand::CheckRoot {
            tree_head,
            require_current_root,
        }) => {
            let text = std::fs::read_to_string(&tree_head).map_err(|error| {
                anyhow::anyhow!("The signed tree head file could not be read: {error}")
            })?;
            let parsed =
                match prometheus_identity::log_tree_head::parse_signed_tree_head_json(&text) {
                    Ok(value) => value,
                    Err(error) => {
                        eprintln!(
                            "{}",
                            serde_json::json!({
                                "result": "refused",
                                "reason": error.to_string()
                            })
                        );
                        return Ok(ExitCode::from(1));
                    }
                };
            match kernel.check_issuance_log_tree_head(&parsed, require_current_root) {
                Ok(()) => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "result": "accepted",
                            "message": "The signed tree head signature matches the key in the file and that key is on this store accept list. This is a locally signed Merkle root. This is not Certificate Transparency."
                        })
                    );
                }
                Err(error) => {
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "result": "refused",
                            "reason": error.to_string()
                        })
                    );
                    return Ok(ExitCode::from(1));
                }
            }
        }
        Command::Issuer(IssuerCommand::Accept {
            public_key_hex,
            kill_date,
        }) => {
            let issuer = if let Some(kill_date_text) = kill_date {
                let parsed = chrono::DateTime::parse_from_rfc3339(kill_date_text.trim())
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "The kill_date value must be RFC3339 UTC: {error}. The check fails closed."
                        )
                    })?
                    .with_timezone(&chrono::Utc);
                kernel.accept_previous_issuer_key(&public_key_hex, parsed)?
            } else {
                kernel.accept_issuer_public_key(&public_key_hex)?
            };
            print_json(&issuer)?;
        }
        Command::Issuer(IssuerCommand::Rotate { kill_after_seconds }) => {
            let issuer = kernel.rotate_issuer_key(kill_after_seconds)?;
            print_json(&issuer)?;
        }
        Command::Issuer(IssuerCommand::Seal { after_seconds }) => {
            let issuer = kernel.seal_issuer(after_seconds)?;
            print_json(&issuer)?;
        }
        Command::Issuer(IssuerCommand::Threshold { n }) => {
            let issuer = kernel.set_issuer_threshold(n)?;
            print_json(&issuer)?;
        }
        Command::Issuer(IssuerCommand::VerifyThreshold { n }) => {
            let issuer = kernel.set_verify_threshold(n)?;
            print_json(&issuer)?;
        }
        Command::Issuer(IssuerCommand::Member(IssuerMemberCommand::Add { secret_path })) => {
            let issuer = kernel.add_issuer_member_with_secret_path(Some(secret_path.as_path()))?;
            print_json(&issuer)?;
        }
        Command::Receipt(ReceiptCommand::Verify {
            receipt,
            issuance_log,
        }) => {
            let text = std::fs::read_to_string(&receipt)
                .map_err(|error| anyhow::anyhow!("The receipt file could not be read: {error}"))?;
            let parsed: DecisionReceipt = serde_json::from_str(&text)
                .map_err(|error| anyhow::anyhow!("The receipt fields did not parse: {error}"))?;
            match kernel
                .verify_decision_receipt_against_issuance_log(&parsed, issuance_log.as_deref())
            {
                Ok(()) => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "result": "accepted",
                            "message": "The decision receipt signature matches an accepted issuer public key, the issuance-log line is present, and the issuance log hash chain is intact. This is an accept list. This is not a global name system. This is not SPIFFE federation."
                        })
                    );
                }
                Err(error) => {
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "result": "refused",
                            "reason": error.to_string()
                        })
                    );
                    return Ok(ExitCode::from(1));
                }
            }
        }
        Command::Act(ActCommand::Export {
            receipt,
            output_directory,
        }) => {
            let text = std::fs::read_to_string(&receipt)
                .map_err(|error| anyhow::anyhow!("The receipt file could not be read: {error}"))?;
            if text.trim().is_empty() {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "result": "refused",
                        "reason": "The receipt file is empty. The act export fails closed."
                    })
                );
                return Ok(ExitCode::from(1));
            }
            let parsed: DecisionReceipt = serde_json::from_str(&text)
                .map_err(|error| anyhow::anyhow!("The receipt fields did not parse: {error}"))?;
            match kernel.export_act_bundle(&parsed, &output_directory) {
                Ok(_) => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "result": "accepted",
                            "output_directory": output_directory.display().to_string(),
                            "message": "The act bundle was written as receipt.json, proof.json, and tree-head.json. This is a local export of three existing artifacts. This is not a global name system. This is not SPIFFE federation. This is not Certificate Transparency gossip."
                        })
                    );
                }
                Err(error) => {
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "result": "refused",
                            "reason": error.to_string()
                        })
                    );
                    return Ok(ExitCode::from(1));
                }
            }
        }
        Command::Act(ActCommand::Accept { bundle_directory }) => {
            match kernel.accept_act_bundle(&bundle_directory) {
                Ok(()) => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "result": "accepted",
                            "message": "The act bundle verifies against this store accept list. The second store does not become a second identity kernel. This is not a global name system. This is not SPIFFE federation. This is not Certificate Transparency gossip."
                        })
                    );
                }
                Err(error) => {
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "result": "refused",
                            "reason": error.to_string()
                        })
                    );
                    return Ok(ExitCode::from(1));
                }
            }
        }
        Command::Kill(KillCommand::Export {
            instance,
            capability,
            output,
        }) => {
            if output.as_os_str().is_empty() {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "result": "refused",
                        "reason": "The output directory is empty. The kill export fails closed."
                    })
                );
                return Ok(ExitCode::from(1));
            }
            match kernel.export_kill_bundle(instance.as_deref(), capability.as_deref(), &output) {
                Ok(_) => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "result": "accepted",
                            "output": output.display().to_string(),
                            "message": "The kill bundle was written as event.json, proof.json, and tree-head.json. This is a local export of existing artifacts. This is not a sixth identity record. This is not a global name system. This is not SPIFFE federation. This is not Certificate Transparency gossip."
                        })
                    );
                }
                Err(error) => {
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "result": "refused",
                            "reason": error.to_string()
                        })
                    );
                    return Ok(ExitCode::from(1));
                }
            }
        }
        Command::Kill(KillCommand::Accept { bundle }) => match kernel.accept_kill_bundle(&bundle) {
            Ok(_) => {
                println!(
                    "{}",
                    serde_json::json!({
                        "result": "accepted",
                        "message": "The kill bundle verifies against this store accept list. Accepted death is verifier state on the issuer. This is not a sixth identity record. The second store does not become a second identity kernel. This is not a global name system. This is not SPIFFE federation. This is not Certificate Transparency gossip."
                    })
                );
            }
            Err(error) => {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "result": "refused",
                        "reason": error.to_string()
                    })
                );
                return Ok(ExitCode::from(1));
            }
        },
        Command::Present {
            action,
            instance,
            capability,
            output,
            format,
            holder_secret_path,
            holder_proof,
            challenge_nonce,
        } => match action {
            Some(PresentAction::Verify {
                presentation,
                format: verify_format,
                svid,
            }) => {
                if verify_format == "x509-svid" {
                    let svid = svid.ok_or_else(|| {
                        anyhow::anyhow!(
                            "present verify --format x509-svid requires --svid. The relying party hashes the presentation bytes it was shown."
                        )
                    })?;
                    return verify_svid_command(&kernel, &svid, &presentation);
                }
                let text = std::fs::read_to_string(&presentation).map_err(|error| {
                    anyhow::anyhow!("The presentation file could not be read: {error}")
                })?;
                let parsed = match prometheus_identity::presentation::parse_presentation_json(&text)
                {
                    Ok(value) => value,
                    Err(error) => {
                        eprintln!(
                            "{}",
                            serde_json::json!({
                                "result": "refused",
                                "reason": error.to_string()
                            })
                        );
                        return Ok(ExitCode::from(1));
                    }
                };
                match kernel.verify_presentation(&parsed) {
                    Ok(()) => {
                        println!(
                            "{}",
                            serde_json::json!({
                                "result": "accepted",
                                "message": "The presentation signature matches the issuer public key in the file and that key is on this store accept list. The presentation has not expired. This is a signed presentation document, not a name. A laboratory X.509-SVID wrap is a separate artifact."
                            })
                        );
                    }
                    Err(error) => {
                        eprintln!(
                            "{}",
                            serde_json::json!({
                                "result": "refused",
                                "reason": error.to_string()
                            })
                        );
                        return Ok(ExitCode::from(1));
                    }
                }
            }
            Some(PresentAction::VerifySvid { svid, presentation }) => {
                return verify_svid_command(&kernel, &svid, &presentation);
            }
            Some(PresentAction::Spiffe) | None => {
                let emit_svid =
                    matches!(action, Some(PresentAction::Spiffe)) || format == "x509-svid";
                let instance = instance.ok_or_else(|| {
                    anyhow::anyhow!(
                        "The present command requires --instance. Present is a document, not a name. Present is not a bearer document."
                    )
                })?;
                let capability = capability.ok_or_else(|| {
                    anyhow::anyhow!(
                        "The present command requires --capability. The kernel does not guess which capability."
                    )
                })?;
                let output = output.ok_or_else(|| {
                    anyhow::anyhow!(
                        "The present command requires --output. The presentation document must be written to a file."
                    )
                })?;
                if challenge_nonce
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty()
                {
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "result": "refused",
                            "reason": "The present command requires --challenge-nonce from prometheus challenge --instance. Present is not a bearer document. The check fails closed."
                        })
                    );
                    return Ok(ExitCode::from(1));
                }
                let proof = holder_proof_from_flags(holder_secret_path, holder_proof);
                if proof.is_none() {
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "result": "refused",
                            "reason": "A holder proof is required. Pass a holder secret path or a holder signature. Present is not a bearer document. The check fails closed."
                        })
                    );
                    return Ok(ExitCode::from(1));
                }
                if emit_svid {
                    match kernel.present_x509_svid(
                        &instance,
                        &capability,
                        proof.as_ref(),
                        challenge_nonce.as_deref(),
                    ) {
                        Ok(artifact) => {
                            std::fs::write(&output, artifact.presentation_json.as_bytes())
                                .map_err(|error| {
                                    anyhow::anyhow!(
                                        "The presentation file could not be written: {error}"
                                    )
                                })?;
                            let mut svid_path = output.clone();
                            let mut name = svid_path
                                .file_name()
                                .map(|value| value.to_os_string())
                                .unwrap_or_else(|| "present".into());
                            name.push(".svid.pem");
                            svid_path.set_file_name(name);
                            std::fs::write(&svid_path, artifact.certificate_pem.as_bytes())
                                .map_err(|error| {
                                    anyhow::anyhow!(
                                        "The X.509-SVID file could not be written: {error}"
                                    )
                                })?;
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&serde_json::json!({
                                    "presentation": artifact.presentation,
                                    "presentation_path": output,
                                    "svid_path": svid_path,
                                    "spiffe_uri": artifact.spiffe_uri,
                                    "svid_signer": "laboratory-ed25519-envelope",
                                    "message": "The Uniform Resource Identifier subject alternative name names the presentation, not the instance. Short life is not kill. The certificate is signed with the laboratory Ed25519 envelope key. The identity root stays Module-Lattice Digital Signature Algorithm. This is not SPIRE."
                                }))?
                            );
                        }
                        Err(error) => {
                            eprintln!(
                                "{}",
                                serde_json::json!({
                                    "result": "refused",
                                    "reason": error.to_string()
                                })
                            );
                            return Ok(ExitCode::from(1));
                        }
                    }
                } else {
                    match kernel.present_capability(
                        &instance,
                        &capability,
                        proof.as_ref(),
                        challenge_nonce.as_deref(),
                    ) {
                        Ok(presentation) => {
                            let pretty = serde_json::to_string_pretty(&presentation)?;
                            std::fs::write(
                                &output,
                                format!(
                                    "{pretty}
"
                                ),
                            )
                            .map_err(|error| {
                                anyhow::anyhow!(
                                    "The presentation file could not be written: {error}"
                                )
                            })?;
                            println!("{pretty}");
                        }
                        Err(error) => {
                            eprintln!(
                                "{}",
                                serde_json::json!({
                                    "result": "refused",
                                    "reason": error.to_string()
                                })
                            );
                            return Ok(ExitCode::from(1));
                        }
                    }
                }
            }
        },
    }
    Ok(ExitCode::SUCCESS)
}

fn verify_svid_command(
    kernel: &prometheus_identity::Kernel,
    svid: &std::path::Path,
    presentation: &std::path::Path,
) -> Result<ExitCode> {
    let certificate_pem = std::fs::read_to_string(svid)
        .map_err(|error| anyhow::anyhow!("The X.509-SVID file could not be read: {error}"))?;
    let presentation_bytes = std::fs::read(presentation)
        .map_err(|error| anyhow::anyhow!("The presentation file could not be read: {error}"))?;
    match kernel.verify_x509_svid(&certificate_pem, &presentation_bytes) {
        Ok(()) => {
            println!(
                "{}",
                serde_json::json!({
                    "result": "accepted",
                    "message": "The laboratory X.509-SVID wrap parsed. The subject distinguished name is omitted. The Uniform Resource Identifier subject alternative name names the presentation. Present-verify accepted the inner document. Short life is not kill. This is not SPIRE."
                })
            );
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::json!({
                    "result": "refused",
                    "reason": error.to_string()
                })
            );
            Ok(ExitCode::from(1))
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}
