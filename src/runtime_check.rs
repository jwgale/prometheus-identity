//! Laboratory runtime that learns check paths from GET /.well-known/prometheus-check.
//!
//! This runtime is a consumer of the well-known document. This runtime is not
//! an issuer. This runtime is not a directory. This runtime is not a public
//! listener. This runtime is not a sixth identity record.
//!
//! The helper accepts http://127.0.0.1 or https://check.prestigeworldwide.digital.
//! Loopback stays raw HTTP. The locked public name uses TLS and verifies the
//! server name against ordinary public roots. The helper reads check paths and
//! the verifier-challenge path from the document JSON only. The helper does not
//! read holder secrets. The caller supplies the holder signature. Death still wins.

use crate::error::{Error, Result};
use crate::host::LABORATORY_PUBLIC_CHECK_NAME;
use crate::kernel::CheckDecision;
use crate::presentation::parse_presentation_json;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// The one known discovery path. Check paths come from the document, not from this module.
const LABORATORY_WELL_KNOWN_CHECK_PATH: &str = "/.well-known/prometheus-check";

/// On-ramp name used to select a check path from the document list.
pub const LABORATORY_ON_RAMP_WIMSE: &str = "WIMSE";

/// On-ramp name used to select the X.509-SVID check path from the document list.
pub const LABORATORY_ON_RAMP_SVID: &str = "X.509-SVID";

/// Loopback host the laboratory runtime accepts for raw HTTP.
const LABORATORY_LOOPBACK_HOST: &str = "127.0.0.1";

/// Transport chosen from the base URL. Loopback stays raw HTTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeTransport {
    LoopbackHttp,
    PublicHttps,
}

/// Method and path named by the well-known document.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DocumentedPath {
    pub method: String,
    pub path: String,
}

/// Parsed laboratory well-known check document.
/// Paths are taken from this document. This module does not invent check paths.
#[derive(Debug, Clone)]
pub struct WellKnownCheckDocument {
    pub bind: String,
    pub checks: Vec<DocumentedPath>,
    pub verifier_challenge: DocumentedPath,
    pub operator_pin_paths: Vec<DocumentedPath>,
    pub on_ramp_artifacts: Vec<String>,
    pub death_wins: bool,
}

/// Present bytes and the HTTP Message Signature the caller already made.
/// The helper does not read holder secrets or envelope secrets.
#[derive(Debug, Clone)]
pub struct WimsePresent {
    pub presentation_json: String,
    pub workload_identity_token: String,
    pub content_digest: String,
    pub signature_input: String,
    pub signature: String,
}

/// Present bytes and the laboratory X.509-SVID PEM the caller already holds.
/// The helper does not read holder secrets or envelope secrets.
#[derive(Debug, Clone)]
pub struct SvidPresent {
    pub presentation_json: String,
    pub certificate_pem: String,
}

/// Present an agent process can check with one verb.
/// X.509-SVID is the first on-ramp. WIMSE uses the same verb and the documented check path.
/// This is not a third presenter.
#[derive(Debug, Clone)]
pub enum RuntimePresent {
    Svid(SvidPresent),
    Wimse(WimsePresent),
}

/// One-shot act and before-tool name exactly one on-ramp.
/// Mixing an X.509-SVID wrap with a WIMSE present is refused.
/// Completing both checks is the durable agent-process path, not this verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OneShotOnRamp {
    Svid,
    Wimse,
}

/// Verifier nonce returned by the path named in the well-known document.
#[derive(Debug, Clone)]
pub struct RuntimeVerifierChallenge {
    pub challenge_nonce: String,
    pub challenge_message: String,
}

/// First honest well-known bind, checks, and verifier-challenge.
/// A swapped or grown document is not a new allow.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WellKnownPin {
    bind: String,
    checks: Vec<DocumentedPath>,
    verifier_challenge: DocumentedPath,
    operator_pin_paths: Vec<DocumentedPath>,
    on_ramp_artifacts: Vec<String>,
}

impl WellKnownPin {
    fn from_document(document: &WellKnownCheckDocument) -> Self {
        Self {
            bind: document.bind.clone(),
            checks: document.checks.clone(),
            verifier_challenge: document.verifier_challenge.clone(),
            operator_pin_paths: document.operator_pin_paths.clone(),
            on_ramp_artifacts: document.on_ramp_artifacts.clone(),
        }
    }
}

/// Laboratory runtime bound to one accepted check host.
/// The first honest well-known document is pinned for the life of this runtime.
/// A later GET that changes bind, checks, or verifier-challenge is refused.
/// A missing document after that first honest fetch is refused.
/// This runtime does not cache ALLOWED.
#[derive(Debug, Clone)]
pub struct LaboratoryRuntime {
    host: String,
    port: u16,
    transport: RuntimeTransport,
    pinned_well_known: Arc<OnceLock<WellKnownPin>>,
}

impl LaboratoryRuntime {
    /// Accept http://127.0.0.1 or https://check.prestigeworldwide.digital.
    /// HTTP to the locked name is refused. Any other host is refused.
    pub fn connect(base_url: &str) -> Result<Self> {
        let (host, port, transport) = require_runtime_base_url(base_url)?;
        Ok(Self {
            host,
            port,
            transport,
            pinned_well_known: Arc::new(OnceLock::new()),
        })
    }

    pub fn base_url(&self) -> String {
        match self.transport {
            RuntimeTransport::LoopbackHttp => format!("http://{}:{}", self.host, self.port),
            RuntimeTransport::PublicHttps if self.port == 443 => {
                format!("https://{}", self.host)
            }
            RuntimeTransport::PublicHttps => format!("https://{}:{}", self.host, self.port),
        }
    }

    /// GET the well-known document and refuse a document that is not safe to follow.
    /// The first honest document is pinned. A later GET must match that pin.
    /// A swapped or grown document is not a new allow. A restored honest
    /// document may proceed. ALLOWED is not cached.
    pub fn load_document(&self) -> Result<WellKnownCheckDocument> {
        let document = self.fetch_well_known_document()?;
        refuse_well_known_bind_mismatch(self.transport, &self.host, &document)?;
        pin_or_refuse_well_known(&self.pinned_well_known, &document)?;
        Ok(document)
    }

    /// POST a named operator pin using only a path listed in the well-known
    /// document. A missing pin is refused. A write-verb pin is refused.
    /// The document is fetched twice so a swap between resolve and post is refused.
    pub fn post_documented_pin(&self, pin_name: &str, body: &str) -> Result<(u16, String)> {
        let first = self.load_document()?;
        let pin = resolve_operator_pin(&first, pin_name)?;
        let again = self.load_document()?;
        let again_pin = resolve_operator_pin(&again, pin_name)?;
        if pin != again_pin {
            return Err(Error::denied(
                "The well-known check document changed bind, checks, verifier-challenge, or operator pin paths. A swapped or grown document is not a new allow. The laboratory runtime refuses.",
            ));
        }
        self.exchange(&again_pin.method, &again_pin.path, body, &[])
    }

    fn fetch_well_known_document(&self) -> Result<WellKnownCheckDocument> {
        let (status, body) = self.exchange("GET", LABORATORY_WELL_KNOWN_CHECK_PATH, "", &[])?;
        if status != 200 {
            return Err(Error::denied(format!(
                "GET {LABORATORY_WELL_KNOWN_CHECK_PATH} did not return 200. The laboratory runtime refuses. HTTP status {status}."
            )));
        }
        parse_well_known_document(&body)
    }

    /// POST the verifier-challenge path named in the well-known document.
    pub fn request_verifier_challenge(&self) -> Result<RuntimeVerifierChallenge> {
        let document = self.load_document()?;
        self.request_verifier_challenge_from(&document)
    }

    fn request_verifier_challenge_from(
        &self,
        document: &WellKnownCheckDocument,
    ) -> Result<RuntimeVerifierChallenge> {
        require_documented_method(&document.verifier_challenge.method, "verifier-challenge")?;
        let (status, body) = self.exchange(
            &document.verifier_challenge.method,
            &document.verifier_challenge.path,
            "{}",
            &[],
        )?;
        if status != 200 {
            return Err(Error::denied(format!(
                "The documented verifier-challenge path did not return 200. The laboratory runtime refuses. HTTP status {status}."
            )));
        }
        parse_verifier_challenge_body(&body)
    }

    /// On a verifier: load the document, POST the named verifier-challenge path,
    /// then POST the named WIMSE check with the present, the nonce, and the
    /// caller-supplied holder signature. The helper does not read holder secrets.
    pub fn complete_wimse_check<F>(
        &self,
        present: &WimsePresent,
        sign_holder_nonce: F,
    ) -> Result<CheckDecision>
    where
        F: FnOnce(&RuntimeVerifierChallenge) -> Result<String>,
    {
        let document = self.load_document()?;
        let challenge = self.request_verifier_challenge_from(&document)?;
        let holder_proof = sign_holder_nonce(&challenge)?;
        if holder_proof.trim().is_empty() {
            return Err(Error::denied(
                "A holder signature is required. The laboratory runtime does not read holder secrets. The check fails closed.",
            ));
        }
        let document = self.load_document()?;
        self.post_named_wimse_check_from(
            &document,
            present,
            &challenge.challenge_nonce,
            holder_proof.trim(),
        )
    }

    /// POST the WIMSE check path named in the well-known document.
    /// The caller supplies the nonce and the holder signature.
    pub fn post_named_wimse_check(
        &self,
        present: &WimsePresent,
        challenge_nonce: &str,
        holder_proof: &str,
    ) -> Result<CheckDecision> {
        let document = self.load_document()?;
        self.post_named_wimse_check_from(&document, present, challenge_nonce, holder_proof)
    }

    fn post_named_wimse_check_from(
        &self,
        document: &WellKnownCheckDocument,
        present: &WimsePresent,
        challenge_nonce: &str,
        holder_proof: &str,
    ) -> Result<CheckDecision> {
        let check = documented_check_for_on_ramp(document, LABORATORY_ON_RAMP_WIMSE)?;
        require_documented_method(&check.method, "WIMSE check")?;
        let presentation = parse_presentation_json(&present.presentation_json)?;
        let body = serde_json::json!({
            "presentation_json": present.presentation_json,
            "workload_identity_token": present.workload_identity_token,
            "content_digest": present.content_digest,
            "intent": presentation.intent,
            "audience": presentation.audience,
            "holder_proof": holder_proof,
            "challenge_nonce": challenge_nonce,
            "on_behalf_of": "autonomous",
            "signature_input": present.signature_input,
            "signature": present.signature,
        })
        .to_string();
        let extra = [
            ("Signature-Input", present.signature_input.as_str()),
            ("Signature", present.signature.as_str()),
            ("Content-Digest", present.content_digest.as_str()),
        ];
        let (status, response_body) = self.exchange(&check.method, &check.path, &body, &extra)?;
        check_decision_from_http_response(status, &response_body, "WIMSE")
    }

    /// On a verifier: load the document, POST the named verifier-challenge path,
    /// then POST the named X.509-SVID check with the PEM, the present, the nonce,
    /// and the caller-supplied holder signature. The helper does not read holder secrets.
    pub fn complete_svid_check<F>(
        &self,
        present: &SvidPresent,
        sign_holder_nonce: F,
    ) -> Result<CheckDecision>
    where
        F: FnOnce(&RuntimeVerifierChallenge) -> Result<String>,
    {
        let document = self.load_document()?;
        let challenge = self.request_verifier_challenge_from(&document)?;
        let holder_proof = sign_holder_nonce(&challenge)?;
        if holder_proof.trim().is_empty() {
            return Err(Error::denied(
                "A holder signature is required. The laboratory runtime does not read holder secrets. The check fails closed.",
            ));
        }
        let document = self.load_document()?;
        self.post_named_svid_check_from(
            &document,
            present,
            &challenge.challenge_nonce,
            holder_proof.trim(),
        )
    }

    /// POST the X.509-SVID check path named in the well-known document.
    /// The caller supplies the nonce and the holder signature.
    pub fn post_named_svid_check(
        &self,
        present: &SvidPresent,
        challenge_nonce: &str,
        holder_proof: &str,
    ) -> Result<CheckDecision> {
        let document = self.load_document()?;
        self.post_named_svid_check_from(&document, present, challenge_nonce, holder_proof)
    }

    fn post_named_svid_check_from(
        &self,
        document: &WellKnownCheckDocument,
        present: &SvidPresent,
        challenge_nonce: &str,
        holder_proof: &str,
    ) -> Result<CheckDecision> {
        let check = documented_check_for_on_ramp(document, LABORATORY_ON_RAMP_SVID)?;
        require_documented_method(&check.method, "X.509-SVID check")?;
        let presentation = parse_presentation_json(&present.presentation_json)?;
        let body = serde_json::json!({
            "presentation_json": present.presentation_json,
            "certificate_pem": present.certificate_pem,
            "intent": presentation.intent,
            "audience": presentation.audience,
            "holder_proof": holder_proof,
            "challenge_nonce": challenge_nonce,
            "on_behalf_of": "autonomous",
        })
        .to_string();
        let (status, response_body) = self.exchange(&check.method, &check.path, &body, &[])?;
        check_decision_from_http_response(status, &response_body, "X.509-SVID")
    }

    /// One laboratory runtime verb an agent process can call before a tool.
    /// Connect is already bound to an accepted base URL. This verb follows GET
    /// /.well-known/prometheus-check, requests a verifier challenge, and posts
    /// the documented check with a caller-supplied holder signature.
    /// X.509-SVID is the first on-ramp. WIMSE uses the same verb and the documented check path.
    /// This runtime does not read holder secrets. This runtime is not an issuer.
    /// This runtime is not a directory. Unknown is not live. Death still wins.
    pub fn act<F>(&self, present: &RuntimePresent, sign_holder_nonce: F) -> Result<CheckDecision>
    where
        F: FnOnce(&RuntimeVerifierChallenge) -> Result<String>,
    {
        match present {
            RuntimePresent::Svid(present) => self.complete_svid_check(present, sign_holder_nonce),
            RuntimePresent::Wimse(present) => self.complete_wimse_check(present, sign_holder_nonce),
        }
    }

    fn exchange(
        &self,
        method: &str,
        path: &str,
        body: &str,
        extra_headers: &[(&str, &str)],
    ) -> Result<(u16, String)> {
        let host_header = match self.transport {
            RuntimeTransport::LoopbackHttp => format!("{}:{}", self.host, self.port),
            RuntimeTransport::PublicHttps if self.port == 443 => self.host.clone(),
            RuntimeTransport::PublicHttps => format!("{}:{}", self.host, self.port),
        };
        let mut request =
            format!("{method} {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n");
        if method != "GET" {
            request.push_str("Content-Type: application/json\r\n");
            request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        for (name, value) in extra_headers {
            if !value.trim().is_empty() {
                request.push_str(&format!("{name}: {value}\r\n"));
            }
        }
        request.push_str("\r\n");
        if method != "GET" {
            request.push_str(body);
        }
        match self.transport {
            RuntimeTransport::LoopbackHttp => self.exchange_raw_http(&request),
            RuntimeTransport::PublicHttps => self.exchange_public_https(&request),
        }
    }

    fn exchange_raw_http(&self, request: &str) -> Result<(u16, String)> {
        let mut stream = TcpStream::connect((self.host.as_str(), self.port)).map_err(|error| {
            Error::denied(format!(
                "The laboratory runtime could not connect to http://{}:{}. {error}",
                self.host, self.port
            ))
        })?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| Error::kernel(error.to_string()))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| Error::kernel(error.to_string()))?;
        stream
            .write_all(request.as_bytes())
            .map_err(|error| Error::kernel(error.to_string()))?;
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .map_err(|error| Error::kernel(error.to_string()))?;
        parse_http_response(&response)
    }

    fn exchange_public_https(&self, request: &str) -> Result<(u16, String)> {
        let server_name = ServerName::try_from(LABORATORY_PUBLIC_CHECK_NAME.to_string()).map_err(
            |_| {
                Error::denied(
                    "The laboratory public check name is not a valid DNS server name. The check fails closed.",
                )
            },
        )?;
        let tcp = TcpStream::connect((LABORATORY_PUBLIC_CHECK_NAME, self.port)).map_err(|error| {
            Error::denied(format!(
                "The laboratory runtime could not connect to https://{LABORATORY_PUBLIC_CHECK_NAME}. {error}"
            ))
        })?;
        tcp.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| Error::kernel(error.to_string()))?;
        tcp.set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| Error::kernel(error.to_string()))?;
        let connection = ClientConnection::new(public_https_client_config(), server_name).map_err(
            |error| {
                Error::denied(format!(
                    "The laboratory runtime could not start TLS to {LABORATORY_PUBLIC_CHECK_NAME}. The server name is verified against ordinary public roots. {error}"
                ))
            },
        )?;
        let mut tls = StreamOwned::new(connection, tcp);
        tls.write_all(request.as_bytes()).map_err(|error| {
            Error::denied(format!(
                "The laboratory runtime could not write TLS to {LABORATORY_PUBLIC_CHECK_NAME}. The server name is verified against ordinary public roots. {error}"
            ))
        })?;
        let mut response = String::new();
        tls.read_to_string(&mut response).map_err(|error| {
            Error::denied(format!(
                "The laboratory runtime could not read TLS from {LABORATORY_PUBLIC_CHECK_NAME}. The server name is verified against ordinary public roots. {error}"
            ))
        })?;
        parse_http_response(&response)
    }
}

fn public_https_client_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let config = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("the laboratory TLS client uses ordinary public roots")
                .with_root_certificates(roots)
                .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

fn refused_runtime_base_url() -> Error {
    Error::denied(
        "The laboratory runtime accepts http://127.0.0.1 or https://check.prestigeworldwide.digital. Other hosts are refused.",
    )
}

fn require_runtime_base_url(base_url: &str) -> Result<(String, u16, RuntimeTransport)> {
    let trimmed = base_url.trim();
    if let Some(rest) = trimmed.strip_prefix("http://") {
        let (host, port) = parse_base_url_authority(rest, 80)?;
        if host == LABORATORY_LOOPBACK_HOST {
            return Ok((host, port, RuntimeTransport::LoopbackHttp));
        }
        if host.eq_ignore_ascii_case(LABORATORY_PUBLIC_CHECK_NAME) {
            return Err(Error::denied(
                "HTTP to check.prestigeworldwide.digital is refused. The laboratory runtime uses HTTPS for that name. Loopback stays raw HTTP on 127.0.0.1.",
            ));
        }
        return Err(refused_runtime_base_url());
    }
    if let Some(rest) = trimmed.strip_prefix("https://") {
        let (host, port) = parse_base_url_authority(rest, 443)?;
        if host.eq_ignore_ascii_case(LABORATORY_PUBLIC_CHECK_NAME) && port == 443 {
            return Ok((
                LABORATORY_PUBLIC_CHECK_NAME.to_string(),
                443,
                RuntimeTransport::PublicHttps,
            ));
        }
        return Err(refused_runtime_base_url());
    }
    Err(refused_runtime_base_url())
}

fn parse_base_url_authority(rest: &str, default_port: u16) -> Result<(String, u16)> {
    let authority = match rest.split_once('/') {
        None => rest,
        Some((hostport, tail)) if tail.is_empty() => hostport,
        Some(_) => {
            return Err(Error::denied(
                "The laboratory runtime accepts a loopback base URL only. A path on the base URL is refused.",
            ));
        }
    };
    if authority.contains('@') {
        return Err(refused_runtime_base_url());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port_text)) => {
            let port: u16 = port_text.parse().map_err(|_| {
                Error::denied(
                    "The laboratory runtime accepts http://127.0.0.1 or https://check.prestigeworldwide.digital. The port is not valid.",
                )
            })?;
            (host, port)
        }
        None => (authority, default_port),
    };
    if host.is_empty() {
        return Err(refused_runtime_base_url());
    }
    Ok((host.to_string(), port))
}

/// Parse and refuse a well-known document that is not safe to follow.
pub fn parse_well_known_document(raw: &str) -> Result<WellKnownCheckDocument> {
    refuse_secrets_in_document(raw)?;
    let value: serde_json::Value = serde_json::from_str(raw).map_err(|error| {
        Error::denied(format!(
            "The well-known check document is not valid JSON. The laboratory runtime refuses. {error}"
        ))
    })?;
    let bind = value["bind"].as_str().unwrap_or("").trim().to_string();
    if bind != LABORATORY_LOOPBACK_HOST && bind != LABORATORY_PUBLIC_CHECK_NAME {
        return Err(Error::denied(
            "The well-known check document bind must be 127.0.0.1 or check.prestigeworldwide.digital. The laboratory runtime refuses.",
        ));
    }
    if value["instance_identifier_in_path"].as_bool() == Some(true) {
        return Err(Error::denied(
            "The well-known check document names an instance identifier in a path. The laboratory runtime refuses.",
        ));
    }
    let checks = parse_documented_paths(&value["checks"], "checks")?;
    let verifier_challenge =
        parse_one_documented_path(&value["verifier_challenge"], "verifier_challenge")?;
    for documented in checks.iter().chain(std::iter::once(&verifier_challenge)) {
        refuse_instance_identifier_in_path(&documented.path)?;
        refuse_secret_material_in_path(&documented.path)?;
        refuse_write_verb_path(&documented.path)?;
    }
    let on_ramp_artifacts = value["on_ramp_artifacts"]
        .as_array()
        .ok_or_else(|| {
            Error::denied(
                "The well-known check document must name on-ramp artifacts. The laboratory runtime refuses.",
            )
        })?
        .iter()
        .filter_map(|item| item.as_str().map(|text| text.to_string()))
        .collect();
    let operator_pin_paths = parse_optional_operator_pin_paths(&value["operator_pin_paths"])?;
    for documented in &operator_pin_paths {
        refuse_instance_identifier_in_path(&documented.path)?;
        refuse_secret_material_in_path(&documented.path)?;
    }
    Ok(WellKnownCheckDocument {
        bind,
        checks,
        verifier_challenge,
        operator_pin_paths,
        on_ramp_artifacts,
        death_wins: value["death_wins"].as_bool().unwrap_or(false),
    })
}

fn refuse_well_known_bind_mismatch(
    transport: RuntimeTransport,
    host: &str,
    document: &WellKnownCheckDocument,
) -> Result<()> {
    let expected = match transport {
        RuntimeTransport::LoopbackHttp => LABORATORY_LOOPBACK_HOST,
        RuntimeTransport::PublicHttps => LABORATORY_PUBLIC_CHECK_NAME,
    };
    if document.bind != expected || host != expected {
        return Err(Error::denied(
            "The well-known check document bind does not match the accepted check host. http://127.0.0.1 and https://check.prestigeworldwide.digital are not interchangeable. The laboratory runtime refuses.",
        ));
    }
    Ok(())
}

fn pin_or_refuse_well_known(
    pinned: &OnceLock<WellKnownPin>,
    document: &WellKnownCheckDocument,
) -> Result<()> {
    let pin = WellKnownPin::from_document(document);
    let first = pinned.get_or_init(|| pin.clone());
    if first != &pin {
        return Err(Error::denied(
            "The well-known check document changed bind, checks, verifier-challenge, or operator pin paths. A swapped or grown document is not a new allow. The laboratory runtime refuses.",
        ));
    }
    Ok(())
}

fn parse_optional_operator_pin_paths(value: &serde_json::Value) -> Result<Vec<DocumentedPath>> {
    if value.is_null() {
        return Ok(Vec::new());
    }
    if let Some(array) = value.as_array() {
        if array.is_empty() {
            return Ok(Vec::new());
        }
    }
    parse_documented_paths(value, "operator_pin_paths")
}

/// Pin names GET / may resolve from operator_pin_paths, checks[], or verifier-challenge.
/// Paths come from the document. These names are not destination constants.
const OPERATOR_PIN_NAMES: &[&str] = &[
    "issuer-accept",
    "kill-accept",
    "seal-accept",
    "previous-key-accept",
    "act-accept",
    "check-svid",
    "check-wimse",
    "verifier-challenge",
];

fn normalize_pin_name(name: &str) -> String {
    name.trim().trim_start_matches('/').to_ascii_lowercase()
}

fn pin_path_matches(path: &str, want: &str) -> bool {
    let got = normalize_pin_name(path);
    if got == want {
        return true;
    }
    OPERATOR_PIN_NAMES.contains(&want) && got.ends_with(&format!("-{want}"))
}

/// Resolve a pin name to the method and path named by the well-known document.
/// Uses operator_pin_paths, checks[], and verifier_challenge. Refuses a missing
/// pin. Refuses a write-verb pin. The destination is the document path.
pub fn resolve_operator_pin(
    document: &WellKnownCheckDocument,
    pin_name: &str,
) -> Result<DocumentedPath> {
    let want = normalize_pin_name(pin_name);
    if want.is_empty() {
        return Err(Error::denied(
            "The well-known check document does not name that operator pin. The check fails closed.",
        ));
    }
    let documented = if want == "verifier-challenge" {
        document.verifier_challenge.clone()
    } else if want == "check-svid" {
        documented_check_for_on_ramp(document, LABORATORY_ON_RAMP_SVID)?.clone()
    } else if want == "check-wimse" {
        documented_check_for_on_ramp(document, LABORATORY_ON_RAMP_WIMSE)?.clone()
    } else {
        let mut candidates: Vec<&DocumentedPath> = Vec::new();
        candidates.extend(document.operator_pin_paths.iter());
        candidates.extend(document.checks.iter());
        candidates
            .into_iter()
            .find(|item| pin_path_matches(&item.path, &want))
            .cloned()
            .ok_or_else(|| {
                Error::denied(
                    "The well-known check document does not name that operator pin. The check fails closed.",
                )
            })?
    };
    require_documented_method(&documented.method, "operator pin")?;
    refuse_write_verb_path(&documented.path)?;
    refuse_instance_identifier_in_path(&documented.path)?;
    refuse_secret_material_in_path(&documented.path)?;
    Ok(documented)
}

/// Parsed well-known fields GET / may follow. Secret bytes are not included.
pub fn well_known_follow_payload(document: &WellKnownCheckDocument) -> serde_json::Value {
    serde_json::json!({
        "bind": document.bind,
        "checks": document.checks,
        "verifier_challenge": document.verifier_challenge,
        "operator_pin_paths": document.operator_pin_paths,
        "on_ramp_artifacts": document.on_ramp_artifacts,
        "death_wins": document.death_wins
    })
}

fn parse_documented_paths(value: &serde_json::Value, field: &str) -> Result<Vec<DocumentedPath>> {
    let array = value.as_array().ok_or_else(|| {
        Error::denied(format!(
            "The well-known check document must list {field}. The laboratory runtime refuses."
        ))
    })?;
    let mut paths = Vec::new();
    for item in array {
        paths.push(parse_one_documented_path(item, field)?);
    }
    if paths.is_empty() {
        return Err(Error::denied(format!(
            "The well-known check document must list {field}. The laboratory runtime refuses."
        )));
    }
    Ok(paths)
}

fn parse_one_documented_path(value: &serde_json::Value, field: &str) -> Result<DocumentedPath> {
    let method = value["method"].as_str().unwrap_or("").trim().to_string();
    let path = value["path"].as_str().unwrap_or("").trim().to_string();
    if method.is_empty() || path.is_empty() {
        return Err(Error::denied(format!(
            "The well-known check document {field} entry must name a method and a path. The laboratory runtime refuses."
        )));
    }
    if !path.starts_with('/') {
        return Err(Error::denied(
            "A documented path must start with a solidus. The laboratory runtime refuses.",
        ));
    }
    Ok(DocumentedPath { method, path })
}

fn documented_check_for_on_ramp<'a>(
    document: &'a WellKnownCheckDocument,
    on_ramp: &str,
) -> Result<&'a DocumentedPath> {
    let index = document
        .on_ramp_artifacts
        .iter()
        .position(|name| name == on_ramp)
        .ok_or_else(|| {
            Error::denied(format!(
                "The well-known check document does not name the {on_ramp} on-ramp. The laboratory runtime refuses."
            ))
        })?;
    document.checks.get(index).ok_or_else(|| {
        Error::denied(format!(
            "The well-known check document does not name a check path for the {on_ramp} on-ramp. The laboratory runtime refuses."
        ))
    })
}

fn require_documented_method(method: &str, role: &str) -> Result<()> {
    if method != "POST" {
        return Err(Error::denied(format!(
            "The documented {role} path must use POST. The laboratory runtime refuses."
        )));
    }
    Ok(())
}

fn refuse_secrets_in_document(raw: &str) -> Result<()> {
    let lower = raw.to_ascii_lowercase();
    let forbidden = [
        "issuer.secret",
        "biscuit.secret",
        "member-two.secret",
        "holder.secret",
        "holder_secret",
        "holder-secret",
        "holder_secret_path",
        "private_key",
        "private-key",
    ];
    for marker in forbidden {
        if lower.contains(marker) {
            return Err(Error::denied(
                "The well-known check document contains secret material. The laboratory runtime refuses.",
            ));
        }
    }
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) {
        if json_has_secret_key(&value) {
            return Err(Error::denied(
                "The well-known check document contains secret material. The laboratory runtime refuses.",
            ));
        }
    }
    Ok(())
}

fn json_has_secret_key(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => map.iter().any(|(key, child)| {
            let lower = key.to_ascii_lowercase();
            lower == "secret"
                || lower.ends_with("_secret")
                || lower.ends_with("_secret_path")
                || lower.ends_with("_secret_hex")
                || json_has_secret_key(child)
        }),
        serde_json::Value::Array(items) => items.iter().any(json_has_secret_key),
        _ => false,
    }
}

fn refuse_instance_identifier_in_path(path: &str) -> Result<()> {
    let lower = path.to_ascii_lowercase();
    if lower.contains("instance") {
        return Err(Error::denied(
            "The well-known check document names an instance identifier in a path. The laboratory runtime refuses.",
        ));
    }
    if path_contains_ulid(path) {
        return Err(Error::denied(
            "The well-known check document names an instance identifier in a path. The laboratory runtime refuses.",
        ));
    }
    Ok(())
}

fn refuse_write_verb_path(path: &str) -> Result<()> {
    let trimmed = path.trim();
    let lower = trimmed.to_ascii_lowercase();
    let write_verbs = [
        "/birth",
        "/spawn",
        "/present-svid",
        "/present-wimse",
        "/agent-type",
        "/kill",
        "/seal",
        "/rotate",
        "/sign-holder-nonce",
        "/member-two",
        "/set-issuer-threshold",
        "/set-verify-threshold",
        "/challenge",
        "/act-export",
        "/kill-export",
        "/seal-export",
        "/previous-key-export",
    ];
    for verb in write_verbs {
        if lower == verb
            || lower.starts_with(&format!("{verb}/"))
            || lower.starts_with(&format!("{verb}?"))
        {
            return Err(Error::denied(
                "The well-known check document names a write verb. Create Agent Principal, spawn, and Assertion Act mint stay off the check document. The laboratory runtime refuses.",
            ));
        }
    }
    Ok(())
}

fn refuse_secret_material_in_path(path: &str) -> Result<()> {
    let lower = path.to_ascii_lowercase();
    if lower.contains(".secret") {
        return Err(Error::denied(
            "The well-known check document contains secret material. The laboratory runtime refuses.",
        ));
    }
    Ok(())
}

/// Refuse a holder secret path argument. The act verb does not open secret bytes.
pub fn refuse_holder_secret_path(holder_secret_path: Option<&Path>) -> Result<()> {
    if holder_secret_path.is_some() {
        return Err(Error::denied(
            "A holder secret path is refused. The laboratory runtime does not read holder secrets. Secret bytes are not opened. The check fails closed.",
        ));
    }
    Ok(())
}

/// Select the one on-ramp for act or before-tool.
/// A mixed X.509-SVID wrap and WIMSE present is refused.
/// Any WIMSE field plus a certificate PEM is a mix.
/// Completing both checks is the durable agent-process path.
pub fn one_shot_on_ramp(
    verb: &str,
    has_certificate_pem: bool,
    has_workload_identity_token: bool,
    has_content_digest: bool,
    has_signature_input: bool,
    has_signature: bool,
) -> Result<OneShotOnRamp> {
    let has_svid = has_certificate_pem;
    let has_wimse =
        has_workload_identity_token || has_content_digest || has_signature_input || has_signature;
    if has_svid && has_wimse {
        return Err(Error::denied(format!(
            "The laboratory runtime {verb} verb names one on-ramp. Do not mix an X.509-SVID wrap with a WIMSE present on the same {verb} line. Completing both checks is the durable agent-process path. The check fails closed."
        )));
    }
    if has_svid {
        return Ok(OneShotOnRamp::Svid);
    }
    if has_wimse {
        return Ok(OneShotOnRamp::Wimse);
    }
    Err(Error::denied(format!(
        "The laboratory runtime {verb} verb needs one on-ramp. Pass --certificate-pem or the documented WIMSE fields. This command does not open a third presenter."
    )))
}

fn path_contains_ulid(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.len() < 26 {
        return false;
    }
    for window in bytes.windows(26) {
        if is_ulid_bytes(window) {
            return true;
        }
    }
    false
}

fn is_ulid_bytes(bytes: &[u8]) -> bool {
    if bytes.len() != 26 {
        return false;
    }
    let first = bytes[0];
    if !first.is_ascii_digit() || first > b'7' {
        return false;
    }
    bytes[1..].iter().all(|byte| {
        let upper = byte.to_ascii_uppercase();
        matches!(
            upper,
            b'0'..=b'9' | b'A'..=b'H' | b'J' | b'K' | b'M' | b'N' | b'P'..=b'T' | b'V'..=b'Z'
        )
    })
}

fn parse_verifier_challenge_body(body: &str) -> Result<RuntimeVerifierChallenge> {
    let value: serde_json::Value = serde_json::from_str(body).map_err(|error| {
        Error::denied(format!(
            "The documented verifier-challenge path did not return JSON. The laboratory runtime refuses. {error}"
        ))
    })?;
    let challenge_nonce = value["challenge_nonce"]
        .as_str()
        .unwrap_or("")
        .trim()
        .to_string();
    let challenge_message = value["challenge_message"]
        .as_str()
        .unwrap_or("")
        .trim()
        .to_string();
    if challenge_nonce.is_empty() || challenge_message.is_empty() {
        return Err(Error::denied(
            "The documented verifier-challenge path must return a nonce and a challenge message. The laboratory runtime refuses.",
        ));
    }
    Ok(RuntimeVerifierChallenge {
        challenge_nonce,
        challenge_message,
    })
}

/// One laboratory runtime verb. Connect to an accepted base URL, follow GET
/// /.well-known/prometheus-check, request a verifier challenge, and post the
/// documented check with a caller-supplied holder signature.
/// X.509-SVID is the first on-ramp. WIMSE uses the same verb and the documented check path.
/// This runtime does not read holder secrets. This runtime is not an issuer.
/// This runtime is not a directory. Unknown is not live. Death still wins.
pub fn act<F>(
    base_url: &str,
    present: &RuntimePresent,
    sign_holder_nonce: F,
) -> Result<CheckDecision>
where
    F: FnOnce(&RuntimeVerifierChallenge) -> Result<String>,
{
    let runtime = LaboratoryRuntime::connect(base_url)?;
    runtime.act(present, sign_holder_nonce)
}

/// Exit 0 only when the documented check is allowed.
/// Any refuse or transport failure is non-zero. Unknown is not live.
pub fn exit_code_for_runtime_act(result: &Result<CheckDecision>) -> u8 {
    match result {
        Ok(decision) if decision.result == "allowed" => 0,
        _ => 1,
    }
}

/// One-word gate for an agent process that runs before a tool.
/// ALLOWED only when the tool may run. Unknown is not live. This process does not override a refuse.
pub fn gate_line_for_before_tool(result: &Result<CheckDecision>) -> &'static str {
    if exit_code_for_runtime_act(result) == 0 {
        "ALLOWED"
    } else {
        "REFUSED"
    }
}

/// Outcome of the before-tool process. The tool runs only when the act is allowed.
#[derive(Debug)]
pub struct BeforeToolOutcome {
    pub gate: &'static str,
    pub decision: Result<CheckDecision>,
    pub tool_ran: bool,
}

impl BeforeToolOutcome {
    pub fn exit_code(&self) -> u8 {
        exit_code_for_runtime_act(&self.decision)
    }

    pub fn tool_may_run(&self) -> bool {
        self.exit_code() == 0
    }
}

/// Run a tool callback only when the laboratory act gate is allowed.
/// Refuse, unknown, and transport failure do not run the tool. This process does not override a refuse.
pub fn run_tool_only_when_allowed<T>(result: &Result<CheckDecision>, tool: Option<T>) -> bool
where
    T: FnOnce(),
{
    if exit_code_for_runtime_act(result) == 0 {
        if let Some(tool) = tool {
            tool();
            return true;
        }
    }
    false
}

/// Smallest process an agent can run before a tool.
/// Reuses `act` and LaboratoryRuntime. The tool callback runs only when allowed.
/// Transport failure, refuse, and unknown do not run the tool. This process does not override a refuse.
/// This runtime does not read holder secrets. Sign stays with the caller.
pub fn before_tool<F, T>(
    base_url: &str,
    present: &RuntimePresent,
    sign_holder_nonce: F,
    tool: Option<T>,
) -> BeforeToolOutcome
where
    F: FnOnce(&RuntimeVerifierChallenge) -> Result<String>,
    T: FnOnce(),
{
    let decision = act(base_url, present, sign_holder_nonce);
    let tool_ran = run_tool_only_when_allowed(&decision, tool);
    BeforeToolOutcome {
        gate: gate_line_for_before_tool(&decision),
        decision,
        tool_ran,
    }
}

/// Durable agent process. This process is a feature, not chrome.
/// This process is not a one-shot Saturday walk script.
/// This process is not a public listener. This process is not a store.
/// This process does not cache ALLOWED. Death is picked up without a restart.
/// The first honest well-known document is pinned for the life of this process.
/// One process lifetime may hold more than one Assertion Act. X.509-SVID and
/// WIMSE may sit together. A later Assertion Act may be added without a restart.
/// Every held act is re-checked before a tool. The tool runs only when every
/// held act is allowed. This is not a third presenter.
#[derive(Debug, Clone)]
pub struct AgentProcess {
    runtime: LaboratoryRuntime,
    presents: Vec<RuntimePresent>,
}

impl AgentProcess {
    /// Bind one accepted check host and one Assertion Act. Validate the base URL now.
    /// This process is not a public listener. This process is not a store.
    pub fn start(base_url: &str, present: RuntimePresent) -> Result<Self> {
        Self::start_acts(base_url, vec![present])
    }

    /// Bind one accepted check host and one or more Assertion Acts.
    /// An empty list is refused. This process is not a public listener.
    pub fn start_acts(base_url: &str, presents: Vec<RuntimePresent>) -> Result<Self> {
        if presents.is_empty() {
            return Err(Error::denied(
                "The laboratory runtime agent-process verb needs at least one Assertion Act. Pass --certificate-pem and or the documented WIMSE fields. This command does not open a third presenter.",
            ));
        }
        let runtime = LaboratoryRuntime::connect(base_url)?;
        Ok(Self { runtime, presents })
    }

    /// Re-check every held Assertion Act before the next tool. Do not cache allow.
    /// Death is picked up without a restart. Reuse act. Fresh verifier challenge
    /// each time. Fresh holder proof each time. The tool runs only when every
    /// held act is allowed.
    pub fn before_next_tool<F, T>(
        &self,
        mut sign_holder_nonce: F,
        tool: Option<T>,
    ) -> BeforeToolOutcome
    where
        F: FnMut(&RuntimeVerifierChallenge) -> Result<String>,
        T: FnOnce(),
    {
        let mut last_decision = None;
        for present in &self.presents {
            let decision = self
                .runtime
                .act(present, |challenge| sign_holder_nonce(challenge));
            if exit_code_for_runtime_act(&decision) != 0 {
                return BeforeToolOutcome {
                    gate: gate_line_for_before_tool(&decision),
                    decision,
                    tool_ran: false,
                };
            }
            last_decision = Some(decision);
        }
        let decision = last_decision.expect("start_acts requires at least one Assertion Act");
        let tool_ran = run_tool_only_when_allowed(&decision, tool);
        BeforeToolOutcome {
            gate: gate_line_for_before_tool(&decision),
            decision,
            tool_ran,
        }
    }

    /// How many Assertion Acts this process currently holds.
    pub fn held_act_count(&self) -> usize {
        self.presents.len()
    }

    /// Add one later Assertion Act without a restart. The next tool line checks
    /// that new act fresh. A WIMSE child is a first-class sibling of an
    /// X.509-SVID child. This process does not cache ALLOWED. This process
    /// does not read holder secrets. A blank present is refused.
    pub fn add_act(&mut self, present: RuntimePresent) -> Result<()> {
        require_add_act_present(&present)?;
        self.presents.push(present);
        Ok(())
    }

    /// Re-check one named held Assertion Act. Index is one-based.
    /// An unnamed tool line still checks every held act. A missing index or
    /// an index that this process does not hold is refused. Do not cache allow.
    pub fn before_named_act<F, T>(
        &self,
        act_number: usize,
        sign_holder_nonce: F,
        tool: Option<T>,
    ) -> BeforeToolOutcome
    where
        F: FnOnce(&RuntimeVerifierChallenge) -> Result<String>,
        T: FnOnce(),
    {
        if act_number == 0 || act_number > self.presents.len() {
            let decision = Err(Error::denied(format!(
                "The act line must name a held Assertion Act. This process holds {} Assertion Act(s). The check fails closed.",
                self.presents.len()
            )));
            return BeforeToolOutcome {
                gate: gate_line_for_before_tool(&decision),
                decision,
                tool_ran: false,
            };
        }
        let present = &self.presents[act_number - 1];
        let decision = self.runtime.act(present, sign_holder_nonce);
        if exit_code_for_runtime_act(&decision) != 0 {
            return BeforeToolOutcome {
                gate: gate_line_for_before_tool(&decision),
                decision,
                tool_ran: false,
            };
        }
        let tool_ran = run_tool_only_when_allowed(&decision, tool);
        BeforeToolOutcome {
            gate: gate_line_for_before_tool(&decision),
            decision,
            tool_ran,
        }
    }
}

/// Stdin line that adds one later Assertion Act to a still-running process.
/// Name present files the same way start does. One on-ramp on that line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentProcessAddActRequest {
    pub presentation_json_path: String,
    pub certificate_pem_path: Option<String>,
    pub svid_presentation_json_path: Option<String>,
    pub workload_identity_token_path: Option<String>,
    pub content_digest: Option<String>,
    pub signature_input: Option<String>,
    pub signature: Option<String>,
    pub holder_proof: Option<String>,
    pub holder_proof_command: Option<String>,
    pub holder_secret_path: Option<String>,
}

/// True when the stdin line names one held Assertion Act for that tool.
pub fn is_agent_process_named_act_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed == "act" || trimmed.starts_with("act ") || trimmed.starts_with("act\t")
}

/// Parse `act <n> [tool]`. The number is one-based. The rest is the tool command.
/// `add-act` is not this line.
pub fn parse_agent_process_named_act_line(line: &str) -> Result<(usize, String)> {
    if !is_agent_process_named_act_line(line) || is_agent_process_add_act_line(line) {
        return Err(Error::denied(
            "The act line must begin with act and a held Assertion Act number. The check fails closed.",
        ));
    }
    let tokens = tokenize_agent_process_add_act_line(line)?;
    if tokens.first().map(String::as_str) != Some("act") {
        return Err(Error::denied(
            "The act line must begin with act and a held Assertion Act number. The check fails closed.",
        ));
    }
    let number = tokens.get(1).ok_or_else(|| {
        Error::denied("The act line needs a held Assertion Act number. The check fails closed.")
    })?;
    let act_number: usize = number.parse().map_err(|_| {
        Error::denied("The act line needs a held Assertion Act number. The check fails closed.")
    })?;
    if act_number == 0 {
        return Err(Error::denied(
            "The act line must name a held Assertion Act. Act numbers start at 1. The check fails closed.",
        ));
    }
    let tool = tokens[2..].join(" ");
    Ok((act_number, tool))
}

/// True when the stdin line is the add-act command, not a tool line.
pub fn is_agent_process_add_act_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed == "add-act" || trimmed.starts_with("add-act ") || trimmed.starts_with("add-act\t")
}

/// Parse one add-act stdin line. This parser does not open files.
/// Mixing an X.509-SVID wrap with a WIMSE present on the same line is refused.
/// A holder secret path on that line is named so the caller can refuse it
/// without opening secret bytes.
pub fn parse_agent_process_add_act_line(line: &str) -> Result<AgentProcessAddActRequest> {
    if !is_agent_process_add_act_line(line) {
        return Err(Error::denied(
            "The add-act line must begin with add-act. The add fails closed.",
        ));
    }
    let tokens = tokenize_agent_process_add_act_line(line)?;
    if tokens.first().map(String::as_str) != Some("add-act") {
        return Err(Error::denied(
            "The add-act line must begin with add-act. The add fails closed.",
        ));
    }
    let mut presentation_json_path = None;
    let mut certificate_pem_path = None;
    let mut svid_presentation_json_path = None;
    let mut workload_identity_token_path = None;
    let mut content_digest = None;
    let mut signature_input = None;
    let mut signature = None;
    let mut holder_proof = None;
    let mut holder_proof_command = None;
    let mut holder_secret_path = None;
    let mut index = 1;
    while index < tokens.len() {
        let flag = tokens[index].as_str();
        if !flag.starts_with("--") {
            return Err(Error::denied(format!(
                "The add-act line does not accept {flag}. Name present files the same way start does. The add fails closed."
            )));
        }
        index += 1;
        let value = tokens.get(index).cloned().ok_or_else(|| {
            Error::denied(format!(
                "The add-act flag {flag} needs a value. The add fails closed."
            ))
        })?;
        index += 1;
        match flag {
            "--presentation-json" => presentation_json_path = Some(value),
            "--certificate-pem" => certificate_pem_path = Some(value),
            "--svid-presentation-json" => svid_presentation_json_path = Some(value),
            "--workload-identity-token" => workload_identity_token_path = Some(value),
            "--content-digest" => content_digest = Some(value),
            "--signature-input" => signature_input = Some(value),
            "--signature" => signature = Some(value),
            "--holder-proof" => holder_proof = Some(value),
            "--holder-proof-command" => holder_proof_command = Some(value),
            "--holder-secret-path" => holder_secret_path = Some(value),
            other => {
                return Err(Error::denied(format!(
                    "The add-act line does not accept {other}. Name present files the same way start does. This command does not change the check host. The add fails closed."
                )));
            }
        }
    }
    let presentation_json_path = presentation_json_path.ok_or_else(|| {
        Error::denied(
            "The add-act line needs --presentation-json. Name present files the same way start does. The add fails closed.",
        )
    })?;
    let has_svid = certificate_pem_path.is_some();
    let has_wimse = workload_identity_token_path.is_some()
        || content_digest.is_some()
        || signature_input.is_some()
        || signature.is_some();
    if has_svid && has_wimse {
        return Err(Error::denied(
            "The add-act line names one on-ramp. Do not mix an X.509-SVID wrap with a WIMSE present on the same add-act line. The add fails closed.",
        ));
    }
    if !has_svid && !has_wimse {
        return Err(Error::denied(
            "The add-act line needs one on-ramp. Pass --certificate-pem or the documented WIMSE fields. The add fails closed.",
        ));
    }
    if has_wimse
        && (workload_identity_token_path.is_none()
            || content_digest
                .as_deref()
                .map(str::trim)
                .unwrap_or("")
                .is_empty()
            || signature_input
                .as_deref()
                .map(str::trim)
                .unwrap_or("")
                .is_empty()
            || signature.as_deref().map(str::trim).unwrap_or("").is_empty())
    {
        return Err(Error::denied(
            "The add-act WIMSE line needs --workload-identity-token, --content-digest, --signature-input, and --signature. The add fails closed.",
        ));
    }
    if has_svid
        && certificate_pem_path
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .is_empty()
    {
        return Err(Error::denied(
            "The add-act line needs --certificate-pem. The add fails closed.",
        ));
    }
    Ok(AgentProcessAddActRequest {
        presentation_json_path,
        certificate_pem_path,
        svid_presentation_json_path,
        workload_identity_token_path,
        content_digest,
        signature_input,
        signature,
        holder_proof,
        holder_proof_command,
        holder_secret_path,
    })
}

fn tokenize_agent_process_add_act_line(line: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.trim().chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '\\' if in_quotes => match chars.next() {
                Some('"') => current.push('"'),
                Some(escaped) => {
                    current.push('\\');
                    current.push(escaped);
                }
                None => {
                    return Err(Error::denied(
                        "The add-act line has a dangling escape. The add fails closed.",
                    ));
                }
            },
            '"' if in_quotes => {
                tokens.push(std::mem::take(&mut current));
                in_quotes = false;
            }
            '"' => {
                if !current.is_empty() {
                    return Err(Error::denied(
                        "The add-act line has a quote in the middle of a token. The add fails closed.",
                    ));
                }
                in_quotes = true;
            }
            character if character.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            character => current.push(character),
        }
    }
    if in_quotes {
        return Err(Error::denied(
            "The add-act line has an unclosed quote. The add fails closed.",
        ));
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

/// Read one add-act WIMSE field. A value that starts with @ names a local file.
/// Secret paths are refused. An empty file is refused. This does not read holder secrets.
pub fn add_act_field_value(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if let Some(path) = trimmed.strip_prefix('@') {
        if path.is_empty() {
            return Err(Error::denied(
                "The add-act @-file path is empty. The add fails closed.",
            ));
        }
        refuse_secret_material_in_path(path)?;
        let mut file = std::fs::File::open(path).map_err(|_| {
            Error::denied("The add-act @-file path could not be read. The add fails closed.")
        })?;
        let mut text = String::new();
        file.read_to_string(&mut text).map_err(|_| {
            Error::denied("The add-act @-file path could not be read. The add fails closed.")
        })?;
        let text = text.trim().to_string();
        if text.is_empty() {
            return Err(Error::denied(
                "The add-act @-file path is empty. The add fails closed.",
            ));
        }
        return Ok(text);
    }
    if trimmed.is_empty() {
        return Err(Error::denied(
            "The add-act WIMSE field is empty. The add fails closed.",
        ));
    }
    Ok(trimmed.to_string())
}

fn require_add_act_present(present: &RuntimePresent) -> Result<()> {
    match present {
        RuntimePresent::Svid(present) => {
            if present.presentation_json.trim().is_empty() {
                return Err(Error::denied(
                    "The add-act X.509-SVID present needs presentation bytes. The add fails closed.",
                ));
            }
            if present.certificate_pem.trim().is_empty() {
                return Err(Error::denied(
                    "The add-act X.509-SVID present needs a laboratory wrap. The add fails closed.",
                ));
            }
        }
        RuntimePresent::Wimse(present) => {
            if present.presentation_json.trim().is_empty()
                || present.workload_identity_token.trim().is_empty()
                || present.content_digest.trim().is_empty()
                || present.signature_input.trim().is_empty()
                || present.signature.trim().is_empty()
            {
                return Err(Error::denied(
                    "The add-act WIMSE present needs the documented WIMSE fields. The add fails closed.",
                ));
            }
        }
    }
    Ok(())
}

fn check_decision_from_http_response(
    status: u16,
    body: &str,
    on_ramp: &str,
) -> Result<CheckDecision> {
    if status != 200 && status != 403 {
        return Err(Error::denied(format!(
            "The documented {on_ramp} check path did not return a check decision. The laboratory runtime refuses. HTTP status {status}."
        )));
    }
    if body.trim().is_empty() {
        return Err(Error::denied(format!(
            "The documented {on_ramp} check path returned HTTP {status} with an empty body. The laboratory runtime refuses. Unknown is not live."
        )));
    }
    let decision = serde_json::from_str::<CheckDecision>(body).map_err(|error| {
        Error::denied(format!(
            "The documented {on_ramp} check path did not return a check decision JSON: {error}"
        ))
    })?;
    let result = decision.result.trim();
    if result == "allowed" {
        if status != 200 {
            return Err(Error::denied(format!(
                "The documented {on_ramp} check path returned HTTP {status} whose JSON is allowed. The laboratory runtime refuses. A forbidden status is not an allow."
            )));
        }
        return Ok(decision);
    }
    if result == "refused" || result == "denied" || result == "refuse" {
        if status == 200 {
            return Err(Error::denied(format!(
                "The documented {on_ramp} check path returned HTTP 200 whose JSON is {result}. The laboratory runtime refuses. A 200 check body is not an allow."
            )));
        }
        return Ok(decision);
    }
    Err(Error::denied(
        "The documented check path returned an unknown check result. The laboratory runtime refuses. Unknown is not live.",
    ))
}

fn parse_http_response(response: &str) -> Result<(u16, String)> {
    let status = response
        .split_whitespace()
        .nth(1)
        .and_then(|text| text.parse::<u16>().ok())
        .ok_or_else(|| {
            Error::denied(
                "The laboratory runtime did not receive an HTTP status. The check fails closed.",
            )
        })?;
    let body = response.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    Ok((status, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::serve_loopback_listener;
    use crate::issuer_crypto::LABORATORY_ISSUER_CRYPTO_PROFILE;
    use crate::kernel::{CheckDecision, HolderProof, Kernel};
    use crate::wimse::{
        sign_laboratory_wimse_http_message, LABORATORY_WIMSE_CHECK_METHOD,
        LABORATORY_WIMSE_CHECK_PATH,
    };
    use std::collections::BTreeMap;
    use std::net::TcpListener;
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;
    use tempfile::tempdir;

    fn documented_sample(svid_path: &str, wimse_path: &str, challenge_path: &str) -> String {
        serde_json::json!({
            "laboratory_name": "prometheus-check",
            "bind": "127.0.0.1",
            "refuses_other_interfaces": true,
            "checks": [
                {"method": "POST", "path": svid_path},
                {"method": "POST", "path": wimse_path}
            ],
            "verifier_challenge": {"method": "POST", "path": challenge_path},
            "store_b_check": "A Store B check needs a holder signature over that nonce.",
            "present": "document",
            "on_ramp_artifacts": ["X.509-SVID", "WIMSE"],
            "death_wins": true,
            "short_life_is_not_kill": true,
            "instance_identifier_in_path": false
        })
        .to_string()
    }

    #[test]
    fn laboratory_runtime_reads_check_paths_from_the_document_not_from_hard_coded_constants() {
        let raw = documented_sample("/renamed-svid", "/renamed-wimse", "/renamed-challenge");
        let document = parse_well_known_document(&raw).expect("parse a renamed document");
        let wimse = documented_check_for_on_ramp(&document, LABORATORY_ON_RAMP_WIMSE)
            .expect("select the WIMSE check from the document");
        let svid = documented_check_for_on_ramp(&document, LABORATORY_ON_RAMP_SVID)
            .expect("select the X.509-SVID check from the document");
        assert_eq!(wimse.path, "/renamed-wimse");
        assert_eq!(svid.path, "/renamed-svid");
        assert_eq!(document.verifier_challenge.path, "/renamed-challenge");
        assert_eq!(document.checks[0].path, "/renamed-svid");
        let source = include_str!("runtime_check.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source sits before the test module");
        assert!(
            !production.contains("/renamed-svid")
                && !production.contains("/check-svid")
                && !production.contains("/check-wimse")
                && !production.contains("/verifier-challenge"),
            "the helper must learn check paths from the document JSON only"
        );
    }

    fn documented_sample_with_pins(
        svid_path: &str,
        wimse_path: &str,
        challenge_path: &str,
        pins: &[(&str, &str)],
    ) -> String {
        let mut value: serde_json::Value =
            serde_json::from_str(&documented_sample(svid_path, wimse_path, challenge_path))
                .expect("documented sample is JSON");
        value["operator_pin_paths"] = pins
            .iter()
            .map(|(method, path)| serde_json::json!({"method": method, "path": path}))
            .collect();
        value.to_string()
    }

    #[test]
    fn resolve_operator_pin_uses_document_paths() {
        let raw = documented_sample_with_pins(
            "/renamed-svid",
            "/renamed-wimse",
            "/renamed-challenge",
            &[
                ("POST", "/renamed-issuer-accept"),
                ("POST", "/renamed-kill-accept"),
            ],
        );
        let document = parse_well_known_document(&raw).expect("parse a renamed pin document");
        let issuer = resolve_operator_pin(&document, "issuer-accept")
            .expect("issuer-accept must follow the document path");
        assert_eq!(issuer.method, "POST");
        assert_eq!(issuer.path, "/renamed-issuer-accept");
        let kill = resolve_operator_pin(&document, "kill-accept")
            .expect("kill-accept must follow the document path");
        assert_eq!(kill.path, "/renamed-kill-accept");
        let challenge = resolve_operator_pin(&document, "verifier-challenge")
            .expect("verifier-challenge must follow the document path");
        assert_eq!(challenge.path, "/renamed-challenge");
        let svid = resolve_operator_pin(&document, "check-svid")
            .expect("checks[] must resolve from the document");
        assert_eq!(svid.path, "/renamed-svid");
    }

    #[test]
    fn resolve_operator_pin_refuses_a_missing_pin() {
        let raw = documented_sample_with_pins(
            "/check-svid-ok",
            "/check-wimse-ok",
            "/challenge-ok",
            &[("POST", "/seal-accept")],
        );
        let document =
            parse_well_known_document(&raw).expect("parse a document that omits issuer-accept");
        let error = resolve_operator_pin(&document, "issuer-accept")
            .expect_err("a missing operator pin must be refused");
        assert!(
            error
                .to_string()
                .contains("does not name that operator pin"),
            "the refuse must name the missing pin: {error}"
        );
        let empty = parse_well_known_document(&documented_sample(
            "/check-svid-ok",
            "/check-wimse-ok",
            "/challenge-ok",
        ))
        .expect("a document without operator_pin_paths must still parse");
        assert!(empty.operator_pin_paths.is_empty());
        resolve_operator_pin(&empty, "issuer-accept")
            .expect_err("an omitted operator_pin_paths list must refuse issuer-accept");
    }

    #[test]
    fn resolve_operator_pin_refuses_a_write_verb_pin() {
        let raw = documented_sample_with_pins(
            "/check-svid-ok",
            "/check-wimse-ok",
            "/challenge-ok",
            &[
                ("POST", "/seal-export"),
                ("POST", "/birth"),
                ("POST", "/issuer-accept"),
            ],
        );
        let document = parse_well_known_document(&raw)
            .expect("export pins may sit in operator_pin_paths on parse");
        let export = resolve_operator_pin(&document, "seal-export")
            .expect_err("a write-verb pin must be refused");
        assert!(
            export.to_string().contains("write verb"),
            "the refuse must name a write verb: {export}"
        );
        let birth = resolve_operator_pin(&document, "birth")
            .expect_err("Create Agent Principal as a pin must be refused");
        assert!(
            birth.to_string().contains("write verb")
                || birth
                    .to_string()
                    .contains("does not name that operator pin"),
            "birth as a pin must fail closed: {birth}"
        );
        let issuer = resolve_operator_pin(&document, "issuer-accept")
            .expect("an honest accept pin must still resolve");
        assert_eq!(issuer.path, "/issuer-accept");
    }

    #[test]
    fn load_operator_pins_refuses_an_off_name_base() {
        for url in [
            "http://127.0.0.2:18765",
            "https://www.prestigeworldwide.digital",
            "https://prestigeworldwide.digital",
            "http://check.prestigeworldwide.digital",
            "https://check.prestigeworldwide.digital:8443",
        ] {
            let error = LaboratoryRuntime::connect(url)
                .expect_err("an off-name typed verifier base must be refused");
            assert!(
                error.to_string().contains("127.0.0.1")
                    || error
                        .to_string()
                        .contains("check.prestigeworldwide.digital")
                    || error.to_string().contains("HTTPS"),
                "the refuse must name the accepted bases: {error} for {url}"
            );
        }
    }

    #[test]
    fn hardcoded_public_operator_pins_resolve_when_the_document_lists_them() {
        let public = crate::host::laboratory_well_known_check_document(
            &crate::host::HostMode::check_only_public(),
        );
        let document = parse_well_known_document(&public)
            .expect("the laboratory runtime must follow the public well-known document");
        for pin in [
            "issuer-accept",
            "kill-accept",
            "seal-accept",
            "previous-key-accept",
            "act-accept",
        ] {
            let documented = resolve_operator_pin(&document, pin)
                .expect("the live public pin list must resolve");
            assert_eq!(documented.method, "POST");
            assert_eq!(documented.path, format!("/{pin}"));
        }
        resolve_operator_pin(&document, "seal-export")
            .expect_err("the public document must not name an export write pin");
    }

    #[test]
    fn laboratory_runtime_refuses_a_non_loopback_base_url() {
        for url in [
            "http://0.0.0.0:18765",
            "http://example.com:18765",
            "http://localhost:18765",
            "http://127.0.0.2:18765",
            "https://127.0.0.1:18765",
            "http://[::1]:18765",
        ] {
            let error = LaboratoryRuntime::connect(url)
                .expect_err("a non-loopback base URL must be refused");
            assert!(
                error.to_string().contains("127.0.0.1") || error.to_string().contains("loopback"),
                "the refuse must name the loopback bind: {error} for {url}"
            );
        }
        LaboratoryRuntime::connect("http://127.0.0.1:18765")
            .expect("http://127.0.0.1:18765 must be accepted");
    }

    #[test]
    fn laboratory_runtime_refuses_http_to_the_locked_public_check_name() {
        let error = LaboratoryRuntime::connect("http://check.prestigeworldwide.digital")
            .expect_err("HTTP to the locked public check name must be refused");
        assert!(
            error.to_string().contains("HTTPS")
                && error
                    .to_string()
                    .contains("check.prestigeworldwide.digital"),
            "the refuse must name HTTPS for the locked check name: {error}"
        );
        let with_port = LaboratoryRuntime::connect("http://check.prestigeworldwide.digital:443")
            .expect_err("HTTP with port 443 must still be refused");
        assert!(
            with_port.to_string().contains("HTTPS") || with_port.to_string().contains("127.0.0.1"),
            "HTTP to the locked name must be refused: {with_port}"
        );
    }

    #[test]
    fn laboratory_runtime_refuses_https_to_any_other_host() {
        for url in [
            "https://evil.example",
            "https://evil.example:443",
            "https://www.prestigeworldwide.digital",
            "https://prestigeworldwide.digital",
            "https://check.prestigeworldwide.digital:8443",
            "https://127.0.0.1",
            "https://check.prestigeworldwide.digital/check-svid",
        ] {
            let error =
                LaboratoryRuntime::connect(url).expect_err("any other HTTPS host must be refused");
            assert!(
                error.to_string().contains("127.0.0.1")
                    || error
                        .to_string()
                        .contains("check.prestigeworldwide.digital")
                    || error.to_string().contains("path"),
                "the refuse must name the accepted bases: {error} for {url}"
            );
        }
    }

    #[test]
    fn laboratory_runtime_accepts_the_locked_https_name_at_connect_parse() {
        let runtime = LaboratoryRuntime::connect("https://check.prestigeworldwide.digital")
            .expect("https://check.prestigeworldwide.digital must be accepted");
        assert_eq!(runtime.host, "check.prestigeworldwide.digital");
        assert_eq!(runtime.port, 443);
        assert_eq!(runtime.transport, RuntimeTransport::PublicHttps);
        assert_eq!(
            runtime.base_url(),
            "https://check.prestigeworldwide.digital"
        );
        let with_port = LaboratoryRuntime::connect("https://check.prestigeworldwide.digital:443")
            .expect("https://check.prestigeworldwide.digital:443 must be accepted");
        assert_eq!(with_port.port, 443);
        assert_eq!(with_port.transport, RuntimeTransport::PublicHttps);
        let production = include_str!("runtime_check.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source sits before the test module");
        assert!(
            !production.contains("danger_accept_invalid_certs")
                && !production.contains("skip-verify")
                && !production.contains("force-allow")
                && !production.contains("force_allow"),
            "the laboratory runtime must not skip TLS verify"
        );
    }

    #[test]
    fn laboratory_runtime_refuses_a_document_that_is_not_bound_or_contains_secrets() {
        let mut bad_bind: serde_json::Value =
            serde_json::from_str(&documented_sample("/a", "/b", "/c")).unwrap();
        bad_bind["bind"] = serde_json::json!("0.0.0.0");
        let error = parse_well_known_document(&bad_bind.to_string())
            .expect_err("a non-loopback document bind must be refused");
        assert!(
            error.to_string().contains("127.0.0.1"),
            "bind 0.0.0.0 must be refused: {error}"
        );

        let mut public_bind: serde_json::Value =
            serde_json::from_str(&documented_sample("/a", "/b", "/c")).unwrap();
        public_bind["bind"] = serde_json::json!("check.prestigeworldwide.digital");
        let public = parse_well_known_document(&public_bind.to_string())
            .expect("bind check.prestigeworldwide.digital must be accepted");
        assert_eq!(public.bind, "check.prestigeworldwide.digital");

        let mut secret =
            serde_json::from_str::<serde_json::Value>(&documented_sample("/a", "/b", "/c"))
                .unwrap();
        secret["holder_secret_path"] = serde_json::json!("/tmp/holder.secret");
        let error = parse_well_known_document(&secret.to_string())
            .expect_err("secret material in the document must be refused");
        assert!(error.to_string().contains("secret"));

        let mut instance_path =
            serde_json::from_str::<serde_json::Value>(&documented_sample("/a", "/b", "/c"))
                .unwrap();
        instance_path["checks"][1]["path"] = serde_json::json!("/check/01ARZ3NDEKTSV4RRFFQ69G5FAV");
        let error = parse_well_known_document(&instance_path.to_string())
            .expect_err("an instance identifier in a documented path must be refused");
        assert!(error.to_string().contains("instance identifier"));

        let mut instance_word =
            serde_json::from_str::<serde_json::Value>(&documented_sample("/a", "/b", "/c"))
                .unwrap();
        instance_word["checks"][0]["path"] = serde_json::json!("/check/instance");
        let error = parse_well_known_document(&instance_word.to_string())
            .expect_err("the word instance in a documented path must be refused");
        assert!(error.to_string().contains("instance identifier"));

        let mut holder_secret_file =
            serde_json::from_str::<serde_json::Value>(&documented_sample("/a", "/b", "/c"))
                .unwrap();
        holder_secret_file["checks"][0]["path"] = serde_json::json!("/tmp/holder.secret");
        let error = parse_well_known_document(&holder_secret_file.to_string())
            .expect_err("a documented path that names holder secret material must be refused");
        assert!(error.to_string().contains("secret"));
    }

    #[test]
    fn laboratory_runtime_refuses_a_document_that_names_write_verbs() {
        for path in [
            "/birth",
            "/spawn",
            "/present-svid",
            "/present-wimse",
            "/agent-type",
            "/kill",
            "/seal",
            "/rotate",
            "/sign-holder-nonce",
            "/seal-export",
            "/challenge",
        ] {
            let mut write_check: serde_json::Value = serde_json::from_str(&documented_sample(
                "/check-svid",
                "/check-wimse",
                "/verifier-challenge",
            ))
            .unwrap();
            write_check["checks"][0]["path"] = serde_json::json!(path);
            let error = parse_well_known_document(&write_check.to_string()).expect_err(
                "a well-known document that names a write verb as a check path must be refused",
            );
            assert!(
                error.to_string().contains("write verb")
                    || error.to_string().contains("Create Agent Principal"),
                "the refuse must name the write verb: {error} for {path}"
            );
        }
        let mut write_challenge: serde_json::Value = serde_json::from_str(&documented_sample(
            "/check-svid",
            "/check-wimse",
            "/verifier-challenge",
        ))
        .unwrap();
        write_challenge["verifier_challenge"]["path"] = serde_json::json!("/birth");
        let error = parse_well_known_document(&write_challenge.to_string())
            .expect_err("a verifier-challenge path that names a write verb must be refused");
        assert!(
            error.to_string().contains("write verb")
                || error.to_string().contains("Create Agent Principal"),
            "the refuse must name the write verb: {error}"
        );
        let honest = parse_well_known_document(&documented_sample(
            "/check-svid",
            "/check-wimse",
            "/verifier-challenge",
        ))
        .expect("an honest check document must still parse");
        assert_eq!(honest.checks[0].path, "/check-svid");
        assert_eq!(honest.verifier_challenge.path, "/verifier-challenge");
    }

    fn laboratory_birth(kernel: &Kernel) -> crate::kernel::BirthWrite {
        let agent_type = kernel
            .add_agent_type(
                "laboratory".to_string(),
                vec!["read".to_string()],
                "internal".to_string(),
                2,
                LABORATORY_ISSUER_CRYPTO_PROFILE.to_string(),
                3600,
            )
            .expect("add a laboratory agent type");
        kernel
            .birth_write(
                &agent_type.id,
                "laboratory".to_string(),
                BTreeMap::new(),
                "read",
                "internal",
                None,
            )
            .expect("birth a live instance")
    }

    fn laboratory_wimse_present(
        kernel: &Kernel,
        birth: &crate::kernel::BirthWrite,
    ) -> WimsePresent {
        let nonce = kernel
            .issue_holder_challenge(&birth.instance.id)
            .expect("issue a holder challenge for present")
            .nonce;
        let secret = kernel.store().holder_secret_path(&birth.instance.id);
        let artifact = kernel
            .present_wimse(
                &birth.instance.id,
                &birth.capability.id,
                Some(&HolderProof::SecretPath(secret)),
                Some(&nonce),
            )
            .expect("emit a live laboratory Workload Identity Token");
        let envelope_secret = kernel
            .store()
            .load_biscuit_secret()
            .expect("load the issuing envelope secret");
        let (signature_input, signature) = sign_laboratory_wimse_http_message(
            LABORATORY_WIMSE_CHECK_METHOD,
            LABORATORY_WIMSE_CHECK_PATH,
            &artifact.content_digest,
            &envelope_secret,
        )
        .expect("sign the laboratory HTTP Message Signature");
        WimsePresent {
            presentation_json: artifact.presentation_json,
            workload_identity_token: artifact.workload_identity_token,
            content_digest: artifact.content_digest,
            signature_input,
            signature,
        }
    }

    fn laboratory_svid_present(kernel: &Kernel, birth: &crate::kernel::BirthWrite) -> SvidPresent {
        let nonce = kernel
            .issue_holder_challenge(&birth.instance.id)
            .expect("issue a holder challenge for present")
            .nonce;
        let secret = kernel.store().holder_secret_path(&birth.instance.id);
        let artifact = kernel
            .present_x509_svid(
                &birth.instance.id,
                &birth.capability.id,
                Some(&HolderProof::SecretPath(secret)),
                Some(&nonce),
            )
            .expect("emit a live laboratory X.509-SVID wrap");
        SvidPresent {
            presentation_json: artifact.presentation_json,
            certificate_pem: artifact.certificate_pem,
        }
    }

    fn laboratory_svid_present_for(
        kernel: &Kernel,
        instance_id: &str,
        capability_id: &str,
    ) -> SvidPresent {
        let nonce = kernel
            .issue_holder_challenge(instance_id)
            .expect("issue a holder challenge for present")
            .nonce;
        let secret = kernel.store().holder_secret_path(instance_id);
        let artifact = kernel
            .present_x509_svid(
                instance_id,
                capability_id,
                Some(&HolderProof::SecretPath(secret)),
                Some(&nonce),
            )
            .expect("emit a live laboratory X.509-SVID wrap");
        SvidPresent {
            presentation_json: artifact.presentation_json,
            certificate_pem: artifact.certificate_pem,
        }
    }

    fn laboratory_wimse_present_for(
        kernel: &Kernel,
        instance_id: &str,
        capability_id: &str,
    ) -> WimsePresent {
        let nonce = kernel
            .issue_holder_challenge(instance_id)
            .expect("issue a holder challenge for present")
            .nonce;
        let secret = kernel.store().holder_secret_path(instance_id);
        let artifact = kernel
            .present_wimse(
                instance_id,
                capability_id,
                Some(&HolderProof::SecretPath(secret)),
                Some(&nonce),
            )
            .expect("emit a live laboratory Workload Identity Token");
        let envelope_secret = kernel
            .store()
            .load_biscuit_secret()
            .expect("load the issuing envelope secret");
        let (signature_input, signature) = sign_laboratory_wimse_http_message(
            LABORATORY_WIMSE_CHECK_METHOD,
            LABORATORY_WIMSE_CHECK_PATH,
            &artifact.content_digest,
            &envelope_secret,
        )
        .expect("sign the laboratory HTTP Message Signature");
        WimsePresent {
            presentation_json: artifact.presentation_json,
            workload_identity_token: artifact.workload_identity_token,
            content_digest: artifact.content_digest,
            signature_input,
            signature,
        }
    }

    fn laboratory_spawn_child(
        kernel: &Kernel,
        parent: &crate::kernel::BirthWrite,
    ) -> crate::kernel::SpawnWrite {
        let nonce = kernel
            .issue_holder_challenge(&parent.instance.id)
            .expect("issue a holder challenge for spawn")
            .nonce;
        let secret = kernel.store().holder_secret_path(&parent.instance.id);
        kernel
            .spawn_child(
                &parent.instance.id,
                &parent.capability.id,
                "child".to_string(),
                BTreeMap::new(),
                "read",
                "internal/prod",
                Some("autonomous".to_string()),
                Some(&HolderProof::SecretPath(secret)),
                Some(&nonce),
            )
            .expect("spawn a narrower child")
    }

    fn spawn_loopback_host(kernel: Kernel) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback test listener");
        let address = listener
            .local_addr()
            .expect("read the bound loopback address");
        let handle = thread::spawn(move || {
            let _ = serve_loopback_listener(&kernel, listener);
        });
        let base = format!("http://127.0.0.1:{}", address.port());
        for _ in 0..50 {
            if TcpStream::connect_timeout(&address, Duration::from_millis(40)).is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        (base, handle)
    }

    fn two_store_runtime_setup() -> (
        tempfile::TempDir,
        Kernel,
        tempfile::TempDir,
        String,
        crate::kernel::BirthWrite,
        WimsePresent,
    ) {
        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let birth = laboratory_birth(&store_a);
        let present = laboratory_wimse_present(&store_a, &birth);

        let directory_b = tempdir().expect("create store B");
        let store_b = Kernel::open(directory_b.path());
        store_b.initialize().expect("initialize store B");
        let public_key = store_a
            .store()
            .load_issuer()
            .expect("load store A issuer")
            .current_public_key_hex();
        store_b
            .accept_issuer_public_key(&public_key)
            .expect("pin the foreign issuer public key");
        let (base, _handle) = spawn_loopback_host(store_b);
        (directory_a, store_a, directory_b, base, birth, present)
    }

    fn two_store_svid_runtime_setup() -> (
        tempfile::TempDir,
        Kernel,
        tempfile::TempDir,
        String,
        crate::kernel::BirthWrite,
        SvidPresent,
    ) {
        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let birth = laboratory_birth(&store_a);
        let present = laboratory_svid_present(&store_a, &birth);

        let directory_b = tempdir().expect("create store B");
        let store_b = Kernel::open(directory_b.path());
        store_b.initialize().expect("initialize store B");
        let public_key = store_a
            .store()
            .load_issuer()
            .expect("load store A issuer")
            .current_public_key_hex();
        store_b
            .accept_issuer_public_key(&public_key)
            .expect("pin the foreign issuer public key");
        let (base, _handle) = spawn_loopback_host(store_b);
        (directory_a, store_a, directory_b, base, birth, present)
    }

    #[test]
    fn laboratory_runtime_allows_an_honest_wimse_check_using_only_the_well_known_document() {
        let (_directory_a, store_a, directory_b, base, birth, present) = two_store_runtime_setup();
        let runtime = LaboratoryRuntime::connect(&base).expect("connect on 127.0.0.1");
        let document = runtime
            .load_document()
            .expect("GET the well-known document");
        assert_eq!(document.bind, "127.0.0.1");
        let wimse = documented_check_for_on_ramp(&document, LABORATORY_ON_RAMP_WIMSE)
            .expect("learn the WIMSE check path from the document");
        assert!(
            !wimse.path.is_empty() && wimse.path.starts_with('/'),
            "the helper must use a path from the document"
        );
        let decision = runtime
            .complete_wimse_check(&present, |challenge| {
                store_a.sign_holder_nonce(
                    &challenge.challenge_message,
                    store_a.store().holder_secret_path(&birth.instance.id),
                )
            })
            .expect("the laboratory runtime must return a check decision");
        assert_eq!(
            decision.result, "allowed",
            "an honest WIMSE present on the verifier must allow: {:?}",
            decision.reason
        );
        assert_eq!(decision.instance_id, birth.instance.id);
        let store_b = Kernel::open(directory_b.path());
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "the laboratory runtime must not copy the issuing inode"
        );
        assert!(
            store_b
                .store()
                .list_instances()
                .expect("list store B instances")
                .is_empty(),
            "the laboratory runtime is not a directory"
        );
    }

    #[test]
    fn laboratory_runtime_refuses_after_kill_accept() {
        let (_directory_a, store_a, directory_b, base, birth, present) = two_store_runtime_setup();
        let runtime = LaboratoryRuntime::connect(&base).expect("connect on 127.0.0.1");
        let allow = runtime
            .complete_wimse_check(&present, |challenge| {
                store_a.sign_holder_nonce(
                    &challenge.challenge_message,
                    store_a.store().holder_secret_path(&birth.instance.id),
                )
            })
            .expect("the honest check must return a decision");
        assert_eq!(allow.result, "allowed", "the honest check must allow first");

        let challenge = runtime
            .request_verifier_challenge()
            .expect("issue a fresh verifier nonce while the instance is still live");
        let holder_proof = store_a
            .sign_holder_nonce(
                &challenge.challenge_message,
                store_a.store().holder_secret_path(&birth.instance.id),
            )
            .expect("sign the verifier nonce on the issuing store before local kill");

        store_a
            .kill_instance(&birth.instance.id)
            .expect("store A must persist local kill");
        let bundle = store_a
            .build_kill_bundle(Some(&birth.instance.id), None)
            .expect("export the signed death bundle");
        let store_b = Kernel::open(directory_b.path());
        store_b
            .accept_kill_bundle_artifacts(&bundle)
            .expect("store B must accept the signed death bundle");

        let refuse = runtime
            .post_named_wimse_check(&present, &challenge.challenge_nonce, &holder_proof)
            .expect("the laboratory runtime must return a check decision after kill accept");
        assert_eq!(
            refuse.result, "refused",
            "death must win: {:?}",
            refuse.reason
        );
        let reason = refuse.reason.unwrap_or_default();
        assert!(
            reason.contains("kill accept") || reason.contains("kill"),
            "store B must refuse from accepted death: {reason}"
        );
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "store B must still write no instance record"
        );
    }

    #[test]
    fn laboratory_runtime_allows_an_honest_svid_check_using_only_the_well_known_document() {
        let (_directory_a, store_a, directory_b, base, birth, present) =
            two_store_svid_runtime_setup();
        let runtime = LaboratoryRuntime::connect(&base).expect("connect on 127.0.0.1");
        let document = runtime
            .load_document()
            .expect("GET the well-known document");
        assert_eq!(document.bind, "127.0.0.1");
        let svid = documented_check_for_on_ramp(&document, LABORATORY_ON_RAMP_SVID)
            .expect("learn the X.509-SVID check path from the document");
        assert!(
            !svid.path.is_empty() && svid.path.starts_with('/'),
            "the helper must use a path from the document"
        );
        let decision = runtime
            .complete_svid_check(&present, |challenge| {
                store_a.sign_holder_nonce(
                    &challenge.challenge_message,
                    store_a.store().holder_secret_path(&birth.instance.id),
                )
            })
            .expect("the laboratory runtime must return a check decision");
        assert_eq!(
            decision.result, "allowed",
            "an honest X.509-SVID present on the verifier must allow: {:?}",
            decision.reason
        );
        assert_eq!(decision.instance_id, birth.instance.id);
        let store_b = Kernel::open(directory_b.path());
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "the laboratory runtime must not copy the issuing inode"
        );
        assert!(
            store_b
                .store()
                .list_instances()
                .expect("list store B instances")
                .is_empty(),
            "the laboratory runtime is not a directory"
        );
    }

    #[test]
    fn laboratory_runtime_svid_refuses_after_kill_accept() {
        let (_directory_a, store_a, directory_b, base, birth, present) =
            two_store_svid_runtime_setup();
        let runtime = LaboratoryRuntime::connect(&base).expect("connect on 127.0.0.1");
        let allow = runtime
            .complete_svid_check(&present, |challenge| {
                store_a.sign_holder_nonce(
                    &challenge.challenge_message,
                    store_a.store().holder_secret_path(&birth.instance.id),
                )
            })
            .expect("the honest check must return a decision");
        assert_eq!(allow.result, "allowed", "the honest check must allow first");

        let challenge = runtime
            .request_verifier_challenge()
            .expect("issue a fresh verifier nonce while the instance is still live");
        let holder_proof = store_a
            .sign_holder_nonce(
                &challenge.challenge_message,
                store_a.store().holder_secret_path(&birth.instance.id),
            )
            .expect("sign the verifier nonce on the issuing store before local kill");

        store_a
            .kill_instance(&birth.instance.id)
            .expect("store A must persist local kill");
        let bundle = store_a
            .build_kill_bundle(Some(&birth.instance.id), None)
            .expect("export the signed death bundle");
        let store_b = Kernel::open(directory_b.path());
        store_b
            .accept_kill_bundle_artifacts(&bundle)
            .expect("store B must accept the signed death bundle");

        let refuse = runtime
            .post_named_svid_check(&present, &challenge.challenge_nonce, &holder_proof)
            .expect("the laboratory runtime must return a check decision after kill accept");
        assert_eq!(
            refuse.result, "refused",
            "death must win: {:?}",
            refuse.reason
        );
        let reason = refuse.reason.unwrap_or_default();
        assert!(
            reason.contains("kill accept") || reason.contains("kill"),
            "store B must refuse from accepted death: {reason}"
        );
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "store B must still write no instance record"
        );
    }

    fn sample_decision(result: &str) -> CheckDecision {
        CheckDecision {
            result: result.to_string(),
            instance_id: "laboratory".to_string(),
            capability_id: None,
            intent: "read".to_string(),
            audience: "internal".to_string(),
            reason: None,
            challenge_nonce: None,
            on_behalf_of: None,
            receipt: None,
        }
    }

    #[test]
    fn laboratory_runtime_act_exit_code_is_zero_only_when_allowed() {
        assert_eq!(
            exit_code_for_runtime_act(&Ok(sample_decision("allowed"))),
            0,
            "exit 0 only on allowed"
        );
        assert_eq!(
            exit_code_for_runtime_act(&Ok(sample_decision("refused"))),
            1,
            "a refuse must be non-zero"
        );
        assert_eq!(
            exit_code_for_runtime_act(&Err(Error::denied(
                "The laboratory runtime could not connect. The check fails closed."
            ))),
            1,
            "a transport failure must be non-zero"
        );
        assert_eq!(
            exit_code_for_runtime_act(&Ok(sample_decision("unknown"))),
            1,
            "unknown is not live"
        );
    }

    #[test]
    fn laboratory_runtime_act_allows_an_honest_svid_present() {
        let (_directory_a, store_a, directory_b, base, birth, present) =
            two_store_svid_runtime_setup();
        let decision = act(&base, &RuntimePresent::Svid(present), |challenge| {
            store_a.sign_holder_nonce(
                &challenge.challenge_message,
                store_a.store().holder_secret_path(&birth.instance.id),
            )
        })
        .expect("the laboratory runtime act verb must return a check decision");
        assert_eq!(
            decision.result, "allowed",
            "an honest X.509-SVID present on the verifier must allow: {:?}",
            decision.reason
        );
        assert_eq!(
            exit_code_for_runtime_act(&Ok(decision.clone())),
            0,
            "exit 0 only on allowed"
        );
        let store_b = Kernel::open(directory_b.path());
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "the laboratory runtime must not copy the issuing inode"
        );
        assert!(
            store_b
                .store()
                .list_instances()
                .expect("list store B instances")
                .is_empty(),
            "the laboratory runtime is not a directory"
        );
    }

    #[test]
    fn laboratory_runtime_act_refuses_after_kill_accept() {
        let (_directory_a, store_a, directory_b, base, birth, present) =
            two_store_svid_runtime_setup();
        let allow = act(&base, &RuntimePresent::Svid(present.clone()), |challenge| {
            store_a.sign_holder_nonce(
                &challenge.challenge_message,
                store_a.store().holder_secret_path(&birth.instance.id),
            )
        })
        .expect("the honest act must return a decision");
        assert_eq!(allow.result, "allowed", "the honest act must allow first");

        store_a
            .kill_instance(&birth.instance.id)
            .expect("store A must persist local kill");
        let bundle = store_a
            .build_kill_bundle(Some(&birth.instance.id), None)
            .expect("export the signed death bundle");
        let store_b = Kernel::open(directory_b.path());
        store_b
            .accept_kill_bundle_artifacts(&bundle)
            .expect("store B must accept the signed death bundle");

        let refuse = act(&base, &RuntimePresent::Svid(present), |_challenge| {
            Ok("00".repeat(32))
        })
        .expect("the laboratory runtime act verb must return a check decision after kill accept");
        assert_eq!(
            refuse.result, "refused",
            "death must win: {:?}",
            refuse.reason
        );
        assert_eq!(
            exit_code_for_runtime_act(&Ok(refuse.clone())),
            1,
            "the same verb on the historical present must exit non-zero"
        );
        let reason = refuse.reason.unwrap_or_default();
        assert!(
            reason.contains("kill accept") || reason.contains("kill"),
            "store B must refuse from accepted death: {reason}"
        );
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "store B must still write no instance record"
        );
    }

    #[test]
    fn laboratory_runtime_act_transport_failure_is_denied() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
        let port = listener
            .local_addr()
            .expect("read the bound loopback address")
            .port();
        drop(listener);
        let present = RuntimePresent::Svid(SvidPresent {
            presentation_json: "{}".to_string(),
            certificate_pem: String::new(),
        });
        let error = act(
            &format!("http://127.0.0.1:{port}"),
            &present,
            |_challenge| Ok("00".repeat(32)),
        )
        .expect_err("a transport failure must be denied");
        assert_eq!(
            exit_code_for_runtime_act(&Err(Error::denied(error.to_string()))),
            1,
            "a transport failure must be non-zero"
        );
        assert!(
            error.to_string().contains("could not connect")
                || error.to_string().contains("refuses")
                || error.to_string().contains("127.0.0.1"),
            "the refuse must name the failed loopback connect: {error}"
        );
    }

    #[test]
    fn laboratory_runtime_act_does_not_read_holder_secrets() {
        let production = include_str!("runtime_check.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source sits before the test module");
        assert!(
            !production.contains("HolderProof::SecretPath")
                && !production.contains("store().holder_secret_path")
                && !production.contains("std::fs::read"),
            "the laboratory runtime act verb must not read holder secrets"
        );
        let main_source = include_str!("main.rs");
        assert!(
            main_source.contains("runtime-check") && main_source.contains("Act {"),
            "the documented command prometheus runtime-check act must exist"
        );
        let act_block = main_source
            .split("RuntimeCheckCommand::Act {")
            .nth(1)
            .expect("the act verb must have a command handler");
        let act_handler = act_block
            .split("Command::RuntimeCheck(RuntimeCheckCommand::Wimse")
            .next()
            .expect("the act handler sits before the split WIMSE verb");
        assert!(
            act_handler.contains("refuse_holder_secret_path")
                && !act_handler.contains("HolderProof::SecretPath")
                && !act_handler.contains("std::fs::read_to_string(&holder_secret_path)")
                && !act_handler.contains("std::fs::read(&holder_secret_path)"),
            "a holder secret path argument must be refused. Secret bytes are not opened."
        );
        let refuse_index = act_handler
            .find("refuse_holder_secret_path")
            .expect("the act handler must refuse a holder secret path");
        let presentation_read_index = act_handler
            .find("std::fs::read_to_string(&presentation_json)")
            .expect("the act handler reads the present after the secret-path refuse");
        assert!(
            refuse_index < presentation_read_index,
            "the holder secret path refuse must run before any present file is opened"
        );
    }

    #[test]
    fn laboratory_runtime_act_refuses_an_off_loopback_base_url() {
        let present = RuntimePresent::Svid(SvidPresent {
            presentation_json: "{}".to_string(),
            certificate_pem: String::new(),
        });
        for url in [
            "http://0.0.0.0:18765",
            "http://example.com:18765",
            "http://localhost:18765",
            "http://127.0.0.2:18765",
            "https://127.0.0.1:18765",
            "http://[::1]:18765",
        ] {
            let result = act(url, &present, |_challenge| Ok("00".repeat(32)));
            assert!(
                result.is_err(),
                "an off-loopback act base URL must be refused: {url}"
            );
            assert_eq!(
                exit_code_for_runtime_act(&result),
                1,
                "an off-loopback act base URL must be non-zero: {url}"
            );
            let error = result.expect_err("an off-loopback act base URL must be refused");
            assert!(
                error.to_string().contains("127.0.0.1") || error.to_string().contains("loopback"),
                "the refuse must name the loopback bind: {error} for {url}"
            );
        }
    }

    #[test]
    fn laboratory_runtime_act_refuses_a_missing_holder_signature() {
        let (_directory_a, _store_a, directory_b, base, birth, present) =
            two_store_svid_runtime_setup();
        let result = act(&base, &RuntimePresent::Svid(present), |_challenge| {
            Ok(String::new())
        });
        assert!(
            result.is_err(),
            "a missing holder signature must be refused: {result:?}"
        );
        assert_eq!(
            exit_code_for_runtime_act(&result),
            1,
            "a missing holder signature must be non-zero"
        );
        let error = result.expect_err("a missing holder signature must be refused");
        assert!(
            error.to_string().contains("holder signature")
                || error.to_string().contains("holder secrets"),
            "the refuse must name the missing holder signature: {error}"
        );
        let production = include_str!("runtime_check.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source sits before the test module");
        assert!(
            !production.contains("HolderProof::SecretPath")
                && !production.contains("store().holder_secret_path"),
            "the act verb must not read a holder secret path when the signature is missing"
        );
        let store_b = Kernel::open(directory_b.path());
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "a missing holder signature must not write an instance on store B"
        );
    }

    #[test]
    fn laboratory_runtime_act_refuses_a_holder_secret_path_argument_without_opening_secret_bytes() {
        refuse_holder_secret_path(None)
            .expect("an absent holder secret path argument is not a refuse of that argument");
        let directory = tempdir().expect("create a temporary directory");
        let secret_path = directory.path().join("holder.secret");
        std::fs::write(&secret_path, "MUST-NOT-BE-READ").expect("write a marker file");
        let error = refuse_holder_secret_path(Some(&secret_path))
            .expect_err("a holder secret path argument must be refused");
        assert!(
            error.to_string().contains("holder secret")
                && error.to_string().contains("Secret bytes are not opened"),
            "the refuse must name the holder secret path and that secret bytes are not opened: {error}"
        );
        let unread =
            std::fs::read_to_string(&secret_path).expect("the marker file must still exist");
        assert_eq!(
            unread, "MUST-NOT-BE-READ",
            "the refuse must not rewrite holder secret bytes"
        );
        let missing = directory.path().join("missing-holder.secret");
        let error = refuse_holder_secret_path(Some(&missing))
            .expect_err("a missing holder secret path argument must still be refused");
        assert!(
            error.to_string().contains("does not read holder secrets"),
            "the refuse must not open secret bytes: {error}"
        );
        assert!(
            !missing.exists(),
            "the refuse must not create or open a missing holder secret path"
        );
    }

    #[test]
    fn laboratory_runtime_act_does_not_mint_birth_kill_or_write_an_instance() {
        let production = include_str!("runtime_check.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source sits before the test module");
        assert!(
            !production.contains("birth_write")
                && !production.contains("kill_instance")
                && !production.contains("save_instance")
                && !production.contains("spawn_child")
                && !production.contains("add_agent_type"),
            "the laboratory runtime act verb must not mint, birth, kill, or write an instance"
        );
        let (_directory_a, _store_a, directory_b, base, birth, present) =
            two_store_svid_runtime_setup();
        let decision = act(&base, &RuntimePresent::Svid(present), |_challenge| {
            Ok("00".repeat(32))
        });
        let _ = decision;
        let store_b = Kernel::open(directory_b.path());
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "act must not write the issuing inode on store B"
        );
        assert!(
            store_b
                .store()
                .list_instances()
                .expect("list store B instances")
                .is_empty(),
            "act must not write an instance on store B"
        );
        assert!(
            store_b
                .store()
                .list_agent_types()
                .expect("list store B agent types")
                .is_empty(),
            "act must not mint an agent type on store B"
        );
        assert!(
            store_b
                .store()
                .list_capabilities()
                .expect("list store B capabilities")
                .is_empty(),
            "act must not mint a capability on store B"
        );
    }

    #[test]
    fn laboratory_runtime_act_wimse_uses_the_same_verb_and_the_documented_check_path() {
        let (_directory_a, store_a, directory_b, base, birth, present) = two_store_runtime_setup();
        let decision = act(&base, &RuntimePresent::Wimse(present), |challenge| {
            store_a.sign_holder_nonce(
                &challenge.challenge_message,
                store_a.store().holder_secret_path(&birth.instance.id),
            )
        })
        .expect("the laboratory runtime act verb must return a check decision");
        assert_eq!(
            decision.result, "allowed",
            "an honest WIMSE present on the verifier must allow through the same act verb: {:?}",
            decision.reason
        );
        let store_b = Kernel::open(directory_b.path());
        assert!(
            store_b
                .store()
                .list_instances()
                .expect("list store B instances")
                .is_empty(),
            "the laboratory runtime is not a directory"
        );
    }

    #[test]
    fn laboratory_runtime_one_shot_refuses_a_mixed_svid_and_wimse_on_ramp() {
        let mix = one_shot_on_ramp("act", true, true, true, true, true)
            .expect_err("mixing on-ramps on one-shot act must be refused");
        assert!(
            mix.to_string().contains("mix") || mix.to_string().contains("on-ramp"),
            "the mix refuse must name the on-ramp mix: {mix}"
        );
        assert!(
            mix.to_string().contains("act"),
            "the mix refuse must name the act verb: {mix}"
        );

        let before = one_shot_on_ramp("before-tool", true, true, false, false, false)
            .expect_err("a certificate PEM plus a WIMSE token on before-tool must be refused");
        assert!(
            before.to_string().contains("mix") || before.to_string().contains("on-ramp"),
            "the before-tool mix refuse must name the on-ramp mix: {before}"
        );
        assert!(
            before.to_string().contains("before-tool"),
            "the mix refuse must name the before-tool verb: {before}"
        );

        let digest_only = one_shot_on_ramp("act", true, false, true, false, false)
            .expect_err("a certificate PEM plus a WIMSE content-digest must be refused");
        assert!(
            digest_only.to_string().contains("mix") || digest_only.to_string().contains("on-ramp"),
            "a partial WIMSE flag with a certificate PEM must still refuse: {digest_only}"
        );

        let svid = one_shot_on_ramp("act", true, false, false, false, false)
            .expect("an honest X.509-SVID one-shot must select that on-ramp");
        assert!(matches!(svid, OneShotOnRamp::Svid));

        let wimse = one_shot_on_ramp("before-tool", false, true, true, true, true)
            .expect("an honest WIMSE one-shot must select that on-ramp");
        assert!(matches!(wimse, OneShotOnRamp::Wimse));

        let neither = one_shot_on_ramp("act", false, false, false, false, false)
            .expect_err("a one-shot with no on-ramp must be refused");
        assert!(
            neither.to_string().contains("on-ramp")
                || neither.to_string().contains("certificate-pem"),
            "the missing on-ramp refuse must name the one-shot need: {neither}"
        );

        let main_source = include_str!("main.rs");
        for (verb, marker, next) in [
            (
                "act",
                "RuntimeCheckCommand::Act {",
                "Command::RuntimeCheck(RuntimeCheckCommand::Challenge",
            ),
            (
                "before-tool",
                "RuntimeCheckCommand::BeforeTool {",
                "Command::RuntimeCheck(RuntimeCheckCommand::AgentProcess",
            ),
        ] {
            let block = main_source
                .split(marker)
                .nth(1)
                .expect("the one-shot verb must have a command handler");
            let handler = block
                .split(next)
                .next()
                .expect("the one-shot handler must have a following command");
            assert!(
                handler.contains("one_shot_on_ramp"),
                "{verb} must refuse a mixed on-ramp before it selects a present"
            );
            let mix_index = handler
                .find("one_shot_on_ramp")
                .expect("the one-shot handler must call one_shot_on_ramp");
            let svid_index = handler
                .find("RuntimePresent::Svid")
                .expect("the one-shot handler still constructs an X.509-SVID present");
            assert!(
                mix_index < svid_index,
                "{verb} must refuse a mixed on-ramp before it constructs an X.509-SVID present"
            );
            let read_index = handler
                .find("std::fs::read_to_string(&presentation_json)")
                .expect("the one-shot handler reads the present after the mix refuse");
            assert!(
                mix_index < read_index,
                "{verb} must refuse a mixed on-ramp before any present file is opened"
            );
        }
    }

    #[test]
    fn laboratory_runtime_before_tool_prints_allowed_and_may_run_the_tool() {
        let (_directory_a, store_a, directory_b, base, birth, present) =
            two_store_svid_runtime_setup();
        let ran = std::cell::Cell::new(false);
        let outcome = before_tool(
            &base,
            &RuntimePresent::Svid(present),
            |challenge| {
                store_a.sign_holder_nonce(
                    &challenge.challenge_message,
                    store_a.store().holder_secret_path(&birth.instance.id),
                )
            },
            Some(|| ran.set(true)),
        );
        assert_eq!(
            outcome.gate, "ALLOWED",
            "an honest Assertion Act must print ALLOWED"
        );
        assert_eq!(outcome.exit_code(), 0, "exit 0 only when the tool may run");
        assert!(
            outcome.tool_may_run() && outcome.tool_ran && ran.get(),
            "the tool must run only after ALLOWED"
        );
        let decision = outcome
            .decision
            .expect("the honest before-tool process must return a check decision");
        assert_eq!(
            decision.result, "allowed",
            "an honest X.509-SVID Assertion Act on the verifier must allow: {:?}",
            decision.reason
        );
        let store_b = Kernel::open(directory_b.path());
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "before-tool must not copy the issuing inode"
        );
        assert!(
            store_b
                .store()
                .list_instances()
                .expect("list store B instances")
                .is_empty(),
            "before-tool is not a directory"
        );
    }

    #[test]
    fn laboratory_runtime_before_tool_refuses_after_kill_accept_and_does_not_run_the_tool() {
        let (_directory_a, store_a, directory_b, base, birth, present) =
            two_store_svid_runtime_setup();
        let allow = before_tool(
            &base,
            &RuntimePresent::Svid(present.clone()),
            |challenge| {
                store_a.sign_holder_nonce(
                    &challenge.challenge_message,
                    store_a.store().holder_secret_path(&birth.instance.id),
                )
            },
            None::<fn()>,
        );
        assert_eq!(
            allow.gate, "ALLOWED",
            "the honest before-tool process must allow first"
        );
        assert!(
            !allow.tool_ran,
            "a missing tool command must not invent a run"
        );

        store_a
            .kill_instance(&birth.instance.id)
            .expect("store A must persist local kill");
        let bundle = store_a
            .build_kill_bundle(Some(&birth.instance.id), None)
            .expect("export the signed death bundle");
        let store_b = Kernel::open(directory_b.path());
        store_b
            .accept_kill_bundle_artifacts(&bundle)
            .expect("store B must accept the signed death bundle");

        let ran = std::cell::Cell::new(false);
        let refuse = before_tool(
            &base,
            &RuntimePresent::Svid(present),
            |_challenge| Ok("00".repeat(32)),
            Some(|| ran.set(true)),
        );
        assert_eq!(
            refuse.gate,
            "REFUSED",
            "after Decommission the historical Assertion Act must print REFUSED: {:?}",
            refuse
                .decision
                .as_ref()
                .ok()
                .and_then(|decision| decision.reason.clone())
        );
        assert_eq!(
            refuse.exit_code(),
            1,
            "after Decommission the same process must exit non-zero"
        );
        assert!(
            !refuse.tool_may_run() && !refuse.tool_ran && !ran.get(),
            "the process must not run the tool after Decommission"
        );
        let refuse_decision = refuse
            .decision
            .expect("the laboratory runtime before-tool verb must return a check decision after kill accept");
        assert_eq!(
            refuse_decision.result, "refused",
            "death must win: {:?}",
            refuse_decision.reason
        );
        let reason = refuse_decision.reason.unwrap_or_default();
        assert!(
            reason.contains("kill accept") || reason.contains("kill"),
            "store B must refuse from accepted death: {reason}"
        );
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "store B must still write no instance record"
        );
    }

    #[test]
    fn laboratory_runtime_before_tool_transport_failure_does_not_run_the_tool() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
        let port = listener
            .local_addr()
            .expect("read the bound loopback address")
            .port();
        drop(listener);
        let present = RuntimePresent::Svid(SvidPresent {
            presentation_json: "{}".to_string(),
            certificate_pem: String::new(),
        });
        let ran = std::cell::Cell::new(false);
        let outcome = before_tool(
            &format!("http://127.0.0.1:{port}"),
            &present,
            |_challenge| Ok("00".repeat(32)),
            Some(|| ran.set(true)),
        );
        assert_eq!(
            outcome.gate, "REFUSED",
            "a transport failure must print REFUSED"
        );
        assert_eq!(
            outcome.exit_code(),
            1,
            "a transport failure must be non-zero"
        );
        assert!(
            !outcome.tool_may_run() && !outcome.tool_ran && !ran.get(),
            "a transport failure must not run the tool"
        );
        let error = outcome
            .decision
            .expect_err("a transport failure must be denied");
        assert!(
            error.to_string().contains("could not connect")
                || error.to_string().contains("refuses")
                || error.to_string().contains("127.0.0.1"),
            "the refuse must name the failed loopback connect: {error}"
        );
    }

    #[test]
    fn laboratory_runtime_before_tool_unknown_is_not_live_and_does_not_run_the_tool() {
        let ran = std::cell::Cell::new(false);
        let result = Ok(sample_decision("unknown"));
        assert_eq!(
            gate_line_for_before_tool(&result),
            "REFUSED",
            "unknown is not live"
        );
        assert_eq!(
            exit_code_for_runtime_act(&result),
            1,
            "unknown must be non-zero"
        );
        let tool_ran = run_tool_only_when_allowed(&result, Some(|| ran.set(true)));
        assert!(!tool_ran && !ran.get(), "unknown must not run the tool");
    }

    #[test]
    fn laboratory_runtime_before_tool_has_no_force_allow() {
        let production = include_str!("runtime_check.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source sits before the test module");
        assert!(
            production.contains("pub fn before_tool")
                && production.contains("act(base_url, present, sign_holder_nonce)"),
            "before-tool must reuse act"
        );
        assert!(
            !production.contains("--force-allow")
                && !production.contains("force_allow")
                && !production.contains("fn force"),
            "there is no flag that overrides a refuse"
        );
        let main_source = include_str!("main.rs");
        assert!(
            main_source.contains("BeforeTool {")
                && (main_source.contains("name = \"before-tool\"")
                    || main_source.contains("before-tool")),
            "the documented command prometheus runtime-check before-tool must exist"
        );
        assert!(
            !main_source.contains("--force-allow")
                && !main_source.contains("force_allow")
                && !main_source.contains("arg = \"force\""),
            "the command line must not offer force-allow"
        );
        let before_block = main_source
            .split("RuntimeCheckCommand::BeforeTool {")
            .nth(1)
            .expect("the before-tool verb must have a command handler");
        let before_handler = before_block
            .split("Command::AgentType")
            .next()
            .expect("the before-tool handler sits before agent-type");
        assert!(
            before_handler.contains("refuse_holder_secret_path")
                && before_handler.contains("before_tool")
                && before_handler.contains("ALLOWED")
                && before_handler.contains("REFUSED")
                && !before_handler.contains("HolderProof::SecretPath")
                && !before_handler.contains("std::fs::read_to_string(&holder_secret_path)")
                && !before_handler.contains("std::fs::read(&holder_secret_path)"),
            "before-tool must refuse a holder secret path and must print ALLOWED or REFUSED. Secret bytes are not opened."
        );
        let refuse_index = before_handler
            .find("refuse_holder_secret_path")
            .expect("the before-tool handler must refuse a holder secret path");
        let presentation_read_index = before_handler
            .find("std::fs::read_to_string(&presentation_json)")
            .expect("the before-tool handler reads the present after the secret-path refuse");
        assert!(
            refuse_index < presentation_read_index,
            "the holder secret path refuse must run before any present file is opened"
        );
        let gate_index = before_handler
            .find("println!(\"REFUSED\")")
            .expect("the before-tool handler must print REFUSED when the tool may not run");
        let allowed_index = before_handler
            .find("println!(\"ALLOWED\")")
            .expect("the before-tool handler must print ALLOWED when the tool may run");
        let tool_index = before_handler
            .find("run_authorized_tool")
            .expect("the before-tool handler must run the tool only through the authorized helper");
        assert!(
            gate_index < allowed_index && allowed_index < tool_index,
            "the process must print REFUSED or ALLOWED before it can run the tool"
        );
        assert!(
            before_handler.contains("tool_may_run") || before_handler.contains("exit_code() == 0"),
            "the tool must run only when the gate allows"
        );
    }

    #[test]
    fn laboratory_runtime_before_tool_does_not_read_holder_secrets() {
        let production = include_str!("runtime_check.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source sits before the test module");
        let before_fn = production
            .split("pub fn before_tool")
            .nth(1)
            .expect("before_tool must exist");
        let before_body = before_fn.split("pub fn").next().unwrap_or(before_fn);
        assert!(
            !before_body.contains("HolderProof::SecretPath")
                && !before_body.contains("store().holder_secret_path")
                && !before_body.contains("std::fs::read"),
            "the laboratory runtime before-tool verb must not read holder secrets"
        );
    }

    #[test]
    fn laboratory_runtime_before_tool_refuses_an_off_loopback_base_url() {
        let present = RuntimePresent::Svid(SvidPresent {
            presentation_json: "{}".to_string(),
            certificate_pem: String::new(),
        });
        for url in [
            "http://0.0.0.0:18765",
            "http://example.com:18765",
            "http://localhost:18765",
            "http://127.0.0.2:18765",
            "https://127.0.0.1:18765",
            "http://[::1]:18765",
        ] {
            let ran = std::cell::Cell::new(false);
            let outcome = before_tool(
                url,
                &present,
                |_challenge| Ok("00".repeat(32)),
                Some(|| ran.set(true)),
            );
            assert_eq!(
                outcome.gate, "REFUSED",
                "an off-loopback before-tool base URL must print REFUSED: {url}"
            );
            assert_eq!(
                outcome.exit_code(),
                1,
                "an off-loopback before-tool base URL must be non-zero: {url}"
            );
            assert!(
                !outcome.tool_ran && !ran.get(),
                "an off-loopback before-tool base URL must not run the tool: {url}"
            );
            let error = outcome
                .decision
                .expect_err("an off-loopback before-tool base URL must be refused");
            assert!(
                error.to_string().contains("127.0.0.1") || error.to_string().contains("loopback"),
                "the refuse must name the loopback bind: {error} for {url}"
            );
        }
    }

    #[test]
    fn laboratory_runtime_agent_process_allows_then_refuses_after_kill_accept_without_restart() {
        let (_directory_a, store_a, directory_b, base, birth, present) =
            two_store_svid_runtime_setup();
        let process = AgentProcess::start(&base, RuntimePresent::Svid(present))
            .expect("start one durable agent process");
        let ran_first = std::cell::Cell::new(false);
        let allow = process.before_next_tool(
            |challenge| {
                store_a.sign_holder_nonce(
                    &challenge.challenge_message,
                    store_a.store().holder_secret_path(&birth.instance.id),
                )
            },
            Some(|| ran_first.set(true)),
        );
        assert_eq!(
            allow.gate, "ALLOWED",
            "the first before_next_tool on a live instance must print ALLOWED"
        );
        assert!(
            allow.tool_may_run() && allow.tool_ran && ran_first.get(),
            "the first before_next_tool must run the tool"
        );

        store_a
            .kill_instance(&birth.instance.id)
            .expect("store A must persist local kill");
        let bundle = store_a
            .build_kill_bundle(Some(&birth.instance.id), None)
            .expect("export the signed death bundle");
        let store_b = Kernel::open(directory_b.path());
        store_b
            .accept_kill_bundle_artifacts(&bundle)
            .expect("store B must accept the signed death bundle");

        let holder_path = store_a.store().holder_secret_path(&birth.instance.id);
        let ran_second = std::cell::Cell::new(false);
        let refuse = process.before_next_tool(
            |challenge| {
                crate::holder_sign::sign_holder_proof(
                    &holder_path,
                    Some(&challenge.challenge_message),
                    None,
                )
            },
            Some(|| ran_second.set(true)),
        );
        assert_eq!(
            refuse.gate,
            "REFUSED",
            "the same AgentProcess must print REFUSED after Decommission without a restart: {:?}",
            refuse
                .decision
                .as_ref()
                .ok()
                .and_then(|decision| decision.reason.clone())
        );
        assert!(
            !refuse.tool_may_run() && !refuse.tool_ran && !ran_second.get(),
            "the same AgentProcess must not run the tool after Decommission"
        );
        let refuse_decision = refuse
            .decision
            .expect("the second before_next_tool must return a check decision after kill accept");
        assert_eq!(
            refuse_decision.result, "refused",
            "death must win: {:?}",
            refuse_decision.reason
        );
        let reason = refuse_decision.reason.unwrap_or_default();
        assert!(
            reason.contains("accepted a kill") || reason.contains("kill accept"),
            "the refuse must name accepted kill, not a missing holder signature: {reason}"
        );
        assert!(
            !reason.contains("holder signature is required"),
            "the refuse must name accepted kill, not a missing holder signature: {reason}"
        );
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "store B must still write no instance record"
        );
    }

    #[test]
    fn laboratory_runtime_agent_process_wimse_allows_then_refuses_after_kill_accept_without_restart(
    ) {
        let (_directory_a, store_a, directory_b, base, birth, present) = two_store_runtime_setup();
        let process = AgentProcess::start(&base, RuntimePresent::Wimse(present))
            .expect("start one durable agent process on a WIMSE Assertion Act");
        let ran_first = std::cell::Cell::new(false);
        let allow = process.before_next_tool(
            |challenge| {
                store_a.sign_holder_nonce(
                    &challenge.challenge_message,
                    store_a.store().holder_secret_path(&birth.instance.id),
                )
            },
            Some(|| ran_first.set(true)),
        );
        assert_eq!(
            allow.gate, "ALLOWED",
            "the first WIMSE before_next_tool on a live instance must print ALLOWED"
        );
        assert!(
            allow.tool_may_run() && allow.tool_ran && ran_first.get(),
            "the first WIMSE before_next_tool must run the tool"
        );

        store_a
            .kill_instance(&birth.instance.id)
            .expect("store A must persist local kill");
        let bundle = store_a
            .build_kill_bundle(Some(&birth.instance.id), None)
            .expect("export the signed death bundle");
        let store_b = Kernel::open(directory_b.path());
        store_b
            .accept_kill_bundle_artifacts(&bundle)
            .expect("store B must accept the signed death bundle");

        let holder_path = store_a.store().holder_secret_path(&birth.instance.id);
        let ran_second = std::cell::Cell::new(false);
        let refuse = process.before_next_tool(
            |challenge| {
                crate::holder_sign::sign_holder_proof(
                    &holder_path,
                    Some(&challenge.challenge_message),
                    None,
                )
            },
            Some(|| ran_second.set(true)),
        );
        assert_eq!(
            refuse.gate,
            "REFUSED",
            "the same AgentProcess must print REFUSED after Decommission of a WIMSE Assertion Act without a restart: {:?}",
            refuse
                .decision
                .as_ref()
                .ok()
                .and_then(|decision| decision.reason.clone())
        );
        assert!(
            !refuse.tool_may_run() && !refuse.tool_ran && !ran_second.get(),
            "the same AgentProcess must not run the tool after Decommission of a WIMSE Assertion Act"
        );
        let refuse_decision = refuse.decision.expect(
            "the second WIMSE before_next_tool must return a check decision after kill accept",
        );
        assert_eq!(
            refuse_decision.result, "refused",
            "death must win on the WIMSE Assertion Act: {:?}",
            refuse_decision.reason
        );
        let reason = refuse_decision.reason.unwrap_or_default();
        assert!(
            reason.contains("accepted a kill") || reason.contains("kill accept"),
            "the WIMSE refuse must name accepted kill, not a missing holder signature: {reason}"
        );
        assert!(
            !reason.contains("holder signature is required"),
            "the WIMSE refuse must name accepted kill, not a missing holder signature: {reason}"
        );
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "store B must still write no instance record after the WIMSE walk"
        );
    }

    #[test]
    fn laboratory_runtime_agent_process_svid_and_wimse_allow_then_refuse_after_kill_accept_without_restart(
    ) {
        let (_directory_a, store_a, directory_b, base, birth, wimse) = two_store_runtime_setup();
        let svid = laboratory_svid_present(&store_a, &birth);
        let process = AgentProcess::start_acts(
            &base,
            vec![RuntimePresent::Svid(svid), RuntimePresent::Wimse(wimse)],
        )
        .expect("start one durable agent process with both on-ramp Assertion Acts");
        let ran_first = std::cell::Cell::new(false);
        let allow = process.before_next_tool(
            |challenge| {
                store_a.sign_holder_nonce(
                    &challenge.challenge_message,
                    store_a.store().holder_secret_path(&birth.instance.id),
                )
            },
            Some(|| ran_first.set(true)),
        );
        assert_eq!(
            allow.gate, "ALLOWED",
            "both on-ramp Assertion Acts on a live instance must print ALLOWED"
        );
        assert!(
            allow.tool_may_run() && allow.tool_ran && ran_first.get(),
            "the tool must run only after both on-ramp checks allow"
        );

        store_a
            .kill_instance(&birth.instance.id)
            .expect("store A must persist local kill");
        let bundle = store_a
            .build_kill_bundle(Some(&birth.instance.id), None)
            .expect("export the signed death bundle");
        let store_b = Kernel::open(directory_b.path());
        store_b
            .accept_kill_bundle_artifacts(&bundle)
            .expect("store B must accept the signed death bundle");

        let holder_path = store_a.store().holder_secret_path(&birth.instance.id);
        let ran_second = std::cell::Cell::new(false);
        let refuse = process.before_next_tool(
            |challenge| {
                crate::holder_sign::sign_holder_proof(
                    &holder_path,
                    Some(&challenge.challenge_message),
                    None,
                )
            },
            Some(|| ran_second.set(true)),
        );
        assert_eq!(
            refuse.gate,
            "REFUSED",
            "the same multi-act AgentProcess must print REFUSED after Decommission without a restart: {:?}",
            refuse
                .decision
                .as_ref()
                .ok()
                .and_then(|decision| decision.reason.clone())
        );
        assert!(
            !refuse.tool_may_run() && !refuse.tool_ran && !ran_second.get(),
            "the same multi-act AgentProcess must not run the tool after Decommission"
        );
        let refuse_decision = refuse.decision.expect(
            "the second multi-act before_next_tool must return a check decision after kill accept",
        );
        assert_eq!(
            refuse_decision.result, "refused",
            "death must win on every held Assertion Act: {:?}",
            refuse_decision.reason
        );
        let reason = refuse_decision.reason.unwrap_or_default();
        assert!(
            reason.contains("accepted a kill") || reason.contains("kill accept"),
            "the multi-act refuse must name accepted kill, not a missing holder signature: {reason}"
        );
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "store B must still write no instance record after the multi-act walk"
        );
    }

    #[test]
    fn laboratory_runtime_agent_process_start_acts_refuses_an_empty_list() {
        let error = AgentProcess::start_acts("http://127.0.0.1:9", Vec::new())
            .expect_err("an empty Assertion Act list must be refused at start");
        assert!(
            error.to_string().contains("Assertion Act"),
            "the empty-list refuse must name Assertion Act: {error}"
        );
    }

    #[test]
    fn laboratory_runtime_agent_process_allows_then_refuses_after_seal_accept_without_restart() {
        let (_directory_a, store_a, directory_b, base, birth, present) =
            two_store_svid_runtime_setup();
        let process = AgentProcess::start(&base, RuntimePresent::Svid(present))
            .expect("start one durable agent process");
        let ran_first = std::cell::Cell::new(false);
        let allow = process.before_next_tool(
            |challenge| {
                store_a.sign_holder_nonce(
                    &challenge.challenge_message,
                    store_a.store().holder_secret_path(&birth.instance.id),
                )
            },
            Some(|| ran_first.set(true)),
        );
        assert_eq!(
            allow.gate, "ALLOWED",
            "the first before_next_tool on a live issuer pin must print ALLOWED"
        );
        assert!(
            allow.tool_may_run() && allow.tool_ran && ran_first.get(),
            "the first before_next_tool must run the tool"
        );

        store_a
            .seal_issuer(60)
            .expect("store A must persist local seal");
        let bundle = store_a
            .build_seal_bundle()
            .expect("export the signed seal bundle");
        let store_b = Kernel::open(directory_b.path());
        store_b
            .accept_seal_bundle_artifacts(&bundle)
            .expect("store B must accept the signed seal bundle");

        let holder_path = store_a.store().holder_secret_path(&birth.instance.id);
        let ran_second = std::cell::Cell::new(false);
        let refuse = process.before_next_tool(
            |challenge| {
                crate::holder_sign::sign_holder_proof(
                    &holder_path,
                    Some(&challenge.challenge_message),
                    None,
                )
            },
            Some(|| ran_second.set(true)),
        );
        assert_eq!(
            refuse.gate,
            "REFUSED",
            "the same AgentProcess must print REFUSED after seal accept without a restart: {:?}",
            refuse
                .decision
                .as_ref()
                .ok()
                .and_then(|decision| decision.reason.clone())
        );
        assert!(
            !refuse.tool_may_run() && !refuse.tool_ran && !ran_second.get(),
            "the same AgentProcess must not run the tool after seal accept"
        );
        let refuse_decision = refuse
            .decision
            .expect("the second before_next_tool must return a check decision after seal accept");
        assert_eq!(
            refuse_decision.result, "refused",
            "seal accept must win: {:?}",
            refuse_decision.reason
        );
        let reason = refuse_decision.reason.unwrap_or_default();
        assert!(
            reason.contains("accepted a seal") || reason.contains("seal accept"),
            "the refuse must name accepted seal, not a missing holder signature: {reason}"
        );
        assert!(
            !reason.contains("holder signature is required"),
            "the refuse must name accepted seal, not a missing holder signature: {reason}"
        );
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "store B must still write no instance record"
        );
    }

    #[test]
    fn laboratory_runtime_agent_process_allows_then_refuses_after_parent_kill_accept_without_restart(
    ) {
        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let parent = laboratory_birth(&store_a);
        let child = laboratory_spawn_child(&store_a, &parent);
        let present =
            laboratory_svid_present_for(&store_a, &child.instance.id, &child.capability.id);

        let directory_b = tempdir().expect("create store B");
        let store_b_live = Kernel::open(directory_b.path());
        store_b_live.initialize().expect("initialize store B");
        let public_key = store_a
            .store()
            .load_issuer()
            .expect("load store A issuer")
            .current_public_key_hex();
        store_b_live
            .accept_issuer_public_key(&public_key)
            .expect("pin the foreign issuer public key");
        let (base, _handle) = spawn_loopback_host(store_b_live);

        let process = AgentProcess::start(&base, RuntimePresent::Svid(present))
            .expect("start one durable agent process on the child Assertion Act");
        let ran_first = std::cell::Cell::new(false);
        let allow = process.before_next_tool(
            |challenge| {
                store_a.sign_holder_nonce(
                    &challenge.challenge_message,
                    store_a.store().holder_secret_path(&child.instance.id),
                )
            },
            Some(|| ran_first.set(true)),
        );
        assert_eq!(
            allow.gate, "ALLOWED",
            "the first before_next_tool on a live child must print ALLOWED"
        );
        assert!(
            allow.tool_may_run() && allow.tool_ran && ran_first.get(),
            "the first before_next_tool must run the child tool"
        );

        store_a
            .kill_instance(&parent.instance.id)
            .expect("store A must persist parent Decommission");
        let bundle = store_a
            .build_kill_bundle(Some(&parent.instance.id), None)
            .expect("export the signed parent death bundle");
        let store_b = Kernel::open(directory_b.path());
        store_b
            .accept_kill_bundle_artifacts(&bundle)
            .expect("store B must accept the signed parent death bundle");

        let holder_path = store_a.store().holder_secret_path(&child.instance.id);
        let ran_second = std::cell::Cell::new(false);
        let refuse = process.before_next_tool(
            |challenge| {
                crate::holder_sign::sign_holder_proof(
                    &holder_path,
                    Some(&challenge.challenge_message),
                    None,
                )
            },
            Some(|| ran_second.set(true)),
        );
        assert_eq!(
            refuse.gate,
            "REFUSED",
            "the same AgentProcess must print REFUSED after parent kill accept without a restart: {:?}",
            refuse
                .decision
                .as_ref()
                .ok()
                .and_then(|decision| decision.reason.clone())
        );
        assert!(
            !refuse.tool_may_run() && !refuse.tool_ran && !ran_second.get(),
            "the same AgentProcess must not run the child tool after parent Decommission"
        );
        let refuse_decision = refuse.decision.expect(
            "the second before_next_tool must return a check decision after parent kill accept",
        );
        assert_eq!(
            refuse_decision.result, "refused",
            "parent death must win: {:?}",
            refuse_decision.reason
        );
        let reason = refuse_decision.reason.unwrap_or_default();
        assert!(
            reason.contains("accepted a kill") || reason.contains("kill accept"),
            "the refuse must name accepted kill cascade, not a missing holder signature: {reason}"
        );
        assert!(
            reason.contains("ancestor")
                || reason.contains("cascade")
                || reason.contains("accepted a kill"),
            "the refuse must name the parent ancestor kill: {reason}"
        );
        assert!(
            !reason.contains("holder signature is required"),
            "the refuse must name accepted kill, not a missing holder signature: {reason}"
        );
        assert!(
            store_b.store().load_instance(&parent.instance.id).is_err(),
            "store B must still write no parent instance record"
        );
        assert!(
            store_b.store().load_instance(&child.instance.id).is_err(),
            "store B must still write no child instance record"
        );
    }

    #[test]
    fn laboratory_runtime_agent_process_reuses_before_tool_and_does_not_cache_allow() {
        let production = include_str!("runtime_check.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source sits before the test module");
        assert!(
            production.contains("pub struct AgentProcess")
                && production.contains("pub fn start")
                && production.contains("pub fn before_next_tool")
                && production.contains("pub fn add_act")
                && production.contains("pub fn before_named_act"),
            "AgentProcess must ship start, before_next_tool, add_act, and before_named_act"
        );
        let next_tool = production
            .split("pub fn before_next_tool")
            .nth(1)
            .expect("before_next_tool must exist");
        let next_body = next_tool
            .split("fn parse_http_response")
            .next()
            .unwrap_or(next_tool);
        assert!(
            next_body.contains("before_tool(")
                || next_body.contains(".act(")
                || next_body.contains("act("),
            "before_next_tool must reuse before_tool or act each time"
        );
        assert!(
            !production.contains("cached_allow")
                && !production.contains("last_allowed")
                && !production.contains("force_allow"),
            "AgentProcess must not cache ALLOWED"
        );
        assert!(
            production.contains("pin_or_refuse_well_known")
                && production.contains("pinned_well_known")
                && production.contains("self.runtime.act"),
            "AgentProcess must reuse the same LaboratoryRuntime so the first honest well-known document stays pinned"
        );
        assert!(
            !production.contains("TcpListener"),
            "the agent-process production path must not bind a TCP listener"
        );
        let main_source = include_str!("main.rs");
        assert!(
            main_source.contains("AgentProcess {")
                && (main_source.contains("name = \"agent-process\"")
                    || main_source.contains("agent-process")),
            "the documented command prometheus runtime-check agent-process must exist"
        );
        assert!(
            !main_source.contains("cached_allow") && !main_source.contains("last_allowed"),
            "the command line must not cache ALLOWED"
        );
        let agent_block = main_source
            .split("RuntimeCheckCommand::AgentProcess {")
            .nth(1)
            .expect("the agent-process verb must have a command handler");
        let agent_handler = agent_block
            .split("Command::AgentType")
            .next()
            .expect("the agent-process handler sits before agent-type");
        assert!(
            agent_handler.contains("refuse_holder_secret_path")
                && (agent_handler.contains("AgentProcess::start_acts") || agent_handler.contains("AgentProcess::start"))
                && agent_handler.contains("before_next_tool")
                && agent_handler.contains("ALLOWED")
                && agent_handler.contains("REFUSED")
                && agent_handler.contains("ADDED")
                && agent_handler.contains("is_agent_process_add_act_line")
                && agent_handler.contains("is_agent_process_named_act_line")
                && agent_handler.contains("stop")
                && agent_handler.contains("stdin")
                && !agent_handler.contains("TcpListener")
                && !agent_handler.contains("0.0.0.0")
                && !agent_handler.contains("HolderProof::SecretPath")
                && !agent_handler.contains("std::fs::read_to_string(&holder_secret_path)")
                && !agent_handler.contains("std::fs::read(&holder_secret_path)"),
            "agent-process must refuse a holder secret path, print ALLOWED or REFUSED, stay on stdin, and must not be a public listener. Secret bytes are not opened."
        );
        let refuse_index = agent_handler
            .find("refuse_holder_secret_path")
            .expect("the agent-process handler must refuse a holder secret path");
        let presentation_read_index = agent_handler
            .find("std::fs::read_to_string(&presentation_json)")
            .expect("the agent-process handler reads the present after the secret-path refuse");
        assert!(
            refuse_index < presentation_read_index,
            "the holder secret path refuse must run before any present file is opened"
        );
    }

    #[test]
    fn laboratory_runtime_agent_process_missing_holder_signature_refuses_and_does_not_run_the_tool()
    {
        let (_directory_a, _store_a, directory_b, base, birth, present) =
            two_store_svid_runtime_setup();
        let process = AgentProcess::start(&base, RuntimePresent::Svid(present))
            .expect("start may succeed before the act");
        let ran = std::cell::Cell::new(false);
        let outcome =
            process.before_next_tool(|_challenge| Ok(String::new()), Some(|| ran.set(true)));
        assert_eq!(
            outcome.gate, "REFUSED",
            "a missing holder signature on a live process must print REFUSED"
        );
        assert!(
            !outcome.tool_may_run() && !outcome.tool_ran && !ran.get(),
            "a missing holder signature must not run the tool"
        );
        let error = outcome
            .decision
            .expect_err("a missing holder signature must be denied");
        assert!(
            error.to_string().contains("holder signature")
                || error.to_string().contains("holder secrets"),
            "the refuse must name the missing holder signature: {error}"
        );
        let store_b = Kernel::open(directory_b.path());
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "a missing holder signature must not write an instance on store B"
        );
    }

    #[test]
    fn laboratory_runtime_agent_process_unreachable_check_host_refuses_and_does_not_run_the_tool() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
        let port = listener
            .local_addr()
            .expect("read the bound loopback address")
            .port();
        drop(listener);
        let present = RuntimePresent::Svid(SvidPresent {
            presentation_json: "{}".to_string(),
            certificate_pem: String::new(),
        });
        let process = AgentProcess::start(&format!("http://127.0.0.1:{port}"), present)
            .expect("process start may succeed on URL parse");
        let ran = std::cell::Cell::new(false);
        let outcome =
            process.before_next_tool(|_challenge| Ok("00".repeat(32)), Some(|| ran.set(true)));
        assert_eq!(
            outcome.gate, "REFUSED",
            "an unreachable check host must print REFUSED"
        );
        assert!(
            !outcome.tool_may_run() && !outcome.tool_ran && !ran.get(),
            "an unreachable check host must not run the tool"
        );
        let error = outcome
            .decision
            .expect_err("an unreachable check host must be denied");
        assert!(
            error.to_string().contains("could not connect")
                || error.to_string().contains("refuses")
                || error.to_string().contains("127.0.0.1"),
            "the refuse must name the failed loopback connect: {error}"
        );
    }

    #[test]
    fn laboratory_runtime_agent_process_refuses_an_off_name_base_url_at_start() {
        let present = RuntimePresent::Svid(SvidPresent {
            presentation_json: "{}".to_string(),
            certificate_pem: String::new(),
        });
        for url in [
            "http://0.0.0.0:18765",
            "http://example.com:18765",
            "http://localhost:18765",
            "http://127.0.0.2:18765",
            "https://127.0.0.1:18765",
            "http://[::1]:18765",
            "https://www.prestigeworldwide.digital",
            "https://prestigeworldwide.digital",
            "https://evil.example",
            "http://check.prestigeworldwide.digital",
        ] {
            let error = AgentProcess::start(url, present.clone())
                .expect_err("an off-name agent-process base URL must be refused at start");
            assert!(
                error.to_string().contains("127.0.0.1")
                    || error.to_string().contains("loopback")
                    || error
                        .to_string()
                        .contains("check.prestigeworldwide.digital"),
                "the start refuse must name the accepted check host: {error} for {url}"
            );
        }
    }

    #[test]
    fn laboratory_runtime_agent_process_does_not_read_holder_secrets_or_write_an_instance() {
        let production = include_str!("runtime_check.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source sits before the test module");
        let process_src = production
            .split("pub struct AgentProcess")
            .nth(1)
            .expect("AgentProcess must exist");
        assert!(
            !process_src.contains("HolderProof::SecretPath")
                && !process_src.contains("store().holder_secret_path")
                && !process_src.contains("std::fs::read")
                && !process_src.contains("birth_write")
                && !process_src.contains("kill_instance")
                && !process_src.contains("save_instance")
                && !process_src.contains("spawn_child")
                && !process_src.contains("add_agent_type"),
            "AgentProcess must not read holder secrets and must not mint, birth, kill, or write an instance"
        );
        let (_directory_a, _store_a, directory_b, base, birth, present) =
            two_store_svid_runtime_setup();
        let process = AgentProcess::start(&base, RuntimePresent::Svid(present))
            .expect("start one durable agent process");
        let _ = process.before_next_tool(|_challenge| Ok("00".repeat(32)), None::<fn()>);
        let store_b = Kernel::open(directory_b.path());
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "AgentProcess must not write the issuing inode on store B"
        );
        assert!(
            store_b
                .store()
                .list_instances()
                .expect("list store B instances")
                .is_empty(),
            "AgentProcess must not write an instance on store B"
        );
        assert!(
            store_b
                .store()
                .list_agent_types()
                .expect("list store B agent types")
                .is_empty(),
            "AgentProcess must not mint an agent type on store B"
        );
        assert!(
            store_b
                .store()
                .list_capabilities()
                .expect("list store B capabilities")
                .is_empty(),
            "AgentProcess must not mint a capability on store B"
        );
    }

    #[test]
    fn laboratory_runtime_agent_process_add_act_line_is_fail_closed() {
        assert!(is_agent_process_add_act_line("add-act"));
        assert!(is_agent_process_add_act_line(
            "add-act --presentation-json /p.json --certificate-pem /p.pem"
        ));
        assert!(is_agent_process_add_act_line(
            "  add-act --presentation-json /p.json --certificate-pem /p.pem"
        ));
        assert!(!is_agent_process_add_act_line("echo add-act"));
        assert!(!is_agent_process_add_act_line("add-act-now"));
        assert!(!is_agent_process_add_act_line("stop"));

        let svid = parse_agent_process_add_act_line(
            "add-act --presentation-json /p.json --certificate-pem /p.pem --holder-proof-command \"prometheus holder-sign --holder-secret-path /h.secret\"",
        )
        .expect("an honest X.509-SVID add-act line must parse");
        assert_eq!(svid.presentation_json_path, "/p.json");
        assert_eq!(svid.certificate_pem_path.as_deref(), Some("/p.pem"));
        assert_eq!(
            svid.holder_proof_command.as_deref(),
            Some("prometheus holder-sign --holder-secret-path /h.secret")
        );
        assert!(svid.workload_identity_token_path.is_none());

        let wimse = parse_agent_process_add_act_line(
            "add-act --presentation-json /w.json --workload-identity-token /token --content-digest digest --signature-input input --signature sig",
        )
        .expect("an honest WIMSE add-act line must parse");
        assert_eq!(
            wimse.workload_identity_token_path.as_deref(),
            Some("/token")
        );
        assert_eq!(wimse.content_digest.as_deref(), Some("digest"));
        assert!(wimse.certificate_pem_path.is_none());

        let mixed = parse_agent_process_add_act_line(
            "add-act --presentation-json /p.json --certificate-pem /p.pem --workload-identity-token /token --content-digest digest --signature-input input --signature sig",
        )
        .expect_err("mixing on-ramps on one add-act line must be refused");
        assert!(
            mixed.to_string().contains("mix") || mixed.to_string().contains("on-ramp"),
            "the mix refuse must name the on-ramp mix: {mixed}"
        );

        let missing = parse_agent_process_add_act_line("add-act --certificate-pem /p.pem")
            .expect_err("an add-act line without --presentation-json must be refused");
        assert!(
            missing.to_string().contains("presentation-json"),
            "the missing-present refuse must name presentation-json: {missing}"
        );

        let secret = parse_agent_process_add_act_line(
            "add-act --presentation-json /p.json --certificate-pem /p.pem --holder-secret-path /holder.secret",
        )
        .expect("the parser names a holder secret path so the caller can refuse it");
        assert_eq!(secret.holder_secret_path.as_deref(), Some("/holder.secret"));

        let off_name = parse_agent_process_add_act_line(
            "add-act --presentation-json /p.json --certificate-pem /p.pem --base-url https://evil.example",
        )
        .expect_err("add-act must not accept a new check host");
        assert!(
            off_name.to_string().contains("does not accept")
                || off_name.to_string().contains("check host"),
            "the off-name add-act refuse must name the unknown flag: {off_name}"
        );

        let mut process = AgentProcess::start(
            "http://127.0.0.1:9",
            RuntimePresent::Svid(SvidPresent {
                presentation_json: "{}".to_string(),
                certificate_pem: "pem".to_string(),
            }),
        )
        .expect("start may succeed on URL parse");
        assert_eq!(process.held_act_count(), 1);
        let empty_pem = process
            .add_act(RuntimePresent::Svid(SvidPresent {
                presentation_json: "{}".to_string(),
                certificate_pem: String::new(),
            }))
            .expect_err("a blank X.509-SVID wrap on add_act must be refused");
        assert!(
            empty_pem.to_string().contains("wrap") || empty_pem.to_string().contains("add-act"),
            "the blank wrap refuse must name the missing wrap: {empty_pem}"
        );
        let empty_wimse = process
            .add_act(RuntimePresent::Wimse(WimsePresent {
                presentation_json: "{}".to_string(),
                workload_identity_token: String::new(),
                content_digest: "digest".to_string(),
                signature_input: "input".to_string(),
                signature: "sig".to_string(),
            }))
            .expect_err("a blank WIMSE token on add_act must be refused");
        assert!(
            empty_wimse.to_string().contains("WIMSE")
                || empty_wimse.to_string().contains("add-act"),
            "the blank WIMSE refuse must name WIMSE: {empty_wimse}"
        );
        assert_eq!(
            process.held_act_count(),
            1,
            "a refused add must not hold the new Assertion Act"
        );

        let quoted = parse_agent_process_add_act_line(
            r#"add-act --presentation-json /w.json --workload-identity-token /token --content-digest digest --signature-input "sig1=(\"@method\" \"@request-target\")" --signature sig"#,
        )
        .expect("an honest WIMSE add-act line with escaped quotes must parse");
        assert_eq!(
            quoted.signature_input.as_deref(),
            Some(r#"sig1=("@method" "@request-target")"#)
        );
        assert_eq!(
            add_act_field_value("digest").expect("a literal WIMSE field must stay a value"),
            "digest"
        );
        let missing = add_act_field_value("@/tmp/prometheus-missing-add-act-field")
            .expect_err("a missing add-act @-file must be refused");
        assert!(
            missing.to_string().contains("@-file")
                || missing.to_string().contains("could not be read"),
            "the missing @-file refuse must name the file: {missing}"
        );
        let secret = add_act_field_value("@/tmp/holder.secret")
            .expect_err("an add-act @-file that names a secret path must be refused");
        assert!(
            secret.to_string().contains("secret"),
            "the secret @-file refuse must name secret material: {secret}"
        );
        let field_dir = tempfile::tempdir().expect("create a directory for an add-act @-file");
        let field_path = field_dir.path().join("signature_input");
        std::fs::write(&field_path, "sig1=(\"@method\")\n").expect("write the add-act @-file");
        let named = format!("@{}", field_path.display());
        assert_eq!(
            add_act_field_value(&named).expect("an honest add-act @-file must be read"),
            r#"sig1=("@method")"#
        );
    }

    #[test]
    fn laboratory_runtime_agent_process_add_act_allows_then_refuses_after_kill_accept_without_restart(
    ) {
        let (_directory_a, store_a, directory_b, base, birth, svid) =
            two_store_svid_runtime_setup();
        let wimse = laboratory_wimse_present(&store_a, &birth);
        let mut process = AgentProcess::start(&base, RuntimePresent::Svid(svid))
            .expect("start one durable agent process with the first on-ramp");
        assert_eq!(process.held_act_count(), 1);
        let ran_first = std::cell::Cell::new(false);
        let first = process.before_next_tool(
            |challenge| {
                store_a.sign_holder_nonce(
                    &challenge.challenge_message,
                    store_a.store().holder_secret_path(&birth.instance.id),
                )
            },
            Some(|| ran_first.set(true)),
        );
        assert_eq!(
            first.gate, "ALLOWED",
            "the first before_next_tool on the first live act must print ALLOWED"
        );
        assert!(
            first.tool_may_run() && first.tool_ran && ran_first.get(),
            "the first before_next_tool must run the tool"
        );

        process
            .add_act(RuntimePresent::Wimse(wimse))
            .expect("add the second on-ramp without a restart");
        assert_eq!(process.held_act_count(), 2);

        let ran_missing = std::cell::Cell::new(false);
        let missing = process.before_next_tool(
            |_challenge| Ok(String::new()),
            Some(|| ran_missing.set(true)),
        );
        assert_eq!(
            missing.gate, "REFUSED",
            "a missing holder proof after add_act must print REFUSED"
        );
        assert!(
            !missing.tool_may_run() && !missing.tool_ran && !ran_missing.get(),
            "a missing holder proof after add_act must not run the tool"
        );

        let ran_second = std::cell::Cell::new(false);
        let second = process.before_next_tool(
            |challenge| {
                store_a.sign_holder_nonce(
                    &challenge.challenge_message,
                    store_a.store().holder_secret_path(&birth.instance.id),
                )
            },
            Some(|| ran_second.set(true)),
        );
        assert_eq!(
            second.gate, "ALLOWED",
            "after add_act both live on-ramp Assertion Acts must print ALLOWED"
        );
        assert!(
            second.tool_may_run() && second.tool_ran && ran_second.get(),
            "the tool after add_act must run only after both documented checks allow"
        );

        store_a
            .kill_instance(&birth.instance.id)
            .expect("store A must persist local kill");
        let bundle = store_a
            .build_kill_bundle(Some(&birth.instance.id), None)
            .expect("export the signed death bundle");
        let store_b = Kernel::open(directory_b.path());
        store_b
            .accept_kill_bundle_artifacts(&bundle)
            .expect("store B must accept the signed death bundle");

        let holder_path = store_a.store().holder_secret_path(&birth.instance.id);
        let ran_third = std::cell::Cell::new(false);
        let refuse = process.before_next_tool(
            |challenge| {
                crate::holder_sign::sign_holder_proof(
                    &holder_path,
                    Some(&challenge.challenge_message),
                    None,
                )
            },
            Some(|| ran_third.set(true)),
        );
        assert_eq!(
            refuse.gate,
            "REFUSED",
            "the same AgentProcess must print REFUSED after Decommission of an added act without a restart: {:?}",
            refuse
                .decision
                .as_ref()
                .ok()
                .and_then(|decision| decision.reason.clone())
        );
        assert!(
            !refuse.tool_may_run() && !refuse.tool_ran && !ran_third.get(),
            "the same AgentProcess must not run the tool after Decommission of an added act"
        );
        let refuse_decision = refuse.decision.expect(
            "the after-add before_next_tool must return a check decision after kill accept",
        );
        assert_eq!(
            refuse_decision.result, "refused",
            "death must win on the added Assertion Act: {:?}",
            refuse_decision.reason
        );
        let reason = refuse_decision.reason.unwrap_or_default();
        assert!(
            reason.contains("accepted a kill") || reason.contains("kill accept"),
            "the after-add refuse must name accepted kill, not a missing holder signature: {reason}"
        );
        assert!(
            store_b.store().load_instance(&birth.instance.id).is_err(),
            "store B must still write no instance record after add_act"
        );
    }

    #[test]
    fn laboratory_runtime_agent_process_add_act_child_then_refuses_after_parent_kill_accept_without_restart(
    ) {
        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let parent = laboratory_birth(&store_a);
        let parent_present = laboratory_svid_present(&store_a, &parent);
        let child = laboratory_spawn_child(&store_a, &parent);
        let child_present =
            laboratory_svid_present_for(&store_a, &child.instance.id, &child.capability.id);

        let directory_b = tempdir().expect("create store B");
        let store_b_live = Kernel::open(directory_b.path());
        store_b_live.initialize().expect("initialize store B");
        let public_key = store_a
            .store()
            .load_issuer()
            .expect("load store A issuer")
            .current_public_key_hex();
        store_b_live
            .accept_issuer_public_key(&public_key)
            .expect("pin the foreign issuer public key");
        let (base, _handle) = spawn_loopback_host(store_b_live);

        let mut process = AgentProcess::start(&base, RuntimePresent::Svid(parent_present))
            .expect("start one durable agent process on the parent Assertion Act");
        let ran_first = std::cell::Cell::new(false);
        let first = process.before_next_tool(
            |challenge| {
                store_a.sign_holder_nonce(
                    &challenge.challenge_message,
                    store_a.store().holder_secret_path(&parent.instance.id),
                )
            },
            Some(|| ran_first.set(true)),
        );
        assert_eq!(
            first.gate, "ALLOWED",
            "the first before_next_tool on the live parent must print ALLOWED"
        );
        assert!(
            first.tool_may_run() && first.tool_ran && ran_first.get(),
            "the first before_next_tool must run the parent tool"
        );

        process
            .add_act(RuntimePresent::Svid(child_present))
            .expect("add the narrower child without a restart");
        assert_eq!(process.held_act_count(), 2);

        let sign_index = std::cell::Cell::new(0);
        let ran_second = std::cell::Cell::new(false);
        let second = process.before_next_tool(
            |challenge| {
                let index = sign_index.get();
                sign_index.set(index + 1);
                let instance_id = if index == 0 {
                    parent.instance.id.as_str()
                } else {
                    child.instance.id.as_str()
                };
                store_a.sign_holder_nonce(
                    &challenge.challenge_message,
                    store_a.store().holder_secret_path(instance_id),
                )
            },
            Some(|| ran_second.set(true)),
        );
        assert_eq!(
            second.gate, "ALLOWED",
            "after add_act the parent and the narrower child must print ALLOWED"
        );
        assert!(
            second.tool_may_run() && second.tool_ran && ran_second.get(),
            "the tool after child add_act must run only after both checks allow"
        );

        store_a
            .kill_instance(&parent.instance.id)
            .expect("store A must persist parent Decommission");
        let bundle = store_a
            .build_kill_bundle(Some(&parent.instance.id), None)
            .expect("export the signed parent death bundle");
        let store_b = Kernel::open(directory_b.path());
        store_b
            .accept_kill_bundle_artifacts(&bundle)
            .expect("store B must accept the signed parent death bundle");

        let parent_holder = store_a.store().holder_secret_path(&parent.instance.id);
        let child_holder = store_a.store().holder_secret_path(&child.instance.id);
        let refuse_index = std::cell::Cell::new(0);
        let ran_third = std::cell::Cell::new(false);
        let refuse = process.before_next_tool(
            |challenge| {
                let index = refuse_index.get();
                refuse_index.set(index + 1);
                let holder_path = if index == 0 {
                    parent_holder.as_path()
                } else {
                    child_holder.as_path()
                };
                crate::holder_sign::sign_holder_proof(
                    holder_path,
                    Some(&challenge.challenge_message),
                    None,
                )
            },
            Some(|| ran_third.set(true)),
        );
        assert_eq!(
            refuse.gate,
            "REFUSED",
            "the same AgentProcess must print REFUSED after parent kill accept of an added child without a restart: {:?}",
            refuse
                .decision
                .as_ref()
                .ok()
                .and_then(|decision| decision.reason.clone())
        );
        assert!(
            !refuse.tool_may_run() && !refuse.tool_ran && !ran_third.get(),
            "the same AgentProcess must not run the tool after parent Decommission of an added child"
        );
        let refuse_decision = refuse.decision.expect(
            "the after-child-add before_next_tool must return a check decision after parent kill accept",
        );
        assert_eq!(
            refuse_decision.result, "refused",
            "parent death must win on the added child: {:?}",
            refuse_decision.reason
        );
        let reason = refuse_decision.reason.unwrap_or_default();
        assert!(
            reason.contains("accepted a kill") || reason.contains("kill accept"),
            "the after-child-add refuse must name accepted kill cascade, not a missing holder signature: {reason}"
        );
        assert!(
            store_b.store().load_instance(&parent.instance.id).is_err(),
            "store B must still write no parent instance record after child add_act"
        );
        assert!(
            store_b.store().load_instance(&child.instance.id).is_err(),
            "store B must still write no child instance record after child add_act"
        );
    }

    #[test]
    fn laboratory_runtime_agent_process_add_act_wimse_child_then_refuses_after_parent_kill_accept_without_restart(
    ) {
        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let parent = laboratory_birth(&store_a);
        let parent_present = laboratory_svid_present(&store_a, &parent);
        let child = laboratory_spawn_child(&store_a, &parent);
        let child_present =
            laboratory_wimse_present_for(&store_a, &child.instance.id, &child.capability.id);

        let directory_b = tempdir().expect("create store B");
        let store_b_live = Kernel::open(directory_b.path());
        store_b_live.initialize().expect("initialize store B");
        let public_key = store_a
            .store()
            .load_issuer()
            .expect("load store A issuer")
            .current_public_key_hex();
        store_b_live
            .accept_issuer_public_key(&public_key)
            .expect("pin the foreign issuer public key");
        let (base, _handle) = spawn_loopback_host(store_b_live);

        let mut process = AgentProcess::start(&base, RuntimePresent::Svid(parent_present))
            .expect("start one durable agent process on the parent Assertion Act");
        let ran_first = std::cell::Cell::new(false);
        let first = process.before_next_tool(
            |challenge| {
                store_a.sign_holder_nonce(
                    &challenge.challenge_message,
                    store_a.store().holder_secret_path(&parent.instance.id),
                )
            },
            Some(|| ran_first.set(true)),
        );
        assert_eq!(
            first.gate, "ALLOWED",
            "the first before_next_tool on the live parent must print ALLOWED"
        );
        assert!(
            first.tool_may_run() && first.tool_ran && ran_first.get(),
            "the first before_next_tool must run the parent tool"
        );

        process
            .add_act(RuntimePresent::Wimse(child_present))
            .expect("add the narrower WIMSE child without a restart");
        assert_eq!(process.held_act_count(), 2);

        let sign_index = std::cell::Cell::new(0);
        let ran_second = std::cell::Cell::new(false);
        let second = process.before_next_tool(
            |challenge| {
                let index = sign_index.get();
                sign_index.set(index + 1);
                let instance_id = if index == 0 {
                    parent.instance.id.as_str()
                } else {
                    child.instance.id.as_str()
                };
                store_a.sign_holder_nonce(
                    &challenge.challenge_message,
                    store_a.store().holder_secret_path(instance_id),
                )
            },
            Some(|| ran_second.set(true)),
        );
        assert_eq!(
            second.gate, "ALLOWED",
            "after add_act the parent and the narrower WIMSE child must print ALLOWED"
        );
        assert!(
            second.tool_may_run() && second.tool_ran && ran_second.get(),
            "the tool after WIMSE child add_act must run only after both checks allow"
        );

        store_a
            .kill_instance(&parent.instance.id)
            .expect("store A must persist parent Decommission");
        let bundle = store_a
            .build_kill_bundle(Some(&parent.instance.id), None)
            .expect("export the signed parent death bundle");
        let store_b = Kernel::open(directory_b.path());
        store_b
            .accept_kill_bundle_artifacts(&bundle)
            .expect("store B must accept the signed parent death bundle");

        let parent_holder = store_a.store().holder_secret_path(&parent.instance.id);
        let child_holder = store_a.store().holder_secret_path(&child.instance.id);
        let refuse_index = std::cell::Cell::new(0);
        let ran_third = std::cell::Cell::new(false);
        let refuse = process.before_next_tool(
            |challenge| {
                let index = refuse_index.get();
                refuse_index.set(index + 1);
                let holder_path = if index == 0 {
                    parent_holder.as_path()
                } else {
                    child_holder.as_path()
                };
                crate::holder_sign::sign_holder_proof(
                    holder_path,
                    Some(&challenge.challenge_message),
                    None,
                )
            },
            Some(|| ran_third.set(true)),
        );
        assert_eq!(
            refuse.gate,
            "REFUSED",
            "the same AgentProcess must print REFUSED after parent kill accept of an added WIMSE child without a restart: {:?}",
            refuse
                .decision
                .as_ref()
                .ok()
                .and_then(|decision| decision.reason.clone())
        );
        assert!(
            !refuse.tool_may_run() && !refuse.tool_ran && !ran_third.get(),
            "the same AgentProcess must not run the tool after parent Decommission of an added WIMSE child"
        );
        let refuse_decision = refuse.decision.expect(
            "the after-WIMSE-child-add before_next_tool must return a check decision after parent kill accept",
        );
        assert_eq!(
            refuse_decision.result, "refused",
            "parent death must win on the added WIMSE child: {:?}",
            refuse_decision.reason
        );
        let reason = refuse_decision.reason.unwrap_or_default();
        assert!(
            reason.contains("accepted a kill") || reason.contains("kill accept"),
            "the after-WIMSE-child-add refuse must name accepted kill cascade, not a missing holder signature: {reason}"
        );
        assert!(
            store_b.store().load_instance(&parent.instance.id).is_err(),
            "store B must still write no parent instance record after WIMSE child add_act"
        );
        assert!(
            store_b.store().load_instance(&child.instance.id).is_err(),
            "store B must still write no child instance record after WIMSE child add_act"
        );
    }

    #[test]
    fn laboratory_runtime_agent_process_named_act_line_is_fail_closed() {
        assert!(is_agent_process_named_act_line("act 1"));
        assert!(is_agent_process_named_act_line("act 2 echo tool"));
        assert!(!is_agent_process_named_act_line(
            "add-act --presentation-json /p.json --certificate-pem /p.pem"
        ));
        assert!(!is_agent_process_named_act_line("echo act 1"));
        let error = parse_agent_process_named_act_line(
            "add-act --presentation-json /p.json --certificate-pem /p.pem",
        )
        .expect_err("add-act is not a named act line");
        assert!(
            error.to_string().contains("act"),
            "the refuse must name act: {error}"
        );
        let (number, tool) = parse_agent_process_named_act_line("act 2 echo TOOL")
            .expect("an honest named act line must parse");
        assert_eq!(number, 2);
        assert_eq!(tool, "echo TOOL");
        let zero = parse_agent_process_named_act_line("act 0 echo TOOL")
            .expect_err("act 0 must be refused");
        assert!(
            zero.to_string().contains("1") || zero.to_string().contains("held"),
            "act 0 must name the one-based lock: {zero}"
        );
        let missing = parse_agent_process_named_act_line("act")
            .expect_err("act without a number must be refused");
        assert!(
            missing.to_string().contains("number") || missing.to_string().contains("held"),
            "a missing number must be refused: {missing}"
        );
        let process = AgentProcess::start(
            "http://127.0.0.1:9",
            RuntimePresent::Svid(SvidPresent {
                presentation_json: "{}".to_string(),
                certificate_pem: "pem".to_string(),
            }),
        )
        .expect("start may succeed on URL parse");
        let ran = std::cell::Cell::new(false);
        let outcome =
            process.before_named_act(2, |_challenge| Ok("00".repeat(32)), Some(|| ran.set(true)));
        assert_eq!(outcome.gate, "REFUSED");
        assert!(!outcome.tool_may_run() && !outcome.tool_ran && !ran.get());
        let zero_ran = std::cell::Cell::new(false);
        let zero_out = process.before_named_act(
            0,
            |_challenge| Ok("00".repeat(32)),
            Some(|| zero_ran.set(true)),
        );
        assert_eq!(zero_out.gate, "REFUSED");
        assert!(!zero_out.tool_ran && !zero_ran.get());
    }

    #[test]
    fn laboratory_runtime_agent_process_named_act_allows_the_live_act_after_the_other_dies() {
        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let first = laboratory_birth(&store_a);
        let second = laboratory_birth(&store_a);
        let first_present = laboratory_svid_present(&store_a, &first);
        let second_present = laboratory_svid_present(&store_a, &second);

        let directory_b = tempdir().expect("create store B");
        let store_b_live = Kernel::open(directory_b.path());
        store_b_live.initialize().expect("initialize store B");
        let public_key = store_a
            .store()
            .load_issuer()
            .expect("load store A issuer")
            .current_public_key_hex();
        store_b_live
            .accept_issuer_public_key(&public_key)
            .expect("pin the foreign issuer public key");
        let (base, _handle) = spawn_loopback_host(store_b_live);

        let mut process = AgentProcess::start(&base, RuntimePresent::Svid(first_present))
            .expect("start on the first Assertion Act");
        process
            .add_act(RuntimePresent::Svid(second_present))
            .expect("add the second independent Assertion Act");
        assert_eq!(process.held_act_count(), 2);

        let first_id = first.instance.id.clone();
        let second_id = second.instance.id.clone();
        let ran_both = std::cell::Cell::new(false);
        let both_index = std::cell::Cell::new(0);
        let both = process.before_next_tool(
            |challenge| {
                let i = both_index.get();
                both_index.set(i + 1);
                let id = if i == 0 {
                    first_id.as_str()
                } else {
                    second_id.as_str()
                };
                store_a.sign_holder_nonce(
                    &challenge.challenge_message,
                    store_a.store().holder_secret_path(id),
                )
            },
            Some(|| ran_both.set(true)),
        );
        assert_eq!(
            both.gate, "ALLOWED",
            "two live independent acts must print ALLOWED"
        );
        assert!(both.tool_ran && ran_both.get());

        store_a
            .kill_instance(&first.instance.id)
            .expect("store A must persist Decommission of the first instance");
        let bundle = store_a
            .build_kill_bundle(Some(&first.instance.id), None)
            .expect("export the first death bundle");
        let store_b = Kernel::open(directory_b.path());
        store_b
            .accept_kill_bundle_artifacts(&bundle)
            .expect("store B must accept the first death bundle");

        let ran_unnamed = std::cell::Cell::new(false);
        let unnamed_index = std::cell::Cell::new(0);
        let unnamed = process.before_next_tool(
            |challenge| {
                let i = unnamed_index.get();
                unnamed_index.set(i + 1);
                let id = if i == 0 {
                    first_id.as_str()
                } else {
                    second_id.as_str()
                };
                crate::holder_sign::sign_holder_proof(
                    store_a.store().holder_secret_path(id),
                    Some(&challenge.challenge_message),
                    None,
                )
            },
            Some(|| ran_unnamed.set(true)),
        );
        assert_eq!(
            unnamed.gate, "REFUSED",
            "an unnamed tool line must refuse when one held act is dead"
        );
        assert!(!unnamed.tool_ran && !ran_unnamed.get());
        let unnamed_reason = unnamed
            .decision
            .expect("unnamed refuse after one death must return a check decision")
            .reason
            .unwrap_or_default();
        assert!(
            unnamed_reason.contains("accepted a kill") || unnamed_reason.contains("kill accept"),
            "the unnamed refuse must name accepted kill: {unnamed_reason}"
        );

        let first_holder = store_a.store().holder_secret_path(&first.instance.id);
        let ran_dead = std::cell::Cell::new(false);
        let dead = process.before_named_act(
            1,
            |challenge| {
                crate::holder_sign::sign_holder_proof(
                    &first_holder,
                    Some(&challenge.challenge_message),
                    None,
                )
            },
            Some(|| ran_dead.set(true)),
        );
        assert_eq!(dead.gate, "REFUSED", "naming the dead act must refuse");
        assert!(!dead.tool_ran && !ran_dead.get());

        let ran_live = std::cell::Cell::new(false);
        let live = process.before_named_act(
            2,
            |challenge| {
                store_a.sign_holder_nonce(
                    &challenge.challenge_message,
                    store_a.store().holder_secret_path(&second.instance.id),
                )
            },
            Some(|| ran_live.set(true)),
        );
        assert_eq!(
            live.gate,
            "ALLOWED",
            "naming the still-live act must print ALLOWED after the other dies: {:?}",
            live.decision.as_ref().ok().and_then(|d| d.reason.clone())
        );
        assert!(live.tool_may_run() && live.tool_ran && ran_live.get());
        assert!(
            store_b.store().load_instance(&first.instance.id).is_err(),
            "store B must still write no first instance record"
        );
        assert!(
            store_b.store().load_instance(&second.instance.id).is_err(),
            "store B must still write no second instance record"
        );
    }

    #[test]
    fn laboratory_runtime_agent_process_named_act_allows_the_live_wimse_act_after_the_first_dies() {
        let directory_a = tempdir().expect("create store A");
        let store_a = Kernel::open(directory_a.path());
        store_a.initialize().expect("initialize store A");
        let first = laboratory_birth(&store_a);
        let second = laboratory_birth(&store_a);
        let first_present = laboratory_svid_present(&store_a, &first);
        let second_present = laboratory_wimse_present(&store_a, &second);

        let directory_b = tempdir().expect("create store B");
        let store_b_live = Kernel::open(directory_b.path());
        store_b_live.initialize().expect("initialize store B");
        let public_key = store_a
            .store()
            .load_issuer()
            .expect("load store A issuer")
            .current_public_key_hex();
        store_b_live
            .accept_issuer_public_key(&public_key)
            .expect("pin the foreign issuer public key");
        let (base, _handle) = spawn_loopback_host(store_b_live);

        let mut process = AgentProcess::start(&base, RuntimePresent::Svid(first_present))
            .expect("start on the first X.509-SVID Assertion Act");
        process
            .add_act(RuntimePresent::Wimse(second_present))
            .expect("add the second independent WIMSE Assertion Act");
        assert_eq!(process.held_act_count(), 2);

        let first_id = first.instance.id.clone();
        let second_id = second.instance.id.clone();
        let ran_both = std::cell::Cell::new(false);
        let both_index = std::cell::Cell::new(0);
        let both = process.before_next_tool(
            |challenge| {
                let i = both_index.get();
                both_index.set(i + 1);
                let id = if i == 0 {
                    first_id.as_str()
                } else {
                    second_id.as_str()
                };
                store_a.sign_holder_nonce(
                    &challenge.challenge_message,
                    store_a.store().holder_secret_path(id),
                )
            },
            Some(|| ran_both.set(true)),
        );
        assert_eq!(
            both.gate, "ALLOWED",
            "two live independent acts, second WIMSE, must print ALLOWED"
        );
        assert!(both.tool_ran && ran_both.get());

        store_a
            .kill_instance(&first.instance.id)
            .expect("store A must persist Decommission of the first instance");
        let bundle = store_a
            .build_kill_bundle(Some(&first.instance.id), None)
            .expect("export the first death bundle");
        let store_b = Kernel::open(directory_b.path());
        store_b
            .accept_kill_bundle_artifacts(&bundle)
            .expect("store B must accept the first death bundle");

        let ran_unnamed = std::cell::Cell::new(false);
        let unnamed_index = std::cell::Cell::new(0);
        let unnamed = process.before_next_tool(
            |challenge| {
                let i = unnamed_index.get();
                unnamed_index.set(i + 1);
                let id = if i == 0 {
                    first_id.as_str()
                } else {
                    second_id.as_str()
                };
                crate::holder_sign::sign_holder_proof(
                    store_a.store().holder_secret_path(id),
                    Some(&challenge.challenge_message),
                    None,
                )
            },
            Some(|| ran_unnamed.set(true)),
        );
        assert_eq!(
            unnamed.gate, "REFUSED",
            "an unnamed tool line must refuse when one held act is dead"
        );
        assert!(!unnamed.tool_ran && !ran_unnamed.get());
        let unnamed_reason = unnamed
            .decision
            .expect("unnamed refuse after one death must return a check decision")
            .reason
            .unwrap_or_default();
        assert!(
            unnamed_reason.contains("accepted a kill") || unnamed_reason.contains("kill accept"),
            "the unnamed refuse must name accepted kill: {unnamed_reason}"
        );

        let first_holder = store_a.store().holder_secret_path(&first.instance.id);
        let ran_dead = std::cell::Cell::new(false);
        let dead = process.before_named_act(
            1,
            |challenge| {
                crate::holder_sign::sign_holder_proof(
                    &first_holder,
                    Some(&challenge.challenge_message),
                    None,
                )
            },
            Some(|| ran_dead.set(true)),
        );
        assert_eq!(
            dead.gate, "REFUSED",
            "naming the dead first act must refuse"
        );
        assert!(!dead.tool_ran && !ran_dead.get());

        let ran_live = std::cell::Cell::new(false);
        let live = process.before_named_act(
            2,
            |challenge| {
                store_a.sign_holder_nonce(
                    &challenge.challenge_message,
                    store_a.store().holder_secret_path(&second.instance.id),
                )
            },
            Some(|| ran_live.set(true)),
        );
        assert_eq!(
            live.gate,
            "ALLOWED",
            "naming the still-live WIMSE act must print ALLOWED after the first dies: {:?}",
            live.decision.as_ref().ok().and_then(|d| d.reason.clone())
        );
        assert!(live.tool_may_run() && live.tool_ran && ran_live.get());

        store_a
            .kill_instance(&second.instance.id)
            .expect("store A must persist Decommission of the WIMSE instance");
        let wimse_bundle = store_a
            .build_kill_bundle(Some(&second.instance.id), None)
            .expect("export the WIMSE death bundle");
        store_b
            .accept_kill_bundle_artifacts(&wimse_bundle)
            .expect("store B must accept the WIMSE death bundle");

        let second_holder = store_a.store().holder_secret_path(&second.instance.id);
        let ran_dead_wimse = std::cell::Cell::new(false);
        let dead_wimse = process.before_named_act(
            2,
            |challenge| {
                crate::holder_sign::sign_holder_proof(
                    &second_holder,
                    Some(&challenge.challenge_message),
                    None,
                )
            },
            Some(|| ran_dead_wimse.set(true)),
        );
        assert_eq!(
            dead_wimse.gate, "REFUSED",
            "naming the dead WIMSE act must refuse"
        );
        assert!(!dead_wimse.tool_ran && !ran_dead_wimse.get());
        let dead_wimse_reason = dead_wimse
            .decision
            .expect("named dead WIMSE must return a check decision")
            .reason
            .unwrap_or_default();
        assert!(
            dead_wimse_reason.contains("accepted a kill")
                || dead_wimse_reason.contains("kill accept"),
            "the named dead WIMSE refuse must name accepted kill: {dead_wimse_reason}"
        );

        let missing_ran = std::cell::Cell::new(false);
        let missing = process.before_named_act(
            3,
            |_challenge| Ok("00".repeat(32)),
            Some(|| missing_ran.set(true)),
        );
        assert_eq!(
            missing.gate, "REFUSED",
            "an index this process does not hold must refuse"
        );
        assert!(!missing.tool_ran && !missing_ran.get());
        assert!(
            store_b.store().load_instance(&first.instance.id).is_err(),
            "store B must still write no first instance record"
        );
        assert!(
            store_b.store().load_instance(&second.instance.id).is_err(),
            "store B must still write no second instance record"
        );
    }

    struct SwappableWellKnownHost {
        document: Mutex<String>,
        missing: Mutex<bool>,
        swap_after_challenge: Mutex<Option<String>>,
        check_posts: Mutex<u32>,
        check_status: Mutex<u16>,
        check_body: Mutex<Option<String>>,
    }

    fn spawn_swappable_well_known_host(
        document: String,
    ) -> (String, Arc<SwappableWellKnownHost>, thread::JoinHandle<()>) {
        let state = Arc::new(SwappableWellKnownHost {
            document: Mutex::new(document),
            missing: Mutex::new(false),
            swap_after_challenge: Mutex::new(None),
            check_posts: Mutex::new(0),
            check_status: Mutex::new(200),
            check_body: Mutex::new(None),
        });
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback pin-test listener");
        let address = listener
            .local_addr()
            .expect("read the bound loopback pin-test address");
        let state_clone = state.clone();
        let handle = thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(mut stream) = incoming else {
                    continue;
                };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                        Err(_) => break,
                    }
                }
                let request = String::from_utf8_lossy(&request);
                let (status, body) = if request.starts_with("GET /.well-known/prometheus-check") {
                    if *state_clone.missing.lock().expect("missing flag") {
                        (404u16, "missing".to_string())
                    } else {
                        (
                            200u16,
                            state_clone.document.lock().expect("document").clone(),
                        )
                    }
                } else if request.contains("POST /verifier-challenge") {
                    if let Some(next) = state_clone
                        .swap_after_challenge
                        .lock()
                        .expect("swap after challenge")
                        .take()
                    {
                        *state_clone
                            .document
                            .lock()
                            .expect("document after challenge") = next;
                    }
                    (
                        200u16,
                        r#"{"challenge_nonce":"aa","challenge_message":"sign-this"}"#.to_string(),
                    )
                } else if request.contains("POST /check-svid")
                    || request.contains("POST /check-wimse")
                {
                    *state_clone.check_posts.lock().expect("check posts") += 1;
                    let status = *state_clone.check_status.lock().expect("check status");
                    let body = state_clone
                        .check_body
                        .lock()
                        .expect("check body")
                        .clone()
                        .unwrap_or_else(|| {
                            serde_json::json!({
                                "result": "allowed",
                                "instance_id": "pin-test",
                                "intent": "read",
                                "audience": "internal/prod"
                            })
                            .to_string()
                        });
                    (status, body)
                } else {
                    (404u16, "no".to_string())
                };
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        let base = format!("http://127.0.0.1:{}", address.port());
        for _ in 0..50 {
            if TcpStream::connect_timeout(&address, Duration::from_millis(40)).is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        (base, state, handle)
    }

    fn dummy_svid_present() -> SvidPresent {
        SvidPresent {
            presentation_json: serde_json::json!({
                "instance_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                "agent_type_id": "pin-type",
                "capability_id": "pin-cap",
                "on_behalf_of": "autonomous",
                "intent": "read",
                "audience": "internal/prod",
                "holder_public_key": "00",
                "issuer_public_key_hex": "00",
                "presented_at": "2026-08-23T00:00:00Z",
                "expires_at": "2026-08-23T00:01:00Z",
                "signature_hex": "00"
            })
            .to_string(),
            certificate_pem: "-----BEGIN CERTIFICATE-----\nPIN\n-----END CERTIFICATE-----\n"
                .to_string(),
        }
    }

    #[test]
    fn laboratory_runtime_pins_the_first_honest_well_known_document_and_refuses_a_later_swap() {
        let honest = documented_sample("/check-svid", "/check-wimse", "/verifier-challenge");
        let (base, host, _handle) = spawn_swappable_well_known_host(honest.clone());
        let runtime = LaboratoryRuntime::connect(&base).expect("connect the pin-test host");
        let first = runtime
            .load_document()
            .expect("the first honest well-known document must pin");
        assert_eq!(first.bind, "127.0.0.1");
        assert_eq!(first.checks[0].path, "/check-svid");
        assert_eq!(first.verifier_challenge.path, "/verifier-challenge");

        let mut swapped_bind: serde_json::Value = serde_json::from_str(&honest).unwrap();
        swapped_bind["bind"] = serde_json::json!("check.prestigeworldwide.digital");
        *host.document.lock().expect("swap bind") = swapped_bind.to_string();
        let bind_error = runtime
            .load_document()
            .expect_err("a later bind swap must be refused");
        assert!(
            bind_error.to_string().contains("swapped or grown")
                || bind_error.to_string().contains("changed bind")
                || bind_error.to_string().contains("does not match")
                || bind_error.to_string().contains("not interchangeable"),
            "the refuse must name the swapped or mismatched bind: {bind_error}"
        );

        let mut changed_path: serde_json::Value = serde_json::from_str(&honest).unwrap();
        changed_path["checks"][0]["path"] = serde_json::json!("/renamed-svid");
        *host.document.lock().expect("swap path") = changed_path.to_string();
        let path_error = runtime
            .load_document()
            .expect_err("a later check-path change must be refused");
        assert!(
            path_error.to_string().contains("swapped or grown")
                || path_error.to_string().contains("changed bind"),
            "the refuse must name the swapped document: {path_error}"
        );

        let mut grown: serde_json::Value = serde_json::from_str(&honest).unwrap();
        grown["checks"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"method": "POST", "path": "/check-extra"}));
        *host.document.lock().expect("grow checks") = grown.to_string();
        let grown_error = runtime
            .load_document()
            .expect_err("a later grown checks list must be refused");
        assert!(
            grown_error.to_string().contains("swapped or grown")
                || grown_error.to_string().contains("changed bind"),
            "the refuse must name the grown document: {grown_error}"
        );

        *host.document.lock().expect("restore") = honest.clone();
        let restored = runtime
            .load_document()
            .expect("a restored honest document must proceed");
        assert_eq!(restored.bind, "127.0.0.1");
        assert_eq!(restored.checks[0].path, "/check-svid");

        *host.missing.lock().expect("missing") = true;
        let missing = runtime
            .load_document()
            .expect_err("a missing document after the first honest fetch must be refused");
        assert!(
            missing.to_string().contains("did not return 200")
                || missing.to_string().contains("refuses"),
            "the missing document must fail closed: {missing}"
        );

        *host.missing.lock().expect("restore missing") = false;
        runtime
            .load_document()
            .expect("a restored honest document after a missing fetch must proceed");
    }

    #[test]
    fn laboratory_runtime_agent_process_refuses_a_swapped_well_known_document_without_caching_allow(
    ) {
        let honest = documented_sample("/check-svid", "/check-wimse", "/verifier-challenge");
        let (base, host, _handle) = spawn_swappable_well_known_host(honest.clone());
        let process = AgentProcess::start(&base, RuntimePresent::Svid(dummy_svid_present()))
            .expect("start one durable agent process against the pin-test host");
        let ran_first = std::cell::Cell::new(false);
        let allow = process.before_next_tool(
            |_challenge| Ok("11".repeat(32)),
            Some(|| ran_first.set(true)),
        );
        assert_eq!(
            allow.gate,
            "ALLOWED",
            "the first honest well-known document must allow the first tool line: {:?}",
            allow.decision.as_ref().err().map(|error| error.to_string())
        );
        assert!(
            allow.tool_may_run() && allow.tool_ran && ran_first.get(),
            "the first honest pin must still run the tool"
        );

        let mut swapped_bind: serde_json::Value = serde_json::from_str(&honest).unwrap();
        swapped_bind["bind"] = serde_json::json!("check.prestigeworldwide.digital");
        *host.document.lock().expect("swap bind") = swapped_bind.to_string();
        let ran_swap = std::cell::Cell::new(false);
        let refuse = process.before_next_tool(
            |_challenge| Ok("11".repeat(32)),
            Some(|| ran_swap.set(true)),
        );
        assert_eq!(
            refuse.gate, "REFUSED",
            "the same AgentProcess must refuse a swapped well-known bind"
        );
        assert!(
            !refuse.tool_may_run() && !refuse.tool_ran && !ran_swap.get(),
            "a swapped well-known document must not run the tool"
        );
        let swap_error = refuse
            .decision
            .expect_err("a swapped well-known document must fail closed");
        assert!(
            swap_error.to_string().contains("swapped or grown")
                || swap_error.to_string().contains("changed bind")
                || swap_error.to_string().contains("does not match")
                || swap_error.to_string().contains("not interchangeable"),
            "the refuse must name the swapped or mismatched bind: {swap_error}"
        );

        *host.document.lock().expect("restore") = honest;
        let ran_restored = std::cell::Cell::new(false);
        let restored = process.before_next_tool(
            |_challenge| Ok("11".repeat(32)),
            Some(|| ran_restored.set(true)),
        );
        assert_eq!(
            restored.gate,
            "ALLOWED",
            "a restored honest document must proceed: {:?}",
            restored
                .decision
                .as_ref()
                .err()
                .map(|error| error.to_string())
        );
        assert!(
            restored.tool_may_run() && restored.tool_ran && ran_restored.get(),
            "a restored honest document must run the tool again and must not cache ALLOWED"
        );
    }

    #[test]
    fn laboratory_runtime_one_shot_refuses_when_the_well_known_document_changes_between_challenge_and_check(
    ) {
        let honest = documented_sample("/check-svid", "/check-wimse", "/verifier-challenge");
        let (base, host, _handle) = spawn_swappable_well_known_host(honest.clone());
        let mut swapped_bind: serde_json::Value = serde_json::from_str(&honest).unwrap();
        swapped_bind["bind"] = serde_json::json!("check.prestigeworldwide.digital");
        *host.swap_after_challenge.lock().expect("arm bind swap") = Some(swapped_bind.to_string());
        let present = RuntimePresent::Svid(dummy_svid_present());
        let ran = std::cell::Cell::new(false);
        let outcome = before_tool(
            &base,
            &present,
            |_challenge| Ok("11".repeat(32)),
            Some(|| ran.set(true)),
        );
        assert_eq!(
            outcome.gate, "REFUSED",
            "one-shot before-tool must refuse a well-known bind swap between challenge and check"
        );
        assert!(
            !outcome.tool_ran && !ran.get(),
            "a TOCTOU well-known swap must not run the tool"
        );
        let error = outcome
            .decision
            .expect_err("a TOCTOU well-known swap must fail closed");
        assert!(
            error.to_string().contains("swapped or grown")
                || error.to_string().contains("changed bind")
                || error.to_string().contains("write verb")
                || error.to_string().contains("does not match")
                || error.to_string().contains("not interchangeable"),
            "the refuse must name the swapped or mismatched document: {error}"
        );
        assert_eq!(
            *host.check_posts.lock().expect("check posts"),
            0,
            "a TOCTOU well-known swap must not post the check"
        );

        let mut grown_write: serde_json::Value = serde_json::from_str(&honest).unwrap();
        grown_write["checks"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"method": "POST", "path": "/birth"}));
        *host.document.lock().expect("restore honest") = honest;
        *host.swap_after_challenge.lock().expect("arm write growth") =
            Some(grown_write.to_string());
        let ran_write = std::cell::Cell::new(false);
        let write = before_tool(
            &base,
            &present,
            |_challenge| Ok("11".repeat(32)),
            Some(|| ran_write.set(true)),
        );
        assert_eq!(
            write.gate, "REFUSED",
            "one-shot before-tool must refuse a write-verb growth between challenge and check"
        );
        assert!(!write.tool_ran && !ran_write.get());
        let write_error = write
            .decision
            .expect_err("a write-verb growth between challenge and check must fail closed");
        assert!(
            write_error.to_string().contains("write verb")
                || write_error.to_string().contains("swapped or grown")
                || write_error.to_string().contains("changed bind"),
            "the refuse must name the grown write verb or the swapped document: {write_error}"
        );
        assert_eq!(
            *host.check_posts.lock().expect("check posts after write"),
            0,
            "a write-verb growth between challenge and check must not post the check"
        );
    }

    #[test]
    fn laboratory_runtime_refuses_a_well_known_bind_that_does_not_match_the_accepted_host() {
        let honest = documented_sample("/check-svid", "/check-wimse", "/verifier-challenge");
        let mut public_bind: serde_json::Value = serde_json::from_str(&honest).unwrap();
        public_bind["bind"] = serde_json::json!("check.prestigeworldwide.digital");
        let (base, _host, _handle) = spawn_swappable_well_known_host(public_bind.to_string());
        let runtime = LaboratoryRuntime::connect(&base).expect("connect loopback");
        let error = runtime.load_document().expect_err(
            "a public bind on a loopback runtime must be refused even on the first fetch",
        );
        assert!(
            error.to_string().contains("does not match")
                || error.to_string().contains("not interchangeable"),
            "the refuse must name the bind mismatch: {error}"
        );

        let process = AgentProcess::start(&base, RuntimePresent::Svid(dummy_svid_present()))
            .expect("start may succeed before the document is fetched");
        let ran = std::cell::Cell::new(false);
        let outcome =
            process.before_next_tool(|_challenge| Ok("11".repeat(32)), Some(|| ran.set(true)));
        assert_eq!(
            outcome.gate, "REFUSED",
            "AgentProcess must refuse a well-known bind that is not the start() host"
        );
        assert!(!outcome.tool_ran && !ran.get());
        let process_error = outcome
            .decision
            .expect_err("a mismatched well-known bind must fail closed");
        assert!(
            process_error.to_string().contains("does not match")
                || process_error.to_string().contains("not interchangeable"),
            "the AgentProcess refuse must name the bind mismatch: {process_error}"
        );
    }

    fn refused_check_decision_json(result: &str) -> String {
        serde_json::json!({
            "result": result,
            "instance_id": "pin-test",
            "intent": "read",
            "audience": "internal/prod",
            "reason": "laboratory refuse body"
        })
        .to_string()
    }

    #[test]
    fn laboratory_runtime_refuses_http_200_whose_json_is_refused_or_empty() {
        let honest = documented_sample("/check-svid", "/check-wimse", "/verifier-challenge");
        let (base, host, _handle) = spawn_swappable_well_known_host(honest);
        let present = RuntimePresent::Svid(dummy_svid_present());

        *host.check_body.lock().expect("set refused 200 body") =
            Some(refused_check_decision_json("refused"));
        let ran = std::cell::Cell::new(false);
        let outcome = before_tool(
            &base,
            &present,
            |_challenge| Ok("11".repeat(32)),
            Some(|| ran.set(true)),
        );
        assert_eq!(
            outcome.gate, "REFUSED",
            "HTTP 200 whose JSON is refused must print REFUSED"
        );
        assert!(
            !outcome.tool_may_run() && !outcome.tool_ran && !ran.get(),
            "HTTP 200 whose JSON is refused must not run the tool"
        );
        let error = outcome
            .decision
            .expect_err("HTTP 200 whose JSON is refused must fail closed");
        assert!(
            error.to_string().contains("200")
                && (error.to_string().contains("refused")
                    || error.to_string().contains("not an allow")),
            "the refuse must name HTTP 200 and the refused body: {error}"
        );
        assert_eq!(
            *host
                .check_posts
                .lock()
                .expect("check posts after refused 200"),
            1,
            "parse honesty still posts the documented check and then refuses the dishonest 200"
        );

        *host.check_body.lock().expect("set denied 200 body") =
            Some(refused_check_decision_json("denied"));
        let denied_ran = std::cell::Cell::new(false);
        let denied = before_tool(
            &base,
            &present,
            |_challenge| Ok("11".repeat(32)),
            Some(|| denied_ran.set(true)),
        );
        assert_eq!(denied.gate, "REFUSED");
        assert!(!denied.tool_ran && !denied_ran.get());
        let denied_error = denied
            .decision
            .expect_err("HTTP 200 whose JSON is denied must fail closed");
        assert!(
            denied_error.to_string().contains("200")
                && (denied_error.to_string().contains("denied")
                    || denied_error.to_string().contains("not an allow")),
            "the refuse must name HTTP 200 and the denied body: {denied_error}"
        );

        *host.check_body.lock().expect("set empty 200 body") = Some(String::new());
        let empty_ran = std::cell::Cell::new(false);
        let empty = before_tool(
            &base,
            &present,
            |_challenge| Ok("11".repeat(32)),
            Some(|| empty_ran.set(true)),
        );
        assert_eq!(
            empty.gate, "REFUSED",
            "HTTP 200 with an empty body must print REFUSED"
        );
        assert!(
            !empty.tool_may_run() && !empty.tool_ran && !empty_ran.get(),
            "HTTP 200 with an empty body must not run the tool"
        );
        let empty_error = empty
            .decision
            .expect_err("HTTP 200 with an empty body must fail closed");
        assert!(
            empty_error.to_string().contains("empty")
                || empty_error.to_string().contains("Unknown is not live"),
            "the refuse must name the empty body: {empty_error}"
        );

        *host
            .check_body
            .lock()
            .expect("set refused 200 for AgentProcess") =
            Some(refused_check_decision_json("refused"));
        let process = AgentProcess::start(&base, present.clone())
            .expect("start may succeed before the dishonest check body");
        let process_ran = std::cell::Cell::new(false);
        let process_out = process.before_next_tool(
            |_challenge| Ok("11".repeat(32)),
            Some(|| process_ran.set(true)),
        );
        assert_eq!(
            process_out.gate, "REFUSED",
            "AgentProcess must refuse HTTP 200 whose JSON is refused"
        );
        assert!(!process_out.tool_ran && !process_ran.get());
        let process_error = process_out
            .decision
            .expect_err("AgentProcess must fail closed on a dishonest 200 refuse body");
        assert!(
            process_error.to_string().contains("200")
                && (process_error.to_string().contains("refused")
                    || process_error.to_string().contains("not an allow")),
            "the AgentProcess refuse must name HTTP 200 and the refused body: {process_error}"
        );
    }

    #[test]
    fn laboratory_runtime_refuses_http_403_whose_json_is_allowed() {
        let honest = documented_sample("/check-svid", "/check-wimse", "/verifier-challenge");
        let (base, host, _handle) = spawn_swappable_well_known_host(honest);
        *host.check_status.lock().expect("set dishonest 403") = 403;
        *host.check_body.lock().expect("set allowed 403 body") =
            Some(refused_check_decision_json("allowed"));
        let present = RuntimePresent::Svid(dummy_svid_present());
        let ran = std::cell::Cell::new(false);
        let outcome = before_tool(
            &base,
            &present,
            |_challenge| Ok("11".repeat(32)),
            Some(|| ran.set(true)),
        );
        assert_eq!(
            outcome.gate, "REFUSED",
            "HTTP 403 whose JSON is allowed must print REFUSED"
        );
        assert!(
            !outcome.tool_may_run() && !outcome.tool_ran && !ran.get(),
            "HTTP 403 whose JSON is allowed must not run the tool. There is no force-allow."
        );
        let error = outcome
            .decision
            .expect_err("HTTP 403 whose JSON is allowed must fail closed");
        assert!(
            error.to_string().contains("403")
                && (error.to_string().contains("allowed")
                    || error.to_string().contains("force-allow")),
            "the refuse must name HTTP 403 and the force-allow: {error}"
        );
    }
}
