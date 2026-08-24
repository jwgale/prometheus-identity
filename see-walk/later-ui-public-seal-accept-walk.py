#!/usr/bin/env python3
"""Later-UI seal-accept against the live public check name.

Drive the same HTTP JSON GET / posts. Do not use prometheus CLI check verbs.
Do not spawn AgentProcess. Do not copy issuer.secret onto the public host.
Public artifacts only land under see-walk/later-ui-public-seal-accept.
Stolen issuer.secret stays under /tmp only for this walk and is deleted after.
"""

from pathlib import Path
import json
import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request

BIN = "/home/jason/Projects/Prometheus/target/release/prometheus"
STORE = "/tmp/prometheus-later-ui-public-seal-accept-a"
STOLEN = "/tmp/prometheus-later-ui-public-seal-stolen"
WALK = Path("/home/jason/Projects/Prometheus/see-walk/later-ui-public-seal-accept")
ISSUING = "http://127.0.0.1:18806"
STOLEN_HOST = "http://127.0.0.1:18807"
PUBLIC = "https://check.prestigeworldwide.digital"
PORT = 18806
STOLEN_PORT = 18807
AUDIENCE = "check.prestigeworldwide.digital"

WALK.mkdir(parents=True, exist_ok=True)
subprocess.run(["rm", "-rf", STORE, STOLEN], check=True)
os.makedirs(STORE, mode=0o700)


def save(name, obj):
    path = WALK / name
    if isinstance(obj, (dict, list)):
        path.write_text(json.dumps(obj, indent=2) + "\n")
    else:
        path.write_text(str(obj) if str(obj).endswith("\n") else str(obj) + "\n")


def http(method, url, body=None, timeout=30, raw=False):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["content-type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode()
            if raw:
                return resp.status, text, dict(resp.headers)
            try:
                parsed = json.loads(text) if text else {}
            except json.JSONDecodeError:
                parsed = {"raw": text}
            return resp.status, parsed, dict(resp.headers)
    except urllib.error.HTTPError as error:
        raw_text = error.read().decode()
        if raw:
            return error.code, raw_text, dict(error.headers)
        try:
            parsed = json.loads(raw_text) if raw_text else {}
        except json.JSONDecodeError:
            parsed = {"raw": raw_text}
        return error.code, parsed, dict(error.headers)


def require(status, payload, expect, label):
    if status != expect:
        raise SystemExit("%s HTTP %s expected %s: %s" % (label, status, expect, payload))
    return payload


def wait_port(port, proc, label):
    for _ in range(150):
        if proc.poll() is not None:
            raise SystemExit("%s exited %s" % (label, proc.returncode))
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.25).close()
            return
        except OSError:
            time.sleep(0.1)
    raise SystemExit("%s did not bind" % label)


def stop_host(proc):
    if proc is None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def refuse_names_accepted_seal(text):
    lower = (text or "").lower()
    if "expir" in lower:
        return False
    return "seal accept" in lower or "accepted a seal" in lower or "issuer death" in lower


def assert_no_secrets_in_walk():
    forbidden = []
    for path in WALK.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix == ".secret" or path.name in {"issuer.secret", "biscuit.secret"}:
            forbidden.append(str(path))
        text = path.read_text(errors="ignore")
        if "-----BEGIN" in text and "PRIVATE" in text:
            forbidden.append(str(path) + " private-key")
    if forbidden:
        raise SystemExit("see-walk must not hold secrets: %s" % forbidden)


def check_svid_public(presentation_json, certificate_pem, holder_secret):
    status, challenge, _ = http("POST", "%s/verifier-challenge" % PUBLIC, {}, timeout=20)
    if status != 200:
        return status, {"result": "refused", "reason": "verifier-challenge failed: %s" % challenge}
    proof = subprocess.check_output(
        [
            BIN,
            "holder-sign",
            "--holder-secret-path",
            holder_secret,
            "--challenge-message",
            challenge["challenge_message"],
        ],
        text=True,
    ).strip()
    if not proof:
        raise SystemExit("holder-sign must return a proof")
    presentation = json.loads(presentation_json)
    status, payload, _ = http(
        "POST",
        "%s/check-svid" % PUBLIC,
        {
            "presentation_json": presentation_json,
            "certificate_pem": certificate_pem,
            "intent": presentation["intent"],
            "audience": presentation["audience"],
            "holder_proof": proof,
            "challenge_nonce": challenge["challenge_nonce"],
            "on_behalf_of": "autonomous",
        },
        timeout=20,
    )
    return status, payload


print("INIT")
subprocess.check_output([BIN, "--data-directory", STORE, "init"], text=True)
save(
    "a-init-note.txt",
    "init ran on this machine. Secret files stay under /tmp/prometheus-later-ui-public-seal-accept-a. This throwaway issuer is not a standing operator store.\n",
)

host = subprocess.Popen(
    [BIN, "--data-directory", STORE, "host", "--listen-address", "127.0.0.1:%s" % PORT],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
stolen_host = None
try:
    wait_port(PORT, host, "issuing host")
    status, health, _ = http("GET", "%s/health" % ISSUING)
    require(status, health, 200, "GET /health")
    save("a-health.json", health)

    status, root, headers = http("GET", "%s/" % ISSUING, raw=True, timeout=20)
    require(status, root[:80], 200, "GET /")
    content_type = headers.get("Content-Type") or headers.get("content-type") or ""
    markers = [
        'id="check-base"',
        'name="check_base"',
        "https://check.prestigeworldwide.digital",
        "Create Agent Principal",
        "/runtime-check",
        "The holder secret path stays on this host",
        "POST /runtime-check signs the verifier nonce here",
        "The path is not sent to the check base",
        "Check again",
        'id="seal-confirm"',
        'id="seal-issuer"',
        'id="export-seal-bundle"',
        "Seal the issuer",
        'postJson("/seal"',
        'postJson("/seal-export"',
        "Type the word seal to confirm",
    ]
    missing = [marker for marker in markers if marker not in root]
    if missing:
        raise SystemExit("GET / is not the later UI with seal. missing=%s content_type=%s" % (missing, content_type))
    if "issuer.secret" in root or 'type="file"' in root:
        raise SystemExit("GET / must not name issuer.secret or offer a file upload")
    save(
        "a-get-root-proof.txt",
        "\n".join(
            [
                "issuing GET / is the later user interface",
                "GET / already posts POST /seal and POST /seal-export",
                "listen 127.0.0.1:%s" % PORT,
                "content_type %s" % content_type,
                "html_bytes %s" % len(root),
                "markers %s" % ", ".join(markers),
            ]
        )
        + "\n",
    )

    status, public_root, public_headers = http("GET", "%s/" % PUBLIC, timeout=20)
    require(status, public_root, 200, "public GET /")
    save("public-root.json", public_root)
    if public_root.get("role") != "check-only" or public_root.get("bind") != "check.prestigeworldwide.digital":
        raise SystemExit("public GET / must stay check-only JSON: %s" % public_root)
    save(
        "public-root-headers.txt",
        "content_type=%s\n" % (public_headers.get("Content-Type") or public_headers.get("content-type") or ""),
    )

    status, public_rc, _ = http(
        "POST",
        "%s/runtime-check" % PUBLIC,
        {"check_base": PUBLIC, "presentation_json": "{}"},
        timeout=20,
    )
    require(status, public_rc, 403, "public POST /runtime-check")
    save("public-runtime-check-refused.json", public_rc)
    if "check-only" not in json.dumps(public_rc):
        raise SystemExit("public POST /runtime-check must stay check-only: %s" % public_rc)

    status, well_known, _ = http("GET", "%s/.well-known/prometheus-check" % PUBLIC, timeout=20)
    require(status, well_known, 200, "public well-known")
    save("public-well-known.json", well_known)
    well_known_text = json.dumps(well_known)
    if well_known.get("bind") != "check.prestigeworldwide.digital":
        raise SystemExit("public well-known bind must be check.prestigeworldwide.digital")
    pin_paths = [item.get("path") for item in well_known.get("operator_pin_paths", [])]
    if "/seal-accept" not in pin_paths:
        raise SystemExit("public well-known must name /seal-accept as an operator pin")
    check_paths = [item.get("path") for item in well_known.get("checks", [])]
    if "/check-svid" not in check_paths:
        raise SystemExit("public well-known must name /check-svid")
    for write_verb in (
        "/birth",
        "/spawn",
        "/present-svid",
        "/present-wimse",
        "/runtime-check",
        "/seal-export",
        "/previous-key-export",
    ):
        if write_verb in well_known_text:
            raise SystemExit("public well-known still names write verb %s" % write_verb)

    status, agent, _ = http(
        "POST",
        "%s/agent-type" % ISSUING,
        {
            "owner": "jason-gale",
            "allowed_intents": ["read"],
            "authorization_limit": AUDIENCE,
        },
    )
    print("AGENT-TYPE", status)
    require(status, agent, 200, "POST /agent-type")
    save("a-agent-type.json", {"agent_type_id": agent.get("agent_type_id"), "keys": sorted(agent.keys())})

    status, birth, _ = http(
        "POST",
        "%s/birth" % ISSUING,
        {
            "agent_type_id": agent["agent_type_id"],
            "owner": "jason-gale",
            "intent": "read",
            "audience": AUDIENCE,
            "on_behalf_of": "autonomous",
        },
    )
    print("BIRTH", status)
    require(status, birth, 200, "POST /birth")
    if "holder_secret" in birth and "holder_secret_path" not in birth:
        raise SystemExit("POST /birth must not return secret bytes")
    save(
        "a-birth.json",
        {
            "instance_id": birth["instance_id"],
            "capability_id": birth["capability_id"],
            "revoke_identifier": birth["revoke_identifier"],
            "holder_secret_path_present": "holder_secret_path" in birth,
        },
    )
    instance_id = birth["instance_id"]
    capability_id = birth["capability_id"]
    holder_secret_path = birth["holder_secret_path"]
    if not holder_secret_path.startswith(STORE):
        raise SystemExit("holder secret path must stay under the throwaway store")

    status, issuer, _ = http("GET", "%s/issuer-public" % ISSUING)
    print("ISSUER-PUBLIC", status, list(issuer) if isinstance(issuer, dict) else issuer)
    require(status, issuer, 200, "GET /issuer-public")
    save("a-issuer-public-keys.json", {"keys": sorted(issuer.keys())})
    key = issuer.get("current_issuer_public_key_hex") or issuer.get("public_key_hex")
    if not key:
        raise SystemExit("no public key in %s" % list(issuer))
    save("a-issuer-public-key-length.txt", "public_key_hex_length=%s\n" % len(key))
    status, accept, _ = http("POST", "%s/issuer-accept" % PUBLIC, {"public_key_hex": key}, timeout=20)
    print("ISSUER-ACCEPT", status, accept if status != 200 else list(accept))
    require(status, accept, 200, "public POST /issuer-accept")
    save(
        "public-issuer-accept.json",
        {
            "http_status": status,
            "pin_needed": True,
            "request_keys": ["public_key_hex"],
            "response_keys": sorted(accept.keys()) if isinstance(accept, dict) else [],
        },
    )

    def mint_present(base, inst, cap, holder, label):
        status, challenge, _ = http("POST", "%s/challenge" % base, {"instance_id": inst})
        require(status, challenge, 200, "%s POST /challenge" % label)
        status, svid, _ = http(
            "POST",
            "%s/present-svid" % base,
            {
                "instance_id": inst,
                "capability_id": cap,
                "holder_secret_path": holder,
                "challenge_nonce": challenge["challenge_nonce"],
                "intent": "read",
                "audience": AUDIENCE,
                "on_behalf_of": "autonomous",
            },
        )
        require(status, svid, 200, "%s POST /present-svid" % label)
        if "holder_secret" in svid or "issuer.secret" in json.dumps(svid):
            raise SystemExit("%s POST /present-svid must not return secret bytes" % label)
        return svid

    print("PRESENT")
    svid = mint_present(ISSUING, instance_id, capability_id, holder_secret_path, "issuing")
    (WALK / "presentation.json").write_text(svid["presentation_json"])
    (WALK / "presentation.json.svid.pem").write_text(svid["certificate_pem"])
    save("a-present-svid-keys.json", {"keys": sorted(svid.keys())})

    runtime_body = {
        "check_base": PUBLIC,
        "presentation_json": svid["presentation_json"],
        "certificate_pem": svid["certificate_pem"],
        "holder_secret_path": holder_secret_path,
    }
    save(
        "runtime-check-request-keys.json",
        {
            "keys": sorted(runtime_body.keys()),
            "check_base": PUBLIC,
            "holder_secret_path_sent_to_issuing_host": True,
            "holder_secret_bytes_sent_to_public_name": False,
            "note": "GET / posts this JSON to the loopback issuing host. That host signs the verifier nonce locally. Secret bytes are not uploaded. The path is not sent to the public name.",
        },
    )

    print("RUNTIME-CHECK ALLOW")
    status, allow, _ = http("POST", "%s/runtime-check" % ISSUING, runtime_body, timeout=40)
    if status != 200 or (isinstance(allow, dict) and allow.get("result") != "allowed"):
        print("ALLOW failed, remint once", status, allow)
        svid = mint_present(ISSUING, instance_id, capability_id, holder_secret_path, "issuing-remint")
        (WALK / "presentation.json").write_text(svid["presentation_json"])
        (WALK / "presentation.json.svid.pem").write_text(svid["certificate_pem"])
        runtime_body["presentation_json"] = svid["presentation_json"]
        runtime_body["certificate_pem"] = svid["certificate_pem"]
        status, allow, _ = http("POST", "%s/runtime-check" % ISSUING, runtime_body, timeout=40)
    require(status, allow, 200, "POST /runtime-check allow")
    if allow.get("result") != "allowed":
        raise SystemExit("first POST /runtime-check must allow: %s" % allow)
    save(
        "runtime-check-allow.json",
        {
            "http_status": status,
            "result": allow.get("result"),
            "reason": allow.get("reason"),
            "keys": sorted(allow.keys()) if isinstance(allow, dict) else [],
        },
    )
    if "issuer.secret" in json.dumps(allow):
        raise SystemExit("allow body must not name issuer.secret")

    print("STOLEN_COPY")
    shutil.copytree(STORE, STOLEN, dirs_exist_ok=False)
    os.chmod(STOLEN, 0o700)
    if not (Path(STOLEN) / "issuer.secret").is_file():
        raise SystemExit("stolen copy must hold issuer.secret under /tmp only")
    save(
        "stolen-copy-note.txt",
        "Copied the issuing store to /tmp/prometheus-later-ui-public-seal-stolen after the honest Assertion Act and before local seal. That copy stays under /tmp only for this walk. This folder does not hold issuer.secret, biscuit.secret, holder secrets, or member-two secrets.\n",
    )

    status, sealed, _ = http("POST", "%s/seal" % ISSUING, {"confirm": "seal", "after_seconds": 86400})
    print("SEAL", status, sealed if status != 200 else {"status": sealed.get("status"), "kill_date": sealed.get("kill_date")})
    require(status, sealed, 200, "POST /seal")
    if sealed.get("status") != "sealed":
        raise SystemExit("POST /seal must return sealed: %s" % sealed)
    save("a-seal.json", {"status": sealed.get("status"), "kill_date": sealed.get("kill_date"), "keys": sorted(sealed.keys())})

    status, exported, _ = http("POST", "%s/seal-export" % ISSUING, {})
    print("SEAL-EXPORT", status, list(exported) if isinstance(exported, dict) else exported)
    require(status, exported, 200, "POST /seal-export")
    export_keys = sorted(exported.keys()) if isinstance(exported, dict) else []
    save("seal-export-keys.json", {"keys": export_keys})
    if "event" not in exported or "proof" not in exported or "tree_head" not in exported:
        raise SystemExit("POST /seal-export must return event, proof, and tree_head: %s" % export_keys)
    accept_body = {
        "event": exported["event"],
        "proof": exported["proof"],
        "tree_head": exported["tree_head"],
    }
    save(
        "a-seal-export-public-shape.json",
        {
            "keys": export_keys,
            "event_keys": sorted(exported["event"].keys()) if isinstance(exported["event"], dict) else [],
            "proof_keys": sorted(exported["proof"].keys()) if isinstance(exported["proof"], dict) else [],
            "tree_head_keys": sorted(exported["tree_head"].keys()) if isinstance(exported["tree_head"], dict) else [],
            "secret_bytes": False,
        },
    )

    status, seal_accept, _ = http("POST", "%s/seal-accept" % PUBLIC, accept_body, timeout=20)
    print("SEAL-ACCEPT", status, seal_accept if status != 200 else list(seal_accept))
    require(status, seal_accept, 200, "public POST /seal-accept")
    save(
        "public-seal-accept.json",
        {
            "http_status": status,
            "public_key_hex_length": len(seal_accept.get("public_key_hex", "")) if isinstance(seal_accept, dict) else 0,
            "kill_date": seal_accept.get("kill_date") if isinstance(seal_accept, dict) else None,
            "response_keys": sorted(seal_accept.keys()) if isinstance(seal_accept, dict) else [],
        },
    )

    print("RUNTIME-CHECK REFUSE")
    status, refused, _ = http("POST", "%s/runtime-check" % ISSUING, runtime_body, timeout=40)
    if status != 403:
        raise SystemExit("second POST /runtime-check must refuse after seal-accept: HTTP %s %s" % (status, refused))
    reason = refused.get("reason") or ""
    if refused.get("result") != "refused":
        raise SystemExit("second POST /runtime-check must be refused: %s" % refused)
    if not refuse_names_accepted_seal(reason):
        raise SystemExit("typed-base Check again must refuse from accepted seal, not expiry: %s" % reason)
    save(
        "runtime-check-after-seal.json",
        {
            "http_status": status,
            "result": refused.get("result"),
            "reason": reason,
            "keys": sorted(refused.keys()) if isinstance(refused, dict) else [],
        },
    )
    if "issuer.secret" in json.dumps(refused):
        raise SystemExit("refuse body must not name issuer.secret")

    print("PUBLIC CHECK-SVID AFTER SEAL")
    historical_svid_status, historical_svid = check_svid_public(
        svid["presentation_json"],
        svid["certificate_pem"],
        holder_secret_path,
    )
    print("HISTORICAL_CHECK_SVID", historical_svid_status, historical_svid)
    historical_reason = ""
    if isinstance(historical_svid, dict):
        historical_reason = str(historical_svid.get("reason") or "")
    if historical_svid_status == 200 or (isinstance(historical_svid, dict) and historical_svid.get("result") == "allowed"):
        raise SystemExit("historical Assertion Act must refuse after public seal-accept: %s" % historical_svid)
    if not refuse_names_accepted_seal(historical_reason):
        raise SystemExit("historical refuse must name accepted seal, not expiry: %s" % historical_reason)
    save(
        "public-check-svid-after-seal.json",
        {
            "http_status": historical_svid_status,
            "result": historical_svid.get("result") if isinstance(historical_svid, dict) else None,
            "reason": historical_reason,
            "request_keys": [
                "presentation_json",
                "certificate_pem",
                "intent",
                "audience",
                "holder_proof",
                "challenge_nonce",
                "on_behalf_of",
            ],
            "holder_secret_bytes_sent_to_public_name": False,
        },
    )

    print("STOLEN_HOST")
    stolen_host = subprocess.Popen(
        [BIN, "--data-directory", STOLEN, "host", "--listen-address", "127.0.0.1:%s" % STOLEN_PORT],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    wait_port(STOLEN_PORT, stolen_host, "stolen host")
    status, stolen_health, _ = http("GET", "%s/health" % STOLEN_HOST)
    require(status, stolen_health, 200, "stolen GET /health")
    save("stolen-health.json", {"status": stolen_health.get("status")})

    status, stolen_birth, _ = http(
        "POST",
        "%s/birth" % STOLEN_HOST,
        {
            "agent_type_id": agent["agent_type_id"],
            "owner": "stolen-issuer",
            "intent": "read",
            "audience": AUDIENCE,
            "on_behalf_of": "autonomous",
        },
    )
    print("STOLEN_BIRTH", status)
    require(status, stolen_birth, 200, "stolen POST /birth")
    save(
        "stolen-birth.json",
        {
            "instance_id": stolen_birth["instance_id"],
            "capability_id": stolen_birth["capability_id"],
            "holder_secret_path_present": "holder_secret_path" in stolen_birth,
            "new_instance": stolen_birth["instance_id"] != instance_id,
        },
    )
    stolen_holder = stolen_birth["holder_secret_path"]
    if STOLEN not in stolen_holder:
        raise SystemExit("stolen birth must use the /tmp stolen store holder path")

    stolen_svid = mint_present(
        STOLEN_HOST,
        stolen_birth["instance_id"],
        stolen_birth["capability_id"],
        stolen_holder,
        "stolen",
    )
    (WALK / "stolen-presentation.json").write_text(stolen_svid["presentation_json"])
    (WALK / "stolen-presentation.json.svid.pem").write_text(stolen_svid["certificate_pem"])
    save("stolen-present-svid-keys.json", {"keys": sorted(stolen_svid.keys())})

    stolen_runtime_body = {
        "check_base": PUBLIC,
        "presentation_json": stolen_svid["presentation_json"],
        "certificate_pem": stolen_svid["certificate_pem"],
        "holder_secret_path": stolen_holder,
    }
    status, stolen_runtime, _ = http("POST", "%s/runtime-check" % STOLEN_HOST, stolen_runtime_body, timeout=40)
    print("STOLEN_RUNTIME_CHECK", status, stolen_runtime)
    stolen_runtime_reason = stolen_runtime.get("reason") or "" if isinstance(stolen_runtime, dict) else str(stolen_runtime)
    stolen_runtime_allowed = status == 200 or (isinstance(stolen_runtime, dict) and stolen_runtime.get("result") == "allowed")
    save(
        "runtime-check-stolen.json",
        {
            "http_status": status,
            "result": stolen_runtime.get("result") if isinstance(stolen_runtime, dict) else None,
            "reason": stolen_runtime_reason,
            "hole": stolen_runtime_allowed,
        },
    )
    if stolen_runtime_allowed:
        raise SystemExit("HOLE: stolen mint POST /runtime-check was allowed after public seal-accept: %s" % stolen_runtime)
    if not refuse_names_accepted_seal(stolen_runtime_reason):
        raise SystemExit("stolen mint runtime-check must refuse because of accepted seal, not expiry: %s" % stolen_runtime_reason)

    stolen_svid_status, stolen_check = check_svid_public(
        stolen_svid["presentation_json"],
        stolen_svid["certificate_pem"],
        stolen_holder,
    )
    print("STOLEN_CHECK_SVID", stolen_svid_status, stolen_check)
    stolen_reason = ""
    if isinstance(stolen_check, dict):
        stolen_reason = str(stolen_check.get("reason") or "")
    stolen_allowed = stolen_svid_status == 200 or (
        isinstance(stolen_check, dict) and stolen_check.get("result") == "allowed"
    )
    save(
        "public-check-svid-stolen.json",
        {
            "http_status": stolen_svid_status,
            "result": stolen_check.get("result") if isinstance(stolen_check, dict) else None,
            "reason": stolen_reason,
            "hole": stolen_allowed,
        },
    )
    if stolen_allowed:
        raise SystemExit(
            "HOLE: stolen mint Assertion Act was allowed on the public host after seal-accept: %s" % stolen_check
        )
    if not refuse_names_accepted_seal(stolen_reason):
        raise SystemExit("stolen mint check-svid must refuse because of accepted seal, not expiry: %s" % stolen_reason)

    save(
        "http-codes.json",
        {
            "public_well_known": 200,
            "issuing_health": 200,
            "agent_type": 200,
            "birth": 200,
            "present_svid": 200,
            "issuer_accept": 200,
            "runtime_check_allow": 200,
            "seal": 200,
            "seal_export": 200,
            "seal_accept": 200,
            "runtime_check_after_seal": 403,
            "historical_check_svid": historical_svid_status,
            "stolen_birth": 200,
            "stolen_present_svid": 200,
            "stolen_runtime_check": status,
            "stolen_check_svid": stolen_svid_status,
        },
    )
    print("OK allow then seal-accept then refuse including stolen mint")
finally:
    stop_host(stolen_host)
    stop_host(host)
    save("a-host-stopped.txt", "issuing host on 127.0.0.1:%s is stopped. stolen host on 127.0.0.1:%s is stopped.\n" % (PORT, STOLEN_PORT))
    subprocess.run(["rm", "-rf", STORE, STOLEN], check=True)
    leftover = []
    for path in (STORE, STOLEN):
        if Path(path).exists():
            leftover.append(path)
        secret = Path(path) / "issuer.secret"
        if secret.exists():
            leftover.append(str(secret))
    if leftover:
        raise SystemExit("stolen issuer.secret must not remain under /tmp: %s" % leftover)
    save(
        "tmp-cleaned.txt",
        "Deleted /tmp/prometheus-later-ui-public-seal-accept-a and /tmp/prometheus-later-ui-public-seal-stolen after the walk. issuer.secret is not left under /tmp from this walk.\n",
    )
