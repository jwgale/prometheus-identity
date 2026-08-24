#!/usr/bin/env python3
"""Later-UI act-accept against the live public check name.

Drive the same HTTP JSON GET / posts. Do not use prometheus CLI check verbs.
Do not spawn AgentProcess. Do not copy issuer.secret onto the public host.
Public artifacts only land under see-walk/later-ui-public-act-accept.
"""

from pathlib import Path
import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request

BIN = "/home/jason/Projects/Prometheus/target/release/prometheus"
STORE = "/tmp/prometheus-later-ui-public-act-accept-a"
WALK = Path("/home/jason/Projects/Prometheus/see-walk/later-ui-public-act-accept")
ISSUING = "http://127.0.0.1:18812"
PUBLIC = "https://check.prestigeworldwide.digital"
PORT = 18812
AUDIENCE = "check.prestigeworldwide.digital"

WALK.mkdir(parents=True, exist_ok=True)
subprocess.run(["rm", "-rf", STORE], check=True)
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


print("INIT")
subprocess.check_output([BIN, "--data-directory", STORE, "init"], text=True)
save(
    "a-init-note.txt",
    "init ran on this machine. Secret files stay under /tmp/prometheus-later-ui-public-act-accept-a.\n",
)

host = subprocess.Popen(
    [BIN, "--data-directory", STORE, "host", "--listen-address", "127.0.0.1:%s" % PORT],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
try:
    for _ in range(80):
        try:
            socket.create_connection(("127.0.0.1", PORT), timeout=0.25).close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        raise SystemExit("issuing host did not bind 127.0.0.1:%s" % PORT)

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
        "/act-export",
        "/act-accept",
        'id="act-export-receipt"',
        'id="accept-act-bundle"',
        "The holder secret path stays on this host",
        "POST /runtime-check signs the verifier nonce here",
        "The path is not sent to the check base",
        "Check again",
    ]
    missing = [marker for marker in markers if marker not in root]
    if missing:
        raise SystemExit("GET / is not the later UI. missing=%s content_type=%s" % (missing, content_type))
    if "issuer.secret" in root or 'type="file"' in root:
        raise SystemExit("GET / must not name issuer.secret or offer a file upload")
    save(
        "a-get-root-proof.txt",
        "\n".join(
            [
                "issuing GET / is the later user interface",
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
        "/act-export",
        "/kill-export",
    ):
        if write_verb in well_known_text:
            raise SystemExit("public well-known still names write verb %s" % write_verb)

    pin_names = [
        item.get("path")
        for item in well_known.get("operator_pin_paths", [])
        if isinstance(item, dict)
    ]
    save(
        "public-well-known-pins.json",
        {
            "operator_pin_paths": well_known.get("operator_pin_paths"),
            "names_act_accept": "/act-accept" in pin_names,
            "names_act_export": "/act-export" in pin_names,
            "note": "Live POST /act-accept is allowed even when the published document omits that pin. This walk does not invent a public write.",
        },
    )

    status, public_export, _ = http(
        "POST",
        "%s/act-export" % PUBLIC,
        {"receipt": {"result": "allowed"}},
        timeout=20,
    )
    require(status, public_export, 403, "public POST /act-export")
    if "check-only" not in json.dumps(public_export):
        raise SystemExit("public POST /act-export must stay check-only: %s" % public_export)
    save("public-act-export-refused.json", {"http_status": status, "body": public_export})

    status, empty_accept, _ = http("POST", "%s/act-accept" % PUBLIC, {}, timeout=20)
    if status == 403 and "check-only" in json.dumps(empty_accept):
        raise SystemExit("public POST /act-accept is check-only 403. Do not invent a public write: %s" % empty_accept)
    if status != 400:
        raise SystemExit("public POST /act-accept empty body must be 400 missing receipt, not %s: %s" % (status, empty_accept))
    save(
        "public-act-accept-empty.json",
        {
            "http_status": status,
            "body": empty_accept,
            "allowed_operator_pin": True,
            "note": "400 missing field receipt means the path is not check-only 403.",
        },
    )

    status, public_instances_before, _ = http("GET", "%s/instances" % PUBLIC, timeout=20)
    require(status, public_instances_before, 403, "public GET /instances before")
    save("public-instances-before.json", {"http_status": status, "body": public_instances_before})

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

    print("PIN LEFTOVERS")
    leftover = {}
    status, trunc, _ = http(
        "POST",
        "%s/issuer-accept" % PUBLIC,
        {"public_key_hex": key[:8] + "..." + key[-8:]},
        timeout=20,
    )
    leftover["issuer-accept-truncated-hex"] = {
        "http_status": status,
        "result": trunc.get("result") if isinstance(trunc, dict) else None,
        "reason": trunc.get("reason") if isinstance(trunc, dict) else trunc,
    }
    if status == 200:
        raise SystemExit("public POST /issuer-accept must refuse truncated hex: %s" % trunc)
    status, empty_pin, _ = http(
        "POST",
        "%s/issuer-accept" % PUBLIC,
        {"public_key_hex": ""},
        timeout=20,
    )
    leftover["issuer-accept-empty-hex"] = {
        "http_status": status,
        "result": empty_pin.get("result") if isinstance(empty_pin, dict) else None,
        "reason": empty_pin.get("reason") if isinstance(empty_pin, dict) else empty_pin,
    }
    if status == 200:
        raise SystemExit("public POST /issuer-accept must refuse empty hex: %s" % empty_pin)
    status, env_pin, _ = http(
        "POST",
        "%s/issuer-accept" % PUBLIC,
        {"public_key_hex": "00" * 32},
        timeout=20,
    )
    leftover["issuer-accept-short-hex"] = {
        "http_status": status,
        "result": env_pin.get("result") if isinstance(env_pin, dict) else None,
        "reason": env_pin.get("reason") if isinstance(env_pin, dict) else env_pin,
    }
    if status == 200:
        raise SystemExit("public POST /issuer-accept must refuse a short hex that is not an identity root: %s" % env_pin)
    status, pk_trunc, _ = http(
        "POST",
        "%s/previous-key-accept" % PUBLIC,
        {"public_key_hex": key[:8] + "..." + key[-8:], "kill_date": "2026-08-23T00:00:00Z"},
        timeout=20,
    )
    leftover["previous-key-accept-truncated-hex"] = {
        "http_status": status,
        "result": pk_trunc.get("result") if isinstance(pk_trunc, dict) else None,
        "reason": pk_trunc.get("reason") if isinstance(pk_trunc, dict) else pk_trunc,
    }
    if status == 200:
        raise SystemExit("public POST /previous-key-accept must refuse truncated hex: %s" % pk_trunc)
    status, act_junk, _ = http(
        "POST",
        "%s/act-accept" % PUBLIC,
        {"receipt": {}, "proof": {}, "tree_head": {}},
        timeout=20,
    )
    leftover["act-accept-empty-artifacts"] = {
        "http_status": status,
        "result": act_junk.get("result") if isinstance(act_junk, dict) else None,
        "reason": act_junk.get("reason") if isinstance(act_junk, dict) else act_junk,
    }
    if status == 200:
        raise SystemExit("public POST /act-accept must refuse empty artifacts: %s" % act_junk)
    status, kill_junk, _ = http(
        "POST",
        "%s/kill-accept" % PUBLIC,
        {"event": {}, "proof": {}, "tree_head": {}},
        timeout=20,
    )
    leftover["kill-accept-empty-artifacts"] = {
        "http_status": status,
        "result": kill_junk.get("result") if isinstance(kill_junk, dict) else None,
        "reason": kill_junk.get("reason") if isinstance(kill_junk, dict) else kill_junk,
    }
    if status == 200:
        raise SystemExit("public POST /kill-accept must refuse empty artifacts: %s" % kill_junk)
    status, seal_junk, _ = http(
        "POST",
        "%s/seal-accept" % PUBLIC,
        {"event": {}, "proof": {}, "tree_head": {}},
        timeout=20,
    )
    leftover["seal-accept-empty-artifacts"] = {
        "http_status": status,
        "result": seal_junk.get("result") if isinstance(seal_junk, dict) else None,
        "reason": seal_junk.get("reason") if isinstance(seal_junk, dict) else seal_junk,
    }
    if status == 200:
        raise SystemExit("public POST /seal-accept must refuse empty artifacts: %s" % seal_junk)
    save("public-pin-leftovers.json", leftover)

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

    def mint_present():
        status, challenge, _ = http("POST", "%s/challenge" % ISSUING, {"instance_id": instance_id})
        require(status, challenge, 200, "POST /challenge")
        status, svid, _ = http(
            "POST",
            "%s/present-svid" % ISSUING,
            {
                "instance_id": instance_id,
                "capability_id": capability_id,
                "holder_secret_path": holder_secret_path,
                "challenge_nonce": challenge["challenge_nonce"],
                "intent": "read",
                "audience": AUDIENCE,
                "on_behalf_of": "autonomous",
            },
        )
        require(status, svid, 200, "POST /present-svid")
        return svid

    print("PRESENT")
    svid = mint_present()
    (WALK / "presentation.json").write_text(svid["presentation_json"])
    (WALK / "presentation.json.svid.pem").write_text(svid["certificate_pem"])
    save("a-present-svid-keys.json", {"keys": sorted(svid.keys())})
    if "holder_secret" in svid or "issuer.secret" in json.dumps(svid):
        raise SystemExit("POST /present-svid must not return secret bytes")

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
        svid = mint_present()
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
            "has_receipt": isinstance(allow, dict) and allow.get("receipt") is not None,
        },
    )
    if "issuer.secret" in json.dumps(allow):
        raise SystemExit("allow body must not name issuer.secret")

    print("ISSUING CHECK FOR RECEIPT")
    status, local_challenge, _ = http("POST", "%s/challenge" % ISSUING, {"instance_id": instance_id})
    require(status, local_challenge, 200, "POST /challenge for local check")
    status, local_check, _ = http(
        "POST",
        "%s/check" % ISSUING,
        {
            "instance_id": instance_id,
            "capability_id": capability_id,
            "intent": "read",
            "audience": AUDIENCE,
            "holder_secret_path": holder_secret_path,
            "challenge_nonce": local_challenge["challenge_nonce"],
            "on_behalf_of": "autonomous",
        },
    )
    require(status, local_check, 200, "issuing POST /check")
    if local_check.get("result") != "allowed":
        raise SystemExit("issuing POST /check must allow so act-export has a receipt: %s" % local_check)
    receipt = local_check.get("receipt")
    if not isinstance(receipt, dict):
        raise SystemExit("issuing POST /check must return a signed receipt: %s" % local_check)
    save(
        "a-check-receipt-keys.json",
        {
            "http_status": status,
            "result": local_check.get("result"),
            "receipt_keys": sorted(receipt.keys()),
            "receipt_result": receipt.get("result"),
            "note": "The public host already allowed this act. The issuing store also checked so the receipt stays on the issuing store. Public act-export stays 403.",
        },
    )

    print("ACT-EXPORT")
    status, exported, _ = http("POST", "%s/act-export" % ISSUING, {"receipt": receipt})
    print("ACT-EXPORT", status, list(exported) if isinstance(exported, dict) else exported)
    require(status, exported, 200, "issuing POST /act-export")
    for field in ("receipt", "proof", "tree_head"):
        if field not in exported:
            raise SystemExit("act-export must return %s: %s" % (field, exported))
    if "presentation" in exported:
        raise SystemExit("act-export must not invent a presentation artifact")
    save(
        "a-act-export-keys.json",
        {
            "http_status": status,
            "keys": sorted(exported.keys()),
            "receipt_result": exported.get("receipt", {}).get("result")
            if isinstance(exported.get("receipt"), dict)
            else None,
        },
    )
    if "issuer.secret" in json.dumps(exported) or "holder_secret" in json.dumps(exported):
        raise SystemExit("act-export must not return secret bytes")
    accept_act_body = {
        "receipt": exported["receipt"],
        "proof": exported["proof"],
        "tree_head": exported["tree_head"],
    }

    print("PUBLIC ACT-ACCEPT")
    status, act_accept, _ = http("POST", "%s/act-accept" % PUBLIC, accept_act_body, timeout=20)
    print("PUBLIC ACT-ACCEPT", status, act_accept if status != 200 else list(act_accept))
    require(status, act_accept, 200, "public POST /act-accept")
    if act_accept.get("result") != "accepted":
        raise SystemExit("public POST /act-accept must return accepted: %s" % act_accept)
    save(
        "public-act-accept.json",
        {
            "http_status": status,
            "result": act_accept.get("result"),
            "keys": sorted(act_accept.keys()) if isinstance(act_accept, dict) else [],
            "wrote_instance": False,
        },
    )
    if "instance_id" in act_accept and act_accept.get("instance_id"):
        raise SystemExit("public POST /act-accept must write no instance: %s" % act_accept)

    status, public_instances_after, _ = http("GET", "%s/instances" % PUBLIC, timeout=20)
    require(status, public_instances_after, 403, "public GET /instances after act-accept")
    save(
        "public-instances-after-act-accept.json",
        {
            "http_status": status,
            "body": public_instances_after,
            "note": "Public GET /instances stayed 403. Act-accept wrote no instance record.",
        },
    )
    if "check-only" not in json.dumps(public_instances_after):
        raise SystemExit("public GET /instances must stay check-only after act-accept: %s" % public_instances_after)

    status, public_export_after, _ = http(
        "POST",
        "%s/act-export" % PUBLIC,
        {"receipt": exported["receipt"]},
        timeout=20,
    )
    require(status, public_export_after, 403, "public POST /act-export after act-accept")
    save("public-act-export-after-act-accept.json", {"http_status": status, "body": public_export_after})

    kill_body = {"instance_id": instance_id, "confirm": instance_id}
    status, killed, _ = http("POST", "%s/kill" % ISSUING, kill_body)
    print("KILL", status)
    require(status, killed, 200, "POST /kill")
    save("a-kill.json", {"instance_id": killed.get("instance_id"), "status": killed.get("status"), "keys": sorted(killed.keys())})

    status, kill_exported, _ = http("POST", "%s/kill-export" % ISSUING, kill_body)
    print("KILL-EXPORT", status, list(kill_exported) if isinstance(kill_exported, dict) else kill_exported)
    require(status, kill_exported, 200, "POST /kill-export")
    save("kill-export-keys.json", {"keys": sorted(kill_exported.keys())})
    kill_accept_body = {
        "event": kill_exported["event"],
        "proof": kill_exported["proof"],
        "tree_head": kill_exported["tree_head"],
    }
    status, kill_accept, _ = http("POST", "%s/kill-accept" % PUBLIC, kill_accept_body, timeout=20)
    print("PUBLIC KILL-ACCEPT", status, kill_accept if status != 200 else list(kill_accept))
    require(status, kill_accept, 200, "public POST /kill-accept")
    save(
        "public-kill-accept.json",
        {
            "http_status": status,
            "accepted_killed_instance_ids": kill_accept.get("accepted_killed_instance_ids"),
            "accepted_killed_capability_ids": kill_accept.get("accepted_killed_capability_ids"),
            "keys": sorted(kill_accept.keys()) if isinstance(kill_accept, dict) else [],
        },
    )

    print("RUNTIME-CHECK REFUSE")
    status, refused, _ = http("POST", "%s/runtime-check" % ISSUING, runtime_body, timeout=40)
    if status != 403:
        raise SystemExit("second POST /runtime-check must refuse after kill-accept: HTTP %s %s" % (status, refused))
    reason = refused.get("reason") or ""
    if refused.get("result") != "refused":
        raise SystemExit("second POST /runtime-check must be refused: %s" % refused)
    if "accepted a kill" not in reason.lower() and "kill accept" not in reason.lower():
        raise SystemExit("typed-base Check again must refuse from accepted kill: %s" % reason)
    save(
        "runtime-check-after-decommission.json",
        {
            "http_status": status,
            "result": refused.get("result"),
            "reason": reason,
            "keys": sorted(refused.keys()) if isinstance(refused, dict) else [],
        },
    )
    if "issuer.secret" in json.dumps(refused):
        raise SystemExit("refuse body must not name issuer.secret")

    print("PUBLIC CHECK-SVID AFTER DECOMMISSION")
    status, challenge, _ = http("POST", "%s/verifier-challenge" % PUBLIC, {}, timeout=20)
    require(status, challenge, 200, "public POST /verifier-challenge")
    proof = subprocess.check_output(
        [
            BIN,
            "holder-sign",
            "--holder-secret-path",
            holder_secret_path,
            "--challenge-message",
            challenge["challenge_message"],
        ],
        text=True,
    ).strip()
    if not proof:
        raise SystemExit("holder-sign must return a proof")
    presentation = json.loads(svid["presentation_json"])
    status, public_refused, _ = http(
        "POST",
        "%s/check-svid" % PUBLIC,
        {
            "presentation_json": svid["presentation_json"],
            "certificate_pem": svid["certificate_pem"],
            "intent": presentation["intent"],
            "audience": presentation["audience"],
            "holder_proof": proof,
            "challenge_nonce": challenge["challenge_nonce"],
            "on_behalf_of": "autonomous",
        },
        timeout=20,
    )
    if status != 403 or public_refused.get("result") != "refused":
        raise SystemExit("public POST /check-svid must refuse after kill-accept: HTTP %s %s" % (status, public_refused))
    public_reason = public_refused.get("reason") or ""
    if "accepted a kill" not in public_reason.lower() and "kill accept" not in public_reason.lower():
        raise SystemExit("public POST /check-svid must name accepted kill: %s" % public_reason)
    save(
        "public-check-svid-after-decommission.json",
        {
            "http_status": status,
            "result": public_refused.get("result"),
            "reason": public_reason,
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

    print("OK allow, act-accept, then refuse")
finally:
    host.terminate()
    try:
        host.wait(timeout=5)
    except subprocess.TimeoutExpired:
        host.kill()
        host.wait(timeout=5)
    save("a-host-stopped.txt", "issuing host on 127.0.0.1:%s is stopped\n" % PORT)
    subprocess.run(["rm", "-rf", STORE], check=True)
    leftover_paths = []
    if Path(STORE).exists():
        leftover_paths.append(STORE)
    secret = Path(STORE) / "issuer.secret"
    if secret.exists():
        leftover_paths.append(str(secret))
    if leftover_paths:
        raise SystemExit("issuer.secret must not remain under /tmp: %s" % leftover_paths)
    save(
        "tmp-cleaned.txt",
        "Deleted /tmp/prometheus-later-ui-public-act-accept-a after the walk. issuer.secret is not left under /tmp from this walk.\n",
    )
