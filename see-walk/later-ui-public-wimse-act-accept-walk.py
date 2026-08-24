#!/usr/bin/env python3
"""Later-UI WIMSE act-accept via operator-pin against the live public check name.

Sibling of Rung 79 (SVID act-accept) using the Rung 81 helper.
Drive the same HTTP JSON GET / posts: present-wimse, runtime-check WIMSE,
issuing check so a receipt exists, act-export on the issuing store,
well-known-follow, operator-pin act-accept, then kill-export plus
operator-pin kill-accept. Do not hardcode public /act-accept as the accept path.
Do not spawn AgentProcess. Do not copy issuer.secret onto the public host.
Public artifacts only land under see-walk/later-ui-public-wimse-act-accept.
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
STORE = "/tmp/prometheus-later-ui-public-wimse-act-accept-a"
WALK = Path("/home/jason/Projects/Prometheus/see-walk/later-ui-public-wimse-act-accept")
ISSUING = "http://127.0.0.1:18816"
PUBLIC = "https://check.prestigeworldwide.digital"
PORT = 18816
AUDIENCE = "check.prestigeworldwide.digital"
WRITE_VERBS = (
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
    "/act-export",
    "/kill-export",
    "/seal-export",
    "/previous-key-export",
    "/runtime-check",
)

WALK.mkdir(parents=True, exist_ok=True)
subprocess.run(["rm", "-rf", STORE], check=True)
os.makedirs(STORE, mode=0o700)


def save(name, obj):
    dest = WALK / name
    if isinstance(obj, (dict, list)):
        dest.write_text(json.dumps(obj, indent=2) + "\n")
    else:
        dest.write_text(str(obj) if str(obj).endswith("\n") else str(obj) + "\n")


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


def documented_pin_path(document, pin_name):
    want = str(pin_name or "").lstrip("/").lower()
    if not want:
        raise SystemExit("The well-known check document does not name that operator pin.")
    lists = list(document.get("operator_pin_paths") or []) + list(document.get("checks") or [])
    challenge = document.get("verifier_challenge")
    if challenge:
        lists.append(challenge)
    found = None
    for item in lists:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "").lstrip("/").lower()
        if path == want or path.endswith("-" + want):
            found = item
            break
    if not found or not found.get("path"):
        raise SystemExit("The well-known check document does not name %s: %s" % (pin_name, document))
    if (found.get("method") or "POST") != "POST":
        raise SystemExit("The documented pin method must be POST: %s" % found)
    exact = found["path"]
    for verb in WRITE_VERBS:
        if exact == verb or exact.startswith(verb + "/") or exact.startswith(verb + "?"):
            raise SystemExit("The well-known check document names a write verb: %s" % exact)
    return exact


print("INIT")
subprocess.check_output([BIN, "--data-directory", STORE, "init"], text=True)
save(
    "a-init-note.txt",
    "init ran on this machine. Secret files stay under /tmp/prometheus-later-ui-public-wimse-act-accept-a.\n",
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
        "https://check.prestigeworldwide.digital",
        "Create Agent Principal",
        "/runtime-check",
        "/present-wimse",
        "emit-wimse",
        "/well-known-follow",
        "/operator-pin",
        "function documentedPinPath(",
        "function followWellKnownThenPin(",
        'followWellKnownThenPin("act-accept"',
        'followWellKnownThenPin("kill-accept"',
        "/act-export",
        'id="act-export-receipt"',
        "The holder secret path stays on this host",
        "The path is not sent to the check base",
    ]
    missing = [marker for marker in markers if marker not in root]
    if missing:
        raise SystemExit("GET / is not the later UI. missing=%s content_type=%s" % (missing, content_type))
    if "issuer.secret" in root or 'type="file"' in root:
        raise SystemExit("GET / must not name issuer.secret or offer a file upload")
    if 'fetch("https://' in root or 'fetch("http://' in root:
        raise SystemExit("GET / JS must not CORS-fetch an off-origin host")
    save(
        "a-get-root-proof.txt",
        "\n".join(
            [
                "issuing GET / is the later user interface",
                "GET / Check WIMSE posts POST /runtime-check with present-wimse fields",
                "GET / act-accept follows well-known through POST /operator-pin",
                "listen 127.0.0.1:%s" % PORT,
                "content_type %s" % content_type,
                "html_bytes %s" % len(root),
                "markers %s" % ", ".join(markers),
            ]
        )
        + "\n",
    )

    status, public_root, _ = http("GET", "%s/" % PUBLIC, timeout=20)
    require(status, public_root, 200, "public GET /")
    save("public-root.json", public_root)
    if public_root.get("role") != "check-only" or public_root.get("bind") != "check.prestigeworldwide.digital":
        raise SystemExit("public GET / must stay check-only JSON: %s" % public_root)

    print("PUBLIC HELPER 403")
    public_helpers = {}
    for path_name, body in (
        ("/operator-pin", {"check_base": PUBLIC, "pin": "act-accept", "body": {}}),
        ("/well-known-follow", {"check_base": PUBLIC}),
        ("/runtime-check", {"check_base": PUBLIC, "presentation_json": "{}"}),
        ("/act-export", {"receipt": {"result": "allowed"}}),
    ):
        status, payload, _ = http("POST", "%s%s" % (PUBLIC, path_name), body, timeout=20)
        require(status, payload, 403, "public POST %s" % path_name)
        if "check-only" not in json.dumps(payload):
            raise SystemExit("public POST %s must stay check-only: %s" % (path_name, payload))
        public_helpers[path_name] = {"http_status": status, "body": payload}
    save("public-helpers-refused.json", public_helpers)

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

    print("WELL-KNOWN-FOLLOW")
    status, follow, _ = http("POST", "%s/well-known-follow" % ISSUING, {"check_base": PUBLIC}, timeout=30)
    require(status, follow, 200, "POST /well-known-follow public")
    if follow.get("bind") != "check.prestigeworldwide.digital":
        raise SystemExit("well-known-follow bind must be the public name: %s" % follow)
    follow_text = json.dumps(follow)
    if "issuer.secret" in follow_text or "holder_secret" in follow_text:
        raise SystemExit("well-known-follow must not return secrets")
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
        if write_verb in follow_text:
            raise SystemExit("well-known-follow still names write verb %s" % write_verb)
    act_accept_path = documented_pin_path(follow, "act-accept")
    kill_accept_path = documented_pin_path(follow, "kill-accept")
    issuer_accept_path = documented_pin_path(follow, "issuer-accept")
    save("issuing-well-known-follow.json", follow)
    save(
        "resolved-operator-pins.json",
        {
            "check_base": PUBLIC,
            "act_accept_pin_name": "act-accept",
            "act_accept_path": act_accept_path,
            "kill_accept_path": kill_accept_path,
            "issuer_accept_path": issuer_accept_path,
            "note": "GET / resolves these paths from the well-known document. POST /operator-pin then posts that pin name. This walk does not hardcode public /act-accept as the accept URL.",
        },
    )
    if act_accept_path != "/act-accept":
        raise SystemExit("public document act-accept path was %s" % act_accept_path)

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
    require(status, issuer, 200, "GET /issuer-public")
    save("a-issuer-public-keys.json", {"keys": sorted(issuer.keys())})
    key = issuer.get("current_issuer_public_key_hex") or issuer.get("public_key_hex")
    if not key:
        raise SystemExit("no public key in %s" % list(issuer))
    save("a-issuer-public-key-length.txt", "public_key_hex_length=%s\n" % len(key))

    print("OPERATOR-PIN ISSUER-ACCEPT")
    status, accept, _ = http(
        "POST",
        "%s/operator-pin" % ISSUING,
        {
            "check_base": PUBLIC,
            "pin": "issuer-accept",
            "body": {"public_key_hex": key},
        },
        timeout=30,
    )
    print("ISSUER-ACCEPT", status, accept if status != 200 else list(accept))
    require(status, accept, 200, "POST /operator-pin issuer-accept")
    save(
        "operator-pin-issuer-accept.json",
        {
            "http_status": status,
            "pin": "issuer-accept",
            "resolved_path": issuer_accept_path,
            "request_keys": ["check_base", "pin", "body"],
            "response_keys": sorted(accept.keys()) if isinstance(accept, dict) else [],
        },
    )

    def mint_present():
        status, challenge, _ = http("POST", "%s/challenge" % ISSUING, {"instance_id": instance_id})
        require(status, challenge, 200, "POST /challenge")
        status, wimse, _ = http(
            "POST",
            "%s/present-wimse" % ISSUING,
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
        require(status, wimse, 200, "POST /present-wimse")
        return wimse

    def apply_wimse(wimse):
        (WALK / "presentation.json").write_text(wimse["presentation_json"])
        for field in (
            "workload_identity_token",
            "content_digest",
            "signature_input",
            "signature",
        ):
            if field not in wimse or not wimse[field]:
                raise SystemExit("POST /present-wimse must return %s" % field)
        save(
            "a-present-wimse-keys.json",
            {"keys": sorted(wimse.keys())},
        )
        save(
            "a-present-wimse-field-lengths.json",
            {
                "presentation_json": len(wimse["presentation_json"]),
                "workload_identity_token": len(wimse["workload_identity_token"]),
                "content_digest": len(wimse["content_digest"]),
                "signature_input": len(wimse["signature_input"]),
                "signature": len(wimse["signature"]),
            },
        )
        if "holder_secret" in wimse or "issuer.secret" in json.dumps(wimse):
            raise SystemExit("POST /present-wimse must not return secret bytes")
        return {
            "check_base": PUBLIC,
            "presentation_json": wimse["presentation_json"],
            "workload_identity_token": wimse["workload_identity_token"],
            "content_digest": wimse["content_digest"],
            "signature_input": wimse["signature_input"],
            "signature": wimse["signature"],
            "holder_secret_path": holder_secret_path,
        }

    print("PRESENT-WIMSE")
    wimse = mint_present()
    runtime_body = apply_wimse(wimse)
    save(
        "runtime-check-request-keys.json",
        {
            "keys": sorted(runtime_body.keys()),
            "check_base": PUBLIC,
            "holder_secret_path_sent_to_issuing_host": True,
            "holder_secret_bytes_sent_to_public_name": False,
            "note": "GET / posts this JSON to the loopback issuing host. That host signs the verifier nonce locally. Secret bytes are not uploaded. The path is not sent to the public name. WIMSE token, digest, and signature fields are not trimmed.",
        },
    )

    print("RUNTIME-CHECK ALLOW")
    status, allow, _ = http("POST", "%s/runtime-check" % ISSUING, runtime_body, timeout=40)
    if status != 200 or (isinstance(allow, dict) and allow.get("result") != "allowed"):
        print("ALLOW failed, remint once", status, allow)
        wimse = mint_present()
        runtime_body = apply_wimse(wimse)
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
            "note": "The public host already allowed this WIMSE act. The issuing store also checked so the receipt stays on the issuing store. Public act-export stays 403.",
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

    print("WELL-KNOWN-FOLLOW THEN OPERATOR-PIN ACT-ACCEPT")
    status, follow_act, _ = http("POST", "%s/well-known-follow" % ISSUING, {"check_base": PUBLIC}, timeout=30)
    require(status, follow_act, 200, "POST /well-known-follow before act-accept")
    again_act_path = documented_pin_path(follow_act, "act-accept")
    if again_act_path != act_accept_path:
        raise SystemExit("act-accept path changed between follow and pin: %s vs %s" % (act_accept_path, again_act_path))
    status, act_accept, _ = http(
        "POST",
        "%s/operator-pin" % ISSUING,
        {
            "check_base": PUBLIC,
            "pin": "act-accept",
            "body": accept_act_body,
        },
        timeout=40,
    )
    print("OPERATOR-PIN ACT-ACCEPT", status, act_accept if status != 200 else list(act_accept))
    require(status, act_accept, 200, "POST /operator-pin act-accept")
    if act_accept.get("result") != "accepted":
        raise SystemExit("POST /operator-pin act-accept must return accepted: %s" % act_accept)
    save(
        "operator-pin-act-accept.json",
        {
            "http_status": status,
            "pin": "act-accept",
            "resolved_path": again_act_path,
            "result": act_accept.get("result"),
            "keys": sorted(act_accept.keys()) if isinstance(act_accept, dict) else [],
            "wrote_instance": False,
            "hardcoded_public_act_accept": False,
        },
    )
    if "instance_id" in act_accept and act_accept.get("instance_id"):
        raise SystemExit("operator-pin act-accept must write no instance: %s" % act_accept)

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

    print("WELL-KNOWN-FOLLOW THEN OPERATOR-PIN KILL-ACCEPT")
    status, follow_again, _ = http("POST", "%s/well-known-follow" % ISSUING, {"check_base": PUBLIC}, timeout=30)
    require(status, follow_again, 200, "POST /well-known-follow before kill-accept")
    again_path = documented_pin_path(follow_again, "kill-accept")
    if again_path != kill_accept_path:
        raise SystemExit("kill-accept path changed between follow and pin: %s vs %s" % (kill_accept_path, again_path))
    status, kill_accept, _ = http(
        "POST",
        "%s/operator-pin" % ISSUING,
        {
            "check_base": PUBLIC,
            "pin": "kill-accept",
            "body": kill_accept_body,
        },
        timeout=40,
    )
    print("OPERATOR-PIN KILL-ACCEPT", status, kill_accept if status != 200 else list(kill_accept))
    require(status, kill_accept, 200, "POST /operator-pin kill-accept")
    save(
        "operator-pin-kill-accept.json",
        {
            "http_status": status,
            "pin": "kill-accept",
            "resolved_path": again_path,
            "accepted_killed_instance_ids": kill_accept.get("accepted_killed_instance_ids"),
            "accepted_killed_capability_ids": kill_accept.get("accepted_killed_capability_ids"),
            "keys": sorted(kill_accept.keys()) if isinstance(kill_accept, dict) else [],
            "hardcoded_public_kill_accept": False,
        },
    )

    print("RUNTIME-CHECK REFUSE")
    status, refused, _ = http("POST", "%s/runtime-check" % ISSUING, runtime_body, timeout=40)
    if status != 403:
        raise SystemExit("second POST /runtime-check must refuse after operator-pin kill-accept: HTTP %s %s" % (status, refused))
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

    print("PUBLIC CHECK-WIMSE AFTER DECOMMISSION")
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
    presentation = json.loads(wimse["presentation_json"])
    status, public_refused, _ = http(
        "POST",
        "%s/check-wimse" % PUBLIC,
        {
            "presentation_json": wimse["presentation_json"],
            "workload_identity_token": wimse["workload_identity_token"],
            "content_digest": wimse["content_digest"],
            "intent": presentation["intent"],
            "audience": presentation["audience"],
            "holder_proof": proof,
            "challenge_nonce": challenge["challenge_nonce"],
            "on_behalf_of": "autonomous",
            "signature_input": wimse["signature_input"],
            "signature": wimse["signature"],
        },
        timeout=20,
    )
    if status != 403 or public_refused.get("result") != "refused":
        raise SystemExit("public POST /check-wimse must refuse after operator-pin kill-accept: HTTP %s %s" % (status, public_refused))
    public_reason = public_refused.get("reason") or ""
    if "accepted a kill" not in public_reason.lower() and "kill accept" not in public_reason.lower():
        raise SystemExit("public POST /check-wimse must name accepted kill: %s" % public_reason)
    save(
        "public-check-wimse-after-decommission.json",
        {
            "http_status": status,
            "result": public_refused.get("result"),
            "reason": public_reason,
            "request_keys": [
                "presentation_json",
                "workload_identity_token",
                "content_digest",
                "intent",
                "audience",
                "holder_proof",
                "challenge_nonce",
                "on_behalf_of",
                "signature_input",
                "signature",
            ],
            "holder_secret_bytes_sent_to_public_name": False,
        },
    )

    print("OK WIMSE operator-pin act-accept allow then refuse")
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
        "Deleted /tmp/prometheus-later-ui-public-wimse-act-accept-a after the walk. issuer.secret is not left under /tmp from this walk.\n",
    )
