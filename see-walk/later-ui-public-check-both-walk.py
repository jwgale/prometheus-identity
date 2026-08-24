#!/usr/bin/env python3
"""Later user interface Check both against the live public check name.

Drive the same HTTP JSON GET / posts. Check both posts POST /runtime-check
once per present. Off-origin pins use POST /well-known-follow then
POST /operator-pin. Do not hardcode public /kill-accept as the accept path.
Do not spawn AgentProcess. Do not copy issuer.secret onto the public host.
Public artifacts only land under see-walk/later-ui-public-check-both.
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
STORE = "/tmp/prometheus-later-ui-public-check-both-a"
WALK = Path("/home/jason/Projects/Prometheus/see-walk/later-ui-public-check-both")
ISSUING = "http://127.0.0.1:18826"
PUBLIC = "https://check.prestigeworldwide.digital"
PORT = 18826
AUDIENCE = "check.prestigeworldwide.digital"
NARROWER = "check.prestigeworldwide.digital/child"
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


def mint_present(instance_id, capability_id, holder_secret_path, audience, label):
    status, challenge, _ = http("POST", "%s/challenge" % ISSUING, {"instance_id": instance_id})
    require(status, challenge, 200, "POST /challenge %s" % label)
    status, svid, _ = http(
        "POST",
        "%s/present-svid" % ISSUING,
        {
            "instance_id": instance_id,
            "capability_id": capability_id,
            "holder_secret_path": holder_secret_path,
            "challenge_nonce": challenge["challenge_nonce"],
            "intent": "read",
            "audience": audience,
            "on_behalf_of": "autonomous",
        },
    )
    require(status, svid, 200, "POST /present-svid %s" % label)
    if "holder_secret" in svid or "issuer.secret" in json.dumps(svid):
        raise SystemExit("POST /present-svid must not return secret bytes")
    return svid


def runtime_body(svid, holder_secret_path):
    return {
        "check_base": PUBLIC,
        "presentation_json": svid["presentation_json"],
        "certificate_pem": svid["certificate_pem"],
        "holder_secret_path": holder_secret_path,
    }


def runtime_check(body, label, timeout=40):
    status, payload, _ = http("POST", "%s/runtime-check" % ISSUING, body, timeout=timeout)
    return status, payload


def must_allow(status, payload, label):
    if status != 200 or (isinstance(payload, dict) and payload.get("result") != "allowed"):
        raise SystemExit("%s must allow: HTTP %s %s" % (label, status, payload))
    if "issuer.secret" in json.dumps(payload):
        raise SystemExit("%s body must not name issuer.secret" % label)
    return payload


def must_refuse_accepted_kill(status, payload, label, cascade=False):
    if status != 403:
        raise SystemExit("%s must refuse after operator-pin kill-accept: HTTP %s %s" % (label, status, payload))
    reason = (payload.get("reason") or "") if isinstance(payload, dict) else ""
    if payload.get("result") != "refused":
        raise SystemExit("%s must be refused: %s" % (label, payload))
    low = reason.lower()
    if "expir" in low:
        raise SystemExit("%s must refuse from accepted kill, not expiry: %s" % (label, reason))
    if cascade:
        if "accepted a kill" not in low and "kill accept" not in low and "kill" not in low and "cascade" not in low:
            raise SystemExit("%s must name accepted parent death cascade: %s" % (label, reason))
    elif "accepted a kill" not in low and "kill accept" not in low:
        raise SystemExit("%s must refuse from accepted kill: %s" % (label, reason))
    if "issuer.secret" in json.dumps(payload):
        raise SystemExit("%s body must not name issuer.secret" % label)
    return reason


print("INIT")
subprocess.check_output([BIN, "--data-directory", STORE, "init"], text=True)
save(
    "a-init-note.txt",
    "init ran on this machine. Secret files stay under /tmp/prometheus-later-ui-public-check-both-a.\n",
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
        'id="check-both"',
        "Check both",
        "function checkBoth(",
        "function checkThisActOnly(",
        'id="check-this-act"',
        'id="check-act-number"',
        "Hold two Assertion Acts",
        "accepted a kill cascade",
        "named check of the live act",
        "This page does not store ALLOWED",
        "Each present is a separate host hit",
        "/well-known-follow",
        "/operator-pin",
        "The path is not sent to the check base",
        "Spawn a narrower child",
    ]
    missing = [marker for marker in markers if marker not in root]
    if missing:
        raise SystemExit("GET / is not the later UI with Check both. missing=%s content_type=%s" % (missing, content_type))
    if "issuer.secret" in root or 'type="file"' in root:
        raise SystemExit("GET / must not name issuer.secret or offer a file upload")
    if 'fetch("https://' in root or 'fetch("http://' in root:
        raise SystemExit("GET / JS must not CORS-fetch an off-origin host")
    save(
        "a-get-root-proof.txt",
        "\n".join(
            [
                "issuing GET / is the later user interface with Check both and a named check",
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

    print("PUBLIC HELPER 403")
    public_helpers = {}
    for path_name, body in (
        ("/operator-pin", {"check_base": PUBLIC, "pin": "kill-accept", "body": {}}),
        ("/well-known-follow", {"check_base": PUBLIC}),
        ("/runtime-check", {"check_base": PUBLIC, "presentation_json": "{}"}),
    ):
        status, payload, _ = http("POST", "%s%s" % (PUBLIC, path_name), body, timeout=20)
        require(status, payload, 403, "public POST %s" % path_name)
        if "check-only" not in json.dumps(payload):
            raise SystemExit("public POST %s must stay check-only: %s" % (path_name, payload))
        public_helpers[path_name] = {"http_status": status, "body": payload}
    save("public-helpers-refused.json", public_helpers)

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
    ):
        if write_verb in well_known_text:
            raise SystemExit("public well-known still names write verb %s" % write_verb)

    print("WELL-KNOWN-FOLLOW")
    status, follow, _ = http("POST", "%s/well-known-follow" % ISSUING, {"check_base": PUBLIC}, timeout=30)
    require(status, follow, 200, "POST /well-known-follow public")
    if follow.get("bind") != "check.prestigeworldwide.digital":
        raise SystemExit("well-known-follow bind must be the public name: %s" % follow)
    follow_text = json.dumps(follow)
    if "issuer.secret" in follow_text or "holder_secret" in follow_text:
        raise SystemExit("well-known-follow must not return secrets")
    kill_accept_path = documented_pin_path(follow, "kill-accept")
    issuer_accept_path = documented_pin_path(follow, "issuer-accept")
    save("issuing-well-known-follow.json", follow)
    save(
        "resolved-operator-pins.json",
        {
            "check_base": PUBLIC,
            "kill_accept_pin_name": "kill-accept",
            "kill_accept_path": kill_accept_path,
            "issuer_accept_path": issuer_accept_path,
            "note": "GET / resolves these paths from the well-known document. POST /operator-pin then posts that pin name. This walk does not hardcode public /kill-accept as the accept URL.",
        },
    )
    if kill_accept_path != "/kill-accept":
        raise SystemExit("public document kill-accept path was %s" % kill_accept_path)

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
    print("BIRTH PARENT", status)
    require(status, birth, 200, "POST /birth parent")
    if "holder_secret" in birth and "holder_secret_path" not in birth:
        raise SystemExit("POST /birth must not return secret bytes")
    save(
        "a-birth-parent.json",
        {
            "instance_id": birth["instance_id"],
            "capability_id": birth["capability_id"],
            "revoke_identifier": birth["revoke_identifier"],
            "holder_secret_path_present": "holder_secret_path" in birth,
        },
    )
    parent_instance_id = birth["instance_id"]
    parent_capability_id = birth["capability_id"]
    parent_holder = birth["holder_secret_path"]
    if not parent_holder.startswith(STORE):
        raise SystemExit("parent holder secret path must stay under the throwaway store")

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

    print("SPAWN NARROWER CHILD")
    status, spawn_challenge, _ = http("POST", "%s/challenge" % ISSUING, {"instance_id": parent_instance_id})
    require(status, spawn_challenge, 200, "POST /challenge spawn")
    status, spawn, _ = http(
        "POST",
        "%s/spawn" % ISSUING,
        {
            "parent_instance_id": parent_instance_id,
            "parent_capability_id": parent_capability_id,
            "owner": "jason-gale",
            "intent": "read",
            "audience": NARROWER,
            "holder_secret_path": parent_holder,
            "challenge_nonce": spawn_challenge["challenge_nonce"],
            "on_behalf_of": "autonomous",
        },
    )
    print("SPAWN", status, spawn if status != 200 else list(spawn))
    require(status, spawn, 200, "POST /spawn narrower child")
    if spawn.get("instance_id") == parent_instance_id:
        raise SystemExit("POST /spawn must write a child instance, not reuse the parent")
    if "holder_secret" in spawn and "holder_secret_path" not in spawn:
        raise SystemExit("POST /spawn must not return secret bytes")
    child_instance_id = spawn["instance_id"]
    child_capability_id = spawn["capability_id"]
    child_holder = spawn["holder_secret_path"]
    if not child_holder.startswith(STORE):
        raise SystemExit("child holder secret path must stay under the throwaway store")
    save(
        "a-spawn-child.json",
        {
            "parent_instance_id": parent_instance_id,
            "instance_id": child_instance_id,
            "capability_id": child_capability_id,
            "audience": NARROWER,
            "holder_secret_path_present": "holder_secret_path" in spawn,
            "keys": sorted(spawn.keys()) if isinstance(spawn, dict) else [],
        },
    )

    print("PRESENT PARENT AND CHILD")
    parent_svid = mint_present(parent_instance_id, parent_capability_id, parent_holder, AUDIENCE, "parent")
    child_svid = mint_present(child_instance_id, child_capability_id, child_holder, NARROWER, "child")
    (WALK / "parent-presentation.json").write_text(parent_svid["presentation_json"])
    (WALK / "parent-presentation.json.svid.pem").write_text(parent_svid["certificate_pem"])
    (WALK / "child-presentation.json").write_text(child_svid["presentation_json"])
    (WALK / "child-presentation.json.svid.pem").write_text(child_svid["certificate_pem"])
    save("a-present-svid-keys.json", {"parent": sorted(parent_svid.keys()), "child": sorted(child_svid.keys())})

    parent_body = runtime_body(parent_svid, parent_holder)
    child_body = runtime_body(child_svid, child_holder)
    save(
        "runtime-check-request-keys.json",
        {
            "parent_keys": sorted(parent_body.keys()),
            "child_keys": sorted(child_body.keys()),
            "check_base": PUBLIC,
            "holder_secret_path_sent_to_issuing_host": True,
            "holder_secret_bytes_sent_to_public_name": False,
            "two_runtime_check_hits": True,
            "note": "GET / Check both posts this JSON once per present to the loopback issuing host. That host signs the verifier nonce locally. Secret bytes are not uploaded. The path is not sent to the public name.",
        },
    )

    print("CHECK BOTH ALLOW")
    status_p, allow_p = runtime_check(parent_body, "parent")
    status_c, allow_c = runtime_check(child_body, "child")
    if status_p != 200 or allow_p.get("result") != "allowed" or status_c != 200 or allow_c.get("result") != "allowed":
        print("ALLOW failed, remint once", status_p, allow_p, status_c, allow_c)
        parent_svid = mint_present(parent_instance_id, parent_capability_id, parent_holder, AUDIENCE, "parent remint")
        child_svid = mint_present(child_instance_id, child_capability_id, child_holder, NARROWER, "child remint")
        (WALK / "parent-presentation.json").write_text(parent_svid["presentation_json"])
        (WALK / "parent-presentation.json.svid.pem").write_text(parent_svid["certificate_pem"])
        (WALK / "child-presentation.json").write_text(child_svid["presentation_json"])
        (WALK / "child-presentation.json.svid.pem").write_text(child_svid["certificate_pem"])
        parent_body = runtime_body(parent_svid, parent_holder)
        child_body = runtime_body(child_svid, child_holder)
        status_p, allow_p = runtime_check(parent_body, "parent remint")
        status_c, allow_c = runtime_check(child_body, "child remint")
    must_allow(status_p, allow_p, "Check both parent POST /runtime-check")
    must_allow(status_c, allow_c, "Check both child POST /runtime-check")
    save(
        "runtime-check-both-allow.json",
        {
            "parent": {
                "http_status": status_p,
                "result": allow_p.get("result"),
                "reason": allow_p.get("reason"),
                "keys": sorted(allow_p.keys()) if isinstance(allow_p, dict) else [],
            },
            "child": {
                "http_status": status_c,
                "result": allow_c.get("result"),
                "reason": allow_c.get("reason"),
                "keys": sorted(allow_c.keys()) if isinstance(allow_c, dict) else [],
            },
            "check_both_allowed": True,
            "cached_allowed": False,
            "two_runtime_check_hits": True,
        },
    )

    kill_body = {"instance_id": parent_instance_id, "confirm": parent_instance_id}
    status, killed, _ = http("POST", "%s/kill" % ISSUING, kill_body)
    print("KILL PARENT", status)
    require(status, killed, 200, "POST /kill parent")
    save(
        "a-kill-parent.json",
        {
            "instance_id": killed.get("instance_id"),
            "status": killed.get("status"),
            "keys": sorted(killed.keys()),
        },
    )

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

    print("CHECK BOTH AFTER PARENT DECOMMISSION")
    status_p, refuse_p = runtime_check(parent_body, "parent after kill")
    status_c, refuse_c = runtime_check(child_body, "child after kill")
    parent_reason = must_refuse_accepted_kill(status_p, refuse_p, "Check both parent after kill-accept")
    child_reason = must_refuse_accepted_kill(
        status_c, refuse_c, "Check both child after parent kill-accept", cascade=True
    )
    save(
        "runtime-check-both-after-decommission.json",
        {
            "parent": {
                "http_status": status_p,
                "result": refuse_p.get("result"),
                "reason": parent_reason,
                "same_present": True,
            },
            "child": {
                "http_status": status_c,
                "result": refuse_c.get("result"),
                "reason": child_reason,
                "same_present": True,
            },
            "check_both_allowed": False,
            "cached_allowed": False,
            "two_runtime_check_hits": True,
            "refuse_from_accepted_kill_cascade": True,
        },
    )

    print("NAMED CHECK OF CHILD AFTER CASCADE")
    status_named, named, _ = http("POST", "%s/runtime-check" % ISSUING, child_body, timeout=40)
    named_reason = must_refuse_accepted_kill(
        status_named, named, "named check of the child after parent kill-accept", cascade=True
    )
    save(
        "named-check-child-after-decommission.json",
        {
            "http_status": status_named,
            "result": named.get("result"),
            "reason": named_reason,
            "act": 2,
            "same_child_present": True,
            "cached_allowed": False,
            "refuse_from_accepted_kill_cascade": True,
            "keys": sorted(named.keys()) if isinstance(named, dict) else [],
        },
    )

    print("PUBLIC CHECK-SVID CHILD AFTER DECOMMISSION")
    status, challenge, _ = http("POST", "%s/verifier-challenge" % PUBLIC, {}, timeout=20)
    require(status, challenge, 200, "public POST /verifier-challenge")
    proof = subprocess.check_output(
        [
            BIN,
            "holder-sign",
            "--holder-secret-path",
            child_holder,
            "--challenge-message",
            challenge["challenge_message"],
        ],
        text=True,
    ).strip()
    if not proof:
        raise SystemExit("holder-sign must return a proof")
    presentation = json.loads(child_svid["presentation_json"])
    status, public_refused, _ = http(
        "POST",
        "%s/check-svid" % PUBLIC,
        {
            "presentation_json": child_svid["presentation_json"],
            "certificate_pem": child_svid["certificate_pem"],
            "intent": presentation["intent"],
            "audience": presentation["audience"],
            "holder_proof": proof,
            "challenge_nonce": challenge["challenge_nonce"],
            "on_behalf_of": "autonomous",
        },
        timeout=20,
    )
    if status != 403 or public_refused.get("result") != "refused":
        raise SystemExit(
            "public POST /check-svid of the child must refuse after parent kill-accept: HTTP %s %s"
            % (status, public_refused)
        )
    public_reason = public_refused.get("reason") or ""
    public_low = public_reason.lower()
    if "expir" in public_low:
        raise SystemExit("public child refuse must name accepted kill cascade, not expiry: %s" % public_reason)
    if "accepted a kill" not in public_low and "kill accept" not in public_low and "kill" not in public_low and "cascade" not in public_low:
        raise SystemExit("public POST /check-svid of the child must name accepted kill cascade: %s" % public_reason)
    save(
        "public-check-svid-child-after-decommission.json",
        {
            "http_status": status,
            "result": public_refused.get("result"),
            "reason": public_reason,
            "holder_secret_bytes_sent_to_public_name": False,
        },
    )

    print("OK later-UI Check both parent-child allow then cascade refuse")
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
        "Deleted /tmp/prometheus-later-ui-public-check-both-a after the walk. issuer.secret is not left under /tmp from this walk.\n",
    )
