#!/usr/bin/env python3
"""Laboratory operator page Check against the live public check name.

Drive the same HTTP JSON GET /laboratory posts. Check again posts that JSON
a second time. Off-origin pins use POST /well-known-follow then POST /operator-pin.
Do not hardcode public /kill-accept as the accept path.
Do not spawn AgentProcess. Do not copy issuer.secret onto the public host.
Public artifacts only land under see-walk/later-ui-laboratory-public-check.
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
STORE = "/tmp/prometheus-later-ui-laboratory-public-check-a"
WALK = Path("/home/jason/Projects/Prometheus/see-walk/later-ui-laboratory-public-check")
ISSUING = "http://127.0.0.1:18818"
PUBLIC = "https://check.prestigeworldwide.digital"
PORT = 18818
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
    "init ran on this machine. Secret files stay under /tmp/prometheus-later-ui-laboratory-public-check-a.\n",
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

    status, laboratory, headers = http("GET", "%s/laboratory" % ISSUING, raw=True, timeout=20)
    require(status, laboratory[:80], 200, "GET /laboratory")
    content_type = headers.get("Content-Type") or headers.get("content-type") or ""
    markers = [
        'id="check-base"',
        'name="check_base"',
        "https://check.prestigeworldwide.digital",
        "Birth an instance",
        "/runtime-check",
        'id="check-again"',
        "Check again",
        "function checkAgain(",
        "Each click hits the host",
        "/well-known-follow",
        "/operator-pin",
        "The path is not sent to the check base",
    ]
    missing = [marker for marker in markers if marker not in laboratory]
    if missing:
        raise SystemExit("GET /laboratory is not the operator page with Check again. missing=%s content_type=%s" % (missing, content_type))
    if "issuer.secret" in laboratory or 'type="file"' in laboratory:
        raise SystemExit("GET /laboratory must not name issuer.secret or offer a file upload")
    if 'fetch("https://' in laboratory or 'fetch("http://' in laboratory:
        raise SystemExit("GET /laboratory JS must not CORS-fetch an off-origin host")
    if 'id="check-both"' in laboratory or 'id="check-this-act"' in laboratory:
        raise SystemExit("GET /laboratory must not invent Check both or a named act")
    save(
        "a-get-laboratory-proof.txt",
        "\n".join(
            [
                "issuing GET /laboratory is the laboratory operator page with Check again",
                "listen 127.0.0.1:%s" % PORT,
                "content_type %s" % content_type,
                "html_bytes %s" % len(laboratory),
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
            "note": "GET /laboratory resolves these paths from the well-known document. POST /operator-pin then posts that pin name. This walk does not hardcode public /kill-accept as the accept URL.",
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
            "note": "GET /laboratory Check and Check again post this JSON to the loopback issuing host. That host signs the verifier nonce locally. Secret bytes are not uploaded. The path is not sent to the public name.",
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
        },
    )
    if "issuer.secret" in json.dumps(allow):
        raise SystemExit("allow body must not name issuer.secret")

    print("CHECK AGAIN SAME PRESENT")
    status, again_allow, _ = http("POST", "%s/runtime-check" % ISSUING, runtime_body, timeout=40)
    require(status, again_allow, 200, "Check again POST /runtime-check allow")
    if again_allow.get("result") != "allowed":
        raise SystemExit("Check again of the same live present must allow: %s" % again_allow)
    save(
        "runtime-check-again-allow.json",
        {
            "http_status": status,
            "result": again_allow.get("result"),
            "reason": again_allow.get("reason"),
            "same_present": True,
            "cached_allowed": False,
            "keys": sorted(again_allow.keys()) if isinstance(again_allow, dict) else [],
        },
    )

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

    print("CHECK AGAIN AFTER DECOMMISSION")
    status, refused, _ = http("POST", "%s/runtime-check" % ISSUING, runtime_body, timeout=40)
    if status != 403:
        raise SystemExit("Check again POST /runtime-check must refuse after operator-pin kill-accept: HTTP %s %s" % (status, refused))
    reason = refused.get("reason") or ""
    if refused.get("result") != "refused":
        raise SystemExit("Check again of the same present must be refused: %s" % refused)
    if "accepted a kill" not in reason.lower() and "kill accept" not in reason.lower():
        raise SystemExit("GET /laboratory Check again must refuse from accepted kill: %s" % reason)
    if "expir" in reason.lower():
        raise SystemExit("refuse must name accepted kill, not expiry: %s" % reason)
    save(
        "runtime-check-after-decommission.json",
        {
            "http_status": status,
            "result": refused.get("result"),
            "reason": reason,
            "same_present": True,
            "cached_allowed": False,
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
        raise SystemExit("public POST /check-svid must refuse after operator-pin kill-accept: HTTP %s %s" % (status, public_refused))
    public_reason = public_refused.get("reason") or ""
    if "accepted a kill" not in public_reason.lower() and "kill accept" not in public_reason.lower():
        raise SystemExit("public POST /check-svid must name accepted kill: %s" % public_reason)
    save(
        "public-check-svid-after-decommission.json",
        {
            "http_status": status,
            "result": public_refused.get("result"),
            "reason": public_reason,
            "holder_secret_bytes_sent_to_public_name": False,
        },
    )

    print("OK laboratory Check again allow then refuse")
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
        "Deleted /tmp/prometheus-later-ui-laboratory-public-check-a after the walk. issuer.secret is not left under /tmp from this walk.\n",
    )
