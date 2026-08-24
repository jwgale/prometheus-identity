#!/usr/bin/env python3
"""Rung 100: later UI remote member-secret path, WIMSE public allow then refuse.

Drive the same HTTP JSON GET / posts. Init stays on the command line.
Host start is a listen command. Do not use prometheus CLI birth, present,
kill, or check verbs after the host is up. Holder-sign is local workstation
proof. Do not spawn AgentProcess. Do not raise the standing issuer.
Do not copy issuer.secret or the laptop member-two.secret.
Public artifacts only land under see-walk/later-ui-laboratory-member-two-public-wimse.

POST /check-wimse request JSON matches later-ui-public-wimse-check-again
and later-ui-laboratory-public-wimse.
"""

from pathlib import Path
import base64
import hashlib
import json
import os
import socket
import stat
import subprocess
import time
import urllib.error
import urllib.request

BIN = "/home/jason/Projects/Prometheus/target/release/prometheus"
STORE = "/tmp/prometheus-later-ui-laboratory-member-two-public-wimse-20260823"
WALK = Path("/home/jason/Projects/Prometheus/see-walk/later-ui-laboratory-member-two-public-wimse")
MEMBER = "/home/jason/Projects/prometheus-lab-vpc/mnt-member-two/member-two.secret"
MOUNT = "/home/jason/Projects/prometheus-lab-vpc/mnt-member-two"
SSHFS = "/home/jason/.local/bin/sshfs"
IDENTITY = "/home/jason/.ssh/rustdesk-hermes.pem"
STANDING_LAPTOP_MEMBER = "/home/jason/Projects/prometheus-lab-vpc/member-two.secret"
STANDING_A = "/home/jason/Projects/Prometheus/data-a/issuer.json"
ISSUING = "http://127.0.0.1:18844"
PUBLIC = "https://check.prestigeworldwide.digital"
AUDIENCE = "check.prestigeworldwide.digital"
PORT = 18844

WALK.mkdir(parents=True, exist_ok=True)


def save(name, obj):
    path = WALK / name
    if isinstance(obj, (dict, list)):
        path.write_text(json.dumps(obj, indent=2) + "\n")
    else:
        text = str(obj)
        path.write_text(text if text.endswith("\n") else text + "\n")


def redact(text):
    lower = (text or "").lower()
    if (
        "secret" in lower
        and "issuer.secret" not in lower
        and "member_secret_path" not in lower
        and "member secret path" not in lower
        and "member secret is present" not in lower
        and "member-secret" not in lower
        and "holder_secret_path" not in lower
        and "holder secret path" not in lower
    ):
        return "refused (secret-looking text redacted)"
    return text


def http(method, url, body=None, timeout=40, raw=False):
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
        raise SystemExit("%s HTTP %s expected %s: %s" % (label, status, expect, redact(str(payload)[:800])))
    return payload


def reason_of(payload):
    if isinstance(payload, dict):
        return payload.get("reason") or payload.get("error") or json.dumps(payload)
    return str(payload)


def standing_member_mtime():
    return os.stat(STANDING_LAPTOP_MEMBER).st_mtime


def mount_up():
    if os.path.ismount(MOUNT):
        return
    os.makedirs(MOUNT, exist_ok=True)
    subprocess.check_call(
        [
            SSHFS,
            "-o",
            "IdentityFile=%s" % IDENTITY,
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "reconnect",
            "-o",
            "ServerAliveInterval=15",
            "ubuntu@10.43.1.186:/home/ubuntu/member-two-custody",
            MOUNT,
        ]
    )
    for _ in range(40):
        if os.path.ismount(MOUNT):
            return
        time.sleep(0.1)
    raise SystemExit("sshfs did not remount %s" % MOUNT)


def vpc_issuer_secret_count():
    out = subprocess.check_output(
        [
            "ssh",
            "-i",
            IDENTITY,
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "BatchMode=yes",
            "ubuntu@10.43.1.186",
            "find /home/ubuntu -name issuer.secret 2>/dev/null | wc -l; find /home/ubuntu/member-two-custody -maxdepth 1 -type f | wc -l",
        ],
        text=True,
    )
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    return int(lines[0]), int(lines[1])


def refuse_names_accepted_kill(text):
    lower = (text or "").lower()
    if "expir" in lower and "accepted a kill" not in lower and "kill accept" not in lower:
        return False
    return "accepted a kill" in lower or "kill accept" in lower


def is_allowed(status, payload):
    if status != 200 or not isinstance(payload, dict):
        return False
    result = str(payload.get("result") or payload.get("decision") or "").lower()
    if payload.get("allowed") is True:
        return True
    if "refused" in result:
        return False
    return result in ("allowed", "allow", "")


def holder_sign(holder_secret_path, challenge_message):
    proof = subprocess.check_output(
        [
            BIN,
            "holder-sign",
            "--holder-secret-path",
            holder_secret_path,
            "--challenge-message",
            challenge_message,
        ],
        text=True,
    ).strip()
    if not proof:
        raise SystemExit("holder-sign must return a proof")
    return proof


def b64url_decode(part):
    padding = "=" * ((4 - (len(part) % 4)) % 4)
    return base64.urlsafe_b64decode(part + padding)


def wit_sub_is_present_hash(token, presentation_json):
    parts = (token or "").split(".")
    if len(parts) < 2:
        raise SystemExit("workload identity token is not three parts")
    payload = json.loads(b64url_decode(parts[1]))
    digest = hashlib.sha256(presentation_json.encode()).hexdigest()
    expected = "wimse://prometheus.laboratory/present/%s" % digest
    sub = payload.get("sub")
    if sub != expected:
        raise SystemExit("WIT sub must be the present-hash wimse URI")
    if payload.get("iss") != "wimse://prometheus.laboratory":
        raise SystemExit("WIT iss must stay the laboratory wimse issuer")
    return {
        "sub_prefix": "wimse://prometheus.laboratory/present/",
        "sub_matches_present_sha256": True,
        "iss": "wimse://prometheus.laboratory",
        "instance_identifier_in_sub": False,
    }


def check_wimse_public(wimse, holder_secret_path):
    status, challenge, _ = http("POST", "%s/verifier-challenge" % PUBLIC, {}, timeout=20)
    if status != 200:
        return status, {"result": "refused", "reason": "verifier-challenge failed: %s" % challenge}
    proof = holder_sign(holder_secret_path, challenge["challenge_message"])
    presentation = json.loads(wimse["presentation_json"])
    body = {
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
    }
    return http("POST", "%s/check-wimse" % PUBLIC, body, timeout=20)[:2]


print("PREFLIGHT")
if not os.path.isfile(BIN):
    raise SystemExit("missing binary %s" % BIN)
if not os.path.isfile(SSHFS):
    raise SystemExit("missing sshfs %s" % SSHFS)
subprocess.check_call(["ping", "-c", "1", "-W", "3", "10.43.1.186"], stdout=subprocess.DEVNULL)
mount_up()
before_mtime = standing_member_mtime()
with open(STANDING_A) as handle:
    standing_a = json.load(handle)
if standing_a.get("threshold_n", 1) != 1:
    raise SystemExit("standing data-a threshold_n must stay 1")
save(
    "standing-before.json",
    {
        "data_a_threshold_n": standing_a.get("threshold_n", 1),
        "laptop_member_two_mtime": before_mtime,
        "laptop_member_two_mtime_iso": time.strftime("%Y-%m-%d %H:%M:%S %z", time.localtime(before_mtime)),
    },
)

status, well_known, _ = http("GET", "%s/.well-known/prometheus-check" % PUBLIC, timeout=20)
require(status, well_known, 200, "GET public well-known")
save("public-well-known.json", well_known)
well_known_text = json.dumps(well_known)
if "check.prestigeworldwide.digital" not in well_known_text:
    raise SystemExit("public well-known must bind check.prestigeworldwide.digital")
check_paths = [item.get("path") for item in well_known.get("checks", [])]
if "/check-wimse" not in check_paths:
    raise SystemExit("public well-known must name /check-wimse: %s" % check_paths)
if "/check-svid" not in check_paths:
    raise SystemExit("public well-known must still name /check-svid")
for write_verb in ("/birth", "/present-svid", "/present-wimse", "/runtime-check", "issuer.secret"):
    if write_verb in well_known_text:
        raise SystemExit("public well-known still names write verb %s" % write_verb)
status, health, _ = http("GET", "%s/health" % PUBLIC, timeout=20)
require(status, health, 200, "GET public /health")
save("public-health.json", health)

subprocess.run(["rm", "-rf", STORE], check=True)
os.makedirs(STORE, mode=0o700)

print("INIT")
subprocess.check_output([BIN, "--data-directory", STORE, "init"], text=True)
save(
    "a-init-note.txt",
    "init ran on hostname 5090. Secret files stay under %s. The standing issuer was not used.\n" % STORE,
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

    status, root, headers = http("GET", "%s/laboratory" % ISSUING, raw=True, timeout=20)
    require(status, root[:80], 200, "GET /laboratory")
    content_type = headers.get("Content-Type") or headers.get("content-type") or ""
    markers = [
        "Prometheus loopback operator page",
        'id="birth-member-secret-path"',
        'name="member_secret_path"',
        "This page is a laboratory operator surface",
        "After issuance threshold_n is 2",
        "This page is not the later full user interface",
        "https://check.prestigeworldwide.digital",
        'id="emit-wimse"',
        "workload-identity-token",
        "function submitCheckWimse(",
        "/present-wimse",
        "/check-wimse",
    ]
    missing = [marker for marker in markers if marker not in root]
    if missing:
        raise SystemExit("GET /laboratory is not the operator page with WIMSE. missing=%s content_type=%s" % (missing, content_type))
    if "issuer.secret" in root or 'type="file"' in root:
        raise SystemExit("GET /laboratory must not name issuer.secret or offer a file upload")
    save(
        "a-get-laboratory-proof.txt",
        "\n".join(
            [
                "issuing GET /laboratory is the laboratory operator page with present-wimse",
                "listen 127.0.0.1:%s" % PORT,
                "content_type %s" % content_type,
                "html_bytes %s" % len(root),
                "markers %s" % ", ".join(markers),
            ]
        )
        + "\n",
    )
    status, later, later_headers = http("GET", "%s/" % ISSUING, raw=True, timeout=20)
    require(status, later[:80], 200, "GET / contrast")
    pages_differ = later != root
    if "Create Agent Principal" not in later or not pages_differ:
        raise SystemExit("GET / must stay a different later user interface page")
    save("a-get-root-contrast.txt", "GET / is a different page from GET /laboratory. later UI markers present=True pages_differ=%s\n" % pages_differ)


    status, issuer_public, _ = http("GET", "%s/issuer-public" % ISSUING)
    require(status, issuer_public, 200, "GET /issuer-public")
    public_key = issuer_public.get("public_key_hex") or issuer_public.get("current_issuer_public_key_hex")
    if not public_key:
        raise SystemExit("issuer-public missing key: %s" % issuer_public.keys())
    save(
        "a-issuer-public.json",
        {
            "crypto_profile": issuer_public.get("crypto_profile"),
            "public_key_hex_len": len(public_key),
            "has_public_key": True,
        },
    )
    save("a-issuer-public-key-length.txt", "public_key_hex_length=%s\n" % len(public_key))
    (WALK / "a-issuer-public-key.hex").write_text(public_key + "\n")

    print("MEMBER TWO")
    status, member_two, _ = http(
        "POST",
        "%s/member-two" % ISSUING,
        {"member_secret_path": MEMBER},
        timeout=60,
    )
    require(status, member_two, 200, "POST /member-two")
    if not member_two.get("public_key_hex"):
        raise SystemExit("member-two must return public_key_hex only")
    dumped = json.dumps(member_two).lower()
    if "secret" in dumped and "public_key" not in dumped:
        raise SystemExit("member-two response must not return secret bytes")
    save(
        "a-member-two.json",
        {
            "http_status": status,
            "public_key_hex_len": len(member_two["public_key_hex"]),
            "response_keys": sorted(member_two.keys()),
            "secret_bytes_returned": False,
            "remote_path_used": True,
            "path_is_sshfs_mount": os.path.ismount(MOUNT),
        },
    )
    if not os.path.isfile(MEMBER):
        raise SystemExit("kernel did not write member two through the mount")
    mode = stat.S_IMODE(os.stat(MEMBER).st_mode)
    if mode != 0o600:
        raise SystemExit("remote member-two.secret mode must be 0600, got %o" % mode)

    print("ISSUER THRESHOLD")
    status, threshold, _ = http(
        "POST",
        "%s/set-issuer-threshold" % ISSUING,
        {"confirm": "issuer-threshold", "n": 2},
    )
    require(status, threshold, 200, "POST /set-issuer-threshold")
    if threshold.get("threshold_n") != 2:
        raise SystemExit("threshold_n must be 2: %s" % threshold)
    save("a-issuer-threshold.json", threshold)

    print("AGENT TYPE")
    status, agent_type, _ = http(
        "POST",
        "%s/agent-type" % ISSUING,
        {
            "allowed_intents": ["read"],
            "authorization_limit": AUDIENCE,
            "owner": "jason-gale",
            "member_secret_path": MEMBER,
        },
        timeout=60,
    )
    require(status, agent_type, 200, "POST /agent-type")
    agent_type_id = agent_type.get("agent_type_id")
    if not agent_type_id:
        raise SystemExit("agent-type missing id: %s" % agent_type)
    save(
        "a-agent-type.json",
        {
            "http_status": status,
            "agent_type_id": agent_type_id,
            "allowed_intents": agent_type.get("allowed_intents"),
        },
    )

    print("BIRTH WITHOUT PATH")
    status, no_path, _ = http(
        "POST",
        "%s/birth" % ISSUING,
        {
            "agent_type_id": agent_type_id,
            "owner": "jason-gale",
            "intent": "read",
            "audience": AUDIENCE,
            "on_behalf_of": "autonomous",
        },
        timeout=40,
    )
    if status == 200:
        raise SystemExit("POST /birth without member_secret_path must refuse after n=2")
    no_path_reason = reason_of(no_path)
    if "member_secret_path" not in no_path_reason:
        raise SystemExit("birth without path must name member_secret_path: %s" % redact(no_path_reason))
    save("a-birth-refuse-without-path.json", {"http_status": status, "reason": no_path_reason})

    print("BIRTH WITH PATH")
    status, birth, _ = http(
        "POST",
        "%s/birth" % ISSUING,
        {
            "agent_type_id": agent_type_id,
            "owner": "jason-gale",
            "intent": "read",
            "audience": AUDIENCE,
            "on_behalf_of": "autonomous",
            "member_secret_path": MEMBER,
        },
        timeout=60,
    )
    require(status, birth, 200, "POST /birth with remote path")
    instance_id = birth.get("instance_id")
    capability_id = birth.get("capability_id")
    holder_secret_path = birth.get("holder_secret_path")
    if not instance_id or not capability_id or not holder_secret_path:
        raise SystemExit("birth must return instance, capability, and holder path: %s" % birth.keys())
    if STORE not in holder_secret_path:
        raise SystemExit("holder secret path must stay on the throwaway store")
    save(
        "a-birth-allow.json",
        {
            "http_status": status,
            "instance_id": instance_id,
            "capability_id": capability_id,
            "holder_secret_path_on_throwaway_store": True,
            "response_keys": sorted(birth.keys()),
            "secret_bytes_returned": False,
        },
    )

    print("ISSUER-ACCEPT")
    status, accept, _ = http("POST", "%s/issuer-accept" % PUBLIC, {"public_key_hex": public_key}, timeout=20)
    require(status, accept, 200, "public POST /issuer-accept")
    save(
        "public-issuer-accept.json",
        {
            "http_status": status,
            "request_keys": ["public_key_hex"],
            "response_keys": sorted(accept.keys()) if isinstance(accept, dict) else [],
            "public_key_hex_length": len(accept.get("public_key_hex", "")) if isinstance(accept, dict) else 0,
        },
    )

    def mint_present():
        status, challenge, _ = http(
            "POST",
            "%s/challenge" % ISSUING,
            {"instance_id": instance_id, "member_secret_path": MEMBER},
            timeout=40,
        )
        require(status, challenge, 200, "POST /challenge")
        nonce = challenge.get("challenge_nonce") or challenge.get("nonce")
        if not nonce:
            raise SystemExit("challenge missing nonce: %s" % sorted(challenge.keys()))
        status, present, _ = http(
            "POST",
            "%s/present-wimse" % ISSUING,
            {
                "instance_id": instance_id,
                "capability_id": capability_id,
                "intent": "read",
                "audience": AUDIENCE,
                "holder_secret_path": holder_secret_path,
                "challenge_nonce": nonce,
                "on_behalf_of": "autonomous",
                "member_secret_path": MEMBER,
            },
            timeout=60,
        )
        require(status, present, 200, "POST /present-wimse")
        for field in (
            "presentation_json",
            "workload_identity_token",
            "content_digest",
            "signature_input",
            "signature",
        ):
            if field not in present or not present[field]:
                raise SystemExit("present-wimse must return %s" % field)
        return present

    def apply_present(present):
        presentation = json.loads(present["presentation_json"])
        signatures = presentation.get("issuer_signatures") or []
        if len(signatures) < 2:
            raise SystemExit("present at threshold_n 2 must persist two member signatures, got %s" % len(signatures))
        (WALK / "presentation.json").write_text(
            present["presentation_json"] if present["presentation_json"].endswith("\n") else present["presentation_json"] + "\n"
        )
        wit_bind = wit_sub_is_present_hash(present["workload_identity_token"], present["presentation_json"])
        save("a-present-wimse-keys.json", {"keys": sorted(present.keys())})
        save(
            "a-present-wimse-field-lengths.json",
            {
                "presentation_json": len(present["presentation_json"]),
                "workload_identity_token": len(present["workload_identity_token"]),
                "content_digest": len(present["content_digest"]),
                "signature_input": len(present["signature_input"]),
                "signature": len(present["signature"]),
            },
        )
        save("a-wit-sub.json", wit_bind)
        if "holder_secret" in present or "issuer.secret" in json.dumps(present):
            raise SystemExit("POST /present-wimse must not return secret bytes")
        return presentation, signatures

    print("PRESENT-WIMSE")
    present = mint_present()
    presentation, signatures = apply_present(present)
    save(
        "a-present-allow.json",
        {
            "http_status": 200,
            "has_presentation_json": True,
            "has_workload_identity_token": True,
            "has_content_digest": True,
            "has_signature_input": True,
            "has_signature": True,
            "intent": presentation.get("intent"),
            "audience": presentation.get("audience"),
            "issuer_signature_count": len(signatures),
            "response_keys": sorted(present.keys()),
            "secret_bytes_returned": False,
        },
    )
    save(
        "public-check-wimse-request-keys.json",
        {
            "keys": [
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
            "copied_from": [
                "see-walk/later-ui-public-wimse-check-again-walk.py",
                "see-walk/later-ui-laboratory-public-wimse-walk.py",
            ],
            "holder_secret_bytes_sent_to_public_name": False,
            "member_secret_bytes_sent_to_public_name": False,
        },
    )

    print("CHECK-WIMSE ALLOW")
    status, allow = check_wimse_public(present, holder_secret_path)
    reason = reason_of(allow)
    if not is_allowed(status, allow):
        if "expir" in reason.lower():
            print("ALLOW expired, remint once")
            present = mint_present()
            presentation, signatures = apply_present(present)
            status, allow = check_wimse_public(present, holder_secret_path)
            reason = reason_of(allow)
    if not is_allowed(status, allow):
        raise SystemExit("public check-wimse must allow: HTTP %s %s" % (status, redact(str(allow)[:800])))
    save(
        "public-check-wimse-allow.json",
        {
            "http_status": status,
            "result": allow.get("result") if isinstance(allow, dict) else None,
            "decision": allow.get("decision") if isinstance(allow, dict) else None,
            "reason": allow.get("reason") if isinstance(allow, dict) else None,
            "keys": sorted(allow.keys()) if isinstance(allow, dict) else [],
            "holder_secret_bytes_sent_to_public_name": False,
            "member_secret_bytes_sent_to_public_name": False,
        },
    )
    print("ALLOW", status, allow.get("result") if isinstance(allow, dict) else allow)

    print("KILL")
    kill_body = {"instance_id": instance_id, "confirm": instance_id, "member_secret_path": MEMBER}
    status, killed, _ = http("POST", "%s/kill" % ISSUING, kill_body, timeout=60)
    require(status, killed, 200, "POST /kill")
    save(
        "a-kill.json",
        {
            "instance_id": killed.get("instance_id"),
            "status": killed.get("status"),
            "keys": sorted(killed.keys()) if isinstance(killed, dict) else [],
        },
    )

    print("KILL-EXPORT")
    status, exported, _ = http("POST", "%s/kill-export" % ISSUING, kill_body, timeout=60)
    require(status, exported, 200, "POST /kill-export")
    save("kill-export-keys.json", {"keys": sorted(exported.keys()) if isinstance(exported, dict) else []})
    event = exported["event"]
    proof = exported["proof"]
    tree_head = exported["tree_head"]
    save("kill-event.json", event)
    save("kill-proof.json", proof)
    save("kill-tree-head.json", tree_head)

    print("KILL-ACCEPT")
    status, kill_accept, _ = http(
        "POST",
        "%s/kill-accept" % PUBLIC,
        {"event": event, "proof": proof, "tree_head": tree_head},
        timeout=20,
    )
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

    print("CHECK-WIMSE REFUSE")
    status, refused = check_wimse_public(present, holder_secret_path)
    reason = reason_of(refused)
    print("REFUSE", status, redact(reason))
    if is_allowed(status, refused):
        raise SystemExit("historical present must refuse after kill-accept: %s" % refused)
    if "expir" in reason.lower() and not refuse_names_accepted_kill(reason):
        raise SystemExit("refuse must name accepted kill, not expiry: %s" % reason)
    if not refuse_names_accepted_kill(reason):
        raise SystemExit("refuse must name accepted kill: %s" % reason)
    save(
        "public-check-wimse-after-kill.json",
        {
            "http_status": status,
            "result": refused.get("result") if isinstance(refused, dict) else None,
            "reason": reason,
            "keys": sorted(refused.keys()) if isinstance(refused, dict) else [],
            "holder_secret_bytes_sent_to_public_name": False,
            "member_secret_bytes_sent_to_public_name": False,
        },
    )

    after_mtime = standing_member_mtime()
    if after_mtime != before_mtime:
        raise SystemExit("standing laptop member-two.secret mtime moved")
    with open(STANDING_A) as handle:
        standing_after = json.load(handle)
    if standing_after.get("threshold_n", 1) != 1:
        raise SystemExit("standing data-a threshold_n must stay 1")
    issuer_count, custody_files = vpc_issuer_secret_count()
    if issuer_count != 0:
        raise SystemExit("VPC issuer.secret count must stay 0")
    save(
        "a-custody-locks.json",
        {
            "standing_data_a_threshold_n": standing_after.get("threshold_n", 1),
            "laptop_member_two_mtime_unchanged": True,
            "vpc_issuer_secret_count": issuer_count,
            "vpc_custody_file_count": custody_files,
            "sshfs_mounted": os.path.ismount(MOUNT),
        },
    )
    print("OK later-ui remote path WIMSE public allow then refuse")
finally:
    host.terminate()
    try:
        host.wait(timeout=5)
    except subprocess.TimeoutExpired:
        host.kill()
        host.wait(timeout=5)
    save("a-host-stopped.txt", "issuing host on 127.0.0.1:%s is stopped\n" % PORT)
    if os.path.isdir(STORE):
        for root, _dirs, files in os.walk(STORE):
            for name in files:
                path = os.path.join(root, name)
                try:
                    subprocess.run(
                        ["shred", "-u", path],
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                except OSError:
                    try:
                        os.remove(path)
                    except OSError:
                        pass
        subprocess.run(["rm", "-rf", STORE], check=False)
    save("a-store-shredded.txt", "throwaway store %s was shredded\n" % STORE)
    if Path(STORE).exists():
        raise SystemExit("throwaway store still exists after shred")
    if not os.path.isfile(MEMBER):
        raise SystemExit("VPC member-two.secret missing after shred; custody dir must stay")
    forbidden = []
    for path in WALK.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix == ".secret" or path.name in {"issuer.secret", "biscuit.secret"}:
            forbidden.append(str(path))
    if forbidden:
        raise SystemExit("see-walk must not hold secrets: %s" % forbidden)
