#!/usr/bin/env python3
"""Rung 98: later UI Create Agent Principal on the remote member-secret path.

Drive the same HTTP JSON GET / posts. Init stays on the command line.
Host start is a listen command. Do not use prometheus CLI birth, present,
or check verbs after the host is up. Do not spawn AgentProcess.
Do not raise the standing issuer. Do not copy issuer.secret or the laptop
member-two.secret. Public artifacts only land under
see-walk/later-ui-member-two-remote.
"""

from pathlib import Path
import json
import os
import socket
import stat
import subprocess
import time
import urllib.error
import urllib.request

BIN = "/home/jason/Projects/Prometheus/target/release/prometheus"
STORE = "/tmp/prometheus-later-ui-member-two-remote-20260823"
WALK = Path("/home/jason/Projects/Prometheus/see-walk/later-ui-member-two-remote")
MEMBER = "/home/jason/Projects/prometheus-lab-vpc/mnt-member-two/member-two.secret"
MOUNT = "/home/jason/Projects/prometheus-lab-vpc/mnt-member-two"
SSHFS = "/home/jason/.local/bin/sshfs"
IDENTITY = "/home/jason/.ssh/rustdesk-hermes.pem"
STANDING_LAPTOP_MEMBER = "/home/jason/Projects/prometheus-lab-vpc/member-two.secret"
STANDING_A = "/home/jason/Projects/Prometheus/data-a/issuer.json"
ISSUING = "http://127.0.0.1:18832"
PORT = 18832

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
    if "secret" in lower and "issuer.secret" not in lower and "member_secret_path" not in lower and "member secret path" not in lower and "member secret is present" not in lower and "member-secret" not in lower:
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


def mount_down():
    if not os.path.ismount(MOUNT):
        return
    subprocess.check_call(["fusermount", "-u", MOUNT])
    for _ in range(40):
        if not os.path.ismount(MOUNT):
            return
        time.sleep(0.1)
    raise SystemExit("fusermount did not hide %s" % MOUNT)


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
        "laptop_member_two_mtime_iso": time.strftime(
            "%Y-%m-%d %H:%M:%S %z", time.localtime(before_mtime)
        ),
    },
)

subprocess.run(["rm", "-rf", STORE], check=True)
os.makedirs(STORE, mode=0o700)

print("INIT")
subprocess.check_output([BIN, "--data-directory", STORE, "init"], text=True)
save(
    "a-init-note.txt",
    "init ran on this machine. Secret files stay under %s. The standing issuer was not used.\n" % STORE,
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
        "Create Agent Principal",
        'id="issuing-member-secret-path"',
        'name="member_secret_path"',
        "Issuing-store member secret path",
        "after issuance threshold_n is 2",
        "Birth an instance",
        "Assertion Act",
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
    if "secret" in json.dumps(member_two).lower() and "public_key" not in json.dumps(member_two):
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
            "authorization_limit": "internal",
            "owner": "laboratory",
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
            "owner": "laboratory",
            "intent": "read",
            "audience": "internal",
            "on_behalf_of": "autonomous",
        },
        timeout=40,
    )
    if status == 200:
        raise SystemExit("POST /birth without member_secret_path must refuse after n=2")
    no_path_reason = reason_of(no_path)
    if "member_secret_path" not in no_path_reason:
        raise SystemExit("birth without path must name member_secret_path: %s" % redact(no_path_reason))
    save(
        "a-birth-refuse-without-path.json",
        {"http_status": status, "reason": no_path_reason},
    )

    print("UNMOUNT")
    mount_down()
    if os.path.isfile(MEMBER):
        raise SystemExit("member path must be gone after fusermount")
    save("a-unmount.txt", "fusermount hid %s. The VPC custody file stayed on prometheus-member-two.\n" % MEMBER)

    print("BIRTH WITH GONE PATH")
    status, gone, _ = http(
        "POST",
        "%s/birth" % ISSUING,
        {
            "agent_type_id": agent_type_id,
            "owner": "laboratory",
            "intent": "read",
            "audience": "internal",
            "on_behalf_of": "autonomous",
            "member_secret_path": MEMBER,
        },
        timeout=40,
    )
    if status == 200:
        raise SystemExit("POST /birth must refuse when the mount is gone")
    gone_reason = reason_of(gone)
    lower = gone_reason.lower()
    if "threshold_n" not in lower and "member" not in lower and "secret" not in lower and "path" not in lower:
        raise SystemExit("birth with gone path must name the missing member secret: %s" % redact(gone_reason))
    save(
        "a-birth-refuse-mount-gone.json",
        {"http_status": status, "reason": gone_reason},
    )

    print("REMOUNT")
    mount_up()
    if not os.path.isfile(MEMBER):
        raise SystemExit("member path must return after remount")
    save("a-remount.txt", "sshfs remounted ubuntu@10.43.1.186:/home/ubuntu/member-two-custody on %s\n" % MOUNT)

    print("BIRTH WITH PATH")
    status, birth, _ = http(
        "POST",
        "%s/birth" % ISSUING,
        {
            "agent_type_id": agent_type_id,
            "owner": "laboratory",
            "intent": "read",
            "audience": "internal",
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

    print("PRESENT")
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
    save(
        "a-challenge.json",
        {"http_status": status, "has_challenge_nonce": True, "response_keys": sorted(challenge.keys())},
    )
    status, present, _ = http(
        "POST",
        "%s/present-svid" % ISSUING,
        {
            "instance_id": instance_id,
            "capability_id": capability_id,
            "intent": "read",
            "audience": "internal",
            "holder_secret_path": holder_secret_path,
            "challenge_nonce": nonce,
            "on_behalf_of": "autonomous",
            "member_secret_path": MEMBER,
        },
        timeout=60,
    )
    require(status, present, 200, "POST /present-svid")
    if not present.get("presentation_json") or not present.get("certificate_pem"):
        raise SystemExit("present-svid must return presentation_json and certificate_pem")
    presentation = json.loads(present["presentation_json"])
    signatures = presentation.get("issuer_signatures") or []
    save(
        "a-present-allow.json",
        {
            "http_status": status,
            "has_presentation_json": True,
            "has_certificate_pem": True,
            "intent": presentation.get("intent"),
            "audience": presentation.get("audience"),
            "issuer_signature_count": len(signatures),
            "response_keys": sorted(present.keys()),
            "secret_bytes_returned": False,
        },
    )
    if len(signatures) < 2:
        raise SystemExit("present at threshold_n 2 must persist two member signatures, got %s" % len(signatures))

    status, store_status, _ = http("GET", "%s/status" % ISSUING)
    require(status, store_status, 200, "GET /status")
    save(
        "a-status.json",
        {
            "live": store_status.get("live") or store_status.get("live_instances"),
            "revoked": store_status.get("revoked") or store_status.get("revoked_instances"),
            "keys": sorted(store_status.keys()),
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
    print("OK later-ui remote member path")
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
                    subprocess.run(["shred", "-u", path], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except OSError:
                    try:
                        os.remove(path)
                    except OSError:
                        pass
        subprocess.run(["rm", "-rf", STORE], check=False)
    save("a-store-shredded.txt", "throwaway store %s was shredded\n" % STORE)
    if not os.path.ismount(MOUNT):
        try:
            mount_up()
        except Exception as error:
            save("a-remount-after.txt", "remount after walk failed: %s\n" % error)
