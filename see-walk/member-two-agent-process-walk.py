#!/usr/bin/env python3
"""Rung 104: agent-process on hostname 5090 with remote member-two, public allow then refuse.

Throwaway issuer. Member two through SSHFS. One on-ramp: present-svid.
Pin only the throwaway public key on https://check.prestigeworldwide.digital.
Start prometheus runtime-check agent-process on this machine, not Hermes.
Holder-sign is local. First tool line ALLOWED and the tool runs.
Decommission + kill-export + public kill-accept.
Same process identifier, no restart: next tool line REFUSED because this store
accepted a kill, and the tool does not run.

Create Agent Principal stays on 127.0.0.1. AgentProcess is not a store.
LaboratoryRuntime still refuses --holder-secret-path. ALLOWED is not cached.
issuer.secret never on the VPC. Standing laptop member-two.secret is not copied.
Do not start a second durable process on another host.
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
STORE = "/tmp/prometheus-member-two-agent-process-20260823"
AGENT = "/tmp/prometheus-member-two-agent-process-run"
WALK = Path("/home/jason/Projects/Prometheus/see-walk/member-two-agent-process")
MEMBER = "/home/jason/Projects/prometheus-lab-vpc/mnt-member-two/member-two.secret"
MOUNT = "/home/jason/Projects/prometheus-lab-vpc/mnt-member-two"
SSHFS = "/home/jason/.local/bin/sshfs"
IDENTITY = "/home/jason/.ssh/rustdesk-hermes.pem"
STANDING_LAPTOP_MEMBER = "/home/jason/Projects/prometheus-lab-vpc/member-two.secret"
STANDING_A = "/home/jason/Projects/Prometheus/data-a/issuer.json"
ISSUING = "http://127.0.0.1:18846"
PUBLIC = "https://check.prestigeworldwide.digital"
AUDIENCE = "check.prestigeworldwide.digital"
PORT = 18846

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
        and "holder secret" not in lower
        and "secret bytes are not opened" not in lower
    ):
        return "refused (secret-looking text redacted)"
    return text


def http(method, url, body=None, timeout=40):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["content-type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode()
            try:
                parsed = json.loads(text) if text else {}
            except json.JSONDecodeError:
                parsed = {"raw": text}
            return resp.status, parsed
    except urllib.error.HTTPError as error:
        raw_text = error.read().decode()
        try:
            parsed = json.loads(raw_text) if raw_text else {}
        except json.JSONDecodeError:
            parsed = {"raw": raw_text}
        return error.code, parsed


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


def wait_contains(path, needle, timeout=40):
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        if os.path.isfile(path):
            last = Path(path).read_text()
            if needle in last:
                return last
        time.sleep(0.2)
    raise SystemExit("timeout waiting for %s in %s. last=%r" % (needle, path, last[:800]))


def stop_agent():
    for name in ("agent-process.pid", "fifo-keeper.pid"):
        pid_path = os.path.join(AGENT, name)
        if os.path.isfile(pid_path):
            try:
                pid = Path(pid_path).read_text().strip()
                if pid.isdigit():
                    subprocess.run(["kill", pid], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except OSError:
                pass


def start_agent(holder_secret_path):
    stop_agent()
    os.makedirs(AGENT, mode=0o700, exist_ok=True)
    for name in (
        "agent-process.in",
        "agent-process.stdout",
        "agent-process.stderr",
        "agent-process.pid",
        "fifo-keeper.pid",
        "tool-allow.txt",
        "tool-after-refuse.txt",
    ):
        path = os.path.join(AGENT, name)
        if os.path.exists(path):
            os.remove(path)
    os.mkfifo(os.path.join(AGENT, "agent-process.in"), 0o600)
    keeper = subprocess.Popen(
        ["bash", "-c", "exec 3<>%s/agent-process.in; while true; do sleep 3600; done" % AGENT],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    Path(os.path.join(AGENT, "fifo-keeper.pid")).write_text(str(keeper.pid) + "\n")
    stdout_f = open(os.path.join(AGENT, "agent-process.stdout"), "w")
    stderr_f = open(os.path.join(AGENT, "agent-process.stderr"), "w")
    stdin_f = open(os.path.join(AGENT, "agent-process.in"), "r")
    proc = subprocess.Popen(
        [
            BIN,
            "runtime-check",
            "agent-process",
            "--base-url",
            PUBLIC,
            "--presentation-json",
            str(WALK / "presentation.json"),
            "--certificate-pem",
            str(WALK / "presentation.json.svid.pem"),
            "--holder-proof-command",
            "%s holder-sign --holder-secret-path %s" % (BIN, holder_secret_path),
        ],
        stdin=stdin_f,
        stdout=stdout_f,
        stderr=stderr_f,
    )
    stdin_f.close()
    stdout_f.close()
    stderr_f.close()
    Path(os.path.join(AGENT, "agent-process.pid")).write_text(str(proc.pid) + "\n")
    time.sleep(0.4)
    if proc.poll() is not None:
        err = Path(os.path.join(AGENT, "agent-process.stderr")).read_text()
        out = Path(os.path.join(AGENT, "agent-process.stdout")).read_text()
        raise SystemExit("agent-process died at start: %s %s" % (out, err))
    return proc


print("PREFLIGHT")
host_name = subprocess.check_output(["hostname"], text=True).strip()
if host_name != "5090":
    raise SystemExit("hostname must be 5090, got %s" % host_name)
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
        "hostname": host_name,
        "data_a_threshold_n": standing_a.get("threshold_n", 1),
        "laptop_member_two_mtime": before_mtime,
        "laptop_member_two_mtime_iso": time.strftime("%Y-%m-%d %H:%M:%S %z", time.localtime(before_mtime)),
    },
)

status, well_known = http("GET", "%s/.well-known/prometheus-check" % PUBLIC, timeout=20)
require(status, well_known, 200, "GET public well-known")
save("public-well-known.json", well_known)
well_known_text = json.dumps(well_known)
if well_known.get("bind") != "check.prestigeworldwide.digital":
    raise SystemExit("public well-known bind must be check.prestigeworldwide.digital")
check_paths = [item.get("path") for item in well_known.get("checks", [])]
if "/check-svid" not in check_paths:
    raise SystemExit("public well-known must name /check-svid")
for write_verb in ("/birth", "/present-svid", "/runtime-check", "issuer.secret"):
    if write_verb in well_known_text:
        raise SystemExit("public well-known still names write verb %s" % write_verb)
status, health = http("GET", "%s/health" % PUBLIC, timeout=20)
require(status, health, 200, "GET public /health")
save("public-health.json", health)

subprocess.run(["rm", "-rf", STORE, AGENT], check=True)
os.makedirs(STORE, mode=0o700)
os.makedirs(AGENT, mode=0o700)

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
agent_proc = None
try:
    for _ in range(80):
        try:
            socket.create_connection(("127.0.0.1", PORT), timeout=0.25).close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        raise SystemExit("issuing host did not bind 127.0.0.1:%s" % PORT)

    status, health = http("GET", "%s/health" % ISSUING)
    require(status, health, 200, "GET /health")
    save("a-health.json", health)

    status, issuer_public = http("GET", "%s/issuer-public" % ISSUING)
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

    print("MEMBER TWO")
    status, member_two = http("POST", "%s/member-two" % ISSUING, {"member_secret_path": MEMBER}, timeout=60)
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
    status, threshold = http(
        "POST",
        "%s/set-issuer-threshold" % ISSUING,
        {"confirm": "issuer-threshold", "n": 2},
    )
    require(status, threshold, 200, "POST /set-issuer-threshold")
    if threshold.get("threshold_n") != 2:
        raise SystemExit("threshold_n must be 2: %s" % threshold)
    save("a-issuer-threshold.json", threshold)

    print("AGENT TYPE")
    status, agent_type = http(
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
    status, no_path = http(
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
    status, birth = http(
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

    print("ISSUER-ACCEPT BEFORE PRESENT")
    status, accept = http("POST", "%s/issuer-accept" % PUBLIC, {"public_key_hex": public_key}, timeout=20)
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
        status, challenge = http(
            "POST",
            "%s/challenge" % ISSUING,
            {"instance_id": instance_id, "member_secret_path": MEMBER},
            timeout=40,
        )
        require(status, challenge, 200, "POST /challenge")
        nonce = challenge.get("challenge_nonce") or challenge.get("nonce")
        if not nonce:
            raise SystemExit("challenge missing nonce: %s" % sorted(challenge.keys()))
        save("a-challenge-present.json", {"challenge_nonce_present": True})
        status, present = http(
            "POST",
            "%s/present-svid" % ISSUING,
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
        require(status, present, 200, "POST /present-svid")
        if not present.get("presentation_json") or not present.get("certificate_pem"):
            raise SystemExit("present-svid must return presentation_json and certificate_pem")
        return present

    print("PRESENT")
    present = mint_present()
    presentation = json.loads(present["presentation_json"])
    signatures = presentation.get("issuer_signatures") or []
    if len(signatures) < 2:
        raise SystemExit("present at threshold_n 2 must persist two member signatures, got %s" % len(signatures))
    (WALK / "presentation.json").write_text(
        present["presentation_json"] if present["presentation_json"].endswith("\n") else present["presentation_json"] + "\n"
    )
    (WALK / "presentation.json.svid.pem").write_text(
        present["certificate_pem"] if present["certificate_pem"].endswith("\n") else present["certificate_pem"] + "\n"
    )
    save(
        "a-present-allow.json",
        {
            "http_status": 200,
            "has_presentation_json": True,
            "has_certificate_pem": True,
            "intent": presentation.get("intent"),
            "audience": presentation.get("audience"),
            "issuer_signature_count": len(signatures),
            "response_keys": sorted(present.keys()),
            "secret_bytes_returned": False,
            "on_ramp": "X.509-SVID",
        },
    )

    print("HOLDER-SECRET-PATH REFUSE")
    refused_runtime = subprocess.run(
        [
            BIN,
            "runtime-check",
            "agent-process",
            "--base-url",
            PUBLIC,
            "--presentation-json",
            str(WALK / "presentation.json"),
            "--certificate-pem",
            str(WALK / "presentation.json.svid.pem"),
            "--holder-secret-path",
            holder_secret_path,
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    refuse_text = (refused_runtime.stdout or "") + "\n" + (refused_runtime.stderr or "")
    if refused_runtime.returncode == 0:
        raise SystemExit("LaboratoryRuntime must refuse --holder-secret-path")
    if "holder secret" not in refuse_text.lower() or "secret bytes are not opened" not in refuse_text.lower():
        raise SystemExit("holder-secret-path refuse must stay fail-closed: %s" % redact(refuse_text[:800]))
    save(
        "a-holder-secret-path-refuse.txt",
        "LaboratoryRuntime refused --holder-secret-path. Secret bytes were not opened. AgentProcess is not a store.\n",
    )

    print("START LOCAL AGENT-PROCESS")
    agent_proc = start_agent(holder_secret_path)
    pid = str(agent_proc.pid)
    save("agent-process.pid", pid + "\n")
    alive = subprocess.check_output(["ps", "-p", pid, "-o", "pid="], text=True).strip()
    if alive != pid:
        raise SystemExit("durable process is not alive after start")
    save(
        "agent-process-start.txt",
        "prometheus runtime-check agent-process started on hostname 5090 pid %s. Not Hermes. Holder-sign is local.\n" % pid,
    )

    print("SEND ALLOW TOOL")
    with open(os.path.join(AGENT, "agent-process.in"), "w") as fifo:
        fifo.write("echo TOOL_RAN > %s/tool-allow.txt\n" % AGENT)
    stdout_allow = wait_contains(os.path.join(AGENT, "agent-process.stdout"), "ALLOWED", timeout=35)
    stderr_allow = Path(os.path.join(AGENT, "agent-process.stderr")).read_text() if os.path.isfile(os.path.join(AGENT, "agent-process.stderr")) else ""
    if "expir" in (stdout_allow + stderr_allow).lower() and "ALLOWED" not in stdout_allow:
        print("ALLOW expired, remint once")
        stop_agent()
        if agent_proc is not None:
            agent_proc.wait(timeout=5)
        present = mint_present()
        presentation = json.loads(present["presentation_json"])
        (WALK / "presentation.json").write_text(
            present["presentation_json"] if present["presentation_json"].endswith("\n") else present["presentation_json"] + "\n"
        )
        (WALK / "presentation.json.svid.pem").write_text(
            present["certificate_pem"] if present["certificate_pem"].endswith("\n") else present["certificate_pem"] + "\n"
        )
        agent_proc = start_agent(holder_secret_path)
        pid = str(agent_proc.pid)
        save("agent-process.pid", pid + "\n")
        with open(os.path.join(AGENT, "agent-process.in"), "w") as fifo:
            fifo.write("echo TOOL_RAN > %s/tool-allow.txt\n" % AGENT)
        stdout_allow = wait_contains(os.path.join(AGENT, "agent-process.stdout"), "ALLOWED", timeout=35)
        stderr_allow = Path(os.path.join(AGENT, "agent-process.stderr")).read_text()
    save("agent-process-allow.stdout", stdout_allow)
    save("agent-process-allow.stderr", redact(stderr_allow))
    if "REFUSED" in stdout_allow.splitlines()[:1]:
        raise SystemExit("first act refused: %s %s" % (stdout_allow, redact(stderr_allow)))
    if "ALLOWED" not in stdout_allow:
        raise SystemExit("first act must print ALLOWED: %s %s" % (stdout_allow, redact(stderr_allow)))
    if not os.path.isfile(os.path.join(AGENT, "tool-allow.txt")):
        raise SystemExit("tool did not run on hostname 5090")
    tool_check = Path(os.path.join(AGENT, "tool-allow.txt")).read_text()
    save("tool-allow.txt", tool_check)
    if "TOOL_RAN" not in tool_check:
        raise SystemExit("tool marker missing")
    pid_after_allow = subprocess.check_output(["ps", "-p", pid, "-o", "pid="], text=True).strip()
    if pid_after_allow != pid:
        raise SystemExit("process died after ALLOWED. expected pid %s" % pid)
    save(
        "agent-process-allow-summary.json",
        {
            "gate": "ALLOWED",
            "pid": pid,
            "pid_still_alive": True,
            "tool_ran": True,
            "tool_marker": tool_check.strip(),
            "on_ramp": "X.509-SVID",
            "hostname": "5090",
            "not_hermes": True,
        },
    )

    print("KILL")
    kill_body = {"instance_id": instance_id, "confirm": instance_id, "member_secret_path": MEMBER}
    status, killed = http("POST", "%s/kill" % ISSUING, kill_body, timeout=60)
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
    status, exported = http("POST", "%s/kill-export" % ISSUING, kill_body, timeout=60)
    require(status, exported, 200, "POST /kill-export")
    save("kill-export-keys.json", {"keys": sorted(exported.keys()) if isinstance(exported, dict) else []})
    event = exported["event"]
    proof = exported["proof"]
    tree_head = exported["tree_head"]
    save("kill-event.json", event)
    save("kill-proof.json", proof)
    save("kill-tree-head.json", tree_head)

    print("KILL-ACCEPT")
    status, kill_accept = http(
        "POST",
        "%s/kill-accept" % PUBLIC,
        {"event": event, "proof": proof, "tree_head": tree_head},
        timeout=20,
    )
    require(status, kill_accept, 200, "public POST /kill-accept")
    accepted_ids = kill_accept.get("accepted_killed_instance_ids") or []
    save(
        "public-kill-accept.json",
        {
            "http_status": status,
            "accepted_killed_instance_ids": accepted_ids,
            "accepted_killed_capability_ids": kill_accept.get("accepted_killed_capability_ids"),
            "keys": sorted(kill_accept.keys()) if isinstance(kill_accept, dict) else [],
            "includes_this_instance": instance_id in accepted_ids,
        },
    )
    if instance_id not in accepted_ids:
        raise SystemExit("accepted kill list must include this instance")

    print("SEND REFUSE TOOL SAME PID")
    pid_before_refuse = subprocess.check_output(["ps", "-p", pid, "-o", "pid="], text=True).strip()
    if pid_before_refuse != pid:
        raise SystemExit("process died before second tool. expected %s" % pid)
    with open(os.path.join(AGENT, "agent-process.in"), "w") as fifo:
        fifo.write("echo TOOL_RAN_AFTER_REFUSE > %s/tool-after-refuse.txt\n" % AGENT)
    stdout_all = wait_contains(os.path.join(AGENT, "agent-process.stdout"), "REFUSED", timeout=35)
    stderr_all = Path(os.path.join(AGENT, "agent-process.stderr")).read_text() if os.path.isfile(os.path.join(AGENT, "agent-process.stderr")) else ""
    save("agent-process-after-decommission.stdout", stdout_all)
    save("agent-process-after-decommission.stderr", redact(stderr_all))
    lines = [line for line in stdout_all.splitlines() if line.strip()]
    if lines[-1:] != ["REFUSED"]:
        raise SystemExit("second act must print REFUSED last. stdout=%r" % stdout_all)
    pid_after_refuse = subprocess.check_output(["ps", "-p", pid, "-o", "pid="], text=True).strip()
    if pid_after_refuse != pid:
        raise SystemExit("process pid changed or died. expected %s got %s" % (pid, pid_after_refuse))
    if os.path.isfile(os.path.join(AGENT, "tool-after-refuse.txt")):
        raise SystemExit("tool ran after refuse")
    refuse_text = stdout_all + "\n" + stderr_all
    if not refuse_names_accepted_kill(refuse_text):
        raise SystemExit("refuse reason must be accepted kill, not expiry. got: %s" % redact(refuse_text[:800]))
    if "holder proof command did not write" in refuse_text.lower() or "a holder signature is required" in refuse_text.lower():
        raise SystemExit("refuse reason must be accepted kill, not a missing holder signature")
    save("tool-after-refuse.missing", "The tool file is missing. The tool did not run after REFUSED.\n")
    save(
        "agent-process-after-decommission-summary.json",
        {
            "gate": "REFUSED",
            "pid": pid,
            "same_pid": True,
            "restarted": False,
            "tool_ran": False,
            "tool_marker": "missing",
            "on_ramp": "X.509-SVID",
            "hostname": "5090",
            "reason": "this store accepted a kill",
        },
    )

    with open(os.path.join(AGENT, "agent-process.in"), "w") as fifo:
        fifo.write("stop\n")
    time.sleep(0.4)

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
    if os.path.isfile(os.path.join(MOUNT, "issuer.secret")):
        raise SystemExit("issuer.secret must not be on the mount")
    save(
        "a-custody-locks.json",
        {
            "standing_data_a_threshold_n": standing_after.get("threshold_n", 1),
            "laptop_member_two_mtime_unchanged": True,
            "vpc_issuer_secret_count": issuer_count,
            "vpc_custody_file_count": custody_files,
            "sshfs_mounted": os.path.ismount(MOUNT),
            "mount_issuer_secret_present": False,
            "agent_process_is_not_a_store": True,
            "hermes_not_started": True,
        },
    )
    save(
        "SEE.txt",
        """Agent process on hostname 5090 with remote member-two public allow then refuse

Date: 23 August 2026 20:20 America/Chicago

This folder is for Jason Gale. These files are public records and artifacts. This folder does not contain issuer.secret, biscuit.secret, holder secrets, or member-two secrets. The issuing store lived under /tmp/prometheus-member-two-agent-process-20260823 and was shredded after this walk.

Create Agent Principal ran on the operator machine and bound 127.0.0.1:18846 only. The X.509-SVID Assertion Act was minted on that issuing store with member_secret_path on the SSHFS mount of ubuntu@10.43.1.186:/home/ubuntu/member-two-custody. The durable agent process ran on hostname 5090. The process did not run on Hermes. The verifier is https://check.prestigeworldwide.digital. AgentProcess is not a store. LaboratoryRuntime still refuses --holder-secret-path. Holder-sign ran locally.

POST /member-two wrote member two through that mount. Secret bytes were not returned. The standing laptop member-two.secret was not copied. issuer.secret stayed on the issuing computer. POST /set-issuer-threshold set threshold_n to 2 on this throwaway issuer only. POST /birth without member_secret_path returned 403. POST /birth and POST /present-svid with the remote path returned 200 and two issuer member signatures.

POST /issuer-accept pinned this throwaway public key only. prometheus runtime-check agent-process stayed up as one process identifier. The first tool line printed ALLOWED and ran the tool. After Decommission, POST /kill-export, and public POST /kill-accept, a second tool line on that same process identifier printed REFUSED because this store accepted a kill, not because of expiry. The tool did not run. The process did not restart. ALLOWED is not cached.

The throwaway store was shredded. The VPC custody directory was left in place. Standing data-a threshold_n stayed 1. VPC issuer.secret count stayed 0. Rust was not changed.

This is not a public listener for birth. This is not SPIRE. This is not a replica. This is not a sixth identity record. This is not Sanctum.
""",
    )
    print("WALK_OK pid", pid)
finally:
    try:
        with open(os.path.join(AGENT, "agent-process.in"), "w") as fifo:
            fifo.write("stop\n")
    except OSError:
        pass
    stop_agent()
    if agent_proc is not None:
        try:
            agent_proc.wait(timeout=3)
        except Exception:
            agent_proc.kill()
    host.terminate()
    try:
        host.wait(timeout=5)
    except subprocess.TimeoutExpired:
        host.kill()
        host.wait(timeout=5)
    save("a-host-stopped.txt", "issuing host on 127.0.0.1:%s is stopped. Local agent-process is stopped.\n" % PORT)
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
    subprocess.run(["rm", "-rf", AGENT], check=False)
    save("a-store-shredded.txt", "throwaway store %s was shredded. Agent run directory was removed.\n" % STORE)
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
