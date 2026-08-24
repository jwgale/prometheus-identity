from pathlib import Path
import json, os, socket, subprocess, time, urllib.request, urllib.error

BIN = "/home/jason/Projects/Prometheus/target/release/prometheus"
STORE = "/tmp/prometheus-public-add-act-wimse-child-a"
WALK = Path("/home/jason/Projects/Prometheus/see-walk/public-add-act-wimse-child")
ISSUING = "http://127.0.0.1:18801"
PUBLIC = "https://check.prestigeworldwide.digital"
PORT = 18801
SSH = [
    "ssh",
    "-o",
    "ConnectTimeout=12",
    "-o",
    "BatchMode=yes",
    "-i",
    "/home/jason/.ssh/rustdesk-hermes.pem",
    "ubuntu@52.91.253.34",
]
SCP = [
    "scp",
    "-o",
    "ConnectTimeout=12",
    "-o",
    "BatchMode=yes",
    "-i",
    "/home/jason/.ssh/rustdesk-hermes.pem",
]
REMOTE = "/var/lib/prometheus-agent"
PARENT_AUDIENCE = "check.prestigeworldwide.digital"
WIDER_AUDIENCE = "check.prestigeworldwide"
NARROWER_AUDIENCE = "check.prestigeworldwide.digital/child"
WALK.mkdir(parents=True, exist_ok=True)
subprocess.run(["rm", "-rf", STORE], check=True)
os.makedirs(STORE, mode=0o700)


def save(name, obj):
    path = WALK / name
    if isinstance(obj, (dict, list)):
        path.write_text(json.dumps(obj, indent=2) + "\n")
    else:
        path.write_text(str(obj))


def http(method, url, body=None, timeout=25):
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
        raw = error.read().decode()
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"raw": raw}
        return error.code, parsed


def remote(command, timeout=40):
    return subprocess.run(SSH + [command], capture_output=True, text=True, timeout=timeout)


def remote_check(command, timeout=40):
    result = remote(command, timeout=timeout)
    if result.returncode != 0:
        raise SystemExit(
            "remote failed: %s\nstdout=%s\nstderr=%s"
            % (command, result.stdout, result.stderr)
        )
    return result.stdout


def wait_remote_last_gate(expected, timeout=40):
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        last = remote_check("cat %s/agent-process.stdout 2>/dev/null || true" % REMOTE, timeout=20)
        lines = [line for line in last.splitlines() if line.strip()]
        if lines and lines[-1] == expected:
            return last
        time.sleep(0.25)
    raise SystemExit("timeout waiting for last gate %s. last=%r" % (expected, last))


def require_same_pid(pid, when):
    alive = remote_check("ps -p %s -o pid=" % pid).strip()
    if alive != pid:
        stderr = remote_check("cat %s/agent-process.stderr 2>/dev/null || true" % REMOTE)
        raise SystemExit("process pid changed or died %s. expected %s. stderr=%s" % (when, pid, stderr))


print("INIT")
subprocess.check_output([BIN, "--data-directory", STORE, "init"], text=True)
save(
    "a-init-note.txt",
    "init ran on this machine. Secret files stay under /tmp/prometheus-public-add-act-wimse-child-a.\n",
)
host = subprocess.Popen(
    [BIN, "--data-directory", STORE, "host", "--listen-address", "127.0.0.1:%s" % PORT],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
try:
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", PORT), timeout=0.25).close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        raise SystemExit("issuing host did not bind")

    status, health = http("GET", "%s/health" % ISSUING)
    assert status == 200, health
    save("a-health.json", health)

    status, agent = http(
        "POST",
        "%s/agent-type" % ISSUING,
        {
            "owner": "jason-gale",
            "allowed_intents": ["read"],
            "authorization_limit": "check.prestigeworldwide.digital",
        },
    )
    print("AGENT-TYPE", status)
    assert status == 200, agent
    save("a-agent-type.json", agent)

    status, birth = http(
        "POST",
        "%s/birth" % ISSUING,
        {
            "agent_type_id": agent["agent_type_id"],
            "owner": "jason-gale",
            "intent": "read",
            "audience": PARENT_AUDIENCE,
            "on_behalf_of": "autonomous",
        },
    )
    print("BIRTH", status)
    assert status == 200, birth
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

    status, issuer = http("GET", "%s/issuer-public" % ISSUING)
    print("ISSUER-PUBLIC", status, list(issuer))
    assert status == 200, issuer
    save("a-issuer-public-keys.json", {"keys": sorted(issuer.keys())})
    key = issuer.get("current_issuer_public_key_hex") or issuer.get("public_key_hex")
    if not key:
        raise SystemExit("no public key in %s" % list(issuer))
    save("a-issuer-public-key-length.txt", "public_key_hex_length=%s\n" % len(key))
    status, accept = http("POST", "%s/issuer-accept" % PUBLIC, {"public_key_hex": key})
    print("ISSUER-ACCEPT", status, accept if status != 200 else list(accept))
    assert status == 200, accept
    save(
        "public-issuer-accept.json",
        {
            "http_status": status,
            "request_keys": ["public_key_hex"],
            "response_keys": sorted(accept.keys()) if isinstance(accept, dict) else [],
        },
    )

    status, well_known = http("GET", "%s/.well-known/prometheus-check" % PUBLIC)
    print("WELL-KNOWN", status, list(well_known) if isinstance(well_known, dict) else well_known)
    assert status == 200, well_known
    save("live-prometheus-check.json", well_known)
    well_known_text = json.dumps(well_known)
    if well_known.get("bind") != "check.prestigeworldwide.digital":
        raise SystemExit("public well-known bind must be check.prestigeworldwide.digital")
    check_paths = [item.get("path") for item in well_known.get("checks", [])]
    if "/check-svid" not in check_paths or "/check-wimse" not in check_paths:
        raise SystemExit("public well-known must name /check-svid and /check-wimse")
    if well_known.get("verifier_challenge", {}).get("path") != "/verifier-challenge":
        raise SystemExit("public well-known must name POST /verifier-challenge")
    for write_verb in (
        "/birth",
        "/spawn",
        "/present-svid",
        "/present-wimse",
        "/seal-export",
        "/previous-key-export",
    ):
        if write_verb in well_known_text:
            raise SystemExit("public well-known still names write verb %s" % write_verb)

    print("SCP BINARY")
    subprocess.check_call(SCP + [BIN, "ubuntu@52.91.253.34:%s/prometheus" % REMOTE])

    status, challenge = http("POST", "%s/challenge" % ISSUING, {"instance_id": instance_id})
    print("CHALLENGE", status)
    assert status == 200, challenge
    status, svid = http(
        "POST",
        "%s/present-svid" % ISSUING,
        {
            "instance_id": instance_id,
            "capability_id": capability_id,
            "holder_secret_path": holder_secret_path,
            "challenge_nonce": challenge["challenge_nonce"],
            "intent": "read",
            "audience": PARENT_AUDIENCE,
            "on_behalf_of": "autonomous",
        },
    )
    print("PRESENT-SVID", status, svid if status != 200 else sorted(svid.keys()))
    assert status == 200, svid
    (WALK / "presentation.json").write_text(svid["presentation_json"])
    (WALK / "presentation.json.svid.pem").write_text(svid["certificate_pem"])
    save("a-present-svid-keys.json", {"keys": sorted(svid.keys())})

    subprocess.check_call(
        SCP + [str(WALK / "presentation.json"), "ubuntu@52.91.253.34:%s/presentation.json" % REMOTE]
    )
    subprocess.check_call(
        SCP
        + [
            str(WALK / "presentation.json.svid.pem"),
            "ubuntu@52.91.253.34:%s/presentation.json.svid.pem" % REMOTE,
        ]
    )
    subprocess.check_call(
        SCP + [holder_secret_path, "ubuntu@52.91.253.34:%s/holder.secret" % REMOTE]
    )
    start_script = r"""#!/bin/bash
set -euo pipefail
REMOTE=/var/lib/prometheus-agent
if [ -f "$REMOTE/agent-process.pid" ]; then kill "$(cat "$REMOTE/agent-process.pid")" 2>/dev/null || true; fi
if [ -f "$REMOTE/fifo-keeper.pid" ]; then kill "$(cat "$REMOTE/fifo-keeper.pid")" 2>/dev/null || true; fi
rm -f "$REMOTE/agent-process.in" "$REMOTE/agent-process.stdout" "$REMOTE/agent-process.stderr" \
  "$REMOTE/agent-process.pid" "$REMOTE/fifo-keeper.pid" \
  "$REMOTE/tool-allow.txt" "$REMOTE/tool-after-add.txt" "$REMOTE/tool-after-refuse.txt"
mkfifo "$REMOTE/agent-process.in"
chmod 600 "$REMOTE/agent-process.in"
nohup bash -c "exec 3<>$REMOTE/agent-process.in; while true; do sleep 3600; done" >/dev/null 2>&1 &
echo $! > "$REMOTE/fifo-keeper.pid"
nohup "$REMOTE/prometheus" runtime-check agent-process \
  --base-url https://check.prestigeworldwide.digital \
  --presentation-json "$REMOTE/presentation.json" \
  --certificate-pem "$REMOTE/presentation.json.svid.pem" \
  --holder-proof-command "$REMOTE/prometheus holder-sign --holder-secret-path $REMOTE/holder.secret" \
  < "$REMOTE/agent-process.in" > "$REMOTE/agent-process.stdout" 2> "$REMOTE/agent-process.stderr" &
echo $! > "$REMOTE/agent-process.pid"
sleep 0.5
ps -p "$(cat $REMOTE/agent-process.pid)" -o pid=,cmd=
"""
    (WALK / "hermes-start-add-act-wimse-child.sh").write_text(start_script)
    subprocess.check_call(
        SCP
        + [
            str(WALK / "hermes-start-add-act-wimse-child.sh"),
            "ubuntu@52.91.253.34:%s/hermes-start-add-act-wimse-child.sh" % REMOTE,
        ]
    )
    subprocess.check_call(
        SSH
        + [
            "chmod 755 %s/prometheus %s/hermes-start-add-act-wimse-child.sh && chmod 600 %s/holder.secret && chmod 644 %s/presentation.json %s/presentation.json.svid.pem"
            % (REMOTE, REMOTE, REMOTE, REMOTE, REMOTE)
        ]
    )
    listing = subprocess.check_output(
        SSH
        + [
            "ls -l %s && echo --- && test ! -e %s/issuer.secret && test ! -e %s/biscuit.secret && echo no-issuer-secret no-biscuit-secret && stat -c 'holder.secret mode=%%a' %s/holder.secret"
            % (REMOTE, REMOTE, REMOTE, REMOTE)
        ],
        text=True,
    )
    save("hermes-remote-ls.txt", listing)
    if "issuer.secret" in listing.split("no-issuer-secret")[0]:
        raise SystemExit("issuer.secret must not be on Hermes")
    if "holder.secret mode=600" not in listing:
        raise SystemExit("holder.secret must be mode 600 on Hermes")
    save(
        "hermes-copy-note.txt",
        "Copied prometheus binary, parent presentation.json, laboratory X.509-SVID wrap, and holder.secret to Hermes /var/lib/prometheus-agent. Did not copy issuer.secret. Did not copy biscuit.secret.\n",
    )

    print("START DURABLE PROCESS")
    start = remote("bash %s/hermes-start-add-act-wimse-child.sh" % REMOTE, timeout=25)
    print("START", start.returncode, start.stdout, start.stderr)
    if start.returncode != 0:
        raise SystemExit("failed to start durable agent process on Hermes")
    pid_text = remote_check("cat %s/agent-process.pid" % REMOTE).strip()
    if not pid_text.isdigit():
        raise SystemExit("missing agent process pid: %r" % pid_text)
    pid = pid_text
    save("hermes-agent-process.pid", pid + "\n")
    save("hermes-agent-process-start.txt", start.stdout + start.stderr)
    require_same_pid(pid, "after start")

    print("SEND ALLOW TOOL")
    send_allow = remote(
        "echo 'echo TOOL_RAN > %s/tool-allow.txt' > %s/agent-process.in" % (REMOTE, REMOTE)
    )
    if send_allow.returncode != 0:
        raise SystemExit("failed to send first tool line: %s" % send_allow.stderr)
    stdout_allow = wait_remote_last_gate("ALLOWED", timeout=35)
    stderr_allow = remote_check("cat %s/agent-process.stderr 2>/dev/null || true" % REMOTE)
    save("hermes-agent-process-allow.stdout", stdout_allow)
    save("hermes-agent-process-allow.stderr", stderr_allow)
    tool_check = remote_check("test -f %s/tool-allow.txt && cat %s/tool-allow.txt" % (REMOTE, REMOTE))
    save("hermes-tool-allow.txt", tool_check)
    if "TOOL_RAN" not in tool_check:
        raise SystemExit("tool did not run on Hermes")
    require_same_pid(pid, "after first ALLOWED")
    save(
        "hermes-agent-process-allow-summary.json",
        {
            "gate": "ALLOWED",
            "pid": pid,
            "pid_still_alive": True,
            "tool_ran": True,
            "tool_marker": tool_check.strip(),
            "held_acts": "parent X.509-SVID",
        },
    )

    status, spawn_challenge = http("POST", "%s/challenge" % ISSUING, {"instance_id": instance_id})
    print("SPAWN-CHALLENGE", status)
    assert status == 200, spawn_challenge
    wider_request = {
        "parent_instance_id": instance_id,
        "parent_capability_id": capability_id,
        "owner": "jason-gale",
        "intent": "read",
        "audience": WIDER_AUDIENCE,
        "holder_secret_path": holder_secret_path,
        "challenge_nonce": spawn_challenge["challenge_nonce"],
        "on_behalf_of": "autonomous",
    }
    status, wider = http("POST", "%s/spawn" % ISSUING, wider_request)
    print("SPAWN WIDER", status)
    if status == 200:
        raise SystemExit("wider spawn must refuse")
    save("spawn-wider-refuse.json", wider)
    wider_text = json.dumps(wider)
    if "exceeds" not in wider_text and "cannot gain rights" not in wider_text:
        raise SystemExit("wider spawn refuse must name a wider child: %s" % wider)
    status, instances_after_wider = http("GET", "%s/instances" % ISSUING)
    assert status == 200, instances_after_wider
    save("instances-after-wider.json", {"count": len(instances_after_wider.get("instances", []))})
    if len(instances_after_wider.get("instances", [])) != 1:
        raise SystemExit("wider spawn must not write a child")

    status, narrow_challenge = http("POST", "%s/challenge" % ISSUING, {"instance_id": instance_id})
    print("NARROW-CHALLENGE", status)
    assert status == 200, narrow_challenge
    status, spawn = http(
        "POST",
        "%s/spawn" % ISSUING,
        {
            "parent_instance_id": instance_id,
            "parent_capability_id": capability_id,
            "owner": "jason-gale",
            "intent": "read",
            "audience": NARROWER_AUDIENCE,
            "holder_secret_path": holder_secret_path,
            "challenge_nonce": narrow_challenge["challenge_nonce"],
            "on_behalf_of": "autonomous",
        },
    )
    print("SPAWN NARROWER", status, spawn if status != 200 else list(spawn))
    assert status == 200, spawn
    save(
        "spawn.json",
        {
            "instance_id": spawn["instance_id"],
            "capability_id": spawn["capability_id"],
            "holder_secret_path_present": "holder_secret_path" in spawn,
            "response_keys": sorted(spawn.keys()),
        },
    )
    child_instance_id = spawn["instance_id"]
    child_capability_id = spawn["capability_id"]
    child_holder_secret_path = spawn["holder_secret_path"]

    status, child_challenge = http(
        "POST", "%s/challenge" % ISSUING, {"instance_id": child_instance_id}
    )
    print("CHILD-CHALLENGE", status)
    assert status == 200, child_challenge
    status, child_wimse = http(
        "POST",
        "%s/present-wimse" % ISSUING,
        {
            "instance_id": child_instance_id,
            "capability_id": child_capability_id,
            "holder_secret_path": child_holder_secret_path,
            "challenge_nonce": child_challenge["challenge_nonce"],
            "intent": "read",
            "audience": NARROWER_AUDIENCE,
            "on_behalf_of": "autonomous",
        },
    )
    print("CHILD-PRESENT-WIMSE", status, child_wimse if status != 200 else sorted(child_wimse.keys()))
    assert status == 200, child_wimse
    (WALK / "child-presentation.json").write_text(child_wimse["presentation_json"])
    (WALK / "child-workload_identity_token").write_text(child_wimse["workload_identity_token"])
    (WALK / "child-content_digest").write_text(child_wimse["content_digest"])
    (WALK / "child-signature_input").write_text(child_wimse["signature_input"])
    (WALK / "child-signature").write_text(child_wimse["signature"])
    save(
        "a-child-present-wimse-keys.json",
        {
            "keys": sorted(child_wimse.keys()),
            "token_length": len(child_wimse["workload_identity_token"]),
            "content_digest_present": bool(child_wimse.get("content_digest")),
            "signature_input_present": bool(child_wimse.get("signature_input")),
            "signature_present": bool(child_wimse.get("signature")),
        },
    )
    for name in (
        "child-presentation.json",
        "child-workload_identity_token",
        "child-content_digest",
        "child-signature_input",
        "child-signature",
    ):
        subprocess.check_call(
            SCP + [str(WALK / name), "ubuntu@52.91.253.34:%s/%s" % (REMOTE, name)]
        )
    subprocess.check_call(
        SCP + [child_holder_secret_path, "ubuntu@52.91.253.34:%s/child-holder.secret" % REMOTE]
    )
    subprocess.check_call(
        SSH
        + [
            "chmod 600 %s/child-holder.secret && chmod 644 %s/child-presentation.json %s/child-workload_identity_token %s/child-content_digest %s/child-signature_input %s/child-signature"
            % (REMOTE, REMOTE, REMOTE, REMOTE, REMOTE, REMOTE)
        ]
    )
    save(
        "hermes-child-copy-note.txt",
        "Copied child presentation.json, WIMSE token, content-digest, HTTP Message Signature, and child-holder.secret to Hermes. Did not copy issuer.secret.\n",
    )

    print("SEND FAIL-CLOSED MIX ADD")
    mix_line = (
        "add-act --presentation-json %s/presentation.json --certificate-pem %s/presentation.json.svid.pem "
        "--workload-identity-token %s/child-workload_identity_token --content-digest x --signature-input y --signature z"
        % (REMOTE, REMOTE, REMOTE)
    )
    send_mix = remote("echo '%s' > %s/agent-process.in" % (mix_line, REMOTE))
    if send_mix.returncode != 0:
        raise SystemExit("failed to send mix add-act: %s" % send_mix.stderr)
    stdout_mix = wait_remote_last_gate("REFUSED", timeout=20)
    stderr_mix = remote_check("cat %s/agent-process.stderr 2>/dev/null || true" % REMOTE)
    save("hermes-add-act-mix.stdout", stdout_mix)
    save("hermes-add-act-mix.stderr", stderr_mix)
    if "mix" not in stderr_mix.lower() and "on-ramp" not in stderr_mix.lower():
        raise SystemExit("mix add-act must name the on-ramp mix: %s" % stderr_mix)
    require_same_pid(pid, "after mix add-act refuse")

    print("SEND FAIL-CLOSED HOLDER-SECRET ADD")
    secret_line = (
        "add-act --presentation-json %s/child-presentation.json --workload-identity-token %s/child-workload_identity_token "
        "--content-digest @%s/child-content_digest --signature-input @%s/child-signature_input --signature @%s/child-signature "
        "--holder-secret-path %s/child-holder.secret"
        % (REMOTE, REMOTE, REMOTE, REMOTE, REMOTE, REMOTE)
    )
    send_secret = remote("echo '%s' > %s/agent-process.in" % (secret_line, REMOTE))
    if send_secret.returncode != 0:
        raise SystemExit("failed to send holder-secret add-act: %s" % send_secret.stderr)
    stdout_secret = wait_remote_last_gate("REFUSED", timeout=20)
    stderr_secret = remote_check("cat %s/agent-process.stderr 2>/dev/null || true" % REMOTE)
    save("hermes-add-act-holder-secret.stdout", stdout_secret)
    save("hermes-add-act-holder-secret.stderr", stderr_secret)
    if "holder" not in stderr_secret.lower() and "secret" not in stderr_secret.lower():
        raise SystemExit("holder-secret add-act must refuse the holder secret path: %s" % stderr_secret)
    require_same_pid(pid, "after holder-secret add-act refuse")

    print("SEND HONEST WIMSE CHILD ADD-ACT")
    add_script = r"""#!/bin/bash
set -euo pipefail
REMOTE=/var/lib/prometheus-agent
printf '%s\n' "add-act --presentation-json $REMOTE/child-presentation.json --workload-identity-token $REMOTE/child-workload_identity_token --content-digest @$REMOTE/child-content_digest --signature-input @$REMOTE/child-signature_input --signature @$REMOTE/child-signature --holder-proof-command \"$REMOTE/prometheus holder-sign --holder-secret-path $REMOTE/child-holder.secret\"" > "$REMOTE/agent-process.in"
"""
    (WALK / "hermes-send-wimse-child-add-act.sh").write_text(add_script)
    subprocess.check_call(
        SCP
        + [
            str(WALK / "hermes-send-wimse-child-add-act.sh"),
            "ubuntu@52.91.253.34:%s/hermes-send-wimse-child-add-act.sh" % REMOTE,
        ]
    )
    send_add = remote("bash %s/hermes-send-wimse-child-add-act.sh" % REMOTE)
    if send_add.returncode != 0:
        raise SystemExit("failed to send honest WIMSE child add-act: %s" % send_add.stderr)
    stdout_added = wait_remote_last_gate("ADDED", timeout=20)
    stderr_added = remote_check("cat %s/agent-process.stderr 2>/dev/null || true" % REMOTE)
    save("hermes-add-act.stdout", stdout_added)
    save("hermes-add-act.stderr", stderr_added)
    save("add-act-honest.line", "used @-files for WIMSE signature-input, signature, and content-digest\n")
    require_same_pid(pid, "after honest WIMSE child add-act")
    save(
        "hermes-add-act-summary.json",
        {
            "gate": "ADDED",
            "pid": pid,
            "same_pid": True,
            "added": "child WIMSE",
        },
    )

    print("SEND ALLOW TOOL AFTER ADD")
    send_after_add = remote(
        "echo 'echo TOOL_RAN_AFTER_ADD > %s/tool-after-add.txt' > %s/agent-process.in"
        % (REMOTE, REMOTE)
    )
    if send_after_add.returncode != 0:
        raise SystemExit("failed to send after-add tool line: %s" % send_after_add.stderr)
    stdout_after_add = wait_remote_last_gate("ALLOWED", timeout=35)
    stderr_after_add = remote_check("cat %s/agent-process.stderr 2>/dev/null || true" % REMOTE)
    save("hermes-agent-process-after-add.stdout", stdout_after_add)
    save("hermes-agent-process-after-add.stderr", stderr_after_add)
    tool_after_add = remote_check(
        "test -f %s/tool-after-add.txt && cat %s/tool-after-add.txt" % (REMOTE, REMOTE)
    )
    save("hermes-tool-after-add.txt", tool_after_add)
    if "TOOL_RAN_AFTER_ADD" not in tool_after_add:
        raise SystemExit("tool did not run on Hermes after WIMSE child add-act: %s %s" % (stdout_after_add, stderr_after_add))
    require_same_pid(pid, "after WIMSE child add-act ALLOWED")
    save(
        "hermes-agent-process-after-add-summary.json",
        {
            "gate": "ALLOWED",
            "pid": pid,
            "same_pid": True,
            "tool_ran": True,
            "tool_marker": tool_after_add.strip(),
            "held_acts": "parent X.509-SVID + child WIMSE",
        },
    )

    status, killed = http(
        "POST",
        "%s/kill" % ISSUING,
        {"instance_id": instance_id, "confirm": instance_id},
    )
    print("KILL PARENT", status)
    assert status == 200, killed
    save("a-kill.json", {"instance_id": killed.get("instance_id"), "status": killed.get("status")})
    status, exported = http(
        "POST",
        "%s/kill-export" % ISSUING,
        {"instance_id": instance_id, "confirm": instance_id},
    )
    print("KILL-EXPORT", status, list(exported) if isinstance(exported, dict) else exported)
    assert status == 200, exported
    save("kill-export-keys.json", {"keys": sorted(exported.keys())})
    status, accepted = http("POST", "%s/kill-accept" % PUBLIC, exported)
    print("KILL-ACCEPT", status, accepted)
    assert status == 200, accepted
    save("public-kill-accept.json", accepted)

    print("SEND REFUSE TOOL SAME PID")
    send_refuse = remote(
        "echo 'echo TOOL_RAN_AFTER_REFUSE > %s/tool-after-refuse.txt' > %s/agent-process.in"
        % (REMOTE, REMOTE)
    )
    if send_refuse.returncode != 0:
        raise SystemExit("failed to send refuse tool line: %s" % send_refuse.stderr)
    stdout_refuse = wait_remote_last_gate("REFUSED", timeout=35)
    stderr_refuse = remote_check("cat %s/agent-process.stderr 2>/dev/null || true" % REMOTE)
    save("hermes-agent-process-after-decommission.stdout", stdout_refuse)
    save("hermes-agent-process-after-decommission.stderr", stderr_refuse)
    require_same_pid(pid, "after parent Decommission refuse")
    missing = remote("test ! -f %s/tool-after-refuse.txt" % REMOTE)
    if missing.returncode != 0:
        raise SystemExit("tool ran on Hermes after refuse")
    refuse_text = stdout_refuse + "\n" + stderr_refuse
    refuse_lower = refuse_text.lower()
    if "accepted a kill" not in refuse_lower and "kill accept" not in refuse_lower:
        raise SystemExit(
            "refuse reason must be accepted kill, not a missing holder signature. got: %s"
            % refuse_text
        )
    if "holder proof command did not write" in refuse_lower or "a holder signature is required" in refuse_lower:
        raise SystemExit(
            "refuse reason must be accepted kill, not a missing holder signature. got: %s"
            % refuse_text
        )
    save(
        "hermes-tool-after-refuse.missing",
        "The tool file is missing on Hermes. The tool did not run after REFUSED.\n",
    )
    save(
        "hermes-agent-process-after-decommission-summary.json",
        {
            "gate": "REFUSED",
            "pid": pid,
            "same_pid": True,
            "tool_ran": False,
            "tool_marker": "missing",
            "held_acts": "parent X.509-SVID + child WIMSE",
            "reason": stderr_refuse.strip() or stdout_refuse.strip(),
        },
    )

    remote("echo stop > %s/agent-process.in || true" % REMOTE)
    time.sleep(0.4)
    remote(
        "if [ -f %s/agent-process.pid ]; then kill $(cat %s/agent-process.pid) 2>/dev/null || true; fi; if [ -f %s/fifo-keeper.pid ]; then kill $(cat %s/fifo-keeper.pid) 2>/dev/null || true; fi"
        % (REMOTE, REMOTE, REMOTE, REMOTE)
    )

    save(
        "SEE.txt",
        """Public add-act WIMSE child durable agent process walk

Date: 23 August 2026.

This folder is for Jason Gale. These files are public records and artifacts. This folder does not contain issuer.secret, biscuit.secret, holder secrets, or member-two secrets. The issuing store lived under /tmp/prometheus-public-add-act-wimse-child-a.

Create Agent Principal ran on the operator machine and bound 127.0.0.1 only. Spawn of a wider child was refused because that audience is above the authorization limit. Spawn wrote a narrower child. The issuing store minted a WIMSE Assertion Act for that child. The durable agent process ran on Hermes at 52.91.253.34. The verifier is https://check.prestigeworldwide.digital. Hermes held the parent X.509-SVID Assertion Act, then the child WIMSE Assertion Act after add-act, and the holder keys. Hermes did not hold issuer.secret. Hermes is not a second identity store.

prometheus runtime-check agent-process on Hermes started with the parent X.509-SVID Assertion Act, used holder-sign on that machine, and the public check name. The first tool line printed ALLOWED and ran the tool. A mixed on-ramp add-act line printed REFUSED. An add-act line that named a holder secret path printed REFUSED. An honest add-act of the narrower WIMSE child printed ADDED on the same process identifier. The add-act line named WIMSE signature-input, signature, and content-digest from local @-files so quoted HTTP Message Signature bytes did not break the line. A later tool line printed ALLOWED only after both documented checks allowed, and then ran the tool. After parent Decommission by kill accept, a later tool line on the same process identifier printed REFUSED and did not run the tool. Death wins on the added WIMSE child by parent cascade. The refuse names accepted kill. The process did not restart.

This is not SPIRE. This is not a replica. This is not a public listener for birth. This is not Sanctum.
""",
    )
    print("WALK_OK pid", pid)
finally:
    host.terminate()
    try:
        host.wait(timeout=5)
    except subprocess.TimeoutExpired:
        host.kill()
    remote(
        "if [ -f %s/agent-process.pid ]; then kill $(cat %s/agent-process.pid) 2>/dev/null || true; fi; if [ -f %s/fifo-keeper.pid ]; then kill $(cat %s/fifo-keeper.pid) 2>/dev/null || true; fi"
        % (REMOTE, REMOTE, REMOTE, REMOTE)
    )
