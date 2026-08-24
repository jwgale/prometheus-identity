from pathlib import Path
import json, os, socket, subprocess, time, urllib.request, urllib.error

BIN = "/home/jason/Projects/Prometheus/target/release/prometheus"
STORE = "/tmp/prometheus-public-multiact-a"
WALK = Path("/home/jason/Projects/Prometheus/see-walk/public-multiact-agent-process")
ISSUING = "http://127.0.0.1:18798"
PUBLIC = "https://check.prestigeworldwide.digital"
PORT = 18798
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


def wait_remote_contains(path, needle, timeout=40):
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        last = remote_check("cat %s 2>/dev/null || true" % path, timeout=20)
        if needle in last:
            return last
        time.sleep(0.25)
    raise SystemExit("timeout waiting for %s in %s. last=%r" % (needle, path, last))


print("INIT")
subprocess.check_output([BIN, "--data-directory", STORE, "init"], text=True)
save(
    "a-init-note.txt",
    "init ran on this machine. Secret files stay under /tmp/prometheus-public-multiact-a.\n",
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
            "audience": "check.prestigeworldwide.digital",
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
    save(
        "a-challenge-present.json",
        {"challenge_nonce_present": "challenge_nonce" in challenge},
    )

    status, present = http(
        "POST",
        "%s/present-wimse" % ISSUING,
        {
            "instance_id": instance_id,
            "capability_id": capability_id,
            "holder_secret_path": holder_secret_path,
            "challenge_nonce": challenge["challenge_nonce"],
            "intent": "read",
            "audience": "check.prestigeworldwide.digital",
            "on_behalf_of": "autonomous",
        },
    )
    print("PRESENT-WIMSE", status, present if status != 200 else sorted(present.keys()))
    assert status == 200, present
    (WALK / "presentation.json").write_text(present["presentation_json"])
    (WALK / "workload_identity_token").write_text(present["workload_identity_token"])
    (WALK / "content_digest").write_text(present["content_digest"])
    (WALK / "signature_input").write_text(present["signature_input"])
    (WALK / "signature").write_text(present["signature"])
    save(
        "a-present-wimse-keys.json",
        {
            "keys": sorted(present.keys()),
            "token_length": len(present["workload_identity_token"]),
            "content_digest_present": bool(present.get("content_digest")),
            "signature_input_present": bool(present.get("signature_input")),
            "signature_present": bool(present.get("signature")),
        },
    )

    status, svid_challenge = http("POST", "%s/challenge" % ISSUING, {"instance_id": instance_id})
    print("SVID-CHALLENGE", status)
    assert status == 200, svid_challenge
    status, svid = http(
        "POST",
        "%s/present-svid" % ISSUING,
        {
            "instance_id": instance_id,
            "capability_id": capability_id,
            "holder_secret_path": holder_secret_path,
            "challenge_nonce": svid_challenge["challenge_nonce"],
            "intent": "read",
            "audience": "check.prestigeworldwide.digital",
            "on_behalf_of": "autonomous",
        },
    )
    print("PRESENT-SVID", status, svid if status != 200 else sorted(svid.keys()))
    assert status == 200, svid
    (WALK / "presentation.json.svid.pem").write_text(svid["certificate_pem"])
    (WALK / "presentation.svid.json").write_text(svid["presentation_json"])
    save("a-present-svid-keys.json", {"keys": sorted(svid.keys())})

    subprocess.check_call(
        SCP + [str(WALK / "presentation.json"), "ubuntu@52.91.253.34:%s/presentation.json" % REMOTE]
    )
    subprocess.check_call(
        SCP
        + [
            str(WALK / "workload_identity_token"),
            "ubuntu@52.91.253.34:%s/workload_identity_token" % REMOTE,
        ]
    )
    subprocess.check_call(
        SCP + [str(WALK / "content_digest"), "ubuntu@52.91.253.34:%s/content_digest" % REMOTE]
    )
    subprocess.check_call(
        SCP + [str(WALK / "signature_input"), "ubuntu@52.91.253.34:%s/signature_input" % REMOTE]
    )
    subprocess.check_call(
        SCP + [str(WALK / "signature"), "ubuntu@52.91.253.34:%s/signature" % REMOTE]
    )
    subprocess.check_call(
        SCP
        + [
            str(WALK / "presentation.json.svid.pem"),
            "ubuntu@52.91.253.34:%s/presentation.json.svid.pem" % REMOTE,
        ]
    )
    subprocess.check_call(
        SCP
        + [
            str(WALK / "presentation.svid.json"),
            "ubuntu@52.91.253.34:%s/presentation.svid.json" % REMOTE,
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
  "$REMOTE/tool-allow.txt" "$REMOTE/tool-after-refuse.txt"
mkfifo "$REMOTE/agent-process.in"
chmod 600 "$REMOTE/agent-process.in"
nohup bash -c "exec 3<>$REMOTE/agent-process.in; while true; do sleep 3600; done" >/dev/null 2>&1 &
echo $! > "$REMOTE/fifo-keeper.pid"
CONTENT_DIGEST=$(cat "$REMOTE/content_digest")
SIGNATURE_INPUT=$(cat "$REMOTE/signature_input")
SIGNATURE=$(cat "$REMOTE/signature")
nohup "$REMOTE/prometheus" runtime-check agent-process \
  --base-url https://check.prestigeworldwide.digital \
  --presentation-json "$REMOTE/presentation.json" \
  --certificate-pem "$REMOTE/presentation.json.svid.pem" \
  --svid-presentation-json "$REMOTE/presentation.svid.json" \
  --workload-identity-token "$REMOTE/workload_identity_token" \
  --content-digest "$CONTENT_DIGEST" \
  --signature-input "$SIGNATURE_INPUT" \
  --signature "$SIGNATURE" \
  --holder-proof-command "$REMOTE/prometheus holder-sign --holder-secret-path $REMOTE/holder.secret" \
  < "$REMOTE/agent-process.in" > "$REMOTE/agent-process.stdout" 2> "$REMOTE/agent-process.stderr" &
echo $! > "$REMOTE/agent-process.pid"
sleep 0.5
ps -p "$(cat $REMOTE/agent-process.pid)" -o pid=,cmd=
"""
    (WALK / "hermes-start-wimse-agent-process.sh").write_text(start_script)
    subprocess.check_call(
        SCP
        + [
            str(WALK / "hermes-start-wimse-agent-process.sh"),
            "ubuntu@52.91.253.34:%s/hermes-start-wimse-agent-process.sh" % REMOTE,
        ]
    )
    subprocess.check_call(
        SSH
        + [
            "chmod 755 %s/prometheus %s/hermes-start-wimse-agent-process.sh && chmod 600 %s/holder.secret && chmod 644 %s/presentation.json %s/presentation.svid.json %s/presentation.json.svid.pem %s/workload_identity_token %s/content_digest %s/signature_input %s/signature"
            % (REMOTE, REMOTE, REMOTE, REMOTE, REMOTE, REMOTE, REMOTE, REMOTE, REMOTE, REMOTE)
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
        "Copied prometheus binary, presentation.json, laboratory X.509-SVID wrap, WIMSE token, content-digest, HTTP Message Signature, and holder.secret to Hermes /var/lib/prometheus-agent. Did not copy issuer.secret. Did not copy biscuit.secret.\n",
    )

    print("START DURABLE WIMSE PROCESS")
    start = remote("bash %s/hermes-start-wimse-agent-process.sh" % REMOTE, timeout=25)
    print("START", start.returncode, start.stdout, start.stderr)
    if start.returncode != 0:
        raise SystemExit("failed to start durable WIMSE agent process on Hermes")
    pid_text = remote_check("cat %s/agent-process.pid" % REMOTE).strip()
    if not pid_text.isdigit():
        raise SystemExit("missing agent process pid: %r" % pid_text)
    pid = pid_text
    save("hermes-agent-process.pid", pid + "\n")
    save("hermes-agent-process-start.txt", start.stdout + start.stderr)
    alive = remote_check("ps -p %s -o pid=" % pid).strip()
    if alive != pid:
        stderr = remote_check("cat %s/agent-process.stderr 2>/dev/null || true" % REMOTE)
        raise SystemExit("durable process is not alive after start. stderr=%s" % stderr)

    print("SEND ALLOW TOOL")
    send_allow = remote(
        "echo 'echo TOOL_RAN > %s/tool-allow.txt' > %s/agent-process.in" % (REMOTE, REMOTE)
    )
    if send_allow.returncode != 0:
        raise SystemExit("failed to send first tool line: %s" % send_allow.stderr)
    stdout_allow = wait_remote_contains("%s/agent-process.stdout" % REMOTE, "ALLOWED", timeout=35)
    stderr_allow = remote_check("cat %s/agent-process.stderr 2>/dev/null || true" % REMOTE)
    save("hermes-agent-process-allow.stdout", stdout_allow)
    save("hermes-agent-process-allow.stderr", stderr_allow)
    if "REFUSED" in stdout_allow.splitlines()[:1]:
        raise SystemExit("first act refused: %s %s" % (stdout_allow, stderr_allow))
    if "ALLOWED" not in stdout_allow:
        raise SystemExit("first act must print ALLOWED")
    tool_check = remote_check("test -f %s/tool-allow.txt && cat %s/tool-allow.txt" % (REMOTE, REMOTE))
    save("hermes-tool-allow.txt", tool_check)
    if "TOOL_RAN" not in tool_check:
        raise SystemExit("tool did not run on Hermes")
    pid_after_allow = remote_check("ps -p %s -o pid=" % pid).strip()
    if pid_after_allow != pid:
        raise SystemExit("process died after ALLOWED. expected pid %s" % pid)
    save(
        "hermes-agent-process-allow-summary.json",
        {
            "gate": "ALLOWED",
            "pid": pid,
            "pid_still_alive": True,
            "tool_ran": True,
            "tool_marker": tool_check.strip(),
            "on_ramp": "X.509-SVID+WIMSE",
        },
    )

    status, killed = http(
        "POST",
        "%s/kill" % ISSUING,
        {"instance_id": instance_id, "confirm": instance_id},
    )
    print("KILL", status)
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
        raise SystemExit("failed to send second tool line: %s" % send_refuse.stderr)
    stdout_all = wait_remote_contains("%s/agent-process.stdout" % REMOTE, "REFUSED", timeout=35)
    stderr_all = remote_check("cat %s/agent-process.stderr 2>/dev/null || true" % REMOTE)
    save("hermes-agent-process-after-decommission.stdout", stdout_all)
    save("hermes-agent-process-after-decommission.stderr", stderr_all)
    lines = [line for line in stdout_all.splitlines() if line.strip()]
    if lines[-1:] != ["REFUSED"]:
        raise SystemExit("second act must print REFUSED last. stdout=%r" % stdout_all)
    pid_after_refuse = remote_check("ps -p %s -o pid=" % pid).strip()
    if pid_after_refuse != pid:
        raise SystemExit("process pid changed or died. expected %s got %s" % (pid, pid_after_refuse))
    missing = remote("test ! -f %s/tool-after-refuse.txt" % REMOTE)
    if missing.returncode != 0:
        raise SystemExit("tool ran on Hermes after refuse")
    refuse_text = stdout_all + "\n" + stderr_all
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
            "on_ramp": "X.509-SVID+WIMSE",
            "reason": stderr_all.strip() or stdout_all.strip(),
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
        """Public multi-act SVID and WIMSE durable agent process walk

Date: 22 August 2026.

This folder is for Jason Gale. These files are public records and artifacts. This folder does not contain issuer.secret, biscuit.secret, holder secrets, or member-two secrets. The issuing store lived under /tmp/prometheus-public-multiact-a.

Create Agent Principal ran on the operator machine and bound 127.0.0.1 only. The issuing store minted a laboratory X.509-SVID wrap and a WIMSE Assertion Act for the same instance. The durable agent process ran on Hermes at 52.91.253.34. The verifier is https://check.prestigeworldwide.digital. Hermes held both on-ramp artifacts and the holder key. Hermes did not hold issuer.secret. Hermes is not a second identity store.

prometheus runtime-check agent-process on Hermes held both on-ramp Assertion Acts, used holder-sign on that machine, and the public check name. The process stayed up. One tool line printed ALLOWED only after both documented checks allowed, and then ran the tool. After Decommission by kill accept, a second tool line on the same process identifier printed REFUSED and did not run the tool. Death wins on every held act. The refuse names accepted kill. The process did not restart.

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
