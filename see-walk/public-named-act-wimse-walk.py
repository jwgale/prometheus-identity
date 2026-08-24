from pathlib import Path
import json, os, socket, subprocess, time, urllib.request, urllib.error

BIN = "/home/jason/Projects/Prometheus/target/release/prometheus"
STORE = "/tmp/prometheus-public-named-act-wimse-a"
WALK = Path("/home/jason/Projects/Prometheus/see-walk/public-named-act-wimse")
ISSUING = "http://127.0.0.1:18802"
PUBLIC = "https://check.prestigeworldwide.digital"
PORT = 18802
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
AUDIENCE = "check.prestigeworldwide.digital"
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


def wait_remote_new_gate(previous, expected, timeout=40):
    deadline = time.time() + timeout
    last = previous
    while time.time() < deadline:
        last = remote_check("cat %s/agent-process.stdout 2>/dev/null || true" % REMOTE, timeout=20)
        if last != previous:
            lines = [line for line in last.splitlines() if line.strip()]
            if lines and lines[-1] == expected:
                return last
        time.sleep(0.25)
    raise SystemExit("timeout waiting for new gate %s. last=%r" % (expected, last))


def require_same_pid(pid, when):
    alive = remote_check("ps -p %s -o pid=" % pid).strip()
    if alive != pid:
        stderr = remote_check("cat %s/agent-process.stderr 2>/dev/null || true" % REMOTE)
        raise SystemExit("process pid changed or died %s. expected %s. stderr=%s" % (when, pid, stderr))


def send_line(command):
    previous = remote_check("cat %s/agent-process.stdout 2>/dev/null || true" % REMOTE)
    result = remote(command)
    if result.returncode != 0:
        raise SystemExit("failed to send line: %s\n%s" % (command, result.stderr))
    return previous


print("INIT")
subprocess.check_output([BIN, "--data-directory", STORE, "init"], text=True)
save(
    "a-init-note.txt",
    "init ran on this machine. Secret files stay under /tmp/prometheus-public-named-act-wimse-a.\n",
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

    def birth_one(label):
        status, birth = http(
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
        print("BIRTH", label, status)
        assert status == 200, birth
        return {
            "instance_id": birth["instance_id"],
            "capability_id": birth["capability_id"],
            "revoke_identifier": birth["revoke_identifier"],
            "holder_secret_path": birth["holder_secret_path"],
        }

    first = birth_one("first")
    second = birth_one("second")
    save(
        "a-births.json",
        {
            "first": first["instance_id"],
            "second": second["instance_id"],
            "independent": True,
            "first_on_ramp": "x509-svid",
            "second_on_ramp": "wimse",
        },
    )

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
    subprocess.check_call(
        SCP + [first["holder_secret_path"], "ubuntu@52.91.253.34:%s/holder.secret" % REMOTE]
    )
    subprocess.check_call(
        SCP + [second["holder_secret_path"], "ubuntu@52.91.253.34:%s/second-holder.secret" % REMOTE]
    )
    start_script = r"""#!/bin/bash
set -euo pipefail
REMOTE=/var/lib/prometheus-agent
if [ -f "$REMOTE/agent-process.pid" ]; then kill "$(cat "$REMOTE/agent-process.pid")" 2>/dev/null || true; fi
if [ -f "$REMOTE/fifo-keeper.pid" ]; then kill "$(cat "$REMOTE/fifo-keeper.pid")" 2>/dev/null || true; fi
rm -f "$REMOTE/agent-process.in" "$REMOTE/agent-process.stdout" "$REMOTE/agent-process.stderr" \
  "$REMOTE/agent-process.pid" "$REMOTE/fifo-keeper.pid" \
  "$REMOTE/tool-allow.txt" "$REMOTE/tool-both.txt" "$REMOTE/tool-named-live.txt" \
  "$REMOTE/tool-named-dead.txt" "$REMOTE/tool-unnamed-after.txt" "$REMOTE/tool-named-dead-wimse.txt"
mkfifo "$REMOTE/agent-process.in"
chmod 600 "$REMOTE/agent-process.in"
nohup bash -c "exec 3<>$REMOTE/agent-process.in; while true; do sleep 3600; done" >/dev/null 2>&1 &
echo $! > "$REMOTE/fifo-keeper.pid"
nohup "$REMOTE/prometheus" runtime-check agent-process \
  --base-url https://check.prestigeworldwide.digital \
  --presentation-json "$REMOTE/first-presentation.json" \
  --certificate-pem "$REMOTE/first-presentation.json.svid.pem" \
  --holder-proof-command "$REMOTE/prometheus holder-sign --holder-secret-path $REMOTE/holder.secret" \
  < "$REMOTE/agent-process.in" > "$REMOTE/agent-process.stdout" 2> "$REMOTE/agent-process.stderr" &
echo $! > "$REMOTE/agent-process.pid"
sleep 0.5
ps -p "$(cat $REMOTE/agent-process.pid)" -o pid=,cmd=
"""
    (WALK / "hermes-start-named-act-wimse.sh").write_text(start_script)
    subprocess.check_call(
        SCP
        + [
            str(WALK / "hermes-start-named-act-wimse.sh"),
            "ubuntu@52.91.253.34:%s/hermes-start-named-act-wimse.sh" % REMOTE,
        ]
    )
    subprocess.check_call(
        SSH
        + [
            "chmod 755 %s/prometheus %s/hermes-start-named-act-wimse.sh && chmod 600 %s/holder.secret %s/second-holder.secret"
            % (REMOTE, REMOTE, REMOTE, REMOTE)
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
        "Copied prometheus binary, first presentation.json, laboratory X.509-SVID wrap, and holder.secret to Hermes /var/lib/prometheus-agent. Did not copy issuer.secret. Did not copy biscuit.secret.\n",
    )

    print("MINT BOTH PRESENTS LATE")
    status, challenge = http("POST", "%s/challenge" % ISSUING, {"instance_id": first["instance_id"]})
    print("CHALLENGE FIRST", status)
    assert status == 200, challenge
    status, svid = http(
        "POST",
        "%s/present-svid" % ISSUING,
        {
            "instance_id": first["instance_id"],
            "capability_id": first["capability_id"],
            "holder_secret_path": first["holder_secret_path"],
            "challenge_nonce": challenge["challenge_nonce"],
            "intent": "read",
            "audience": AUDIENCE,
            "on_behalf_of": "autonomous",
        },
    )
    print("PRESENT-SVID", status, svid if status != 200 else sorted(svid.keys()))
    assert status == 200, svid
    (WALK / "first-presentation.json").write_text(svid["presentation_json"])
    (WALK / "first-presentation.json.svid.pem").write_text(svid["certificate_pem"])
    save("a-present-svid-keys.json", {"keys": sorted(svid.keys())})
    status, second_challenge = http(
        "POST", "%s/challenge" % ISSUING, {"instance_id": second["instance_id"]}
    )
    print("CHALLENGE SECOND", status)
    assert status == 200, second_challenge
    status, second_wimse = http(
        "POST",
        "%s/present-wimse" % ISSUING,
        {
            "instance_id": second["instance_id"],
            "capability_id": second["capability_id"],
            "holder_secret_path": second["holder_secret_path"],
            "challenge_nonce": second_challenge["challenge_nonce"],
            "intent": "read",
            "audience": AUDIENCE,
            "on_behalf_of": "autonomous",
        },
    )
    print("PRESENT-WIMSE", status, second_wimse if status != 200 else sorted(second_wimse.keys()))
    assert status == 200, second_wimse
    (WALK / "second-presentation.json").write_text(second_wimse["presentation_json"])
    (WALK / "second-workload_identity_token").write_text(second_wimse["workload_identity_token"])
    (WALK / "second-content_digest").write_text(second_wimse["content_digest"])
    (WALK / "second-signature_input").write_text(second_wimse["signature_input"])
    (WALK / "second-signature").write_text(second_wimse["signature"])
    save(
        "a-second-present-wimse-keys.json",
        {
            "keys": sorted(second_wimse.keys()),
            "token_length": len(second_wimse["workload_identity_token"]),
            "content_digest_present": bool(second_wimse.get("content_digest")),
            "signature_input_present": bool(second_wimse.get("signature_input")),
            "signature_present": bool(second_wimse.get("signature")),
        },
    )
    for name in (
        "first-presentation.json",
        "first-presentation.json.svid.pem",
        "second-presentation.json",
        "second-workload_identity_token",
        "second-content_digest",
        "second-signature_input",
        "second-signature",
    ):
        subprocess.check_call(
            SCP + [str(WALK / name), "ubuntu@52.91.253.34:%s/%s" % (REMOTE, name)]
        )
    subprocess.check_call(
        SSH
        + [
            "chmod 600 %s/holder.secret %s/second-holder.secret && chmod 644 %s/first-presentation.json %s/first-presentation.json.svid.pem %s/second-presentation.json %s/second-workload_identity_token %s/second-content_digest %s/second-signature_input %s/second-signature"
            % (REMOTE, REMOTE, REMOTE, REMOTE, REMOTE, REMOTE, REMOTE, REMOTE, REMOTE)
        ]
    )
    save(
        "hermes-second-copy-note.txt",
        "Copied independent second presentation.json, WIMSE token, content-digest, HTTP Message Signature, and second-holder.secret to Hermes. Did not copy issuer.secret.\n",
    )

    print("START DURABLE PROCESS")
    start = remote("bash %s/hermes-start-named-act-wimse.sh" % REMOTE, timeout=25)
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

    print("SEND HONEST INDEPENDENT WIMSE ADD-ACT")
    add_script = r"""#!/bin/bash
set -euo pipefail
REMOTE=/var/lib/prometheus-agent
printf '%s\n' "add-act --presentation-json $REMOTE/second-presentation.json --workload-identity-token $REMOTE/second-workload_identity_token --content-digest @$REMOTE/second-content_digest --signature-input @$REMOTE/second-signature_input --signature @$REMOTE/second-signature --holder-proof-command \"$REMOTE/prometheus holder-sign --holder-secret-path $REMOTE/second-holder.secret\"" > "$REMOTE/agent-process.in"
"""
    (WALK / "hermes-send-wimse-add-act.sh").write_text(add_script)
    subprocess.check_call(
        SCP
        + [
            str(WALK / "hermes-send-wimse-add-act.sh"),
            "ubuntu@52.91.253.34:%s/hermes-send-wimse-add-act.sh" % REMOTE,
        ]
    )
    previous = remote_check("cat %s/agent-process.stdout 2>/dev/null || true" % REMOTE)
    send_add = remote("bash %s/hermes-send-wimse-add-act.sh" % REMOTE)
    if send_add.returncode != 0:
        raise SystemExit("failed to send honest WIMSE add-act: %s" % send_add.stderr)
    stdout_added = wait_remote_new_gate(previous, "ADDED", timeout=20)
    stderr_added = remote_check("cat %s/agent-process.stderr 2>/dev/null || true" % REMOTE)
    save("hermes-add-act.stdout", stdout_added)
    save("hermes-add-act.stderr", stderr_added)
    save(
        "add-act-second.line",
        "add-act of independent WIMSE used @-files for signature-input, signature, and content-digest\n",
    )
    require_same_pid(pid, "after honest independent WIMSE add-act")
    save(
        "hermes-add-act-summary.json",
        {
            "gate": "ADDED",
            "pid": pid,
            "same_pid": True,
            "added": "independent WIMSE",
        },
    )

    print("SEND UNNAMED ALLOW BOTH LIVE")
    previous = send_line(
        "echo 'echo TOOL_BOTH > %s/tool-both.txt' > %s/agent-process.in" % (REMOTE, REMOTE)
    )
    stdout_both = wait_remote_new_gate(previous, "ALLOWED", timeout=35)
    stderr_both = remote_check("cat %s/agent-process.stderr 2>/dev/null || true" % REMOTE)
    save("hermes-unnamed-both.stdout", stdout_both)
    save("hermes-unnamed-both.stderr", stderr_both)
    tool_both = remote_check("test -f %s/tool-both.txt && cat %s/tool-both.txt" % (REMOTE, REMOTE))
    save("hermes-tool-both.txt", tool_both)
    if "TOOL_BOTH" not in tool_both:
        raise SystemExit("tool did not run on Hermes while both acts were live: %s %s" % (stdout_both, stderr_both))
    require_same_pid(pid, "after unnamed both-live ALLOWED")

    status, killed = http(
        "POST",
        "%s/kill" % ISSUING,
        {"instance_id": first["instance_id"], "confirm": first["instance_id"]},
    )
    print("KILL FIRST", status)
    assert status == 200, killed
    save("a-kill-first.json", {"instance_id": killed.get("instance_id"), "status": killed.get("status")})
    status, exported = http(
        "POST",
        "%s/kill-export" % ISSUING,
        {"instance_id": first["instance_id"], "confirm": first["instance_id"]},
    )
    print("KILL-EXPORT FIRST", status, list(exported) if isinstance(exported, dict) else exported)
    assert status == 200, exported
    save("kill-export-first-keys.json", {"keys": sorted(exported.keys())})
    status, accepted = http("POST", "%s/kill-accept" % PUBLIC, exported)
    print("KILL-ACCEPT FIRST", status, accepted)
    assert status == 200, accepted
    save("public-kill-accept-first.json", accepted)

    print("SEND UNNAMED AFTER FIRST DEATH")
    previous = send_line(
        "echo 'echo TOOL_UNNAMED_AFTER > %s/tool-unnamed-after.txt' > %s/agent-process.in"
        % (REMOTE, REMOTE)
    )
    stdout_unnamed = wait_remote_new_gate(previous, "REFUSED", timeout=35)
    stderr_unnamed = remote_check("cat %s/agent-process.stderr 2>/dev/null || true" % REMOTE)
    save("hermes-unnamed-after.stdout", stdout_unnamed)
    save("hermes-unnamed-after.stderr", stderr_unnamed)
    require_same_pid(pid, "after unnamed refuse following first Decommission")
    missing = remote("test ! -f %s/tool-unnamed-after.txt" % REMOTE)
    if missing.returncode != 0:
        raise SystemExit("tool ran on Hermes after unnamed refuse")
    refuse_text = (stdout_unnamed + "\n" + stderr_unnamed).lower()
    if "accepted a kill" not in refuse_text and "kill accept" not in refuse_text:
        raise SystemExit(
            "unnamed refuse must name accepted kill, not a missing holder signature. got: %s"
            % (stdout_unnamed + "\n" + stderr_unnamed)
        )
    if "holder proof command did not write" in refuse_text or "a holder signature is required" in refuse_text:
        raise SystemExit(
            "unnamed refuse must name accepted kill, not a missing holder signature. got: %s"
            % (stdout_unnamed + "\n" + stderr_unnamed)
        )

    print("SEND NAMED ACT 2 LIVE WIMSE")
    previous = send_line(
        "echo 'act 2 echo TOOLLIVE > %s/tool-named-live.txt' > %s/agent-process.in" % (REMOTE, REMOTE)
    )
    stdout_live = wait_remote_new_gate(previous, "ALLOWED", timeout=35)
    stderr_live = remote_check("cat %s/agent-process.stderr 2>/dev/null || true" % REMOTE)
    save("hermes-named-live.stdout", stdout_live)
    save("hermes-named-live.stderr", stderr_live)
    tool_live = remote_check(
        "test -f %s/tool-named-live.txt && cat %s/tool-named-live.txt" % (REMOTE, REMOTE)
    )
    save("hermes-tool-named-live.txt", tool_live)
    if "TOOLLIVE" not in tool_live:
        raise SystemExit("named live WIMSE act 2 did not run the tool: %s %s" % (stdout_live, stderr_live))
    require_same_pid(pid, "after named act 2 ALLOWED")

    print("SEND NAMED ACT 1 DEAD FIRST")
    previous = send_line(
        "echo 'act 1 echo TOOLDEAD > %s/tool-named-dead.txt' > %s/agent-process.in" % (REMOTE, REMOTE)
    )
    stdout_dead = wait_remote_new_gate(previous, "REFUSED", timeout=35)
    stderr_dead = remote_check("cat %s/agent-process.stderr 2>/dev/null || true" % REMOTE)
    save("hermes-named-dead.stdout", stdout_dead)
    save("hermes-named-dead.stderr", stderr_dead)
    require_same_pid(pid, "after named act 1 REFUSED")
    dead_missing = remote("test ! -f %s/tool-named-dead.txt" % REMOTE)
    if dead_missing.returncode != 0:
        raise SystemExit("named dead act 1 ran the tool")
    dead_text = (stdout_dead + "\n" + stderr_dead).lower()
    if "accepted a kill" not in dead_text and "kill accept" not in dead_text:
        raise SystemExit("named dead act 1 must name accepted kill: %s" % (stdout_dead + "\n" + stderr_dead))

    print("SEND FAIL-CLOSED ACT 0")
    previous = send_line("echo 'act 0 echo SHOULD_NOT_RUN' > %s/agent-process.in" % REMOTE)
    stdout_zero = wait_remote_new_gate(previous, "REFUSED", timeout=20)
    stderr_zero = remote_check("cat %s/agent-process.stderr 2>/dev/null || true" % REMOTE)
    save("hermes-act-0.stdout", stdout_zero)
    save("hermes-act-0.stderr", stderr_zero)
    if "1" not in stderr_zero and "held" not in stderr_zero.lower() and "number" not in stderr_zero.lower():
        raise SystemExit("act 0 must name the one-based lock: %s" % stderr_zero)
    require_same_pid(pid, "after act 0 refuse")

    print("SEND FAIL-CLOSED MISSING NUMBER")
    previous = send_line("echo 'act' > %s/agent-process.in" % REMOTE)
    stdout_missing = wait_remote_new_gate(previous, "REFUSED", timeout=20)
    stderr_missing = remote_check("cat %s/agent-process.stderr 2>/dev/null || true" % REMOTE)
    save("hermes-act-missing.stdout", stdout_missing)
    save("hermes-act-missing.stderr", stderr_missing)
    if "number" not in stderr_missing.lower() and "held" not in stderr_missing.lower():
        raise SystemExit("missing act number must be refused: %s" % stderr_missing)
    require_same_pid(pid, "after missing act number refuse")

    print("SEND FAIL-CLOSED INDEX NOT HELD")
    previous = send_line("echo 'act 9 echo SHOULD_NOT_RUN' > %s/agent-process.in" % REMOTE)
    stdout_held = wait_remote_new_gate(previous, "REFUSED", timeout=20)
    stderr_held = remote_check("cat %s/agent-process.stderr 2>/dev/null || true" % REMOTE)
    save("hermes-act-not-held.stdout", stdout_held)
    save("hermes-act-not-held.stderr", stderr_held)
    if "held" not in stderr_held.lower() and "2" not in stderr_held:
        raise SystemExit("unheld act index must be refused: %s" % stderr_held)
    require_same_pid(pid, "after unheld act refuse")

    status, killed_wimse = http(
        "POST",
        "%s/kill" % ISSUING,
        {"instance_id": second["instance_id"], "confirm": second["instance_id"]},
    )
    print("KILL SECOND WIMSE", status)
    assert status == 200, killed_wimse
    save(
        "a-kill-second.json",
        {"instance_id": killed_wimse.get("instance_id"), "status": killed_wimse.get("status")},
    )
    status, exported_wimse = http(
        "POST",
        "%s/kill-export" % ISSUING,
        {"instance_id": second["instance_id"], "confirm": second["instance_id"]},
    )
    print("KILL-EXPORT SECOND", status)
    assert status == 200, exported_wimse
    status, accepted_wimse = http("POST", "%s/kill-accept" % PUBLIC, exported_wimse)
    print("KILL-ACCEPT SECOND", status, accepted_wimse)
    assert status == 200, accepted_wimse
    save("public-kill-accept-second.json", accepted_wimse)

    print("SEND NAMED DEAD WIMSE ACT 2")
    previous = send_line(
        "echo 'act 2 echo TOOLDEADWIMSE > %s/tool-named-dead-wimse.txt' > %s/agent-process.in"
        % (REMOTE, REMOTE)
    )
    stdout_dead_wimse = wait_remote_new_gate(previous, "REFUSED", timeout=35)
    stderr_dead_wimse = remote_check("cat %s/agent-process.stderr 2>/dev/null || true" % REMOTE)
    save("hermes-named-dead-wimse.stdout", stdout_dead_wimse)
    save("hermes-named-dead-wimse.stderr", stderr_dead_wimse)
    require_same_pid(pid, "after named dead WIMSE act 2 REFUSED")
    dead_wimse_missing = remote("test ! -f %s/tool-named-dead-wimse.txt" % REMOTE)
    if dead_wimse_missing.returncode != 0:
        raise SystemExit("named dead WIMSE act 2 ran the tool")
    dead_wimse_text = (stdout_dead_wimse + "\n" + stderr_dead_wimse).lower()
    if "accepted a kill" not in dead_wimse_text and "kill accept" not in dead_wimse_text:
        raise SystemExit(
            "named dead WIMSE must name accepted kill: %s"
            % (stdout_dead_wimse + "\n" + stderr_dead_wimse)
        )

    save(
        "hermes-named-act-wimse-summary.json",
        {
            "pid": pid,
            "same_pid": True,
            "first_on_ramp": "x509-svid",
            "second_on_ramp": "wimse",
            "independent": True,
            "unnamed_both_live": "ALLOWED",
            "unnamed_after_first_death": "REFUSED",
            "named_live_wimse_act_2": "ALLOWED",
            "named_dead_first_act_1": "REFUSED",
            "named_dead_wimse_act_2": "REFUSED",
            "fail_closed_act_0": "REFUSED",
            "fail_closed_missing_number": "REFUSED",
            "fail_closed_index_not_held": "REFUSED",
            "tool_named_live": tool_live.strip(),
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
        """Public named-act WIMSE independent second Assertion Act walk

Date: 23 August 2026.

This folder is for Jason Gale. These files are public records and artifacts. This folder does not contain issuer.secret, biscuit.secret, holder secrets, or member-two secrets. The issuing store lived under /tmp/prometheus-public-named-act-wimse-a.

Create Agent Principal ran on the operator machine and bound 127.0.0.1 only. Two independent live instances were born. The first Assertion Act was a laboratory X.509-SVID wrap. The second Assertion Act was a WIMSE present. The durable agent process ran on Hermes at 52.91.253.34. The verifier is https://check.prestigeworldwide.digital. Hermes held both Assertion Acts and the holder keys. Hermes did not hold issuer.secret. Hermes is not a second identity store.

prometheus runtime-check agent-process on Hermes started with the first X.509-SVID Assertion Act. The first tool line printed ALLOWED. add-act of the second independent WIMSE Assertion Act printed ADDED on the same process identifier. An unnamed tool line printed ALLOWED only after both documented checks allowed. After Decommission of the first instance by kill accept, an unnamed tool line on the same process identifier printed REFUSED because this store accepted a kill. A line that named act 2 printed ALLOWED and ran the tool because that WIMSE Assertion Act was still live. A line that named act 1 printed REFUSED because this store accepted a kill. After Decommission of the second instance, a line that named act 2 printed REFUSED because this store accepted a kill. Act 0, a missing act number, and an act number this process does not hold are refused. The process did not restart.

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
