from pathlib import Path
import json, os, socket, subprocess, time, urllib.request, urllib.error

BIN = "/home/jason/Projects/Prometheus/target/release/prometheus"
STORE = "/tmp/prometheus-hermes-agent-a"
WALK = Path("/home/jason/Projects/Prometheus/see-walk/hermes-agent-before-tool")
ISSUING = "http://127.0.0.1:18791"
PUBLIC = "https://check.prestigeworldwide.digital"
PORT = 18791
SSH = ["ssh", "-o", "ConnectTimeout=12", "-i", "/home/jason/.ssh/rustdesk-hermes.pem", "ubuntu@52.91.253.34"]
SCP = ["scp", "-o", "ConnectTimeout=12", "-i", "/home/jason/.ssh/rustdesk-hermes.pem"]
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

print("INIT")
subprocess.check_output([BIN, "--data-directory", STORE, "init"], text=True)
save("a-init-note.txt", "init ran on this machine. Secret files stay under /tmp/prometheus-hermes-agent-a.\n")
host = subprocess.Popen([BIN, "--data-directory", STORE, "host", "--listen-address", f"127.0.0.1:{PORT}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", PORT), timeout=0.25).close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        raise SystemExit("issuing host did not bind")

    status, health = http("GET", f"{ISSUING}/health")
    assert status == 200, health
    save("a-health.json", health)

    status, agent = http("POST", f"{ISSUING}/agent-type", {
        "owner": "jason-gale",
        "allowed_intents": ["read"],
        "authorization_limit": "check.prestigeworldwide.digital",
    })
    print("AGENT-TYPE", status)
    assert status == 200, agent
    save("a-agent-type.json", agent)

    status, birth = http("POST", f"{ISSUING}/birth", {
        "agent_type_id": agent["agent_type_id"],
        "owner": "jason-gale",
        "intent": "read",
        "audience": "check.prestigeworldwide.digital",
        "on_behalf_of": "autonomous",
    })
    print("BIRTH", status)
    assert status == 200, birth
    save("a-birth.json", {
        "instance_id": birth["instance_id"],
        "capability_id": birth["capability_id"],
        "revoke_identifier": birth["revoke_identifier"],
        "holder_secret_path_present": "holder_secret_path" in birth,
    })
    instance_id = birth["instance_id"]
    capability_id = birth["capability_id"]
    holder_secret_path = birth["holder_secret_path"]

    status, challenge = http("POST", f"{ISSUING}/challenge", {"instance_id": instance_id})
    print("CHALLENGE", status)
    assert status == 200, challenge
    save("a-challenge-present.json", {"challenge_nonce_present": "challenge_nonce" in challenge})

    status, present = http("POST", f"{ISSUING}/present-svid", {
        "instance_id": instance_id,
        "capability_id": capability_id,
        "holder_secret_path": holder_secret_path,
        "challenge_nonce": challenge["challenge_nonce"],
        "intent": "read",
        "audience": "check.prestigeworldwide.digital",
        "on_behalf_of": "autonomous",
    })
    print("PRESENT", status, present if status != 200 else list(present))
    assert status == 200, present
    (WALK / "presentation.json").write_text(present["presentation_json"])
    (WALK / "presentation.json.svid.pem").write_text(present["certificate_pem"])
    save("a-present-svid-keys.json", {"keys": sorted(present.keys())})

    status, issuer = http("GET", f"{ISSUING}/issuer-public")
    print("ISSUER-PUBLIC", status, list(issuer))
    assert status == 200, issuer
    save("a-issuer-public-keys.json", {"keys": sorted(issuer.keys())})
    key = issuer.get("current_issuer_public_key_hex") or issuer.get("public_key_hex")
    if not key:
        raise SystemExit("no public key in %s" % list(issuer))
    save("a-issuer-public-key-length.txt", "public_key_hex_length=%s\n" % len(key))
    status, accept = http("POST", f"{PUBLIC}/issuer-accept", {"public_key_hex": key})
    print("ISSUER-ACCEPT", status, accept if status != 200 else list(accept) if isinstance(accept, dict) else accept)
    assert status == 200, accept
    save("public-issuer-accept.json", {
        "http_status": status,
        "request_keys": ["public_key_hex"],
        "response_keys": sorted(accept.keys()) if isinstance(accept, dict) else [],
    })

    print("SCP")
    subprocess.check_call(SCP + [BIN, "ubuntu@52.91.253.34:%s/prometheus" % REMOTE])
    subprocess.check_call(SCP + [str(WALK / "presentation.json"), "ubuntu@52.91.253.34:%s/presentation.json" % REMOTE])
    subprocess.check_call(SCP + [str(WALK / "presentation.json.svid.pem"), "ubuntu@52.91.253.34:%s/presentation.json.svid.pem" % REMOTE])
    subprocess.check_call(SCP + [holder_secret_path, "ubuntu@52.91.253.34:%s/holder.secret" % REMOTE])
    subprocess.check_call(SSH + ["chmod 755 %s/prometheus && chmod 600 %s/holder.secret && chmod 644 %s/presentation.json %s/presentation.json.svid.pem" % (REMOTE, REMOTE, REMOTE, REMOTE)])
    listing = subprocess.check_output(
        SSH + ["ls -l %s && echo --- && test ! -e %s/issuer.secret && test ! -e %s/biscuit.secret && echo no-issuer-secret no-biscuit-secret && stat -c 'holder.secret mode=%%a' %s/holder.secret" % (REMOTE, REMOTE, REMOTE, REMOTE)],
        text=True,
    )
    save("hermes-remote-ls.txt", listing)
    if "issuer.secret" in listing.split("no-issuer-secret")[0]:
        raise SystemExit("issuer.secret must not be on Hermes")
    if "holder.secret mode=600" not in listing:
        raise SystemExit("holder.secret must be mode 600 on Hermes")
    save("hermes-copy-note.txt", "Copied prometheus binary, presentation.json, presentation.json.svid.pem, and holder.secret to Hermes /var/lib/prometheus-agent. Did not copy issuer.secret. Did not copy biscuit.secret.\n")

    allow_cmd = (
        "%s/prometheus runtime-check before-tool "
        "--base-url %s "
        "--presentation-json %s/presentation.json "
        "--certificate-pem %s/presentation.json.svid.pem "
        "--holder-proof-command '%s/prometheus holder-sign --holder-secret-path %s/holder.secret' "
        "--tool 'echo TOOL_RAN > %s/tool-allow.txt'"
    ) % (REMOTE, PUBLIC, REMOTE, REMOTE, REMOTE, REMOTE, REMOTE)
    allow = subprocess.run(SSH + [allow_cmd], capture_output=True, text=True)
    print("HERMES ALLOW", allow.returncode)
    print(allow.stdout)
    print(allow.stderr)
    save("hermes-before-tool-allow.stdout", allow.stdout)
    save("hermes-before-tool-allow.stderr", allow.stderr)
    save("hermes-before-tool-allow.exit", str(allow.returncode) + "\n")
    if allow.returncode != 0:
        raise SystemExit("Hermes before-tool allow failed")
    if "ALLOWED" not in allow.stdout:
        raise SystemExit("Hermes before-tool allow must print ALLOWED")
    tool_check = subprocess.check_output(SSH + ["test -f %s/tool-allow.txt && cat %s/tool-allow.txt" % (REMOTE, REMOTE)], text=True)
    save("hermes-tool-allow.txt", tool_check)
    if "TOOL_RAN" not in tool_check:
        raise SystemExit("tool did not run on Hermes")
    save("hermes-before-tool-allow-summary.json", {
        "gate": "ALLOWED",
        "exit": allow.returncode,
        "tool_ran": True,
        "tool_marker": tool_check.strip(),
    })

    status, killed = http("POST", f"{ISSUING}/kill", {"instance_id": instance_id, "confirm": instance_id})
    print("KILL", status)
    assert status == 200, killed
    save("a-kill.json", {"instance_id": killed.get("instance_id"), "status": killed.get("status")})
    status, exported = http("POST", f"{ISSUING}/kill-export", {"instance_id": instance_id, "confirm": instance_id})
    print("KILL-EXPORT", status, list(exported) if isinstance(exported, dict) else exported)
    assert status == 200, exported
    save("kill-export-keys.json", {"keys": sorted(exported.keys())})
    status, accepted = http("POST", f"{PUBLIC}/kill-accept", exported)
    print("KILL-ACCEPT", status, accepted)
    assert status == 200, accepted
    save("public-kill-accept.json", accepted)

    refuse_cmd = (
        "rm -f %s/tool-after-refuse.txt; "
        "%s/prometheus runtime-check before-tool "
        "--base-url %s "
        "--presentation-json %s/presentation.json "
        "--certificate-pem %s/presentation.json.svid.pem "
        "--holder-proof-command '%s/prometheus holder-sign --holder-secret-path %s/holder.secret' "
        "--tool 'echo TOOL_RAN_AFTER_REFUSE > %s/tool-after-refuse.txt'"
    ) % (REMOTE, REMOTE, PUBLIC, REMOTE, REMOTE, REMOTE, REMOTE, REMOTE)
    refuse = subprocess.run(SSH + [refuse_cmd], capture_output=True, text=True)
    print("HERMES REFUSE", refuse.returncode)
    print(refuse.stdout)
    print(refuse.stderr)
    save("hermes-before-tool-after-decommission.stdout", refuse.stdout)
    save("hermes-before-tool-after-decommission.stderr", refuse.stderr)
    save("hermes-before-tool-after-decommission.exit", str(refuse.returncode) + "\n")
    missing = subprocess.run(SSH + ["test ! -f %s/tool-after-refuse.txt" % REMOTE], capture_output=True, text=True)
    if refuse.returncode == 0:
        raise SystemExit("Hermes before-tool must refuse after Decommission")
    if "REFUSED" not in refuse.stdout:
        raise SystemExit("Hermes before-tool after Decommission must print REFUSED")
    refuse_text = (refuse.stdout + "\n" + refuse.stderr)
    refuse_lower = refuse_text.lower()
    if "accepted a kill" not in refuse_lower and "kill accept" not in refuse_lower:
        raise SystemExit("refuse reason must be accepted kill, not a missing holder signature. got: %s" % refuse_text)
    if "holder proof command did not write" in refuse_lower or "a holder signature is required" in refuse_lower:
        raise SystemExit("refuse reason must be accepted kill, not a missing holder signature. got: %s" % refuse_text)
    if missing.returncode != 0:
        raise SystemExit("tool ran on Hermes after refuse")
    save("hermes-tool-after-refuse.missing", "The tool file is missing on Hermes. The tool did not run after REFUSED.\n")
    save("hermes-before-tool-after-decommission-summary.json", {
        "gate": "REFUSED",
        "exit": refuse.returncode,
        "tool_ran": False,
        "tool_marker": "missing",
        "reason": refuse.stderr.strip() or refuse.stdout.strip(),
    })
    save("SEE.txt", """Hermes agent before-tool walk

Date: 22 August 2026.

This folder is for Jason Gale. These files are public records and artifacts. This folder does not contain issuer.secret, biscuit.secret, holder secrets, or member-two secrets. The issuing store lived under /tmp/prometheus-hermes-agent-a.

Create Agent Principal ran on the operator machine. The agent ran on Hermes at 52.91.253.34. The verifier is https://check.prestigeworldwide.digital. Hermes held the presentation and the holder key. Hermes did not hold issuer.secret. Hermes is not a second identity store.

prometheus runtime-check before-tool on Hermes used holder-sign on that machine and the public check name. Honest allow printed ALLOWED and ran the tool. After Decommission by kill accept, the same historical Assertion Act on Hermes printed REFUSED and did not run the tool. Death wins. Holder-sign still works after local kill because the agent holds the key. The public host refused because it accepted a kill.

This is not SPIRE. This is not a replica. This is not Sanctum.
""")
    print("WALK_OK")
finally:
    host.terminate()
    try:
        host.wait(timeout=5)
    except subprocess.TimeoutExpired:
        host.kill()
