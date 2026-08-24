from pathlib import Path
import json, os, shutil, socket, subprocess, time, urllib.request, urllib.error

BIN = "/home/jason/Projects/Prometheus/target/release/prometheus"
STORE = "/tmp/prometheus-public-seal-a"
STOLEN = "/tmp/prometheus-public-seal-stolen"
WALK = Path("/home/jason/Projects/Prometheus/see-walk/public-seal-accept")
ISSUING = "http://127.0.0.1:18793"
STOLEN_HOST = "http://127.0.0.1:18794"
PUBLIC = "https://check.prestigeworldwide.digital"
PORT = 18793
STOLEN_PORT = 18794
AUDIENCE = "check.prestigeworldwide.digital"

WALK.mkdir(parents=True, exist_ok=True)
subprocess.run(["rm", "-rf", STORE, STOLEN], check=True)
os.makedirs(STORE, mode=0o700)


def save(name, obj):
    path = WALK / name
    if isinstance(obj, (dict, list)):
        path.write_text(json.dumps(obj, indent=2) + "\n")
    else:
        path.write_text(str(obj))


def http(method, url, body=None, timeout=120):
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


def wait_port(port, proc, label):
    for _ in range(150):
        if proc.poll() is not None:
            raise SystemExit("%s exited %s" % (label, proc.returncode))
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.25).close()
            return
        except OSError:
            time.sleep(0.1)
    raise SystemExit("%s did not bind" % label)


def stop_host(proc):
    if proc is None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def refuse_names_accepted_seal(text):
    lower = text.lower()
    if "expir" in lower:
        return False
    return "seal accept" in lower or "accepted a seal" in lower or "issuer death" in lower


def before_tool(presentation, pem, holder_secret, tool_path):
    if tool_path.exists():
        tool_path.unlink()
    command = [
        BIN,
        "runtime-check",
        "before-tool",
        "--base-url",
        PUBLIC,
        "--presentation-json",
        str(presentation),
        "--certificate-pem",
        str(pem),
        "--holder-proof-command",
        "%s holder-sign --holder-secret-path %s" % (BIN, holder_secret),
        "--tool",
        "echo TOOL_RAN > %s" % tool_path,
    ]
    return subprocess.run(command, capture_output=True, text=True)


def check_svid_public(presentation_json, certificate_pem, holder_secret):
    status, challenge = http("POST", PUBLIC + "/verifier-challenge", {})
    if status != 200:
        return status, {"result": "refused", "reason": "verifier-challenge failed: %s" % challenge}
    message = challenge["challenge_message"]
    proof = subprocess.check_output(
        [BIN, "holder-sign", "--holder-secret-path", holder_secret, "--challenge-message", message],
        text=True,
    ).strip()
    presentation = json.loads(presentation_json)
    body = {
        "presentation_json": presentation_json,
        "certificate_pem": certificate_pem,
        "intent": presentation["intent"],
        "audience": presentation["audience"],
        "holder_proof": proof,
        "challenge_nonce": challenge["challenge_nonce"],
        "on_behalf_of": "autonomous",
    }
    return http("POST", PUBLIC + "/check-svid", body)


def assert_no_secrets_in_walk():
    forbidden = []
    for path in WALK.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix == ".secret" or path.name in {"issuer.secret", "biscuit.secret"}:
            forbidden.append(str(path))
    if forbidden:
        raise SystemExit("see-walk must not hold secrets: %s" % forbidden)


print("PUBLIC_PROBE")
status, well_known = http("GET", PUBLIC + "/.well-known/prometheus-check")
assert status == 200, well_known
save("public-well-known.json", well_known)
pin_paths = [item.get("path") for item in well_known.get("operator_pin_paths", [])]
assert "/seal-accept" in pin_paths, well_known
status, public_health = http("GET", PUBLIC + "/health")
assert status == 200, public_health
save("public-health.json", public_health)

print("INIT")
subprocess.check_output([BIN, "--data-directory", STORE, "init"], text=True)
save(
    "a-init-note.txt",
    "init ran on this machine. Secret files stay under /tmp/prometheus-public-seal-a. This throwaway issuer is not a standing operator store.\n",
)

host = subprocess.Popen(
    [BIN, "--data-directory", STORE, "host", "--listen-address", "127.0.0.1:%s" % PORT],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
stolen_host = None
try:
    wait_port(PORT, host, "issuing host")
    status, health = http("GET", ISSUING + "/health")
    assert status == 200, health
    save("a-health.json", health)

    status, agent = http(
        "POST",
        ISSUING + "/agent-type",
        {
            "owner": "jason-gale",
            "allowed_intents": ["read"],
            "authorization_limit": AUDIENCE,
        },
    )
    print("AGENT-TYPE", status)
    assert status == 200, agent
    save("a-agent-type.json", agent)

    status, birth = http(
        "POST",
        ISSUING + "/birth",
        {
            "agent_type_id": agent["agent_type_id"],
            "owner": "jason-gale",
            "intent": "read",
            "audience": AUDIENCE,
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

    status, challenge = http("POST", ISSUING + "/challenge", {"instance_id": instance_id})
    print("CHALLENGE", status)
    assert status == 200, challenge
    save("a-challenge-present.json", {"challenge_nonce_present": "challenge_nonce" in challenge})

    status, present = http(
        "POST",
        ISSUING + "/present-svid",
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
    print("PRESENT", status, list(present) if isinstance(present, dict) and status == 200 else present)
    assert status == 200, present
    (WALK / "presentation.json").write_text(present["presentation_json"])
    (WALK / "presentation.json.svid.pem").write_text(present["certificate_pem"])
    save("a-present-svid-keys.json", {"keys": sorted(present.keys())})

    status, issuer = http("GET", ISSUING + "/issuer-public")
    print("ISSUER-PUBLIC", status, list(issuer) if isinstance(issuer, dict) else issuer)
    assert status == 200, issuer
    save("a-issuer-public-keys.json", {"keys": sorted(issuer.keys())})
    key = issuer.get("current_issuer_public_key_hex") or issuer.get("public_key_hex")
    if not key:
        raise SystemExit("no public key in %s" % list(issuer))
    save("a-issuer-public-key-length.txt", "public_key_hex_length=%s\n" % len(key))
    (WALK / "a-issuer-public-key.hex").write_text(key + "\n")
    status, accept = http("POST", PUBLIC + "/issuer-accept", {"public_key_hex": key})
    print("ISSUER-ACCEPT", status, list(accept) if isinstance(accept, dict) and status == 200 else accept)
    assert status == 200, accept
    save(
        "public-issuer-accept.json",
        {
            "http_status": status,
            "request_keys": ["public_key_hex"],
            "response_keys": sorted(accept.keys()) if isinstance(accept, dict) else [],
            "public_key_hex_length": len(accept.get("public_key_hex", "")) if isinstance(accept, dict) else 0,
        },
    )

    allow = before_tool(
        WALK / "presentation.json",
        WALK / "presentation.json.svid.pem",
        holder_secret_path,
        WALK / "tool-allow.txt",
    )
    print("HONEST", allow.returncode)
    save("before-tool-allow.stdout", allow.stdout)
    save("before-tool-allow.stderr", allow.stderr)
    save("before-tool-allow.exit", str(allow.returncode) + "\n")
    if allow.returncode != 0:
        raise SystemExit("honest before-tool must allow: %s %s" % (allow.stdout, allow.stderr))
    if "ALLOWED" not in allow.stdout:
        raise SystemExit("honest before-tool must print ALLOWED")
    if not (WALK / "tool-allow.txt").is_file() or "TOOL_RAN" not in (WALK / "tool-allow.txt").read_text():
        raise SystemExit("honest tool did not run")
    save(
        "before-tool-allow-summary.json",
        {"gate": "ALLOWED", "exit": allow.returncode, "tool_ran": True},
    )

    print("STOLEN_COPY")
    shutil.copytree(STORE, STOLEN, dirs_exist_ok=False)
    os.chmod(STOLEN, 0o700)
    if not (Path(STOLEN) / "issuer.secret").is_file():
        raise SystemExit("stolen copy must hold issuer.secret under /tmp only")
    save(
        "stolen-copy-note.txt",
        "Copied the issuing store to /tmp/prometheus-public-seal-stolen after the honest Assertion Act and before local seal. That copy stays under /tmp. This folder does not hold issuer.secret, biscuit.secret, holder secrets, or member-two secrets.\n",
    )

    status, sealed = http("POST", ISSUING + "/seal", {"confirm": "seal", "after_seconds": 86400})
    print("SEAL", status, sealed)
    assert status == 200, sealed
    save("a-seal.json", {"status": sealed.get("status"), "kill_date": sealed.get("kill_date")})
    status, exported = http("POST", ISSUING + "/seal-export", {})
    print("SEAL-EXPORT", status, list(exported) if isinstance(exported, dict) else exported)
    assert status == 200, exported
    save("a-seal-export.json", exported)
    save("seal-export-keys.json", {"keys": sorted(exported.keys()) if isinstance(exported, dict) else []})
    status, seal_accept = http("POST", PUBLIC + "/seal-accept", exported)
    print("SEAL-ACCEPT", status, seal_accept if status != 200 else list(seal_accept))
    assert status == 200, seal_accept
    save(
        "public-seal-accept.json",
        {
            "http_status": status,
            "public_key_hex_length": len(seal_accept.get("public_key_hex", "")) if isinstance(seal_accept, dict) else 0,
            "kill_date": seal_accept.get("kill_date") if isinstance(seal_accept, dict) else None,
            "response_keys": sorted(seal_accept.keys()) if isinstance(seal_accept, dict) else [],
        },
    )

    historical_svid_status, historical_svid = check_svid_public(
        present["presentation_json"],
        present["certificate_pem"],
        holder_secret_path,
    )
    print("HISTORICAL_CHECK_SVID", historical_svid_status, historical_svid)
    historical_reason = ""
    if isinstance(historical_svid, dict):
        historical_reason = str(historical_svid.get("reason") or "")
    save(
        "public-check-svid-after-seal.json",
        {
            "http_status": historical_svid_status,
            "result": historical_svid.get("result") if isinstance(historical_svid, dict) else None,
            "reason": historical_reason,
            "tool_ran": False,
        },
    )
    if historical_svid_status == 200 or (isinstance(historical_svid, dict) and historical_svid.get("result") == "allowed"):
        raise SystemExit("historical Assertion Act must refuse after public seal-accept: %s" % historical_svid)
    if not refuse_names_accepted_seal(historical_reason):
        raise SystemExit("historical refuse must name accepted seal, not expiry: %s" % historical_reason)

    historical = before_tool(
        WALK / "presentation.json",
        WALK / "presentation.json.svid.pem",
        holder_secret_path,
        WALK / "tool-after-seal.txt",
    )
    print("HISTORICAL_BEFORE_TOOL", historical.returncode)
    save("before-tool-after-seal.stdout", historical.stdout)
    save("before-tool-after-seal.stderr", historical.stderr)
    save("before-tool-after-seal.exit", str(historical.returncode) + "\n")
    historical_text = historical.stdout + "\n" + historical.stderr
    if historical.returncode == 0:
        raise SystemExit("historical before-tool must refuse after public seal-accept")
    if "REFUSED" not in historical.stdout:
        raise SystemExit("historical before-tool must print REFUSED")
    if not refuse_names_accepted_seal(historical_text):
        raise SystemExit("historical before-tool refuse must name accepted seal, not expiry: %s" % historical_text)
    if (WALK / "tool-after-seal.txt").exists():
        raise SystemExit("tool ran after historical seal refuse")
    save("tool-after-seal.missing", "The tool file is missing. The tool did not run after REFUSED.\n")
    save(
        "before-tool-after-seal-summary.json",
        {
            "gate": "REFUSED",
            "exit": historical.returncode,
            "tool_ran": False,
            "reason": historical.stderr.strip() or historical.stdout.strip(),
        },
    )

    print("STOLEN_HOST")
    stolen_host = subprocess.Popen(
        [BIN, "--data-directory", STOLEN, "host", "--listen-address", "127.0.0.1:%s" % STOLEN_PORT],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    wait_port(STOLEN_PORT, stolen_host, "stolen host")
    status, stolen_health = http("GET", STOLEN_HOST + "/health")
    assert status == 200, stolen_health
    save("stolen-health.json", {"status": stolen_health.get("status")})

    status, stolen_birth = http(
        "POST",
        STOLEN_HOST + "/birth",
        {
            "agent_type_id": agent["agent_type_id"],
            "owner": "stolen-issuer",
            "intent": "read",
            "audience": AUDIENCE,
            "on_behalf_of": "autonomous",
        },
    )
    print("STOLEN_BIRTH", status)
    assert status == 200, stolen_birth
    save(
        "stolen-birth.json",
        {
            "instance_id": stolen_birth["instance_id"],
            "capability_id": stolen_birth["capability_id"],
            "holder_secret_path_present": "holder_secret_path" in stolen_birth,
            "new_instance": stolen_birth["instance_id"] != instance_id,
        },
    )
    stolen_holder = stolen_birth["holder_secret_path"]
    if STOLEN not in stolen_holder:
        raise SystemExit("stolen birth must use the /tmp stolen store holder path")

    status, stolen_challenge = http(
        "POST", STOLEN_HOST + "/challenge", {"instance_id": stolen_birth["instance_id"]}
    )
    print("STOLEN_CHALLENGE", status)
    assert status == 200, stolen_challenge
    status, stolen_present = http(
        "POST",
        STOLEN_HOST + "/present-svid",
        {
            "instance_id": stolen_birth["instance_id"],
            "capability_id": stolen_birth["capability_id"],
            "holder_secret_path": stolen_holder,
            "challenge_nonce": stolen_challenge["challenge_nonce"],
            "intent": "read",
            "audience": AUDIENCE,
            "on_behalf_of": "autonomous",
        },
    )
    print("STOLEN_PRESENT", status, list(stolen_present) if isinstance(stolen_present, dict) and status == 200 else stolen_present)
    assert status == 200, stolen_present
    (WALK / "stolen-presentation.json").write_text(stolen_present["presentation_json"])
    (WALK / "stolen-presentation.json.svid.pem").write_text(stolen_present["certificate_pem"])
    save("stolen-present-svid-keys.json", {"keys": sorted(stolen_present.keys())})

    stolen_svid_status, stolen_svid = check_svid_public(
        stolen_present["presentation_json"],
        stolen_present["certificate_pem"],
        stolen_holder,
    )
    print("STOLEN_CHECK_SVID", stolen_svid_status, stolen_svid)
    stolen_reason = ""
    if isinstance(stolen_svid, dict):
        stolen_reason = str(stolen_svid.get("reason") or "")
    stolen_allowed = stolen_svid_status == 200 or (
        isinstance(stolen_svid, dict) and stolen_svid.get("result") == "allowed"
    )
    save(
        "public-check-svid-stolen.json",
        {
            "http_status": stolen_svid_status,
            "result": stolen_svid.get("result") if isinstance(stolen_svid, dict) else None,
            "reason": stolen_reason,
            "hole": stolen_allowed,
        },
    )

    stolen_gate = before_tool(
        WALK / "stolen-presentation.json",
        WALK / "stolen-presentation.json.svid.pem",
        stolen_holder,
        WALK / "tool-stolen.txt",
    )
    save("before-tool-stolen.stdout", stolen_gate.stdout)
    save("before-tool-stolen.stderr", stolen_gate.stderr)
    save("before-tool-stolen.exit", str(stolen_gate.returncode) + "\n")
    stolen_text = stolen_gate.stdout + "\n" + stolen_gate.stderr
    stolen_tool_ran = (WALK / "tool-stolen.txt").exists()
    if stolen_tool_ran:
        save("tool-stolen.txt", (WALK / "tool-stolen.txt").read_text())
    else:
        save("tool-stolen.missing", "The tool file is missing. The tool did not run after the stolen mint check.\n")
    save(
        "before-tool-stolen-summary.json",
        {
            "gate": "ALLOWED" if stolen_gate.returncode == 0 else "REFUSED",
            "exit": stolen_gate.returncode,
            "tool_ran": stolen_tool_ran,
            "reason": stolen_gate.stderr.strip() or stolen_gate.stdout.strip(),
            "hole": stolen_gate.returncode == 0,
        },
    )

    if stolen_allowed:
        raise SystemExit(
            "HOLE: stolen mint Assertion Act was allowed on the public host after seal-accept: %s"
            % stolen_svid
        )
    if not refuse_names_accepted_seal(stolen_reason):
        raise SystemExit(
            "stolen mint check-svid must refuse because of accepted seal, not expiry: %s" % stolen_reason
        )
    if stolen_gate.returncode == 0 or "ALLOWED" in stolen_gate.stdout:
        raise SystemExit("HOLE: stolen before-tool allowed after public seal-accept")
    if not refuse_names_accepted_seal(stolen_text):
        raise SystemExit("stolen before-tool must name accepted seal, not expiry: %s" % stolen_text)
    if stolen_tool_ran:
        raise SystemExit("stolen tool ran after public seal-accept")

    save(
        "http-codes.json",
        {
            "public_well_known": 200,
            "issuing_health": 200,
            "agent_type": 200,
            "birth": 200,
            "present_svid": 200,
            "issuer_accept": 200,
            "honest_before_tool": 0,
            "seal": 200,
            "seal_export": 200,
            "seal_accept": 200,
            "historical_check_svid": historical_svid_status,
            "historical_before_tool": historical.returncode,
            "stolen_birth": 200,
            "stolen_present_svid": 200,
            "stolen_check_svid": stolen_svid_status,
            "stolen_before_tool": stolen_gate.returncode,
        },
    )
    save(
        "SEE.txt",
        """Public seal-accept stolen-issuer walk

Date: 22 August 2026.

This folder is for Jason Gale. These files are public records and artifacts. This folder does not contain issuer.secret, biscuit.secret, holder secrets, or member-two secrets. The throwaway issuing store lived under /tmp/prometheus-public-seal-a. The stolen copy lived under /tmp/prometheus-public-seal-stolen only.

The issuing host listened on 127.0.0.1:18793 only and is stopped after this walk. The stolen copy host listened on 127.0.0.1:18794 only and is stopped after this walk. The verifier is the public check-only host at https://check.prestigeworldwide.digital. Create Agent Principal stayed on 127.0.0.1.

prometheus runtime-check before-tool used base URL https://check.prestigeworldwide.digital and prometheus holder-sign on this machine. Honest allow printed ALLOWED, exit 0, and ran the tool.

After local POST /seal with confirm seal and POST /seal-export, POST /seal-accept on the public host returned 200. A following POST /check-svid of the historical Assertion Act returned 403. The reason is accepted seal, not expiry. The tool did not run.

From the stolen /tmp copy, a new Create Agent Principal and a new Assertion Act still minted. POST /check-svid of that new Assertion Act on the public host returned 403 because this store accepted a seal for that issuer pin. A stolen issuer.secret was not enough after public seal-accept.

This throwaway issuer is not a standing operator store. This is not SPIRE. This is not a replica. This is not Sanctum.
""",
    )
    assert_no_secrets_in_walk()
    print("WALK_OK")
finally:
    stop_host(stolen_host)
    stop_host(host)
