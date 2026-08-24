from pathlib import Path
import json, os, socket, subprocess, time, urllib.request, urllib.error

BIN = "/home/jason/Projects/Prometheus/target/release/prometheus"
STORE = "/tmp/prometheus-hermes-child-cascade"
WALK = Path("/home/jason/Projects/Prometheus/see-walk/hermes-child-cascade")
ISSUING = "http://127.0.0.1:18792"
PUBLIC = "https://check.prestigeworldwide.digital"
PORT = 18792
SSH = [
    "ssh",
    "-o",
    "ConnectTimeout=12",
    "-i",
    "/home/jason/.ssh/rustdesk-hermes.pem",
    "ubuntu@52.91.253.34",
]
SCP = ["scp", "-o", "ConnectTimeout=12", "-i", "/home/jason/.ssh/rustdesk-hermes.pem"]
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


def http(method, url, body=None, timeout=60):
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


def challenge(instance_id):
    status, body = http("POST", f"{ISSUING}/challenge", {"instance_id": instance_id})
    if status != 200 or "challenge_nonce" not in body:
        raise SystemExit("challenge failed %s %s" % (status, body))
    return body["challenge_nonce"]


print("INIT")
subprocess.check_output([BIN, "--data-directory", STORE, "init"], text=True)
save(
    "a-init-note.txt",
    "init ran on this machine. Secret files stay under /tmp/prometheus-hermes-child-cascade.\n",
)

print("SCP BINARY")
binary_copy = subprocess.Popen(SCP + [BIN, "ubuntu@52.91.253.34:%s/prometheus" % REMOTE])

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

    status, health = http("GET", f"{ISSUING}/health")
    assert status == 200, health
    save("a-health.json", health)

    status, agent = http(
        "POST",
        f"{ISSUING}/agent-type",
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
        f"{ISSUING}/birth",
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
            "intent": "read",
            "audience": PARENT_AUDIENCE,
        },
    )
    parent_instance_id = birth["instance_id"]
    parent_capability_id = birth["capability_id"]
    parent_holder_secret_path = birth["holder_secret_path"]

    status, instances_before = http("GET", f"{ISSUING}/instances")
    assert status == 200, instances_before
    save("instances-before-spawn.json", instances_before)

    wider_request = {
        "parent_instance_id": parent_instance_id,
        "parent_capability_id": parent_capability_id,
        "owner": "wider",
        "intent": "read",
        "audience": WIDER_AUDIENCE,
        "holder_secret_path": parent_holder_secret_path,
        "challenge_nonce": challenge(parent_instance_id),
        "on_behalf_of": "autonomous",
    }
    save("spawn-wider-request-keys.json", {"keys": sorted(wider_request.keys())})
    status, wider = http("POST", f"{ISSUING}/spawn", wider_request)
    print("SPAWN WIDER", status, wider)
    if status == 200:
        raise SystemExit("wider spawn must refuse")
    save("spawn-wider-refuse.json", wider)
    if wider.get("result") != "refused":
        raise SystemExit("wider spawn must return refused: %s" % wider)
    reason = (wider.get("reason") or "").lower()
    if "exceeds" not in reason and "above" not in reason and "cannot gain rights" not in reason:
        raise SystemExit("wider spawn refuse must name a wider child: %s" % wider)

    status, instances_after_wider = http("GET", f"{ISSUING}/instances")
    assert status == 200, instances_after_wider
    save("instances-after-wider.json", instances_after_wider)
    live_after_wider = [
        item for item in instances_after_wider.get("instances", []) if item.get("status") == "live"
    ]
    if len(live_after_wider) != 1 or live_after_wider[0].get("instance_id") != parent_instance_id:
        raise SystemExit("wider spawn must not write a child: %s" % instances_after_wider)

    spawn_request = {
        "parent_instance_id": parent_instance_id,
        "parent_capability_id": parent_capability_id,
        "owner": "child",
        "intent": "read",
        "audience": NARROWER_AUDIENCE,
        "holder_secret_path": parent_holder_secret_path,
        "challenge_nonce": challenge(parent_instance_id),
        "on_behalf_of": "autonomous",
    }
    save("spawn-request-keys.json", {"keys": sorted(spawn_request.keys())})
    status, spawn = http("POST", f"{ISSUING}/spawn", spawn_request)
    print("SPAWN NARROWER", status, spawn if status != 200 else list(spawn))
    assert status == 200, spawn
    if sorted(spawn.keys()) != ["capability_id", "holder_secret_path", "instance_id"]:
        raise SystemExit("spawn must return child instance, child capability, holder secret path only: %s" % list(spawn))
    save(
        "spawn.json",
        {
            "instance_id": spawn["instance_id"],
            "capability_id": spawn["capability_id"],
            "holder_secret_path_present": "holder_secret_path" in spawn,
            "holder_secret_path_is_child": spawn["instance_id"] in spawn["holder_secret_path"],
            "response_keys": sorted(spawn.keys()),
        },
    )
    child_instance_id = spawn["instance_id"]
    child_capability_id = spawn["capability_id"]
    child_holder_secret_path = spawn["holder_secret_path"]
    if child_instance_id == parent_instance_id:
        raise SystemExit("child instance must differ from parent")
    if not os.path.isfile(child_holder_secret_path):
        raise SystemExit("child holder secret path must exist locally")

    status, instances_after_spawn = http("GET", f"{ISSUING}/instances")
    assert status == 200, instances_after_spawn
    save("instances-after-spawn.json", instances_after_spawn)
    child_listing = next(
        item
        for item in instances_after_spawn["instances"]
        if item["instance_id"] == child_instance_id
    )
    if child_listing.get("parent_instance_id") != parent_instance_id:
        raise SystemExit("child listing must name the parent: %s" % child_listing)

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
    save(
        "public-issuer-accept.json",
        {
            "http_status": status,
            "request_keys": ["public_key_hex"],
            "response_keys": sorted(accept.keys()) if isinstance(accept, dict) else [],
        },
    )

    if binary_copy.wait() != 0:
        raise SystemExit("scp of prometheus binary to Hermes failed")

    present_request = {
        "instance_id": child_instance_id,
        "capability_id": child_capability_id,
        "holder_secret_path": child_holder_secret_path,
        "challenge_nonce": challenge(child_instance_id),
        "intent": "read",
        "audience": NARROWER_AUDIENCE,
        "on_behalf_of": "autonomous",
    }
    save("a-present-svid-request-keys.json", {"keys": sorted(present_request.keys())})
    status, present = http("POST", f"{ISSUING}/present-svid", present_request)
    print("PRESENT", status, present if status != 200 else list(present))
    assert status == 200, present
    (WALK / "presentation.json").write_text(present["presentation_json"])
    (WALK / "presentation.json.svid.pem").write_text(present["certificate_pem"])
    save("a-present-svid-keys.json", {"keys": sorted(present.keys())})
    presentation = json.loads(present["presentation_json"])
    save(
        "presentation-public.json",
        {
            "instance_id": presentation.get("instance_id"),
            "capability_id": presentation.get("capability_id"),
            "intent": presentation.get("intent"),
            "audience": presentation.get("audience"),
            "ancestor_instance_ids": presentation.get("ancestor_instance_ids"),
            "ancestor_capability_ids": presentation.get("ancestor_capability_ids"),
            "presented_at": presentation.get("presented_at"),
            "expires_at": presentation.get("expires_at"),
        },
    )
    if presentation.get("instance_id") != child_instance_id:
        raise SystemExit("present must be the child")
    if parent_instance_id not in (presentation.get("ancestor_instance_ids") or []):
        raise SystemExit("child present must name the parent in the signed ancestor set")

    print("SCP CHILD ARTIFACTS")
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
        SCP + [child_holder_secret_path, "ubuntu@52.91.253.34:%s/holder.secret" % REMOTE]
    )
    subprocess.check_call(
        SSH
        + [
            "chmod 755 %s/prometheus && chmod 600 %s/holder.secret && chmod 644 %s/presentation.json %s/presentation.json.svid.pem && rm -f %s/tool-allow.txt %s/tool-after-refuse.txt"
            % (REMOTE, REMOTE, REMOTE, REMOTE, REMOTE, REMOTE)
        ]
    )
    listing = subprocess.check_output(
        SSH
        + [
            "ls -l %s && echo --- && test ! -e %s/issuer.secret && test ! -e %s/biscuit.secret && echo no-issuer-secret no-biscuit-secret && stat -c 'holder.secret mode=%%a' %s/holder.secret && test ! -e %s/parent.secret && echo no-parent-holder-secret"
            % (REMOTE, REMOTE, REMOTE, REMOTE, REMOTE)
        ],
        text=True,
    )
    save("hermes-remote-ls.txt", listing)
    if "issuer.secret" in listing.split("no-issuer-secret")[0]:
        raise SystemExit("issuer.secret must not be on Hermes")
    if "biscuit.secret" in listing.split("no-biscuit-secret")[0]:
        raise SystemExit("biscuit.secret must not be on Hermes")
    if "holder.secret mode=600" not in listing:
        raise SystemExit("holder.secret must be mode 600 on Hermes")
    save(
        "hermes-copy-note.txt",
        "Copied prometheus binary, child presentation.json, child presentation.json.svid.pem, and child holder.secret to Hermes /var/lib/prometheus-agent. Did not copy issuer.secret. Did not copy biscuit.secret. Did not copy the parent holder secret.\n",
    )

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
        raise SystemExit("Hermes before-tool allow failed: %s %s" % (allow.stdout, allow.stderr))
    if "ALLOWED" not in allow.stdout:
        raise SystemExit("Hermes before-tool allow must print ALLOWED")
    tool_check = subprocess.check_output(
        SSH + ["test -f %s/tool-allow.txt && cat %s/tool-allow.txt" % (REMOTE, REMOTE)],
        text=True,
    )
    save("hermes-tool-allow.txt", tool_check)
    if "TOOL_RAN" not in tool_check:
        raise SystemExit("tool did not run on Hermes")
    save(
        "hermes-before-tool-allow-summary.json",
        {
            "gate": "ALLOWED",
            "exit": allow.returncode,
            "tool_ran": True,
            "tool_marker": tool_check.strip(),
            "child_instance_id": child_instance_id,
        },
    )

    status, killed = http(
        "POST",
        f"{ISSUING}/kill",
        {"instance_id": parent_instance_id, "confirm": parent_instance_id},
    )
    print("PARENT KILL", status, killed)
    assert status == 200, killed
    save(
        "a-parent-kill.json",
        {"instance_id": killed.get("instance_id"), "status": killed.get("status")},
    )
    if killed.get("instance_id") != parent_instance_id:
        raise SystemExit("kill must be the parent, not only the child")
    if killed.get("status") != "revoked":
        raise SystemExit("parent kill must revoke")

    status, exported = http(
        "POST",
        f"{ISSUING}/kill-export",
        {"instance_id": parent_instance_id, "confirm": parent_instance_id},
    )
    print("KILL-EXPORT", status, list(exported) if isinstance(exported, dict) else exported)
    assert status == 200, exported
    save("kill-export-keys.json", {"keys": sorted(exported.keys())})
    event = exported.get("event") or {}
    cascade = {
        "killed_instance_id": event.get("instance_id"),
        "killed_instance_ids": event.get("killed_instance_ids") or [],
        "killed_capability_ids": event.get("killed_capability_ids") or [],
    }
    save("parent-kill-cascade.json", cascade)
    if cascade["killed_instance_id"] != parent_instance_id:
        raise SystemExit("kill-export must bind the parent kill line")
    if child_instance_id not in cascade["killed_instance_ids"]:
        raise SystemExit(
            "HOLE: parent kill-export did not carry the child identifier in the signed cascade: %s"
            % cascade
        )
    if parent_instance_id not in cascade["killed_instance_ids"]:
        raise SystemExit("parent kill-export must carry the parent identifier")
    if child_capability_id not in cascade["killed_capability_ids"]:
        raise SystemExit("parent kill-export must carry the child capability identifier")

    status, instances_after_kill = http("GET", f"{ISSUING}/instances")
    assert status == 200, instances_after_kill
    save("instances-after-parent-kill.json", instances_after_kill)

    status, accepted = http("POST", f"{PUBLIC}/kill-accept", exported)
    print("KILL-ACCEPT", status, accepted)
    assert status == 200, accepted
    save(
        "public-kill-accept.json",
        {
            "accepted_killed_instance_ids": accepted.get("accepted_killed_instance_ids"),
            "accepted_killed_capability_ids": accepted.get("accepted_killed_capability_ids"),
            "accepted_revoke_identifiers": accepted.get("accepted_revoke_identifiers"),
            "child_instance_accepted": child_instance_id
            in (accepted.get("accepted_killed_instance_ids") or []),
            "parent_instance_accepted": parent_instance_id
            in (accepted.get("accepted_killed_instance_ids") or []),
        },
    )
    accepted_instances = accepted.get("accepted_killed_instance_ids") or []
    if child_instance_id not in accepted_instances:
        raise SystemExit(
            "HOLE: parent kill accept did not persist child death from the signed cascade: %s"
            % accepted
        )

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
    save("hermes-before-tool-after-parent-kill.stdout", refuse.stdout)
    save("hermes-before-tool-after-parent-kill.stderr", refuse.stderr)
    save("hermes-before-tool-after-parent-kill.exit", str(refuse.returncode) + "\n")
    missing = subprocess.run(
        SSH + ["test ! -f %s/tool-after-refuse.txt" % REMOTE],
        capture_output=True,
        text=True,
    )
    refuse_text = (refuse.stdout + "\n" + refuse.stderr)
    if refuse.returncode == 0 or "ALLOWED" in refuse.stdout:
        raise SystemExit(
            "HOLE: parent kill accept did not refuse the child present on the public host: %s"
            % refuse_text
        )
    if "REFUSED" not in refuse.stdout:
        raise SystemExit("Hermes before-tool after parent kill accept must print REFUSED: %s" % refuse_text)
    refuse_lower = refuse_text.lower()
    if (
        "accepted a kill" not in refuse_lower
        and "kill accept" not in refuse_lower
        and "cascade" not in refuse_lower
    ):
        raise SystemExit(
            "refuse reason must be accepted kill / kill accept cascade, not a missing holder signature. got: %s"
            % refuse_text
        )
    if "holder proof command did not write" in refuse_lower or "a holder signature is required" in refuse_lower:
        raise SystemExit(
            "refuse reason must be accepted kill / kill accept cascade, not a missing holder signature. got: %s"
            % refuse_text
        )
    if "expir" in refuse_lower and "kill" not in refuse_lower:
        raise SystemExit("refuse must name accepted kill, not only expiry: %s" % refuse_text)
    if missing.returncode != 0:
        raise SystemExit("tool ran on Hermes after refuse")
    save(
        "hermes-tool-after-refuse.missing",
        "The tool file is missing on Hermes. The tool did not run after REFUSED.\n",
    )
    save(
        "hermes-before-tool-after-parent-kill-summary.json",
        {
            "gate": "REFUSED",
            "exit": refuse.returncode,
            "tool_ran": False,
            "tool_marker": "missing",
            "reason": refuse.stderr.strip() or refuse.stdout.strip(),
            "child_instance_id": child_instance_id,
            "parent_instance_id": parent_instance_id,
        },
    )
    save(
        "http-codes.json",
        {
            "GET /health": 200,
            "POST /agent-type": 200,
            "POST /birth": 200,
            "POST /spawn wider": 403,
            "POST /spawn": 200,
            "GET /instances after spawn": 200,
            "POST /present-svid": 200,
            "GET /issuer-public": 200,
            "POST /issuer-accept": 200,
            "POST /kill parent": 200,
            "POST /kill-export": 200,
            "POST /kill-accept": 200,
        },
    )
    save(
        "SEE.txt",
        """Hermes child cascade walk

Date: 22 August 2026.

This folder is for Jason Gale. These files are public records and artifacts. This folder does not contain issuer.secret, biscuit.secret, holder secrets, or member-two secrets. The issuing store lived under /tmp/prometheus-hermes-child-cascade.

Create Agent Principal ran on the operator machine and bound 127.0.0.1 only. Spawn wrote a narrower child. Spawn is not a role catalog. A wider child was refused. The child Assertion Act ran on Hermes at 52.91.253.34. The verifier is https://check.prestigeworldwide.digital. Hermes held the child presentation and the child holder key. Hermes did not hold issuer.secret. Hermes did not hold the parent holder secret. Hermes is not a second identity store.

prometheus runtime-check before-tool on Hermes used holder-sign on the child secret and the public check name. Honest allow printed ALLOWED and ran the tool. After Decommission of the parent by kill accept, the same historical child Assertion Act on Hermes printed REFUSED and did not run the tool. Death wins. The refuse names accepted kill. Holder-sign still works after local parent kill because the agent holds the child key. The public host refused because it accepted the parent kill cascade.

This is not SPIRE. This is not a replica. This is not Sanctum.
""",
    )
    print("WALK_OK")
finally:
    host.terminate()
    try:
        host.wait(timeout=5)
    except subprocess.TimeoutExpired:
        host.kill()
    if binary_copy.poll() is None:
        binary_copy.kill()
