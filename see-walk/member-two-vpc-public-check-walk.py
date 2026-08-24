#!/usr/bin/env python3
"""Rung 97 candidate: throwaway issuer + remote member two + public allow then refuse.

CLI only. No issuing host. No Hermes. No standing issuer.
Public artifacts only land under see-walk/member-two-vpc-public-check.
Secret bytes are not printed and are not written into see-walk.
"""

from pathlib import Path
import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request

BIN = "/home/jason/Projects/Prometheus/target/release/prometheus"
STORE = "/tmp/prometheus-member-two-public-20260823"
MEMBER = "/home/jason/Projects/prometheus-lab-vpc/mnt-member-two/member-two.secret"
WALK = Path("/home/jason/Projects/Prometheus/see-walk/member-two-vpc-public-check")
PUBLIC = "https://check.prestigeworldwide.digital"
AUDIENCE = "check.prestigeworldwide.digital"
STANDING_LAPTOP_MEMBER = "/home/jason/Projects/prometheus-lab-vpc/member-two.secret"

WALK.mkdir(parents=True, exist_ok=True)


def save(name, obj):
    path = WALK / name
    if isinstance(obj, (dict, list)):
        path.write_text(json.dumps(obj, indent=2) + "\n")
    else:
        text = str(obj)
        path.write_text(text if text.endswith("\n") else text + "\n")


def run(args, label):
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip()
        if "secret" in err.lower() and "issuer.secret" not in err.lower():
            err = "command refused (secret-looking stderr redacted)"
        raise SystemExit("%s failed (%s): %s" % (label, result.returncode, err[:800]))
    return result.stdout


def run_json(args, label):
    return json.loads(run(args, label))


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


def prom(*rest):
    return [BIN, "--data-directory", STORE, *rest]


def prom_member(*rest):
    return [BIN, "--data-directory", STORE, "--member-secret", MEMBER, *rest]


def refuse_names_accepted_kill(text):
    lower = (text or "").lower()
    if "expir" in lower:
        return False
    return "accepted a kill" in lower or "kill accept" in lower


def check_svid_public(presentation_json, certificate_pem):
    status, challenge = http("POST", PUBLIC + "/verifier-challenge", {})
    if status != 200:
        return status, {"result": "refused", "reason": "verifier-challenge failed: %s" % challenge}
    message = challenge["challenge_message"]
    holder = str(Path(STORE) / "holders" / ("%s.secret" % instance_id))
    proof = subprocess.check_output(
        [BIN, "holder-sign", "--holder-secret-path", holder, "--challenge-message", message],
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


def mint_present():
    challenge = run_json(prom_member("challenge", "--instance", instance_id), "challenge")
    nonce = challenge.get("nonce") or challenge.get("challenge_nonce")
    if not nonce:
        raise SystemExit("challenge missing nonce: %s" % sorted(challenge.keys()))
    out = WALK / "presentation.json"
    holder = str(Path(STORE) / "holders" / ("%s.secret" % instance_id))
    present = run_json(
        prom_member(
            "present",
            "--instance",
            instance_id,
            "--capability",
            capability_id,
            "--format",
            "x509-svid",
            "--output",
            str(out),
            "--holder-secret-path",
            holder,
            "--challenge-nonce",
            nonce,
        ),
        "present x509-svid",
    )
    pem_path = Path(present.get("svid_path") or (str(out) + ".svid.pem"))
    if not out.is_file() or not pem_path.is_file():
        raise SystemExit("present did not write presentation and pem")
    return out.read_text(), pem_path.read_text(), present


def shred_path(path):
    path = Path(path)
    if not path.exists():
        return
    if path.is_dir():
        for child in sorted(path.rglob("*"), reverse=True):
            if child.is_file():
                shred_file(child)
            elif child.is_dir():
                try:
                    child.rmdir()
                except OSError:
                    shutil.rmtree(child, ignore_errors=True)
        shutil.rmtree(path, ignore_errors=True)
    else:
        shred_file(path)


def shred_file(path):
    path = Path(path)
    try:
        subprocess.run(["shred", "-u", str(path)], check=False, capture_output=True)
    except FileNotFoundError:
        pass
    if path.exists():
        try:
            size = path.stat().st_size
            with open(path, "wb") as handle:
                handle.write(b"\x00" * size)
            path.unlink()
        except OSError:
            path.unlink(missing_ok=True)


def assert_no_secrets_in_walk():
    forbidden = []
    for path in WALK.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix == ".secret" or path.name in {"issuer.secret", "biscuit.secret"}:
            forbidden.append(str(path))
    if forbidden:
        raise SystemExit("see-walk must not hold secrets: %s" % forbidden)


print("PROBE")
if not Path(MEMBER).is_file():
    raise SystemExit("remote member-two.secret is not visible on the mount")
standing_mtime = Path(STANDING_LAPTOP_MEMBER).stat().st_mtime
status, well_known = http("GET", PUBLIC + "/.well-known/prometheus-check")
if status != 200:
    raise SystemExit("well-known failed: %s %s" % (status, well_known))
save("public-well-known.json", well_known)
status, health = http("GET", PUBLIC + "/health")
if status != 200:
    raise SystemExit("public health failed: %s %s" % (status, health))
save("public-health.json", health)

print("INIT")
shred_path(STORE)
os.makedirs(STORE, mode=0o700)
run(prom("init"), "init")
save(
    "a-init-note.txt",
    "init ran on hostname 5090. Secret files stay under /tmp/prometheus-member-two-public-20260823. This throwaway issuer is not the standing operator store.\n",
)

print("AGENT-TYPE")
agent = run_json(
    prom(
        "agent-type",
        "add",
        "--owner",
        "jason-gale",
        "--intent",
        "read",
        "--authorization-limit",
        AUDIENCE,
        "--lifetime-seconds",
        "3600",
    ),
    "agent-type add",
)
agent_type_id = agent.get("id") or agent.get("agent_type_id")
if not agent_type_id:
    raise SystemExit("agent-type missing id: %s" % sorted(agent.keys()))
save("a-agent-type.json", {"id": agent_type_id, "keys": sorted(agent.keys())})

print("MEMBER-ADD")
member = run_json(prom("issuer", "member", "add", "--secret-path", MEMBER), "issuer member add")
save(
    "a-member-two.json",
    {
        "keys": sorted(member.keys()) if isinstance(member, dict) else [],
        "threshold_n": member.get("threshold_n") if isinstance(member, dict) else None,
        "member_count_field_present": "public_keys" in member if isinstance(member, dict) else False,
        "public_keys_count": len(member.get("public_keys", [])) if isinstance(member, dict) else 0,
        "secret_path_was_mount": True,
        "standing_laptop_member_not_used": True,
    },
)
if not Path(MEMBER).is_file():
    raise SystemExit("kernel did not write member two through the mount")

print("THRESHOLD")
threshold = run_json(prom("issuer", "threshold", "--n", "2"), "issuer threshold")
save(
    "a-threshold.json",
    {
        "threshold_n": threshold.get("threshold_n"),
        "keys": sorted(threshold.keys()) if isinstance(threshold, dict) else [],
    },
)
if threshold.get("threshold_n") != 2:
    raise SystemExit("threshold_n must be 2: %s" % threshold.get("threshold_n"))

status_text = run(prom_member("status"), "status")
save("a-status.txt", status_text)
if "threshold_n: 2" not in status_text:
    raise SystemExit("status must show threshold_n 2")

issuer_record = json.loads((Path(STORE) / "issuer.json").read_text())
key = issuer_record.get("current_public_key") or ""
if len(key) < 64:
    raise SystemExit("current_public_key missing or short")
save("a-issuer-public-key-length.txt", "public_key_hex_length=%s\n" % len(key))
(WALK / "a-issuer-public-key.hex").write_text(key + "\n")

print("BIRTH")
birth = run_json(
    prom_member(
        "birth",
        "--agent-type",
        agent_type_id,
        "--owner",
        "jason-gale",
        "--intent",
        "read",
        "--audience",
        AUDIENCE,
    ),
    "birth",
)
instance_id = birth["instance"]["id"]
capability_id = birth["capability"]["id"]
holder = Path(STORE) / "holders" / ("%s.secret" % instance_id)
if not holder.is_file():
    raise SystemExit("holder secret missing under throwaway store")
save(
    "a-birth.json",
    {
        "instance_id": instance_id,
        "capability_id": capability_id,
        "holder_secret_path_under_throwaway": True,
        "member_secret_used": "mount",
        "keys": sorted(birth.keys()),
    },
)

print("ISSUER-ACCEPT")
status, accept = http("POST", PUBLIC + "/issuer-accept", {"public_key_hex": key}, timeout=20)
print("ISSUER-ACCEPT", status, sorted(accept.keys()) if isinstance(accept, dict) else accept)
if status != 200:
    raise SystemExit("public issuer-accept failed: %s %s" % (status, accept))
save(
    "public-issuer-accept.json",
    {
        "http_status": status,
        "request_keys": ["public_key_hex"],
        "response_keys": sorted(accept.keys()) if isinstance(accept, dict) else [],
        "public_key_hex_length": len(accept.get("public_key_hex", "")) if isinstance(accept, dict) else 0,
    },
)

print("PRESENT")
presentation_json, certificate_pem, present_meta = mint_present()
save(
    "a-present-svid-keys.json",
    {
        "keys": sorted(present_meta.keys()) if isinstance(present_meta, dict) else [],
        "svid_signer": present_meta.get("svid_signer") if isinstance(present_meta, dict) else None,
    },
)

print("CHECK-SVID ALLOW")
status, allow = check_svid_public(presentation_json, certificate_pem)
reason = (allow.get("reason") if isinstance(allow, dict) else "") or ""
if status != 200 or (isinstance(allow, dict) and allow.get("result") not in (None, "allowed") and allow.get("result") != "allowed"):
    if "expir" in reason.lower():
        print("ALLOW expired, remint once")
        presentation_json, certificate_pem, present_meta = mint_present()
        status, allow = check_svid_public(presentation_json, certificate_pem)
        reason = (allow.get("reason") if isinstance(allow, dict) else "") or ""
if status != 200:
    raise SystemExit("public check-svid must allow: HTTP %s %s" % (status, allow))
if isinstance(allow, dict) and allow.get("result") not in (None, "allowed") and str(allow.get("result", "")).lower() != "allowed":
    raise SystemExit("public check-svid must allow: %s" % allow)
# Some check responses use decision/allowed.
allowed = False
if isinstance(allow, dict):
    result = str(allow.get("result") or allow.get("decision") or "").lower()
    allowed = result in ("allowed", "allow", "") and status == 200
    if allow.get("allowed") is True:
        allowed = True
    if "refused" in result:
        allowed = False
if not allowed:
    raise SystemExit("public check-svid must allow: %s" % allow)
save(
    "public-check-svid-allow.json",
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
killed = run_json(prom_member("instance", "kill", "--instance", instance_id), "instance kill")
save(
    "a-kill.json",
    {
        "instance_id": killed.get("id") or instance_id,
        "status": killed.get("status"),
        "keys": sorted(killed.keys()) if isinstance(killed, dict) else [],
    },
)

export_dir = Path("/tmp/prometheus-member-two-public-kill-20260823")
if export_dir.exists():
    shutil.rmtree(export_dir)
export_dir.mkdir(mode=0o700)
run(
    prom_member("kill", "export", "--instance", instance_id, "--output", str(export_dir)),
    "kill export",
)
event = json.loads((export_dir / "event.json").read_text())
proof = json.loads((export_dir / "proof.json").read_text())
tree_head = json.loads((export_dir / "tree-head.json").read_text())
# Public artifacts may live in see-walk.
shutil.copy2(export_dir / "event.json", WALK / "kill-event.json")
shutil.copy2(export_dir / "proof.json", WALK / "kill-proof.json")
shutil.copy2(export_dir / "tree-head.json", WALK / "kill-tree-head.json")
save("kill-export-keys.json", {"event_keys": sorted(event.keys()), "proof_keys": sorted(proof.keys()), "tree_head_keys": sorted(tree_head.keys())})

print("KILL-ACCEPT")
status, kill_accept = http(
    "POST",
    PUBLIC + "/kill-accept",
    {"event": event, "proof": proof, "tree_head": tree_head},
    timeout=20,
)
print("KILL-ACCEPT", status, sorted(kill_accept.keys()) if isinstance(kill_accept, dict) and status == 200 else kill_accept)
if status != 200:
    raise SystemExit("public kill-accept failed: %s %s" % (status, kill_accept))
save(
    "public-kill-accept.json",
    {
        "http_status": status,
        "accepted_killed_instance_ids": kill_accept.get("accepted_killed_instance_ids"),
        "accepted_killed_capability_ids": kill_accept.get("accepted_killed_capability_ids"),
        "keys": sorted(kill_accept.keys()) if isinstance(kill_accept, dict) else [],
    },
)

print("CHECK-SVID REFUSE")
status, refused = check_svid_public(presentation_json, certificate_pem)
reason = (refused.get("reason") if isinstance(refused, dict) else "") or ""
print("REFUSE", status, reason)
if status == 200 and str(refused.get("result", "")).lower() in ("allowed", "allow"):
    raise SystemExit("historical present must refuse after kill-accept: %s" % refused)
if "expir" in reason.lower() and not refuse_names_accepted_kill(reason):
    raise SystemExit("refuse must name accepted kill, not expiry: %s" % reason)
if not refuse_names_accepted_kill(reason):
    raise SystemExit("refuse must name accepted kill: %s" % reason)
save(
    "public-check-svid-after-kill.json",
    {
        "http_status": status,
        "result": refused.get("result") if isinstance(refused, dict) else None,
        "reason": reason,
        "keys": sorted(refused.keys()) if isinstance(refused, dict) else [],
        "holder_secret_bytes_sent_to_public_name": False,
        "member_secret_bytes_sent_to_public_name": False,
    },
)

if Path(STANDING_LAPTOP_MEMBER).stat().st_mtime != standing_mtime:
    raise SystemExit("standing laptop member-two.secret mtime changed")

print("SHRED")
# Shred throwaway store and any /tmp issuer.secret copies. Leave VPC custody.
for leftover in Path("/tmp").glob("**/issuer.secret"):
    if STORE in str(leftover) or leftover.is_file():
        if leftover.is_file():
            shred_file(leftover)
shred_path(STORE)
shred_path(export_dir)
if Path(STORE).exists():
    shutil.rmtree(STORE, ignore_errors=True)
if Path(STORE).exists():
    raise SystemExit("throwaway store still exists after shred")
if Path(MEMBER).is_file():
    vpc_left = True
else:
    raise SystemExit("VPC member-two.secret missing after shred; custody dir must stay")

assert_no_secrets_in_walk()
save(
    "shred-note.txt",
    "Throwaway store /tmp/prometheus-member-two-public-20260823 was shredded. Kill-export temp dir shredded. VPC member-two-custody left in place. Standing laptop member-two.secret mtime unchanged. No issuer.secret left under /tmp from this walk.\n",
)
print("DONE allow-then-refuse")
