#!/usr/bin/env bash
# Demonstration: a foreign verifier checks a laboratory X.509-SVID wrap of present.
# Store A writes the wrap. Store B accepts the store A issuer public key only.
# Issuance threshold_n stays 1. This walkthrough does not add a second member.
# Do not pass secrets between stores.
# The wrap is an artifact. Present is a document. This is not a sixth identity record.
# The instance identifier is not a distinguished name. Short life is not kill.
# This is not Sanctum. This is not SPIRE. This is not a public listener.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_A="${DEMO_DATA_A:-}"
DATA_B="${DEMO_DATA_B:-}"
if [ -z "$DATA_A" ]; then
  DATA_A="$(mktemp -d "${TMPDIR:-/tmp}/prometheus-svid-a.XXXXXX")"
fi
if [ -z "$DATA_B" ]; then
  DATA_B="$(mktemp -d "${TMPDIR:-/tmp}/prometheus-svid-b.XXXXXX")"
fi
cleanup() { rm -rf "$DATA_A" "$DATA_B"; }
if [ -z "${DEMO_DATA_A:-}" ] && [ -z "${DEMO_DATA_B:-}" ]; then
  trap cleanup EXIT
fi

if [ "${PROMETHEUS_USE_CARGO:-}" = "1" ]; then
  prometheus() {
    cargo run --release -- "$@"
  }
elif [ -x "$ROOT/target/release/prometheus" ]; then
  BIN="$ROOT/target/release/prometheus"
  prometheus() { "$BIN" "$@"; }
elif [ -x "$ROOT/target/debug/prometheus" ]; then
  BIN="$ROOT/target/debug/prometheus"
  prometheus() { "$BIN" "$@"; }
else
  cargo build --release
  BIN="$ROOT/target/release/prometheus"
  prometheus() { "$BIN" "$@"; }
fi

json_get() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"
}

json_nested() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]][sys.argv[3]])' "$1" "$2" "$3"
}

echo_refuse_reason() {
  python3 - "$1" << 'INNER'
import json, pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text()
try:
    payload = json.loads(text)
    reason = payload.get("reason") or text.strip()
except json.JSONDecodeError:
    reason = text.strip()
if not reason:
    raise SystemExit("The refuse output is empty.")
print(reason)
INNER
}

must_refuse() {
  local out="$1"
  local err="$2"
  local label="$3"
  shift 3
  if "$@" >"$out" 2>"$err"; then
    echo "${label} succeeded. A refuse was required."
    exit 1
  fi
  echo "${label} was refused."
  echo "Refuse reason:"
  echo_refuse_reason "$err"
}

echo "Initializing store A and store B."
prometheus --data-directory "$DATA_A" init >"$DATA_A/init.json"
prometheus --data-directory "$DATA_B" init >"$DATA_B/init.json"

python3 - "$DATA_A" "$DATA_B" "$DATA_A/issuer-public-key.hex" << 'INNER'
import json, pathlib, sys
data_a = pathlib.Path(sys.argv[1])
data_b = pathlib.Path(sys.argv[2])
key_path = pathlib.Path(sys.argv[3])
issuer_a = json.loads((data_a / "issuer.json").read_text())
issuer_b = json.loads((data_b / "issuer.json").read_text())
key = (issuer_a.get("current_public_key") or issuer_a["public_keys"][0]).strip()
if not key:
    raise SystemExit("Store A must have an issuer public key.")
if int(issuer_a.get("threshold_n") or 1) != 1:
    raise SystemExit("Store A issuance threshold_n must stay 1.")
if int(issuer_b.get("threshold_n") or 1) != 1:
    raise SystemExit("Store B issuance threshold_n must stay 1.")
if int(issuer_a.get("verify_threshold_n") or 1) != 1:
    raise SystemExit("Store A verify_threshold_n must stay 1.")
if int(issuer_b.get("verify_threshold_n") or 1) != 1:
    raise SystemExit("Store B verify_threshold_n must stay 1.")
key_path.write_text(key + "\n")
print("Issuance threshold_n is 1. Verify threshold_n is 1. No second member was added.")
print("Store A issuer public key was written to a file.")
INNER
ISSUER_PUBLIC_KEY="$(tr -d "[:space:]" < "$DATA_A/issuer-public-key.hex")"

echo "Store B accepts the store A issuer public key. Store B does not receive a secret."
prometheus --data-directory "$DATA_B" issuer accept --public-key-hex "$ISSUER_PUBLIC_KEY" >"$DATA_B/issuer-accept.json"

echo "Adding an agent type and birthing one parent instance on store A."
prometheus --data-directory "$DATA_A" agent-type add \
  --owner laboratory --intent read --authorization-limit payments \
  --max-delegation-depth 2 --lifetime-seconds 3600 >"$DATA_A/agent-type.json"
AGENT_TYPE_ID="$(json_get "$DATA_A/agent-type.json" id)"
prometheus --data-directory "$DATA_A" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience payments \
  >"$DATA_A/birth.json"
PARENT_INSTANCE="$(json_nested "$DATA_A/birth.json" instance id)"
PARENT_CAPABILITY="$(json_nested "$DATA_A/birth.json" capability id)"
PARENT_SECRET="$DATA_A/holders/${PARENT_INSTANCE}.secret"

echo "Issuing a one-time holder challenge. Present is not a bearer document."
prometheus --data-directory "$DATA_A" challenge --instance "$PARENT_INSTANCE" >"$DATA_A/parent-challenge.json"
PARENT_NONCE="$(json_get "$DATA_A/parent-challenge.json" nonce)"

PARENT_PRESENT="$DATA_A/parent-presentation.json"
PARENT_SVID="$DATA_A/parent-presentation.json.svid.pem"
echo "Writing a laboratory X.509-SVID wrap of the parent presentation."
prometheus --data-directory "$DATA_A" present \
  --format x509-svid \
  --instance "$PARENT_INSTANCE" \
  --capability "$PARENT_CAPABILITY" \
  --output "$PARENT_PRESENT" \
  --holder-secret-path "$PARENT_SECRET" \
  --challenge-nonce "$PARENT_NONCE" >"$DATA_A/parent-present-emit.json"
if [ ! -f "$PARENT_SVID" ]; then
  echo "The parent sidecar PEM is missing."
  exit 1
fi

echo "Store B verifies the parent wrap. Death is not yet accepted. This check must succeed."
prometheus --data-directory "$DATA_B" present verify \
  --format x509-svid \
  --svid "$PARENT_SVID" \
  --presentation "$PARENT_PRESENT" >"$DATA_B/parent-verify-live.json"

echo "Spawning one child instance so the kill cascade is visible."
prometheus --data-directory "$DATA_A" challenge --instance "$PARENT_INSTANCE" >"$DATA_A/spawn-challenge.json"
SPAWN_NONCE="$(json_get "$DATA_A/spawn-challenge.json" nonce)"
prometheus --data-directory "$DATA_A" spawn \
  --parent-instance "$PARENT_INSTANCE" \
  --parent-capability "$PARENT_CAPABILITY" \
  --owner child \
  --intent read \
  --audience payments/prod \
  --holder-secret-path "$PARENT_SECRET" \
  --challenge-nonce "$SPAWN_NONCE" >"$DATA_A/spawn.json"
CHILD_INSTANCE="$(json_nested "$DATA_A/spawn.json" instance id)"
CHILD_CAPABILITY="$(json_nested "$DATA_A/spawn.json" capability id)"
CHILD_SECRET="$DATA_A/holders/${CHILD_INSTANCE}.secret"

echo "Issuing a one-time holder challenge for the child."
prometheus --data-directory "$DATA_A" challenge --instance "$CHILD_INSTANCE" >"$DATA_A/child-challenge.json"
CHILD_NONCE="$(json_get "$DATA_A/child-challenge.json" nonce)"

CHILD_PRESENT="$DATA_A/child-presentation.json"
CHILD_SVID="$DATA_A/child-presentation.json.svid.pem"
echo "Writing a laboratory X.509-SVID wrap of the child presentation."
prometheus --data-directory "$DATA_A" present \
  --format x509-svid \
  --instance "$CHILD_INSTANCE" \
  --capability "$CHILD_CAPABILITY" \
  --output "$CHILD_PRESENT" \
  --holder-secret-path "$CHILD_SECRET" \
  --challenge-nonce "$CHILD_NONCE" >"$DATA_A/child-present-emit.json"
if [ ! -f "$CHILD_SVID" ]; then
  echo "The child sidecar PEM is missing."
  exit 1
fi

echo "Store B verifies the child wrap. Death is not yet accepted. This check must succeed."
prometheus --data-directory "$DATA_B" present verify-svid \
  --svid "$CHILD_SVID" \
  --presentation "$CHILD_PRESENT" >"$DATA_B/child-verify-live.json"

python3 - "$CHILD_PRESENT" "$PARENT_INSTANCE" << 'INNER'
import json, pathlib, sys
presentation = json.loads(pathlib.Path(sys.argv[1]).read_text())
ancestors = presentation.get("ancestor_instance_ids") or []
if sys.argv[2] not in ancestors:
    raise SystemExit("The child presentation must sign the parent as an ancestor.")
print("The child wrap signs the parent as an ancestor.")
INNER

echo "Killing the parent instance on store A."
prometheus --data-directory "$DATA_A" instance kill --instance "$PARENT_INSTANCE" >"$DATA_A/parent-kill.json"

echo "Exporting the parent kill bundle from store A."
KILL_BUNDLE="$DATA_A/kill-bundle"
rm -rf "$KILL_BUNDLE"
prometheus --data-directory "$DATA_A" kill export --instance "$PARENT_INSTANCE" --output "$KILL_BUNDLE" >"$DATA_A/kill-export.json"
python3 - "$KILL_BUNDLE" "$PARENT_INSTANCE" "$CHILD_INSTANCE" << 'INNER'
import json, pathlib, sys
bundle = pathlib.Path(sys.argv[1])
for name in ("event.json", "proof.json", "tree-head.json"):
    if not (bundle / name).exists():
        raise SystemExit(f"The kill bundle is missing {name}.")
event = json.loads((bundle / "event.json").read_text())
if event.get("event") != "kill_instance":
    raise SystemExit("The kill bundle event must be kill_instance.")
if event.get("instance_id") != sys.argv[2]:
    raise SystemExit("The kill bundle must bind the parent instance.")
killed = event.get("killed_instance_ids") or []
if sys.argv[2] not in killed or sys.argv[3] not in killed:
    raise SystemExit("The parent kill line must carry the parent and the child identifiers.")
print("The parent kill bundle carries the signed cascade.")
INNER

echo "Store B accepts the parent kill bundle."
prometheus --data-directory "$DATA_B" kill accept --bundle "$KILL_BUNDLE" >"$DATA_B/kill-accept.json"
python3 - "$DATA_B" "$PARENT_INSTANCE" "$CHILD_INSTANCE" << 'INNER'
import json, pathlib, sys
data_b = pathlib.Path(sys.argv[1])
log = (data_b / "issuance.log").read_text()
if log.strip():
    raise SystemExit("Kill accept must not write a second issuance.log line.")
instances = data_b / "instances"
if instances.exists() and any(instances.glob("*.json")):
    raise SystemExit("Kill accept must not create instance records.")
issuer = json.loads((data_b / "issuer.json").read_text())
killed = issuer.get("accepted_killed_instance_ids") or []
if sys.argv[2] not in killed:
    raise SystemExit("Store B must persist parent death on the issuer.")
if sys.argv[3] not in killed:
    raise SystemExit("Store B must persist child death from the signed cascade.")
print("Accepted death is verifier state on the issuer. This is not a sixth identity record.")
INNER

echo "Store B must refuse the parent wrap after kill accept."
must_refuse \
  "$DATA_B/parent-svid.out" "$DATA_B/parent-svid.err" \
  "Parent verify-svid" \
  prometheus --data-directory "$DATA_B" present verify-svid \
    --svid "$PARENT_SVID" \
    --presentation "$PARENT_PRESENT"

echo "Store B must refuse the child wrap after kill accept."
must_refuse \
  "$DATA_B/child-svid.out" "$DATA_B/child-svid.err" \
  "Child verify-svid" \
  prometheus --data-directory "$DATA_B" present verify-svid \
    --svid "$CHILD_SVID" \
    --presentation "$CHILD_PRESENT"

python3 - "$DATA_B/parent-svid.err" "$DATA_B/child-svid.err" << 'INNER'
import json, pathlib, sys
def reason(path):
    text = pathlib.Path(path).read_text()
    try:
        payload = json.loads(text)
        return payload.get("reason") or text
    except json.JSONDecodeError:
        return text
parent = reason(sys.argv[1]).lower()
child = reason(sys.argv[2]).lower()
if "kill accept" not in parent:
    raise SystemExit("The parent refuse reason must name kill accept.")
if "kill accept" not in child:
    raise SystemExit("The child refuse reason must name kill accept.")
if "ancestor" not in child and "this instance" not in child:
    raise SystemExit("The child refuse reason must name kill accept or a signed ancestor.")
print("Parent refuse names kill accept. Child refuse names kill accept or ancestor.")
INNER

echo "Confirming the parent PEM omits the subject distinguished name and the instance identifier."
python3 - "$PARENT_SVID" "$PARENT_PRESENT" "$PARENT_INSTANCE" << 'INNER'
import pathlib, re, subprocess, sys
pem = pathlib.Path(sys.argv[1])
presentation = json_load = __import__("json").loads(pathlib.Path(sys.argv[2]).read_text())
instance_id = sys.argv[3]
text = subprocess.check_output(["openssl", "x509", "-in", str(pem), "-noout", "-text"], text=True)
subject_line = ""
for line in text.splitlines():
    if line.strip().startswith("Subject:"):
        subject_line = line.split(":", 1)[1].strip()
        break
if instance_id in subject_line:
    raise SystemExit("The subject distinguished name must not contain the instance identifier.")
if re.search(r"\bCN\b", subject_line):
    raise SystemExit("The subject distinguished name must be omitted.")
if subject_line not in ("", "None"):
    # openssl may print an empty SEQUENCE as a blank subject. Any attribute is a failure.
    compact = subject_line.replace(" ", "")
    if compact and compact not in {".", "CN=", "C=", "O=", "OU="}:
        if "=" in subject_line or instance_id in subject_line:
            raise SystemExit(f"The subject distinguished name must be omitted. Found: {subject_line}")
uris = re.findall(r"URI:(\S+)", text)
if len(uris) != 1:
    raise SystemExit(f"The certificate must have exactly one Uniform Resource Identifier. Found {uris!r}.")
uri = uris[0].rstrip(",")
print(f"Uniform Resource Identifier subject alternative name: {uri}")
if instance_id in uri:
    raise SystemExit("The Uniform Resource Identifier must not contain the instance identifier.")
if not uri.startswith("spiffe://prometheus.laboratory/present/"):
    raise SystemExit("The Uniform Resource Identifier must name the presentation document.")
digest = uri.rsplit("/", 1)[-1]
if not re.fullmatch(r"[0-9a-f]{64}", digest):
    raise SystemExit("The Uniform Resource Identifier path must be the SHA-256 hexadecimal of the presentation bytes.")
print("The Uniform Resource Identifier names the presentation. The instance identifier is not in the Uniform Resource Identifier.")
print("The subject distinguished name is omitted.")
INNER

SEE_WALK="$ROOT/see-walk"
if [ -d "$SEE_WALK" ]; then
  cp -f "$PARENT_PRESENT" "$SEE_WALK/parent-x509-svid.json"
  cp -f "$PARENT_SVID" "$SEE_WALK/parent-x509-svid.pem"
  echo "Non-secret parent presentation JSON and PEM were copied to see-walk."
fi

echo "This walkthrough does not clear accepted kills. Clearing is not a success path."
echo "The two-store laboratory X.509-SVID death demonstration completed successfully."
