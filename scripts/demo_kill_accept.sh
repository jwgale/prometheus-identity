#!/usr/bin/env bash
# Demonstration: two-store portable death.
# Store A kills a parent instance. Store B accepts that kill bundle.
# Store B is a verifier. Store B does not mint.
# Issuance threshold_n stays 1. This walkthrough does not add a second member.
# Do not pass secrets between stores.
# This is not Sanctum. This is not a sixth identity record.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_A="${DEMO_DATA_A:-}"
DATA_B="${DEMO_DATA_B:-}"
if [ -z "$DATA_A" ]; then
  DATA_A="$(mktemp -d "${TMPDIR:-/tmp}/prometheus-kill-a.XXXXXX")"
fi
if [ -z "$DATA_B" ]; then
  DATA_B="$(mktemp -d "${TMPDIR:-/tmp}/prometheus-kill-b.XXXXXX")"
fi
cleanup() { rm -rf "$DATA_A" "$DATA_B"; }
if [ -z "${DEMO_DATA_A:-}" ] && [ -z "${DEMO_DATA_B:-}" ]; then
  trap cleanup EXIT
fi

if [ -x "$ROOT/target/release/prometheus" ]; then
  BIN="$ROOT/target/release/prometheus"
elif [ -x "$ROOT/target/debug/prometheus" ]; then
  BIN="$ROOT/target/debug/prometheus"
else
  cargo build --release
  BIN="$ROOT/target/release/prometheus"
fi

json_get() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"
}

json_nested() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]][sys.argv[3]])' "$1" "$2" "$3"
}

save_receipt() {
  python3 - "$1" "$2" << 'PY'
import json, pathlib, sys
decision = json.load(open(sys.argv[1]))
if decision.get("result") != "allowed":
    raise SystemExit("The check must be allowed.")
receipt = decision.get("receipt")
if not isinstance(receipt, dict) or not receipt.get("signature"):
    raise SystemExit("The check must return a signed decision receipt.")
pathlib.Path(sys.argv[2]).write_text(json.dumps(receipt, indent=2) + "\n")
PY
}

echo_refuse_reason() {
  python3 - "$1" << 'PY'
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
PY
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
"$BIN" --data-directory "$DATA_A" init >/dev/null
"$BIN" --data-directory "$DATA_B" init >/dev/null

python3 - "$DATA_A" "$DATA_A/issuer-public-key.hex" << 'PY'
import json, pathlib, sys
issuer = json.loads((pathlib.Path(sys.argv[1]) / "issuer.json").read_text())
key = (issuer.get("current_public_key") or issuer["public_keys"][0]).strip()
if not key:
    raise SystemExit("Store A must have an issuer public key.")
pathlib.Path(sys.argv[2]).write_text(key + "\n")
print("Store A issuer public key was written to a file.")
PY
ISSUER_PUBLIC_KEY="$(tr -d "[:space:]" < "$DATA_A/issuer-public-key.hex")"

echo "Store B accepts the store A issuer public key. Store B does not receive a secret."
"$BIN" --data-directory "$DATA_B" issuer accept --public-key-hex "$ISSUER_PUBLIC_KEY" >/dev/null

echo "Adding an agent type and birthing one parent instance on store A."
"$BIN" --data-directory "$DATA_A" agent-type add \
  --owner laboratory --intent read --authorization-limit payments \
  --max-delegation-depth 2 --lifetime-seconds 3600 >"$DATA_A/agent-type.json"
AGENT_TYPE_ID="$(json_get "$DATA_A/agent-type.json" id)"
"$BIN" --data-directory "$DATA_A" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience payments \
  >"$DATA_A/birth.json"
PARENT_INSTANCE="$(json_nested "$DATA_A/birth.json" instance id)"
PARENT_CAPABILITY="$(json_nested "$DATA_A/birth.json" capability id)"
PARENT_SECRET="$DATA_A/holders/${PARENT_INSTANCE}.secret"

echo "Issuing a one-time holder challenge and allowing a parent tool act."
"$BIN" --data-directory "$DATA_A" challenge --instance "$PARENT_INSTANCE" >"$DATA_A/parent-challenge.json"
PARENT_NONCE="$(json_get "$DATA_A/parent-challenge.json" nonce)"
"$BIN" --data-directory "$DATA_A" check \
  --instance "$PARENT_INSTANCE" --capability "$PARENT_CAPABILITY" \
  --intent read --audience payments \
  --holder-secret-path "$PARENT_SECRET" --challenge-nonce "$PARENT_NONCE" \
  --on-behalf-of autonomous >"$DATA_A/parent-check.json"
PARENT_RECEIPT="$DATA_A/parent-receipt.json"
save_receipt "$DATA_A/parent-check.json" "$PARENT_RECEIPT"

echo "Exporting the parent act bundle from store A."
PARENT_ACT="$DATA_A/parent-act-bundle"
rm -rf "$PARENT_ACT"
"$BIN" --data-directory "$DATA_A" act export \
  --receipt "$PARENT_RECEIPT" --output-directory "$PARENT_ACT" >/dev/null

echo "Store B accepts the parent act bundle. Death is not yet accepted."
"$BIN" --data-directory "$DATA_B" act accept --bundle-directory "$PARENT_ACT"
python3 - "$DATA_B" << 'PY'
import pathlib, sys
log = (pathlib.Path(sys.argv[1]) / "issuance.log").read_text()
if log.strip():
    raise SystemExit("Act accept must not write a second issuance.log line.")
instances = pathlib.Path(sys.argv[1]) / "instances"
if instances.exists() and any(instances.glob("*.json")):
    raise SystemExit("Act accept must not create instance records.")
print("Store B did not mint. Store B did not write a second issuance.log line.")
PY

echo "Spawning one child instance so the kill cascade is visible."
"$BIN" --data-directory "$DATA_A" challenge --instance "$PARENT_INSTANCE" >"$DATA_A/spawn-challenge.json"
SPAWN_NONCE="$(json_get "$DATA_A/spawn-challenge.json" nonce)"
"$BIN" --data-directory "$DATA_A" spawn \
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

echo "Allowing a child tool act and exporting the child act bundle."
"$BIN" --data-directory "$DATA_A" challenge --instance "$CHILD_INSTANCE" >"$DATA_A/child-challenge.json"
CHILD_NONCE="$(json_get "$DATA_A/child-challenge.json" nonce)"
"$BIN" --data-directory "$DATA_A" check \
  --instance "$CHILD_INSTANCE" --capability "$CHILD_CAPABILITY" \
  --intent read --audience payments/prod \
  --holder-secret-path "$CHILD_SECRET" --challenge-nonce "$CHILD_NONCE" \
  --on-behalf-of autonomous >"$DATA_A/child-check.json"
CHILD_RECEIPT="$DATA_A/child-receipt.json"
save_receipt "$DATA_A/child-check.json" "$CHILD_RECEIPT"
CHILD_ACT="$DATA_A/child-act-bundle"
rm -rf "$CHILD_ACT"
"$BIN" --data-directory "$DATA_A" act export \
  --receipt "$CHILD_RECEIPT" --output-directory "$CHILD_ACT" >/dev/null

echo "Writing signed presentation documents for the parent and the child."
"$BIN" --data-directory "$DATA_A" challenge --instance "$PARENT_INSTANCE" >"$DATA_A/parent-present-challenge.json"
PARENT_PRESENT_NONCE="$(json_get "$DATA_A/parent-present-challenge.json" nonce)"
PARENT_PRESENT="$DATA_A/parent-presentation.json"
"$BIN" --data-directory "$DATA_A" present \
  --instance "$PARENT_INSTANCE" \
  --capability "$PARENT_CAPABILITY" \
  --output "$PARENT_PRESENT" \
  --holder-secret-path "$PARENT_SECRET" \
  --challenge-nonce "$PARENT_PRESENT_NONCE" >/dev/null

"$BIN" --data-directory "$DATA_A" challenge --instance "$CHILD_INSTANCE" >"$DATA_A/child-present-challenge.json"
CHILD_PRESENT_NONCE="$(json_get "$DATA_A/child-present-challenge.json" nonce)"
CHILD_PRESENT="$DATA_A/child-presentation.json"
"$BIN" --data-directory "$DATA_A" present \
  --instance "$CHILD_INSTANCE" \
  --capability "$CHILD_CAPABILITY" \
  --output "$CHILD_PRESENT" \
  --holder-secret-path "$CHILD_SECRET" \
  --challenge-nonce "$CHILD_PRESENT_NONCE" >/dev/null

echo "Store B verifies the parent presentation before death. This check must succeed."
"$BIN" --data-directory "$DATA_B" present verify --presentation "$PARENT_PRESENT"

echo "Killing the parent instance on store A."
"$BIN" --data-directory "$DATA_A" instance kill --instance "$PARENT_INSTANCE" >/dev/null

echo "Exporting the parent kill bundle from store A."
KILL_BUNDLE="$DATA_A/kill-bundle"
rm -rf "$KILL_BUNDLE"
"$BIN" --data-directory "$DATA_A" kill export --instance "$PARENT_INSTANCE" --output "$KILL_BUNDLE"
python3 - "$KILL_BUNDLE" "$PARENT_INSTANCE" "$CHILD_INSTANCE" << 'PY'
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
PY

echo "Store B accepts the parent kill bundle."
"$BIN" --data-directory "$DATA_B" kill accept --bundle "$KILL_BUNDLE"
python3 - "$DATA_B" "$PARENT_INSTANCE" "$CHILD_INSTANCE" << 'PY'
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
PY

echo "Store B must refuse present verify and act accept after kill accept."
must_refuse \
  "$DATA_B/parent-present.out" "$DATA_B/parent-present.err" \
  "Parent present verify" \
  "$BIN" --data-directory "$DATA_B" present verify --presentation "$PARENT_PRESENT"

must_refuse \
  "$DATA_B/child-present.out" "$DATA_B/child-present.err" \
  "Child present verify" \
  "$BIN" --data-directory "$DATA_B" present verify --presentation "$CHILD_PRESENT"

must_refuse \
  "$DATA_B/parent-act.out" "$DATA_B/parent-act.err" \
  "Parent act accept" \
  "$BIN" --data-directory "$DATA_B" act accept --bundle-directory "$PARENT_ACT"

must_refuse \
  "$DATA_B/child-act.out" "$DATA_B/child-act.err" \
  "Child act accept" \
  "$BIN" --data-directory "$DATA_B" act accept --bundle-directory "$CHILD_ACT"

echo "This walkthrough does not clear accepted kills. Clearing is not a success path."
echo "The two-store portable death demonstration completed successfully."
