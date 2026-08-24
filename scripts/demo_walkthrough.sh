#!/usr/bin/env bash
# One walkthrough of the Prometheus kernel.
# Init, status, birth, check, present, act, status, then one fail-closed refuse.
# This is shorter than the twenty-four focused demonstrations.
# This is not Sanctum. This is not a sixth identity record.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_DIRECTORY="$(mktemp -d "${TMPDIR:-/tmp}/prometheus-walkthrough.XXXXXX")"
cleanup() { rm -rf "$DATA_DIRECTORY"; }
trap cleanup EXIT

echo "Building the Prometheus package."
cargo build
BIN="$ROOT/target/debug/prometheus"

echo "Initializing the laboratory issuer."
"$BIN" --data-directory "$DATA_DIRECTORY" init >/dev/null

echo "Showing status of the empty store."
STATUS_EMPTY="$("$BIN" --data-directory "$DATA_DIRECTORY" status)"
printf '%s\n' "$STATUS_EMPTY"
python3 -c '
import sys
text = sys.argv[1]
needles = (
    "crypto_profile: lab-ml-dsa-65-hybrid-biscuit-ed25519",
    "The identity root is Module-Lattice Digital Signature Algorithm 65",
    "The Biscuit envelope is laboratory Ed25519 and is not a threshold member",
    "threshold_n: 1",
    "member_count: 1",
    "sealed: no",
    "agent_types: 0",
    "0 live, 0 revoked",
    "issuance_log_leaf_count: 0",
    "The check host must bind to 127.0.0.1 only",
)
for needle in needles:
    if needle not in text:
        raise SystemExit(f"Empty-store status is missing: {needle}")
if "issuer.secret" in text or "biscuit.secret" in text:
    raise SystemExit("Status must not name secret files.")
print("Empty-store status is honest.")
' "$STATUS_EMPTY"

echo "Adding an agent type and birthing one instance as one write."
AGENT_TYPE_ID="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type add \
  --owner laboratory --intent read --authorization-limit internal \
  --max-delegation-depth 2 --lifetime-seconds 3600 | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
BIRTH_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience internal)"
INSTANCE_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["id"])' "$BIRTH_JSON")"
CAPABILITY_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["capability"]["id"])' "$BIRTH_JSON")"
SECRET="$DATA_DIRECTORY/holders/${INSTANCE_ID}.secret"
echo "The instance identifier is ${INSTANCE_ID}."

echo "Issuing a one-time holder challenge and allowing a tool act."
NONCE="$("$BIN" --data-directory "$DATA_DIRECTORY" challenge --instance "$INSTANCE_ID" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])')"
ALLOWED_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" check \
  --instance "$INSTANCE_ID" --capability "$CAPABILITY_ID" \
  --intent read --audience internal \
  --holder-secret-path "$SECRET" --challenge-nonce "$NONCE" \
  --on-behalf-of autonomous)"
RECEIPT_PATH="$DATA_DIRECTORY/allowed_receipt.json"
python3 -c '
import json, pathlib, sys
decision = json.loads(sys.argv[1])
if decision.get("result") != "allowed":
    raise SystemExit("The check must be allowed.")
receipt = decision.get("receipt")
if not isinstance(receipt, dict) or not receipt.get("signature"):
    raise SystemExit("The check must return a signed decision receipt.")
pathlib.Path(sys.argv[2]).write_text(json.dumps(receipt, indent=2) + "\n")
print("The tool act was allowed. The signed receipt was saved.")
' "$ALLOWED_JSON" "$RECEIPT_PATH"

echo "Writing a signed presentation document and verifying it."
PRESENT_NONCE="$("$BIN" --data-directory "$DATA_DIRECTORY" challenge --instance "$INSTANCE_ID" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])')"
PRESENTATION_PATH="$DATA_DIRECTORY/presentation.json"
"$BIN" --data-directory "$DATA_DIRECTORY" present \
  --instance "$INSTANCE_ID" \
  --capability "$CAPABILITY_ID" \
  --output "$PRESENTATION_PATH" \
  --holder-secret-path "$SECRET" \
  --challenge-nonce "$PRESENT_NONCE" >/dev/null
"$BIN" --data-directory "$DATA_DIRECTORY" present verify --presentation "$PRESENTATION_PATH"
echo "The presentation document verified. Present is a document, not a name."

echo "Exporting an act bundle and accepting it on this same store."
BUNDLE_DIRECTORY="$DATA_DIRECTORY/act-bundle"
"$BIN" --data-directory "$DATA_DIRECTORY" act export \
  --receipt "$RECEIPT_PATH" \
  --output-directory "$BUNDLE_DIRECTORY"
"$BIN" --data-directory "$DATA_DIRECTORY" act accept --bundle-directory "$BUNDLE_DIRECTORY"
echo "The act bundle was accepted. This store did not become a second identity kernel."

echo "Showing status after issuance."
STATUS_AFTER="$("$BIN" --data-directory "$DATA_DIRECTORY" status)"
printf '%s\n' "$STATUS_AFTER"
python3 -c '
import sys
text = sys.argv[1]
needles = (
    "threshold_n: 1",
    "member_count: 1",
    "sealed: no",
    "agent_types: 1",
    "1 live, 0 revoked",
    "The identity root is Module-Lattice Digital Signature Algorithm 65",
    "The check host must bind to 127.0.0.1 only",
)
for needle in needles:
    if needle not in text:
        raise SystemExit(f"After-issuance status is missing: {needle}")
if "issuance_log_leaf_count: 0" in text.split("JSON")[0]:
    raise SystemExit("After issuance the leaf count must not stay 0.")
print("After-issuance status counts the live store.")
' "$STATUS_AFTER"

echo "Checking with the wrong act authority. This check must refuse."
REFUSE_NONCE="$("$BIN" --data-directory "$DATA_DIRECTORY" challenge --instance "$INSTANCE_ID" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])')"
if "$BIN" --data-directory "$DATA_DIRECTORY" check \
  --instance "$INSTANCE_ID" --capability "$CAPABILITY_ID" \
  --intent read --audience internal \
  --holder-secret-path "$SECRET" --challenge-nonce "$REFUSE_NONCE" \
  --on-behalf-of jordan; then
  echo "The wrong act authority succeeded, but a failure was required."
  exit 1
fi
echo "The wrong act authority was refused. The kernel fails closed."

echo "The walkthrough completed successfully."
