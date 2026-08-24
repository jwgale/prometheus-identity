#!/usr/bin/env bash
# Demonstration: a pre-committed issuer seal is store-wide death.
# After kill_date the store refuses new mint, birth, and spawn, and refuses act.
# Historical receipt signature check of an already-written receipt still succeeds.
# This is not a previous-key kill_date. This is not a network partition detector.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_DIRECTORY="${DEMO_DATA_DIRECTORY:-$ROOT/data-issuer-seal}"
rm -rf "$DATA_DIRECTORY"
cargo build
BIN="$ROOT/target/debug/prometheus"

challenge_nonce() {
  "$BIN" --data-directory "$DATA_DIRECTORY" challenge --instance "$1" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])'
}

echo "Initializing the laboratory issuer and birthing one instance."
"$BIN" --data-directory "$DATA_DIRECTORY" init >/dev/null
AGENT_TYPE_ID="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type add \
  --owner laboratory --intent read --authorization-limit payments \
  --max-delegation-depth 2 --lifetime-seconds 3600 | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"

BIRTH_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience payments)"
INSTANCE_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["id"])' "$BIRTH_JSON")"
CAPABILITY_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["capability"]["id"])' "$BIRTH_JSON")"
SECRET="$DATA_DIRECTORY/holders/${INSTANCE_ID}.secret"

echo "Checking the live capability and saving the signed decision receipt."
ALLOWED_NONCE="$(challenge_nonce "$INSTANCE_ID")"
ALLOWED_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" check \
  --instance "$INSTANCE_ID" --capability "$CAPABILITY_ID" \
  --intent read --audience payments \
  --holder-secret-path "$SECRET" --challenge-nonce "$ALLOWED_NONCE" \
  --on-behalf-of autonomous)"
RECEIPT_PATH="${DATA_DIRECTORY}/pre_seal_receipt.json"
python3 -c '
import json, pathlib, sys
decision = json.loads(sys.argv[1])
if decision.get("result") != "allowed":
    raise SystemExit("The check before seal must be allowed.")
receipt = decision.get("receipt")
if not isinstance(receipt, dict) or not receipt.get("signature") or not receipt.get("issuance_log_line"):
    raise SystemExit("The check before seal must return a signed receipt bound to the issuance log.")
pathlib.Path(sys.argv[2]).write_text(json.dumps(receipt, indent=2) + "\n")
print("The pre-seal receipt was saved.")
' "$ALLOWED_JSON" "$RECEIPT_PATH"

echo "Sealing the issuer. After two seconds this store must refuse mint and act."
SEALED="$("$BIN" --data-directory "$DATA_DIRECTORY" issuer seal --after-seconds 2)"
python3 -c '
import json, sys
issuer = json.loads(sys.argv[1])
if not issuer.get("kill_date"):
    raise SystemExit("issuer seal must write issuer.kill_date.")
if issuer.get("previous_issuer_keys"):
    raise SystemExit("issuer seal must not write previous_issuer_keys. Realm death is not previous-key death.")
print("The issuer record now has a store-wide kill_date.")
' "$SEALED"

echo "Sleeping three seconds so the injected wall clock passes kill_date."
sleep 3

echo "A new birth after kill_date must be refused."
set +e
BIRTH_OUTPUT="$("$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner after-death --intent read --audience payments 2>&1)"
BIRTH_STATUS=$?
set -e
if [ "$BIRTH_STATUS" -eq 0 ]; then
  echo "Birth succeeded after kill_date, but a refusal was required."
  exit 1
fi
python3 -c '
import sys
text = sys.argv[1]
if "issuer seal" not in text and "kill_date" not in text:
    raise SystemExit("The refused birth must name the issuer seal. Output: %s" % text)
print("Birth after kill_date was refused.")
' "$BIRTH_OUTPUT"

echo "Verify after kill_date must be refused even if the capability is unexpired."
VERIFY_NONCE="$(challenge_nonce "$INSTANCE_ID")"
set +e
VERIFY_OUTPUT="$("$BIN" --data-directory "$DATA_DIRECTORY" capability verify \
  --capability "$CAPABILITY_ID" --audience payments --intent read \
  --holder-secret-path "$SECRET" --challenge-nonce "$VERIFY_NONCE" \
  --on-behalf-of autonomous 2>&1)"
VERIFY_STATUS=$?
set -e
if [ "$VERIFY_STATUS" -eq 0 ]; then
  echo "Verify succeeded after kill_date, but a refusal was required."
  exit 1
fi
python3 -c '
import json, sys
text = sys.argv[1]
if "issuer seal" not in text and "kill_date" not in text:
    raise SystemExit("The refused verify must name the issuer seal. Output: %s" % text)
try:
    decision = json.loads(text)
except json.JSONDecodeError:
    decision = None
if isinstance(decision, dict) and decision.get("receipt"):
    raise SystemExit("After seal the store must not sign a new decision receipt.")
print("Verify after kill_date was refused.")
' "$VERIFY_OUTPUT"

echo "Historical receipt verify of the pre-seal receipt must still succeed."
"$BIN" --data-directory "$DATA_DIRECTORY" receipt verify --receipt "$RECEIPT_PATH"

echo "The issuer seal demonstration completed successfully."
