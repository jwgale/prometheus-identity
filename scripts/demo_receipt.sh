#!/usr/bin/env bash
# Demonstration: a signed decision receipt can be checked by a third party.
# The receipt binds to the local issuance-log line. A signature alone is not enough.
# This is a laboratory signature. This is a local log. This is not a public transparency log. This is not threshold issuance.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_DIRECTORY="${DEMO_DATA_DIRECTORY:-$ROOT/data-receipt}"
rm -rf "$DATA_DIRECTORY"
cargo build
BIN="$ROOT/target/debug/prometheus"

challenge_nonce() {
  "$BIN" --data-directory "$DATA_DIRECTORY" challenge --instance "$1" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])'
}

"$BIN" --data-directory "$DATA_DIRECTORY" init >/dev/null
AGENT_TYPE_ID="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type add \
  --owner laboratory --intent read --authorization-limit internal \
  --max-delegation-depth 2 --lifetime-seconds 3600 | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"

echo "Birthing an autonomous capability."
BIRTH_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience internal)"
INSTANCE_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["id"])' "$BIRTH_JSON")"
CAPABILITY_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["capability"]["id"])' "$BIRTH_JSON")"
SECRET="$DATA_DIRECTORY/holders/${INSTANCE_ID}.secret"

echo "Checking an allowed tool action and saving the signed decision receipt."
ALLOWED_NONCE="$(challenge_nonce "$INSTANCE_ID")"
ALLOWED_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" check \
  --instance "$INSTANCE_ID" --capability "$CAPABILITY_ID" \
  --intent read --audience internal \
  --holder-secret-path "$SECRET" --challenge-nonce "$ALLOWED_NONCE" \
  --on-behalf-of autonomous)"
echo "${ALLOWED_JSON}"
RECEIPT_PATH="${DATA_DIRECTORY}/allowed_receipt.json"
python3 -c '
import json, pathlib, sys
decision = json.loads(sys.argv[1])
if decision.get("result") != "allowed":
    raise SystemExit("The check must be allowed.")
receipt = decision.get("receipt")
if not isinstance(receipt, dict):
    raise SystemExit("The check must return a signed decision receipt.")
if receipt.get("result") != "allowed":
    raise SystemExit("The receipt result must be allowed.")
if "signature" not in receipt or not receipt["signature"]:
    raise SystemExit("The receipt must include a signature.")
if not receipt.get("issuance_log_line"):
    raise SystemExit("The receipt must include issuance_log_line.")
serialized = json.dumps(receipt)
if "secret" in serialized:
    raise SystemExit("The receipt must not contain holder secrets.")
pathlib.Path(sys.argv[2]).write_text(json.dumps(receipt, indent=2) + "\n")
print("The allowed receipt was saved.")
' "$ALLOWED_JSON" "$RECEIPT_PATH"

echo "Verifying the allowed receipt against the issuer public key and the issuance log. This check must succeed."
"$BIN" --data-directory "$DATA_DIRECTORY" receipt verify --receipt "$RECEIPT_PATH"

echo "Copying the store and removing the matching issuance-log line. The receipt verify must fail."
COPY_DIRECTORY="${DATA_DIRECTORY}-without-line"
rm -rf "$COPY_DIRECTORY"
cp -a "$DATA_DIRECTORY" "$COPY_DIRECTORY"
python3 -c '
import json, pathlib, sys
receipt = json.loads(pathlib.Path(sys.argv[1]).read_text())
line = receipt.get("issuance_log_line") or ""
if not line:
    raise SystemExit("The receipt must include issuance_log_line.")
log_path = pathlib.Path(sys.argv[2]) / "issuance.log"
kept = [existing for existing in log_path.read_text().splitlines() if existing != line]
log_path.write_text(("\n".join(kept) + "\n") if kept else "")
print("The matching issuance-log line was removed from the copied store.")
' "$RECEIPT_PATH" "$COPY_DIRECTORY"
if "$BIN" --data-directory "$COPY_DIRECTORY" receipt verify --receipt "$RECEIPT_PATH"; then
  echo "The receipt verified after the issuance-log line was removed, but a failure was required."
  exit 1
fi
echo "The receipt was refused after the issuance-log line was removed. The signature was not enough."

echo "Changing the result field. The receipt verify must fail."
TAMPERED_PATH="${DATA_DIRECTORY}/tampered_receipt.json"
python3 -c '
import json, pathlib, sys
receipt = json.loads(pathlib.Path(sys.argv[1]).read_text())
receipt["result"] = "refused"
pathlib.Path(sys.argv[2]).write_text(json.dumps(receipt, indent=2) + "\n")
' "$RECEIPT_PATH" "$TAMPERED_PATH"
if "$BIN" --data-directory "$DATA_DIRECTORY" receipt verify --receipt "$TAMPERED_PATH"; then
  echo "The tampered receipt verified, but a failure was required."
  exit 1
fi
echo "The tampered receipt was refused."

echo "The decision receipt demonstration completed successfully."
