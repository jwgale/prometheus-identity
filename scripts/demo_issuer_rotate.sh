#!/usr/bin/env bash
# Demonstration: laboratory issuer key rotation with a kill date on the old key.
# After rotate, new acts use the new key. Old capabilities verify until capability expiry.
# A forged-not-in-log token signed with the stolen old secret is refused.
# This is laboratory single-key rotate. This is not threshold issuance. This is not a post-quantum issuer.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_DIRECTORY="${DEMO_DATA_DIRECTORY:-$ROOT/data-issuer-rotate}"
rm -rf "$DATA_DIRECTORY"
cargo build
BIN="$ROOT/target/debug/prometheus"

challenge_nonce() {
  "$BIN" --data-directory "$DATA_DIRECTORY" challenge --instance "$1" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])'
}

echo "Initializing the laboratory issuer."
INIT_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" init)"
OLD_PUBLIC_KEY="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["current_public_key"] or json.loads(sys.argv[1])["public_keys"][0])' "$INIT_JSON")"
OLD_SECRET="$(tr -d '[:space:]' < "$DATA_DIRECTORY/issuer.secret")"

echo "Birthing a capability signed with the first issuer key."
AGENT_TYPE_ID="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type add \
  --owner laboratory --intent read --authorization-limit internal \
  --max-delegation-depth 2 --lifetime-seconds 3600 | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
BIRTH_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience internal)"
INSTANCE_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["id"])' "$BIRTH_JSON")"
CAPABILITY_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["capability"]["id"])' "$BIRTH_JSON")"
SECRET="$DATA_DIRECTORY/holders/${INSTANCE_ID}.secret"

echo "Checking the first capability and saving the signed decision receipt."
ALLOWED_NONCE="$(challenge_nonce "$INSTANCE_ID")"
ALLOWED_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" check \
  --instance "$INSTANCE_ID" --capability "$CAPABILITY_ID" \
  --intent read --audience internal \
  --holder-secret-path "$SECRET" --challenge-nonce "$ALLOWED_NONCE" \
  --on-behalf-of autonomous)"
RECEIPT_PATH="${DATA_DIRECTORY}/old_receipt.json"
python3 -c '
import json, pathlib, sys
decision = json.loads(sys.argv[1])
if decision.get("result") != "allowed":
    raise SystemExit("The first check must be allowed.")
receipt = decision.get("receipt")
if not isinstance(receipt, dict) or not receipt.get("signature") or not receipt.get("issuance_log_line"):
    raise SystemExit("The first check must return a signed receipt bound to the issuance log.")
pathlib.Path(sys.argv[2]).write_text(json.dumps(receipt, indent=2) + "\n")
print("The receipt signed with the first issuer key was saved.")
' "$ALLOWED_JSON" "$RECEIPT_PATH"

echo "Rotating the laboratory issuer key. The old public key stays on the accept list until kill_date."
ROTATED="$("$BIN" --data-directory "$DATA_DIRECTORY" issuer rotate --kill-after-seconds 3600)"
python3 -c '
import json, sys
issuer = json.loads(sys.argv[1])
old = sys.argv[2]
current = issuer.get("current_public_key") or issuer["public_keys"][0]
if current == old:
    raise SystemExit("Rotate must replace the current public key.")
previous = issuer.get("previous_issuer_keys") or []
if len(previous) != 1:
    raise SystemExit("Rotate must keep exactly one previous issuer key.")
if previous[0].get("public_key_hex") != old:
    raise SystemExit("The previous issuer key must be the old public key.")
if not previous[0].get("kill_date"):
    raise SystemExit("The previous issuer key must have a kill_date.")
if old not in issuer.get("accepted_issuer_public_keys", []):
    raise SystemExit("The old public key must stay on the accept list until kill_date.")
if current not in issuer.get("accepted_issuer_public_keys", []):
    raise SystemExit("The new public key must be on the accept list.")
print("Rotate wrote current_public_key and previous_issuer_keys with a kill_date.")
' "$ROTATED" "$OLD_PUBLIC_KEY"

NEW_SECRET="$(tr -d '[:space:]' < "$DATA_DIRECTORY/issuer.secret")"
if [ "$NEW_SECRET" = "$OLD_SECRET" ]; then
  echo "issuer.secret still holds the old key, but rotate must write the new key only."
  exit 1
fi
echo "issuer.secret is the new key only."

echo "A new birth after rotate must work."
NEW_BIRTH="$("$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience internal)"
NEW_INSTANCE_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["id"])' "$NEW_BIRTH")"
NEW_CAPABILITY_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["capability"]["id"])' "$NEW_BIRTH")"
NEW_HOLDER="$DATA_DIRECTORY/holders/${NEW_INSTANCE_ID}.secret"
NEW_NONCE="$(challenge_nonce "$NEW_INSTANCE_ID")"
"$BIN" --data-directory "$DATA_DIRECTORY" capability verify \
  --capability "$NEW_CAPABILITY_ID" --audience internal --intent read \
  --holder-secret-path "$NEW_HOLDER" --challenge-nonce "$NEW_NONCE" \
  --on-behalf-of autonomous
echo "The new birth capability verified with the current key."

echo "The old capability must still verify before kill_date."
OLD_NONCE="$(challenge_nonce "$INSTANCE_ID")"
"$BIN" --data-directory "$DATA_DIRECTORY" capability verify \
  --capability "$CAPABILITY_ID" --audience internal --intent read \
  --holder-secret-path "$SECRET" --challenge-nonce "$OLD_NONCE" \
  --on-behalf-of autonomous
echo "The old capability verified before kill_date."

echo "The old receipt must still verify before kill_date."
"$BIN" --data-directory "$DATA_DIRECTORY" receipt verify --receipt "$RECEIPT_PATH"

echo "A forged-not-in-log token must be refused."
EMPTY_LOG="${DATA_DIRECTORY}/empty-issuance.log"
: > "$EMPTY_LOG"
if "$BIN" --data-directory "$DATA_DIRECTORY" receipt verify \
  --receipt "$RECEIPT_PATH" --issuance-log "$EMPTY_LOG"; then
  echo "A receipt verified against an empty issuance log, but a failure was required."
  exit 1
fi
echo "The forged-not-in-log receipt was refused."

echo "The issuer rotate demonstration completed successfully."
