#!/usr/bin/env bash
# Demonstration: a second Prometheus store can verify a decision receipt from the first issuer.
# The second store accepts the first public key. It does not become a second identity kernel.
# This is an accept list. This is not a global name system. This is not SPIFFE federation.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
FIRST_DIRECTORY="${DEMO_FIRST_DATA_DIRECTORY:-$ROOT/data-accept-first}"
SECOND_DIRECTORY="${DEMO_SECOND_DATA_DIRECTORY:-$ROOT/data-accept-second}"
THIRD_DIRECTORY="${DEMO_THIRD_DATA_DIRECTORY:-$ROOT/data-accept-third}"
rm -rf "$FIRST_DIRECTORY" "$SECOND_DIRECTORY" "$THIRD_DIRECTORY"
cargo build
BIN="$ROOT/target/debug/prometheus"

challenge_nonce() {
  local data_directory="$1"
  local instance_id="$2"
  "$BIN" --data-directory "$data_directory" challenge --instance "$instance_id" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])'
}

write_check_receipt() {
  local data_directory="$1"
  local receipt_path="$2"
  local agent_type_id
  agent_type_id="$("$BIN" --data-directory "$data_directory" agent-type add \
    --owner laboratory --intent read --authorization-limit internal \
    --max-delegation-depth 2 --lifetime-seconds 3600 | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
  local birth_json instance_id capability_id secret allowed_nonce allowed_json
  birth_json="$("$BIN" --data-directory "$data_directory" birth \
    --agent-type "$agent_type_id" --owner laboratory --intent read --audience internal)"
  instance_id="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["id"])' "$birth_json")"
  capability_id="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["capability"]["id"])' "$birth_json")"
  secret="$data_directory/holders/${instance_id}.secret"
  allowed_nonce="$(challenge_nonce "$data_directory" "$instance_id")"
  allowed_json="$("$BIN" --data-directory "$data_directory" check \
    --instance "$instance_id" --capability "$capability_id" \
    --intent read --audience internal \
    --holder-secret-path "$secret" --challenge-nonce "$allowed_nonce" \
    --on-behalf-of autonomous)"
  python3 -c '
import json, pathlib, sys
decision = json.loads(sys.argv[1])
if decision.get("result") != "allowed":
    raise SystemExit("The check must be allowed.")
receipt = decision.get("receipt")
if not isinstance(receipt, dict):
    raise SystemExit("The check must return a signed decision receipt.")
if not receipt.get("signature"):
    raise SystemExit("The receipt must include a signature.")
if not receipt.get("issuance_log_line"):
    raise SystemExit("The receipt must include issuance_log_line.")
pathlib.Path(sys.argv[2]).write_text(json.dumps(receipt, indent=2) + "\n")
print("The allowed receipt was saved.")
' "$allowed_json" "$receipt_path"
}

echo "Initializing two Prometheus stores."
FIRST_ISSUER="$("$BIN" --data-directory "$FIRST_DIRECTORY" init)"
"$BIN" --data-directory "$SECOND_DIRECTORY" init >/dev/null
FIRST_PUBLIC_KEY="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["public_keys"][0])' "$FIRST_ISSUER")"
python3 -c '
import json, sys
issuer = json.loads(sys.argv[1])
own = issuer["public_keys"][0]
if own not in issuer.get("accepted_issuer_public_keys", []):
    raise SystemExit("Init must put this store own public key on accepted_issuer_public_keys.")
print("The first store accept list includes its own public key.")
' "$FIRST_ISSUER"

echo "The second store accepts the first issuer public key."
"$BIN" --data-directory "$SECOND_DIRECTORY" issuer accept --public-key-hex "$FIRST_PUBLIC_KEY"

echo "An empty public key must be refused."
if "$BIN" --data-directory "$SECOND_DIRECTORY" issuer accept --public-key-hex ""; then
  echo "An empty public key was accepted, but a failure was required."
  exit 1
fi
echo "The empty public key was refused."

echo "The first store creates a check receipt."
FIRST_RECEIPT="${FIRST_DIRECTORY}/allowed_receipt.json"
write_check_receipt "$FIRST_DIRECTORY" "$FIRST_RECEIPT"

echo "The first store verifies its own receipt. This check must succeed."
"$BIN" --data-directory "$FIRST_DIRECTORY" receipt verify --receipt "$FIRST_RECEIPT"

echo "The second store verifies the first receipt against the first issuance.log. This check must succeed."
"$BIN" --data-directory "$SECOND_DIRECTORY" receipt verify \
  --receipt "$FIRST_RECEIPT" \
  --issuance-log "$FIRST_DIRECTORY/issuance.log"

echo "The second store verifies the first receipt against its own issuance.log. This check must fail."
if "$BIN" --data-directory "$SECOND_DIRECTORY" receipt verify --receipt "$FIRST_RECEIPT"; then
  echo "The foreign receipt verified without the foreign issuance-log line, but a failure was required."
  exit 1
fi
echo "The foreign receipt was refused without the foreign issuance-log line."

echo "Initializing a third store whose public key is not accepted."
"$BIN" --data-directory "$THIRD_DIRECTORY" init >/dev/null
THIRD_RECEIPT="${THIRD_DIRECTORY}/allowed_receipt.json"
write_check_receipt "$THIRD_DIRECTORY" "$THIRD_RECEIPT"

echo "The second store verifies the third receipt against the third issuance.log. This check must fail."
if "$BIN" --data-directory "$SECOND_DIRECTORY" receipt verify \
  --receipt "$THIRD_RECEIPT" \
  --issuance-log "$THIRD_DIRECTORY/issuance.log"; then
  echo "A receipt from an unknown issuer key verified, but a failure was required."
  exit 1
fi
echo "The third unsigned-to-this-store issuer key was refused."

echo "The issuer accept-list demonstration completed successfully."
