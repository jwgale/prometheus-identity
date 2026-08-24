#!/usr/bin/env bash
# Demonstration of authorization limit, holder proof, intent decrease, and kill.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DATA_DIRECTORY="${DEMO_DATA_DIRECTORY:-$ROOT/data}"
rm -rf "$DATA_DIRECTORY"

echo "Building the Prometheus package."
cargo build

BIN="$ROOT/target/debug/prometheus"

id_from_json() {
  python3 -c 'import json, sys; print(json.load(sys.stdin)["id"])'
}

echo "Running the init command."
"$BIN" --data-directory "$DATA_DIRECTORY" init >/dev/null

echo "Adding an agent type with authorization limit payments."
AGENT_TYPE_ID="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type add \
  --owner laboratory \
  --intent read \
  --intent read/limited \
  --authorization-limit payments \
  --max-delegation-depth 3 \
  --crypto-profile lab-ml-dsa-65-hybrid-biscuit-ed25519 \
  --lifetime-seconds 3600 | id_from_json)"
echo "The agent type identifier is ${AGENT_TYPE_ID}."

echo "Creating an instance."
INSTANCE_ID="$("$BIN" --data-directory "$DATA_DIRECTORY" instance birth \
  --agent-type "$AGENT_TYPE_ID" \
  --owner laboratory \
  --site laboratory \
  --region local \
  --runtime rust | id_from_json)"
echo "The instance identifier is ${INSTANCE_ID}."
HOLDER_SECRET_PATH="$DATA_DIRECTORY/holders/${INSTANCE_ID}.secret"

challenge_nonce() {
  "$BIN" --data-directory "$DATA_DIRECTORY" challenge --instance "$1"     | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])'
}

echo "Minting a capability inside the authorization limit. This operation must succeed."
CAPABILITY_ID="$("$BIN" --data-directory "$DATA_DIRECTORY" capability mint \
  --instance "$INSTANCE_ID" \
  --intent read \
  --audience payments | id_from_json)"
echo "The capability identifier is ${CAPABILITY_ID}."

echo "Minting a capability above the authorization limit. This operation must fail."
if "$BIN" --data-directory "$DATA_DIRECTORY" capability mint \
  --instance "$INSTANCE_ID" \
  --intent read \
  --audience public; then
  echo "The mint operation succeeded, but a failure was required for an audience above the authorization limit."
  exit 1
fi

echo "Verifying the minted capability with a holder proof and a one-time challenge. This check must succeed."
NONCE="$(challenge_nonce "$INSTANCE_ID")"
"$BIN" --data-directory "$DATA_DIRECTORY" capability verify \
  --capability "$CAPABILITY_ID" \
  --audience payments \
  --intent read \
  --holder-secret-path "$HOLDER_SECRET_PATH" \
  --challenge-nonce "$NONCE" \
  --on-behalf-of autonomous

echo "Verifying the minted capability without a holder proof. This check must fail."
if "$BIN" --data-directory "$DATA_DIRECTORY" capability verify \
  --capability "$CAPABILITY_ID" \
  --audience payments \
  --intent read \
  --on-behalf-of autonomous; then
  echo "The verification succeeded, but a failure was required when the holder proof is missing."
  exit 1
fi

echo "Attenuating the capability to a narrower audience and a narrower intent."
NARROW_ID="$("$BIN" --data-directory "$DATA_DIRECTORY" capability attenuate \
  --capability "$CAPABILITY_ID" \
  --audience payments/prod \
  --intent read/limited | id_from_json)"
echo "The narrower capability identifier is ${NARROW_ID}."

echo "Verifying the narrower capability with a holder proof and a one-time challenge. This check must succeed."
NONCE="$(challenge_nonce "$INSTANCE_ID")"
"$BIN" --data-directory "$DATA_DIRECTORY" capability verify \
  --capability "$NARROW_ID" \
  --audience payments/prod \
  --intent read/limited \
  --holder-secret-path "$HOLDER_SECRET_PATH" \
  --challenge-nonce "$NONCE" \
  --on-behalf-of autonomous

echo "Revoking the narrower capability."
"$BIN" --data-directory "$DATA_DIRECTORY" capability kill \
  --capability "$NARROW_ID" >/dev/null

echo "Verifying after the kill operation. This check must fail."
NONCE="$(challenge_nonce "$INSTANCE_ID")"
if "$BIN" --data-directory "$DATA_DIRECTORY" capability verify \
  --capability "$NARROW_ID" \
  --audience payments/prod \
  --intent read/limited \
  --holder-secret-path "$HOLDER_SECRET_PATH" \
  --challenge-nonce "$NONCE" \
  --on-behalf-of autonomous; then
  echo "The verification succeeded, but a failure was required after the kill operation."
  exit 1
fi

echo "Showing the issuance log."
"$BIN" --data-directory "$DATA_DIRECTORY" log show

echo "The demonstration completed successfully."
