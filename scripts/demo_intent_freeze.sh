#!/usr/bin/env bash
# Demonstration: the allowed intents are frozen after the first write.
# A later write that adds an intent is refused.
# Adding an intent is a golden-ticket-class raise. The type must not become more powerful than at birth.
# This is not a sixth identity record.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_DIRECTORY="${DEMO_DATA_DIRECTORY:-$ROOT/data-intent-freeze}"
rm -rf "$DATA_DIRECTORY"
cargo build
BIN="$ROOT/target/debug/prometheus"

echo "Initializing the laboratory issuer and adding one agent type with two allowed intents."
"$BIN" --data-directory "$DATA_DIRECTORY" init >/dev/null
AGENT_TYPE_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type add \
  --owner laboratory --intent read --intent write --authorization-limit payments \
  --max-delegation-depth 2 --lifetime-seconds 3600)"
AGENT_TYPE_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["id"])' "$AGENT_TYPE_JSON")"
python3 -c '
import json, sys
stored = json.loads(sys.argv[1])
if stored["allowed_intents"] != ["read", "write"]:
    raise SystemExit("The first write must set allowed_intents to read and write. Got: %s" % stored["allowed_intents"])
print("The first write set allowed_intents to read and write.")
' "$AGENT_TYPE_JSON"

echo "Attempting a forbidden add-intent before any instance exists. This command must always refuse."
set +e
ADD_OUTPUT="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type add-intent \
  --agent-type "$AGENT_TYPE_ID" --intent public 2>&1)"
ADD_STATUS=$?
set -e
if [ "$ADD_STATUS" -eq 0 ]; then
  echo "The add-intent command succeeded, but a refusal was required."
  exit 1
fi
python3 -c '
import sys
text = sys.argv[1]
if "allowed intents" not in text:
    raise SystemExit("The refused add-intent must name the allowed-intents freeze. Output: %s" % text)
print("The forbidden add-intent with zero instances was refused.")
' "$ADD_OUTPUT"

python3 -c '
import json, sys
stored = json.load(open(sys.argv[1]))
if stored["allowed_intents"] != ["read", "write"]:
    raise SystemExit("The stored allowed_intents must stay read and write after a refused add-intent.")
print("The stored allowed_intents are unchanged after the refused add-intent.")
' "$DATA_DIRECTORY/agent_types/${AGENT_TYPE_ID}.json"

echo "Birthing one instance of the frozen type."
BIRTH_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience payments)"
INSTANCE_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["id"])' "$BIRTH_JSON")"

echo "Attempting the same forbidden add-intent after an instance exists. This command must still refuse."
set +e
ADD_AFTER="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type add-intent \
  --agent-type "$AGENT_TYPE_ID" --intent public 2>&1)"
ADD_AFTER_STATUS=$?
set -e
if [ "$ADD_AFTER_STATUS" -eq 0 ]; then
  echo "The add-intent command succeeded after an instance existed, but a refusal was required."
  exit 1
fi
python3 -c '
import sys
text = sys.argv[1]
if "allowed intents" not in text:
    raise SystemExit("The refused add-intent after an instance exists must name the freeze. Output: %s" % text)
print("The forbidden add-intent after an instance exists was refused.")
' "$ADD_AFTER"

python3 -c '
import json, sys
stored = json.load(open(sys.argv[1]))
if stored["allowed_intents"] != ["read", "write"]:
    raise SystemExit("The stored allowed_intents must stay read and write after the second refused add-intent.")
print("The stored allowed_intents are still read and write.")
' "$DATA_DIRECTORY/agent_types/${AGENT_TYPE_ID}.json"

echo "Minting a capability for a stored intent must still succeed."
"$BIN" --data-directory "$DATA_DIRECTORY" capability mint \
  --instance "$INSTANCE_ID" --intent write --audience payments >/dev/null
echo "A stored intent was accepted."

echo "Minting a capability for an intent that was never stored must still fail. The instance cannot raise the type."
set +e
MINT_OUTPUT="$("$BIN" --data-directory "$DATA_DIRECTORY" capability mint \
  --instance "$INSTANCE_ID" --intent public --audience payments 2>&1)"
MINT_STATUS=$?
set -e
if [ "$MINT_STATUS" -eq 0 ]; then
  echo "Mint of an unstored intent succeeded, but a refusal was required."
  exit 1
fi
python3 -c '
import sys
text = sys.argv[1]
if "allowed intents" not in text:
    raise SystemExit("Mint of an unstored intent must name the allowed intents. Output: %s" % text)
print("The instance still cannot mint an intent that is not in the stored set.")
' "$MINT_OUTPUT"

echo "The allowed-intents freeze demonstration completed successfully."
