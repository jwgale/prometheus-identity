#!/usr/bin/env bash
# Demonstration: the authorization limit is frozen after the first write.
# A later write that raises authorization_limit is refused.
# A raise is a golden-ticket-class raise. The type must not become more powerful than at birth.
# This is not a sixth identity record.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_DIRECTORY="${DEMO_DATA_DIRECTORY:-$ROOT/data-limit-freeze}"
rm -rf "$DATA_DIRECTORY"
cargo build
BIN="$ROOT/target/debug/prometheus"

echo "Initializing the laboratory issuer and adding one agent type with authorization limit payments."
"$BIN" --data-directory "$DATA_DIRECTORY" init >/dev/null
AGENT_TYPE_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type add \
  --owner laboratory --intent read --authorization-limit payments \
  --max-delegation-depth 2 --lifetime-seconds 3600)"
AGENT_TYPE_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["id"])' "$AGENT_TYPE_JSON")"
STORED_LIMIT="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["authorization_limit"])' "$AGENT_TYPE_JSON")"
if [ "$STORED_LIMIT" != "payments" ]; then
  echo "The first write must set authorization_limit to payments."
  exit 1
fi

echo "Attempting a forbidden authorization-limit raise before any instance exists. This command must always refuse."
set +e
RAISE_OUTPUT="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type raise \
  --agent-type "$AGENT_TYPE_ID" --authorization-limit public 2>&1)"
RAISE_STATUS=$?
set -e
if [ "$RAISE_STATUS" -eq 0 ]; then
  echo "The raise command succeeded, but a refusal was required."
  exit 1
fi
python3 -c '
import json, sys
text = sys.argv[1]
if "authorization limit" not in text or "raise" not in text:
    raise SystemExit("The refused raise must name the authorization-limit freeze. Output: %s" % text)
print("The forbidden raise with zero instances was refused.")
' "$RAISE_OUTPUT"

python3 -c '
import json, sys
stored = json.load(open(sys.argv[1]))
if stored["authorization_limit"] != "payments":
    raise SystemExit("The stored authorization_limit must stay payments after a refused raise.")
print("The stored authorization_limit is unchanged after the refused raise.")
' "$DATA_DIRECTORY/agent_types/${AGENT_TYPE_ID}.json"

echo "Birthing one instance of the frozen type."
BIRTH_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience payments)"
INSTANCE_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["id"])' "$BIRTH_JSON")"

echo "Attempting the same forbidden raise after an instance exists. This command must still refuse."
set +e
RAISE_AFTER="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type raise \
  --agent-type "$AGENT_TYPE_ID" --authorization-limit public 2>&1)"
RAISE_AFTER_STATUS=$?
set -e
if [ "$RAISE_AFTER_STATUS" -eq 0 ]; then
  echo "The raise command succeeded after an instance existed, but a refusal was required."
  exit 1
fi
python3 -c '
import json, sys
text = sys.argv[1]
if "authorization limit" not in text or "raise" not in text:
    raise SystemExit("The refused raise after an instance exists must name the freeze. Output: %s" % text)
print("The forbidden raise after an instance exists was refused.")
' "$RAISE_AFTER"

python3 -c '
import json, sys
stored = json.load(open(sys.argv[1]))
if stored["authorization_limit"] != "payments":
    raise SystemExit("The stored authorization_limit must stay payments after the second refused raise.")
print("The stored authorization_limit is still payments.")
' "$DATA_DIRECTORY/agent_types/${AGENT_TYPE_ID}.json"

echo "Minting a capability inside the stored type limit must still succeed."
"$BIN" --data-directory "$DATA_DIRECTORY" capability mint \
  --instance "$INSTANCE_ID" --intent read --audience payments/prod >/dev/null
echo "A child destination of the stored type limit was accepted."

echo "Minting a capability above the stored type limit must still fail. The instance cannot raise the type."
set +e
MINT_OUTPUT="$("$BIN" --data-directory "$DATA_DIRECTORY" capability mint \
  --instance "$INSTANCE_ID" --intent read --audience public 2>&1)"
MINT_STATUS=$?
set -e
if [ "$MINT_STATUS" -eq 0 ]; then
  echo "Mint above the stored type limit succeeded, but a refusal was required."
  exit 1
fi
python3 -c '
import sys
text = sys.argv[1]
if "authorization limit" not in text:
    raise SystemExit("Mint above the type limit must name the authorization limit. Output: %s" % text)
print("The instance still cannot mint above the stored type limit.")
' "$MINT_OUTPUT"

echo "The authorization-limit freeze demonstration completed successfully."
