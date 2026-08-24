#!/usr/bin/env bash
# Demonstration: the capability expiry is frozen after the first write.
# A later write that moves expires later is refused.
# An extension is a golden-ticket-class extension. The capability must not outlive the mint.
# This is not a sixth identity record.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_DIRECTORY="${DEMO_DATA_DIRECTORY:-$ROOT/data-expiry-freeze}"
rm -rf "$DATA_DIRECTORY"
cargo build
BIN="$ROOT/target/debug/prometheus"

echo "Initializing the laboratory issuer and birthing one instance with a first capability."
"$BIN" --data-directory "$DATA_DIRECTORY" init >/dev/null
AGENT_TYPE_ID="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type add \
  --owner laboratory --intent read --authorization-limit payments \
  --max-delegation-depth 2 --lifetime-seconds 3600 | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"

BIRTH_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience payments)"
CAPABILITY_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["capability"]["id"])' "$BIRTH_JSON")"
STORED_EXPIRES="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["capability"]["expires"])' "$BIRTH_JSON")"
if [ -z "$STORED_EXPIRES" ]; then
  echo "The first persist must set expires."
  exit 1
fi
echo "The first persist set expires to ${STORED_EXPIRES}."

LATER_EXPIRES="$(python3 -c '
from datetime import datetime, timedelta, timezone
import sys
text = sys.argv[1]
if text.endswith("Z"):
    text = text[:-1] + "+00:00"
when = datetime.fromisoformat(text)
print((when + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))
' "$STORED_EXPIRES")"

echo "Attempting a forbidden capability expiry extension. This command must always refuse."
set +e
EXTEND_OUTPUT="$("$BIN" --data-directory "$DATA_DIRECTORY" capability extend \
  --capability "$CAPABILITY_ID" --expires-at "$LATER_EXPIRES" 2>&1)"
EXTEND_STATUS=$?
set -e
if [ "$EXTEND_STATUS" -eq 0 ]; then
  echo "The extend command succeeded, but a refusal was required."
  exit 1
fi
python3 -c '
import sys
text = sys.argv[1]
if "expires" not in text or ("extension" not in text and "frozen" not in text):
    raise SystemExit("The refused extend must name the capability-expiry freeze. Output: %s" % text)
print("The forbidden expiry extension was refused.")
' "$EXTEND_OUTPUT"

python3 -c '
import json, sys
stored = json.load(open(sys.argv[1]))
if stored["expires"] != sys.argv[2]:
    raise SystemExit("The stored expires must stay %s after a refused extend. Found %s." % (sys.argv[2], stored["expires"]))
print("The stored expires is unchanged after the refused extend.")
' "$DATA_DIRECTORY/capabilities/${CAPABILITY_ID}.json" "$STORED_EXPIRES"

echo "Attenuating the capability. The child is a new identifier and must not expire after the parent."
CHILD_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" capability attenuate \
  --capability "$CAPABILITY_ID" --audience payments/prod --intent read)"
python3 -c '
import json, sys
parent_path = sys.argv[1]
child = json.loads(sys.argv[2])
parent = json.load(open(parent_path))
if child["id"] == parent["id"]:
    raise SystemExit("Attenuation must create a new capability identifier.")
if child["expires"] > parent["expires"]:
    raise SystemExit("The child capability must not expire after the parent capability.")
print("The attenuated child expiry does not exceed the parent expiry.")
' "$DATA_DIRECTORY/capabilities/${CAPABILITY_ID}.json" "$CHILD_JSON"

echo "The capability-expiry freeze demonstration completed successfully."
