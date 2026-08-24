#!/usr/bin/env bash
# Demonstration: one birth write creates an instance and the first capability as one issuance.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_DIRECTORY="${DEMO_DATA_DIRECTORY:-$ROOT/data-birth}"
rm -rf "$DATA_DIRECTORY"
cargo build
BIN="$ROOT/target/debug/prometheus"

"$BIN" --data-directory "$DATA_DIRECTORY" init >/dev/null
AGENT_TYPE_ID="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type add \
  --owner laboratory \
  --intent read \
  --authorization-limit payments \
  --max-delegation-depth 2 \
  --lifetime-seconds 3600 | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"

BIRTH_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" \
  --owner laboratory \
  --intent read \
  --audience payments)"

python3 -c '
import json, sys, pathlib
birth = json.loads(sys.argv[1])
data = pathlib.Path(sys.argv[2])
if birth["instance"]["id"] == birth["instance"]["holder_public_key"]:
    raise SystemExit("A name is not a key.")
events = [json.loads(line) for line in (data / "issuance.log").read_text().splitlines() if line.strip()]
birth_events = [event for event in events if event.get("operation") == "birth_write"]
mint_events = [event for event in events if event.get("operation") == "mint"]
if len(birth_events) != 1:
    raise SystemExit("Expected one birth_write event, found %s." % len(birth_events))
if mint_events:
    raise SystemExit("A separate mint event must not exist for a birth write.")
if birth_events[0].get("instance_id") != birth["instance"]["id"]:
    raise SystemExit("The birth_write event must include the instance identifier.")
if birth_events[0].get("capability_id") != birth["capability"]["id"]:
    raise SystemExit("The birth_write event must include the capability identifier.")
print("The birth write created one issuance event.")
' "$BIRTH_JSON" "$DATA_DIRECTORY"

INSTANCE_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["id"])' "$BIRTH_JSON")"
CAPABILITY_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["capability"]["id"])' "$BIRTH_JSON")"
NONCE="$("$BIN" --data-directory "$DATA_DIRECTORY" challenge --instance "$INSTANCE_ID" | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])')"
"$BIN" --data-directory "$DATA_DIRECTORY" capability verify \
  --capability "$CAPABILITY_ID" \
  --audience payments \
  --intent read \
  --holder-secret-path "$DATA_DIRECTORY/holders/${INSTANCE_ID}.secret" \
  --challenge-nonce "$NONCE" \
  --on-behalf-of autonomous

echo "The birth demonstration completed successfully."
