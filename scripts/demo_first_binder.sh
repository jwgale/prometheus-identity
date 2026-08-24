#!/usr/bin/env bash
# Demonstration: the first binder is written once at birth and cannot be replaced.
# A later write that swaps holder_public_key is refused. Identity is not the key.
# This is not a remote proof-of-possession protocol. This is not SPIFFE.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_DIRECTORY="${DEMO_DATA_DIRECTORY:-$ROOT/data-first-binder}"
rm -rf "$DATA_DIRECTORY"
cargo build
BIN="$ROOT/target/debug/prometheus"

echo "Initializing the laboratory issuer and birthing one instance."
"$BIN" --data-directory "$DATA_DIRECTORY" init >/dev/null
AGENT_TYPE_ID="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type add \
  --owner laboratory --intent read --authorization-limit payments \
  --max-delegation-depth 2 --lifetime-seconds 3600 | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"

BIRTH_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience payments)"
INSTANCE_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["id"])' "$BIRTH_JSON")"
BIRTH_HOLDER="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["holder_public_key"])' "$BIRTH_JSON")"

echo "Showing the instance. The printed holder_public_key is the first binder."
SHOW_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" instance show --instance "$INSTANCE_ID")"
python3 -c '
import json, sys
shown = json.loads(sys.argv[1])
if not shown.get("holder_public_key"):
    raise SystemExit("instance show must print holder_public_key.")
if shown["holder_public_key"] != sys.argv[2]:
    raise SystemExit("instance show must print the holder public key written at birth.")
if shown["id"] == shown["holder_public_key"]:
    raise SystemExit("A name is not a key.")
print("The first binder holder_public_key is present and is not the instance identifier.")
' "$SHOW_JSON" "$BIRTH_HOLDER"

FOREIGN_KEY="$(python3 -c 'print("ff" * 32)')"
echo "Attempting a forbidden rebind. This command must always refuse."
set +e
REBIND_OUTPUT="$("$BIN" --data-directory "$DATA_DIRECTORY" instance rebind \
  --instance "$INSTANCE_ID" --public-key-hex "$FOREIGN_KEY" 2>&1)"
REBIND_STATUS=$?
set -e
if [ "$REBIND_STATUS" -eq 0 ]; then
  echo "The rebind command succeeded, but a refusal was required."
  exit 1
fi
python3 -c '
import json, sys
text = sys.argv[1]
if "first binder" not in text:
    raise SystemExit("The refused rebind must name the first binder. Output: %s" % text)
print("The forbidden rebind was refused with a first-binder error.")
' "$REBIND_OUTPUT"

AFTER_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" instance show --instance "$INSTANCE_ID")"
python3 -c '
import json, sys
shown = json.loads(sys.argv[1])
if shown["holder_public_key"] != sys.argv[2]:
    raise SystemExit("The holder public key must not change after a refused rebind.")
print("The holder public key is unchanged after the refused rebind.")
' "$AFTER_JSON" "$BIRTH_HOLDER"

echo "Killing the instance. The first binder must stay."
"$BIN" --data-directory "$DATA_DIRECTORY" instance kill --instance "$INSTANCE_ID" >/dev/null
KILLED_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" instance show --instance "$INSTANCE_ID")"
python3 -c '
import json, sys
shown = json.loads(sys.argv[1])
if shown.get("status") != "revoked":
    raise SystemExit("The instance must be revoked.")
if shown["holder_public_key"] != sys.argv[2]:
    raise SystemExit("Kill must not rewrite holder_public_key.")
print("Kill left holder_public_key unchanged.")
' "$KILLED_JSON" "$BIRTH_HOLDER"

echo "The first-binder demonstration completed successfully."
