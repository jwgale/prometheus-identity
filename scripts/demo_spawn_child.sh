#!/usr/bin/env bash
# Demonstration: parent allowed, child narrower allowed, child widen refused.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_DIRECTORY="${DEMO_DATA_DIRECTORY:-$ROOT/data-spawn}"
rm -rf "$DATA_DIRECTORY"
cargo build
BIN="$ROOT/target/debug/prometheus"

"$BIN" --data-directory "$DATA_DIRECTORY" init >/dev/null
AGENT_TYPE_ID="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type add \
  --owner laboratory --intent read --authorization-limit payments \
  --max-delegation-depth 3 --lifetime-seconds 3600 | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"

BIRTH_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience payments)"
PARENT_INSTANCE="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["id"])' "$BIRTH_JSON")"
PARENT_CAPABILITY="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["capability"]["id"])' "$BIRTH_JSON")"
PARENT_SECRET="$DATA_DIRECTORY/holders/${PARENT_INSTANCE}.secret"

echo "Checking the parent against payments. This check must succeed."
PARENT_NONCE="$("$BIN" --data-directory "$DATA_DIRECTORY" challenge --instance "$PARENT_INSTANCE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])')"
"$BIN" --data-directory "$DATA_DIRECTORY" check \
  --instance "$PARENT_INSTANCE" \
  --capability "$PARENT_CAPABILITY" \
  --intent read \
  --audience payments \
  --holder-secret-path "$PARENT_SECRET" \
  --challenge-nonce "$PARENT_NONCE" \
  --on-behalf-of autonomous

echo "Spawning a child with a narrower audience. This operation must succeed."
SPAWN_NONCE="$("$BIN" --data-directory "$DATA_DIRECTORY" challenge --instance "$PARENT_INSTANCE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])')"
CHILD_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" spawn \
  --parent-instance "$PARENT_INSTANCE" \
  --parent-capability "$PARENT_CAPABILITY" \
  --owner child \
  --intent read \
  --audience payments/prod \
  --holder-secret-path "$PARENT_SECRET" \
  --challenge-nonce "$SPAWN_NONCE")"

CHILD_INSTANCE="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["id"])' "$CHILD_JSON")"
CHILD_CAPABILITY="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["capability"]["id"])' "$CHILD_JSON")"
CHILD_SECRET="$DATA_DIRECTORY/holders/${CHILD_INSTANCE}.secret"

python3 -c '
import json, sys
child = json.loads(sys.argv[1])
parent_instance = sys.argv[2]
if child["instance"].get("parent_instance_id") != parent_instance:
    raise SystemExit("The child instance must point to the parent instance.")
if child["parent_capability_id"] != sys.argv[3]:
    raise SystemExit("The spawn result must record the parent capability.")
print("The child parent pointer is set.")
' "$CHILD_JSON" "$PARENT_INSTANCE" "$PARENT_CAPABILITY"

echo "Checking the child against the narrower audience. This check must succeed."
CHILD_NONCE="$("$BIN" --data-directory "$DATA_DIRECTORY" challenge --instance "$CHILD_INSTANCE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])')"
"$BIN" --data-directory "$DATA_DIRECTORY" check \
  --instance "$CHILD_INSTANCE" \
  --capability "$CHILD_CAPABILITY" \
  --intent read \
  --audience payments/prod \
  --holder-secret-path "$CHILD_SECRET" \
  --challenge-nonce "$CHILD_NONCE" \
  --on-behalf-of autonomous

echo "Spawning a grandchild that widens the child audience. This operation must fail."
WIDER_NONCE="$("$BIN" --data-directory "$DATA_DIRECTORY" challenge --instance "$CHILD_INSTANCE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])')"
if "$BIN" --data-directory "$DATA_DIRECTORY" spawn \
  --parent-instance "$CHILD_INSTANCE" \
  --parent-capability "$CHILD_CAPABILITY" \
  --owner wider \
  --intent read \
  --audience payments \
  --holder-secret-path "$CHILD_SECRET" \
  --challenge-nonce "$WIDER_NONCE"; then
  echo "The wider spawn succeeded, but a failure was required."
  exit 1
fi

echo "The spawn demonstration completed successfully."
