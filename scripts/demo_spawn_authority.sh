#!/usr/bin/env bash
# Demonstration: a parent on behalf of a named user cannot birth an autonomous child.
# Widening act authority to autonomous is refused. The same user is accepted.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_DIRECTORY="${DEMO_DATA_DIRECTORY:-$ROOT/data-spawn-authority}"
rm -rf "$DATA_DIRECTORY"
cargo build
BIN="$ROOT/target/debug/prometheus"

challenge_nonce() {
  "$BIN" --data-directory "$DATA_DIRECTORY" challenge --instance "$1" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])'
}

"$BIN" --data-directory "$DATA_DIRECTORY" init >/dev/null
AGENT_TYPE_ID="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type add \
  --owner laboratory --intent read --authorization-limit payments \
  --max-delegation-depth 3 --lifetime-seconds 3600 | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"

echo "Birthing a parent on behalf of jordan."
PARENT_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience payments \
  --on-behalf-of jordan)"
PARENT_INSTANCE="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["id"])' "$PARENT_JSON")"
PARENT_CAPABILITY="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["capability"]["id"])' "$PARENT_JSON")"
PARENT_SECRET="$DATA_DIRECTORY/holders/${PARENT_INSTANCE}.secret"
python3 -c '
import json, sys
parent = json.loads(sys.argv[1])
if parent["capability"]["on_behalf_of"] != "jordan":
    raise SystemExit("The parent capability must be on behalf of jordan.")
print("The parent act authority is jordan.")
' "$PARENT_JSON"

echo "Spawning a child whose token would say autonomous. This operation must fail."
WIDEN_NONCE="$(challenge_nonce "$PARENT_INSTANCE")"
if "$BIN" --data-directory "$DATA_DIRECTORY" spawn \
  --parent-instance "$PARENT_INSTANCE" \
  --parent-capability "$PARENT_CAPABILITY" \
  --owner child \
  --intent read \
  --audience payments/prod \
  --on-behalf-of autonomous \
  --holder-secret-path "$PARENT_SECRET" \
  --challenge-nonce "$WIDEN_NONCE"; then
  echo "The autonomous child spawn succeeded, but a failure was required."
  exit 1
fi
echo "The widen to autonomous was refused."

echo "Spawning a child on behalf of the same user. This operation must succeed."
SAME_NONCE="$(challenge_nonce "$PARENT_INSTANCE")"
CHILD_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" spawn \
  --parent-instance "$PARENT_INSTANCE" \
  --parent-capability "$PARENT_CAPABILITY" \
  --owner child \
  --intent read \
  --audience payments/prod \
  --on-behalf-of jordan \
  --holder-secret-path "$PARENT_SECRET" \
  --challenge-nonce "$SAME_NONCE")"
CHILD_INSTANCE="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["id"])' "$CHILD_JSON")"
CHILD_CAPABILITY="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["capability"]["id"])' "$CHILD_JSON")"
CHILD_SECRET="$DATA_DIRECTORY/holders/${CHILD_INSTANCE}.secret"
python3 -c '
import json, sys
child = json.loads(sys.argv[1])
if child["capability"]["on_behalf_of"] != "jordan":
    raise SystemExit("The child capability must keep the parent act authority jordan.")
print("The child act authority is jordan.")
' "$CHILD_JSON"

echo "Checking the child with act authority jordan. This check must succeed."
CHILD_NONCE="$(challenge_nonce "$CHILD_INSTANCE")"
"$BIN" --data-directory "$DATA_DIRECTORY" check \
  --instance "$CHILD_INSTANCE" \
  --capability "$CHILD_CAPABILITY" \
  --intent read \
  --audience payments/prod \
  --holder-secret-path "$CHILD_SECRET" \
  --challenge-nonce "$CHILD_NONCE" \
  --on-behalf-of jordan

echo "Checking the child with act authority autonomous. This check must fail."
WRONG_NONCE="$(challenge_nonce "$CHILD_INSTANCE")"
if "$BIN" --data-directory "$DATA_DIRECTORY" check \
  --instance "$CHILD_INSTANCE" \
  --capability "$CHILD_CAPABILITY" \
  --intent read \
  --audience payments/prod \
  --holder-secret-path "$CHILD_SECRET" \
  --challenge-nonce "$WRONG_NONCE" \
  --on-behalf-of autonomous; then
  echo "The child accepted autonomous, but the child token must stay on behalf of jordan."
  exit 1
fi

python3 -c '
import json, pathlib, sys
events = [json.loads(line) for line in (pathlib.Path(sys.argv[1]) / "issuance.log").read_text().splitlines() if line.strip()]
spawns = [event for event in events if event.get("operation") == "spawn"]
if len(spawns) != 1:
    raise SystemExit("The log must contain one spawn event. A refused widen must not write a child.")
print("The issuance log records one accepted spawn and no autonomous child.")
' "$DATA_DIRECTORY"

echo "The spawn authority demonstration completed successfully."
