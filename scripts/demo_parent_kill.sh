#!/usr/bin/env bash
# Demonstration: killing a parent instance stops the child instances and the capabilities in those chains.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_DIRECTORY="${DEMO_DATA_DIRECTORY:-$ROOT/data-parent-kill}"
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

BIRTH_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience payments)"
PARENT_INSTANCE="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["id"])' "$BIRTH_JSON")"
PARENT_CAPABILITY="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["capability"]["id"])' "$BIRTH_JSON")"
PARENT_SECRET="$DATA_DIRECTORY/holders/${PARENT_INSTANCE}.secret"

echo "Spawning a child instance."
SPAWN_NONCE="$(challenge_nonce "$PARENT_INSTANCE")"
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

echo "Checking the child before the parent kill. This check must succeed."
CHILD_NONCE="$(challenge_nonce "$CHILD_INSTANCE")"
"$BIN" --data-directory "$DATA_DIRECTORY" check \
  --instance "$CHILD_INSTANCE" \
  --capability "$CHILD_CAPABILITY" \
  --intent read \
  --audience payments/prod \
  --holder-secret-path "$CHILD_SECRET" \
  --challenge-nonce "$CHILD_NONCE" \
  --on-behalf-of autonomous

echo "Killing the parent instance. The child instance and the capabilities in those chains must stop."
"$BIN" --data-directory "$DATA_DIRECTORY" instance kill --instance "$PARENT_INSTANCE" >/dev/null

python3 -c '
import json, pathlib, sys
data = pathlib.Path(sys.argv[1])
parent = json.loads((data / "instances" / (sys.argv[2] + ".json")).read_text())
child = json.loads((data / "instances" / (sys.argv[3] + ".json")).read_text())
parent_chain = json.loads((data / "chains" / (sys.argv[4] + ".json")).read_text())
child_chain = json.loads((data / "chains" / (sys.argv[5] + ".json")).read_text())
if parent.get("status") != "revoked":
    raise SystemExit("The parent instance must be revoked.")
if child.get("status") != "revoked":
    raise SystemExit("The child instance must be revoked.")
if not parent_chain.get("revoke_from_here"):
    raise SystemExit("The parent capability chain must set revoke_from_here.")
if not child_chain.get("revoke_from_here"):
    raise SystemExit("The child capability chain must set revoke_from_here.")
print("The parent kill cascade revoked the child instance and the capabilities.")
' "$DATA_DIRECTORY" "$PARENT_INSTANCE" "$CHILD_INSTANCE" "$PARENT_CAPABILITY" "$CHILD_CAPABILITY"

echo "Checking the child after the parent kill. This check must fail."
AFTER_CHECK_NONCE="$(challenge_nonce "$CHILD_INSTANCE")"
if "$BIN" --data-directory "$DATA_DIRECTORY" check \
  --instance "$CHILD_INSTANCE" \
  --capability "$CHILD_CAPABILITY" \
  --intent read \
  --audience payments/prod \
  --holder-secret-path "$CHILD_SECRET" \
  --challenge-nonce "$AFTER_CHECK_NONCE" \
  --on-behalf-of autonomous; then
  echo "The child check succeeded after the parent kill, but a failure was required."
  exit 1
fi

echo "Verifying the child capability after the parent kill. This check must fail."
AFTER_VERIFY_NONCE="$(challenge_nonce "$CHILD_INSTANCE")"
if "$BIN" --data-directory "$DATA_DIRECTORY" capability verify \
  --capability "$CHILD_CAPABILITY" \
  --audience payments/prod \
  --intent read \
  --holder-secret-path "$CHILD_SECRET" \
  --challenge-nonce "$AFTER_VERIFY_NONCE" \
  --on-behalf-of autonomous; then
  echo "The child verification succeeded after the parent kill, but a failure was required."
  exit 1
fi

echo "The parent kill demonstration completed successfully."
