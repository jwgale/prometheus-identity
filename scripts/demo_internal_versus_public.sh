#!/usr/bin/env bash
# Demonstration: the same intent is allowed for an internal audience and refused for a public audience.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_DIRECTORY="${DEMO_DATA_DIRECTORY:-$ROOT/data-internal}"
rm -rf "$DATA_DIRECTORY"
cargo build
BIN="$ROOT/target/debug/prometheus"

"$BIN" --data-directory "$DATA_DIRECTORY" init >/dev/null
AGENT_TYPE_ID="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type add \
  --owner laboratory --intent read --authorization-limit internal \
  --max-delegation-depth 2 --lifetime-seconds 3600 | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
BIRTH_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience internal)"
INSTANCE_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["id"])' "$BIRTH_JSON")"
CAPABILITY_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["capability"]["id"])' "$BIRTH_JSON")"
SECRET="$DATA_DIRECTORY/holders/${INSTANCE_ID}.secret"

echo "Checking the same intent against the internal audience. This check must succeed."
INTERNAL_NONCE="$("$BIN" --data-directory "$DATA_DIRECTORY" challenge --instance "$INSTANCE_ID" | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])')"
"$BIN" --data-directory "$DATA_DIRECTORY" check \
  --instance "$INSTANCE_ID" --capability "$CAPABILITY_ID" --intent read --audience internal \
  --holder-secret-path "$SECRET" --challenge-nonce "$INTERNAL_NONCE" \
  --on-behalf-of autonomous

echo "Checking the same intent against the public audience. This check must fail."
PUBLIC_NONCE="$("$BIN" --data-directory "$DATA_DIRECTORY" challenge --instance "$INSTANCE_ID" | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])')"
if "$BIN" --data-directory "$DATA_DIRECTORY" check \
  --instance "$INSTANCE_ID" --capability "$CAPABILITY_ID" --intent read --audience public \
  --holder-secret-path "$SECRET" --challenge-nonce "$PUBLIC_NONCE" \
  --on-behalf-of autonomous; then
  echo "The public check succeeded, but a failure was required."
  exit 1
fi

python3 -c '
import json, pathlib, sys
events = [json.loads(line) for line in (pathlib.Path(sys.argv[1]) / "issuance.log").read_text().splitlines() if line.strip()]
checks = [event for event in events if event.get("operation") == "check"]
if len(checks) < 2:
    raise SystemExit("The log must contain the allowed check and the refused check.")
if checks[0].get("result") != "allowed":
    raise SystemExit("The first check must be allowed.")
if checks[1].get("result") != "refused":
    raise SystemExit("The second check must be refused.")
print("The issuance log contains both check results.")
' "$DATA_DIRECTORY"

echo "The internal versus public demonstration completed successfully."
