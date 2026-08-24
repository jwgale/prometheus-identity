#!/usr/bin/env bash
# Demonstration: a local SHA-256 hash chain on issuance.log.
# A deleted or altered middle line is detectable.
# This is a local hash chain. This is not a public append-only service.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_DIRECTORY="${DEMO_DATA_DIRECTORY:-$ROOT/data-log-chain}"
rm -rf "$DATA_DIRECTORY"
cargo build
BIN="$ROOT/target/debug/prometheus"

challenge_nonce() {
  "$BIN" --data-directory "$DATA_DIRECTORY" challenge --instance "$1" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])'
}

"$BIN" --data-directory "$DATA_DIRECTORY" init >/dev/null
AGENT_TYPE_ID="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type add \
  --owner laboratory --intent read --authorization-limit internal \
  --max-delegation-depth 2 --lifetime-seconds 3600 | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"

echo "Writing several issuance events: birth, challenge, and check."
BIRTH_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience internal)"
INSTANCE_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["id"])' "$BIRTH_JSON")"
CAPABILITY_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["capability"]["id"])' "$BIRTH_JSON")"
SECRET="$DATA_DIRECTORY/holders/${INSTANCE_ID}.secret"

ALLOWED_NONCE="$(challenge_nonce "$INSTANCE_ID")"
"$BIN" --data-directory "$DATA_DIRECTORY" check \
  --instance "$INSTANCE_ID" --capability "$CAPABILITY_ID" \
  --intent read --audience internal \
  --holder-secret-path "$SECRET" --challenge-nonce "$ALLOWED_NONCE" \
  --on-behalf-of autonomous >/dev/null

echo "Verifying the intact issuance log hash chain. This check must succeed."
"$BIN" --data-directory "$DATA_DIRECTORY" log verify

python3 -c '
import json, pathlib, sys
log_path = pathlib.Path(sys.argv[1]) / "issuance.log"
lines = [line for line in log_path.read_text().splitlines() if line.strip()]
if len(lines) < 3:
    raise SystemExit("The demonstration must write several chained events.")
for line in lines:
    event = json.loads(line)
    if not event.get("previous_line_hash"):
        raise SystemExit("Each line must include previous_line_hash.")
    if not event.get("line_hash"):
        raise SystemExit("Each line must include line_hash.")
print("Each issuance-log line includes previous_line_hash and line_hash.")
' "$DATA_DIRECTORY"

echo "Altering one issuance-log field. The log verify must fail."
python3 -c '
import json, pathlib, sys
log_path = pathlib.Path(sys.argv[1]) / "issuance.log"
lines = [line for line in log_path.read_text().splitlines() if line.strip()]
target = len(lines) // 2
event = json.loads(lines[target])
event["operation"] = "altered"
# Keep previous_line_hash and line_hash so the break is a wrong line_hash, not a missing field.
lines[target] = json.dumps(event, separators=(",", ":"))
log_path.write_text("\n".join(lines) + "\n")
print("One issuance-log field was altered.")
' "$DATA_DIRECTORY"

if "$BIN" --data-directory "$DATA_DIRECTORY" log verify; then
  echo "The issuance log verified after a field was altered, but a failure was required."
  exit 1
fi
echo "The issuance log hash chain was refused after a field was altered."

echo "The issuance log hash chain demonstration completed successfully."
