#!/usr/bin/env bash
# Demonstration: autonomous versus on_behalf_of are first-class check fields.
# A check that names the wrong act authority fails closed.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_DIRECTORY="${DEMO_DATA_DIRECTORY:-$ROOT/data-on-behalf}"
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

echo "Birthing an autonomous capability."
BIRTH_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience internal)"
INSTANCE_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["id"])' "$BIRTH_JSON")"
AUTONOMOUS_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["capability"]["id"])' "$BIRTH_JSON")"
python3 -c '
import json, sys
birth = json.loads(sys.argv[1])
if birth["capability"]["on_behalf_of"] != "autonomous":
    raise SystemExit("The birth capability must be autonomous.")
print("The first capability is autonomous.")
' "$BIRTH_JSON"

echo "Minting a second capability on behalf of jordan."
DELEGATED_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" capability mint \
  --instance "$INSTANCE_ID" --intent read --audience internal --on-behalf-of jordan)"
DELEGATED_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["id"])' "$DELEGATED_JSON")"
python3 -c '
import json, sys
capability = json.loads(sys.argv[1])
if capability["on_behalf_of"] != "jordan":
    raise SystemExit("The second capability must be on behalf of jordan.")
print("The second capability is on behalf of jordan.")
' "$DELEGATED_JSON"

SECRET="$DATA_DIRECTORY/holders/${INSTANCE_ID}.secret"

echo "Checking the autonomous capability with act authority autonomous. This check must succeed."
AUTONOMOUS_NONCE="$(challenge_nonce "$INSTANCE_ID")"
"$BIN" --data-directory "$DATA_DIRECTORY" check \
  --instance "$INSTANCE_ID" --capability "$AUTONOMOUS_ID" \
  --intent read --audience internal \
  --holder-secret-path "$SECRET" --challenge-nonce "$AUTONOMOUS_NONCE" \
  --on-behalf-of autonomous

echo "Checking the delegated capability with act authority jordan. This check must succeed."
DELEGATED_NONCE="$(challenge_nonce "$INSTANCE_ID")"
"$BIN" --data-directory "$DATA_DIRECTORY" check \
  --instance "$INSTANCE_ID" --capability "$DELEGATED_ID" \
  --intent read --audience internal \
  --holder-secret-path "$SECRET" --challenge-nonce "$DELEGATED_NONCE" \
  --on-behalf-of jordan

echo "Checking the autonomous capability with act authority jordan. This check must fail."
WRONG_NONCE="$(challenge_nonce "$INSTANCE_ID")"
if "$BIN" --data-directory "$DATA_DIRECTORY" check \
  --instance "$INSTANCE_ID" --capability "$AUTONOMOUS_ID" \
  --intent read --audience internal \
  --holder-secret-path "$SECRET" --challenge-nonce "$WRONG_NONCE" \
  --on-behalf-of jordan; then
  echo "The wrong act authority succeeded, but a failure was required."
  exit 1
fi

echo "Checking the delegated capability with act authority autonomous. This check must fail."
REVERSE_NONCE="$(challenge_nonce "$INSTANCE_ID")"
if "$BIN" --data-directory "$DATA_DIRECTORY" check \
  --instance "$INSTANCE_ID" --capability "$DELEGATED_ID" \
  --intent read --audience internal \
  --holder-secret-path "$SECRET" --challenge-nonce "$REVERSE_NONCE" \
  --on-behalf-of autonomous; then
  echo "The reverse act authority succeeded, but a failure was required."
  exit 1
fi

echo "Checking without on_behalf_of. This check must fail. Empty is not autonomous."
MISSING_NONCE="$(challenge_nonce "$INSTANCE_ID")"
if "$BIN" --data-directory "$DATA_DIRECTORY" check \
  --instance "$INSTANCE_ID" --capability "$AUTONOMOUS_ID" \
  --intent read --audience internal \
  --holder-secret-path "$SECRET" --challenge-nonce "$MISSING_NONCE"; then
  echo "A missing on_behalf_of succeeded, but a failure was required."
  exit 1
fi

python3 -c '
import json, pathlib, sys
events = [json.loads(line) for line in (pathlib.Path(sys.argv[1]) / "issuance.log").read_text().splitlines() if line.strip()]
checks = [event for event in events if event.get("operation") == "check"]
if len(checks) < 5:
    raise SystemExit("The log must contain five check events.")
if checks[0].get("result") != "allowed" or checks[0].get("on_behalf_of") != "autonomous":
    raise SystemExit("The first check must allow the autonomous capability.")
if checks[1].get("result") != "allowed" or checks[1].get("on_behalf_of") != "jordan":
    raise SystemExit("The second check must allow the delegated capability.")
if checks[2].get("result") != "refused":
    raise SystemExit("The third check must refuse the wrong act authority.")
if checks[3].get("result") != "refused":
    raise SystemExit("The fourth check must refuse the reverse act authority.")
if checks[4].get("result") != "refused":
    raise SystemExit("The fifth check must refuse a missing on_behalf_of.")
note = checks[4].get("note") or ""
if "must name on_behalf_of" not in note:
    raise SystemExit("The fifth check must name the missing on_behalf_of field.")
print("The issuance log records both act authorities and a missing-field refusal.")
' "$DATA_DIRECTORY"

echo "The on-behalf-of demonstration completed successfully."
