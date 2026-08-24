#!/usr/bin/env bash
# Demonstration: a local agent host asks Prometheus before each tool action.
# The host starts on 127.0.0.1, births one agent, then runs a three-step tool loop.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_DIRECTORY="${DEMO_DATA_DIRECTORY:-$ROOT/data-tool-loop}"
rm -rf "$DATA_DIRECTORY"
cargo build
BIN="$ROOT/target/debug/prometheus"
LISTEN_ADDRESS="127.0.0.1:18767"
HOST_PID=""

cleanup() {
  if [ -n "${HOST_PID}" ]; then
    kill "${HOST_PID}" 2>/dev/null || true
    wait "${HOST_PID}" 2>/dev/null || true
    HOST_PID=""
  fi
}
trap cleanup EXIT

"$BIN" --data-directory "$DATA_DIRECTORY" init >/dev/null
AGENT_TYPE_ID="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type add \
  --owner laboratory --intent read --authorization-limit internal \
  --max-delegation-depth 2 --lifetime-seconds 3600 | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"

echo "Starting the Prometheus check host on ${LISTEN_ADDRESS}."
"$BIN" --data-directory "$DATA_DIRECTORY" host --listen-address "$LISTEN_ADDRESS" &
HOST_PID=$!

for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  if curl -sf "http://${LISTEN_ADDRESS}/health" >/dev/null; then
    break
  fi
  sleep 0.2
done
if ! curl -sf "http://${LISTEN_ADDRESS}/health" >/dev/null; then
  echo "The check host did not become live on ${LISTEN_ADDRESS}."
  exit 1
fi

echo "Birthing an agent with a capability for the internal tool."
BIRTH_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience internal)"
INSTANCE_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["id"])' "$BIRTH_JSON")"
CAPABILITY_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["capability"]["id"])' "$BIRTH_JSON")"
SECRET="$DATA_DIRECTORY/holders/${INSTANCE_ID}.secret"

challenge_nonce() {
  "$BIN" --data-directory "$DATA_DIRECTORY" challenge --instance "$1" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])'
}

echo "Tool loop step 1: internal tool, valid challenge, named capability. This call must be accepted."
FIRST_NONCE="$(challenge_nonce "$INSTANCE_ID")"
FIRST_BODY="$(python3 -c '
import json, sys
print(json.dumps({
    "instance_id": sys.argv[1],
    "capability_id": sys.argv[2],
    "intent": "read",
    "audience": "internal",
    "holder_secret_path": sys.argv[3],
    "challenge_nonce": sys.argv[4],
    "on_behalf_of": "autonomous",
}))
' "$INSTANCE_ID" "$CAPABILITY_ID" "$SECRET" "$FIRST_NONCE")"
FIRST="$(curl -sS -X POST "http://${LISTEN_ADDRESS}/check" \
  -H "Content-Type: application/json" \
  -d "${FIRST_BODY}")"
echo "${FIRST}"
python3 -c '
import json, sys
decision = json.loads(sys.argv[1])
if decision.get("result") != "allowed":
    raise SystemExit("The host must accept the internal tool call.")
if decision.get("capability_id") != sys.argv[2]:
    raise SystemExit("The host must name the capability identifier.")
print("The host accepted the internal tool call.")
' "$FIRST" "$CAPABILITY_ID"

echo "Tool loop step 2: public destination, valid challenge, same capability. This call must be refused."
SECOND_NONCE="$(challenge_nonce "$INSTANCE_ID")"
SECOND_BODY="$(python3 -c '
import json, sys
print(json.dumps({
    "instance_id": sys.argv[1],
    "capability_id": sys.argv[2],
    "intent": "read",
    "audience": "public",
    "holder_secret_path": sys.argv[3],
    "challenge_nonce": sys.argv[4],
    "on_behalf_of": "autonomous",
}))
' "$INSTANCE_ID" "$CAPABILITY_ID" "$SECRET" "$SECOND_NONCE")"
SECOND_CODE="$(curl -sS -o "${DATA_DIRECTORY}/tool_loop_public.json" -w "%{http_code}" \
  -X POST "http://${LISTEN_ADDRESS}/check" \
  -H "Content-Type: application/json" \
  -d "${SECOND_BODY}")"
if [ "$SECOND_CODE" != "403" ]; then
  echo "The host must return HTTP 403 for a public destination. Received ${SECOND_CODE}."
  exit 1
fi
python3 -c '
import json, pathlib, sys
decision = json.loads(pathlib.Path(sys.argv[1]).read_text())
if decision.get("result") != "refused":
    raise SystemExit("The host must refuse the public destination.")
reason = decision.get("reason") or ""
if "authorization limit" not in reason:
    raise SystemExit("The refusal must name the authorization limit.")
print("The host refused the public destination.")
' "${DATA_DIRECTORY}/tool_loop_public.json"

echo "Tool loop step 3: replay of the spent challenge from step 1. This call must be refused."
REPLAY_BODY="$(python3 -c '
import json, sys
print(json.dumps({
    "instance_id": sys.argv[1],
    "capability_id": sys.argv[2],
    "intent": "read",
    "audience": "internal",
    "holder_secret_path": sys.argv[3],
    "challenge_nonce": sys.argv[4],
    "on_behalf_of": "autonomous",
}))
' "$INSTANCE_ID" "$CAPABILITY_ID" "$SECRET" "$FIRST_NONCE")"
REPLAY_CODE="$(curl -sS -o "${DATA_DIRECTORY}/tool_loop_replay.json" -w "%{http_code}" \
  -X POST "http://${LISTEN_ADDRESS}/check" \
  -H "Content-Type: application/json" \
  -d "${REPLAY_BODY}")"
if [ "$REPLAY_CODE" != "403" ]; then
  echo "The host must return HTTP 403 for a spent challenge. Received ${REPLAY_CODE}."
  exit 1
fi
python3 -c '
import json, pathlib, sys
decision = json.loads(pathlib.Path(sys.argv[1]).read_text())
if decision.get("result") != "refused":
    raise SystemExit("The host must refuse a spent challenge.")
reason = decision.get("reason") or ""
if "already spent" not in reason:
    raise SystemExit("The refusal must name the spent challenge.")
print("The host refused the spent challenge.")
' "${DATA_DIRECTORY}/tool_loop_replay.json"

echo "Stopping the check host."
cleanup
echo "The tool-loop demonstration completed successfully."
