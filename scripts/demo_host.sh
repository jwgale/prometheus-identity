#!/usr/bin/env bash
# Demonstration: the local check host answers POST /check on 127.0.0.1 only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_DIRECTORY="${DEMO_DATA_DIRECTORY:-$ROOT/data-host}"
rm -rf "$DATA_DIRECTORY"
cargo build
BIN="$ROOT/target/debug/prometheus"
LISTEN_ADDRESS="127.0.0.1:18765"

"$BIN" --data-directory "$DATA_DIRECTORY" init >/dev/null
AGENT_TYPE_ID="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type add \
  --owner laboratory --intent read --authorization-limit internal \
  --max-delegation-depth 2 --lifetime-seconds 3600 | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
BIRTH_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience internal)"
INSTANCE_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["id"])' "$BIRTH_JSON")"
CAPABILITY_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["capability"]["id"])' "$BIRTH_JSON")"
SECRET="$DATA_DIRECTORY/holders/${INSTANCE_ID}.secret"

challenge_nonce() {
  "$BIN" --data-directory "$DATA_DIRECTORY" challenge --instance "$1" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])'
}

echo "The host must refuse a non-loopback listen address."
if "$BIN" --data-directory "$DATA_DIRECTORY" host --listen-address 0.0.0.0:18766; then
  echo "The host bound to all interfaces, but a failure was required."
  exit 1
fi

"$BIN" --data-directory "$DATA_DIRECTORY" host --listen-address "$LISTEN_ADDRESS" &
HOST_PID=$!
cleanup() {
  kill "$HOST_PID" 2>/dev/null || true
}
trap cleanup EXIT

for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -sf "http://${LISTEN_ADDRESS}/health" >/dev/null; then
    break
  fi
  sleep 0.2
done

ALLOWED_NONCE="$(challenge_nonce "$INSTANCE_ID")"
ALLOWED="$(curl -sS -X POST "http://${LISTEN_ADDRESS}/check" \
  -H "Content-Type: application/json" \
  -d "{\"instance_id\":\"${INSTANCE_ID}\",\"capability_id\":\"${CAPABILITY_ID}\",\"intent\":\"read\",\"audience\":\"internal\",\"holder_secret_path\":\"${SECRET}\",\"challenge_nonce\":\"${ALLOWED_NONCE}\",\"on_behalf_of\":\"autonomous\"}")"
echo "${ALLOWED}"
python3 -c '
import json, sys
decision = json.loads(sys.argv[1])
if decision.get("result") != "allowed":
    raise SystemExit("The host must allow the internal audience.")
if decision.get("capability_id") != sys.argv[2]:
    raise SystemExit("The host must name the capability identifier.")
' "$ALLOWED" "$CAPABILITY_ID"

REFUSED_NONCE="$(challenge_nonce "$INSTANCE_ID")"
REFUSED="$(curl -sS -o /tmp/prometheus_host_refused.json -w "%{http_code}" -X POST "http://${LISTEN_ADDRESS}/check" \
  -H "Content-Type: application/json" \
  -d "{\"instance_id\":\"${INSTANCE_ID}\",\"capability_id\":\"${CAPABILITY_ID}\",\"intent\":\"read\",\"audience\":\"public\",\"holder_secret_path\":\"${SECRET}\",\"challenge_nonce\":\"${REFUSED_NONCE}\",\"on_behalf_of\":\"autonomous\"}")"
if [ "$REFUSED" != "403" ]; then
  echo "The host must return HTTP 403 for a public audience. Received ${REFUSED}."
  exit 1
fi
python3 -c '
import json
decision = json.loads(open("/tmp/prometheus_host_refused.json").read())
if decision.get("result") != "refused":
    raise SystemExit("The host must refuse the public audience.")
print("The host refused the public audience.")
'

MISSING="$(curl -sS -o /tmp/prometheus_host_missing.json -w "%{http_code}" -X POST "http://${LISTEN_ADDRESS}/check" \
  -H "Content-Type: application/json" \
  -d "{\"instance_id\":\"${INSTANCE_ID}\",\"capability_id\":\"${CAPABILITY_ID}\",\"intent\":\"read\",\"audience\":\"internal\",\"on_behalf_of\":\"autonomous\"}")"
if [ "$MISSING" != "403" ]; then
  echo "The host must return HTTP 403 when the holder proof is missing. Received ${MISSING}."
  exit 1
fi

MISSING_CAPABILITY="$(curl -sS -o /tmp/prometheus_host_missing_capability.json -w "%{http_code}" -X POST "http://${LISTEN_ADDRESS}/check" \
  -H "Content-Type: application/json" \
  -d "{\"instance_id\":\"${INSTANCE_ID}\",\"intent\":\"read\",\"audience\":\"internal\",\"holder_secret_path\":\"${SECRET}\"}")"
if [ "$MISSING_CAPABILITY" != "403" ]; then
  echo "The host must return HTTP 403 when the capability identifier is missing. Received ${MISSING_CAPABILITY}."
  exit 1
fi
python3 -c '
import json
decision = json.loads(open("/tmp/prometheus_host_missing_capability.json").read())
reason = decision.get("reason") or ""
if decision.get("result") != "refused":
    raise SystemExit("The host must refuse a check that omits the capability identifier.")
if "capability identifier" not in reason:
    raise SystemExit("The refusal must name the missing capability identifier.")
print("The host refused a check that omitted the capability identifier.")
'

echo "The host demonstration completed successfully."
