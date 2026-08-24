#!/bin/bash
set -euo pipefail
BIN=/home/jason/Projects/Prometheus/target/release/prometheus
STORE=/tmp/prometheus-public-named-act-wimse-a
WALK=/home/jason/Projects/Prometheus/see-walk/public-named-act-wimse
ISSUING=http://127.0.0.1:18802
PUBLIC=https://check.prestigeworldwide.digital
PORT=18802
REMOTE=/var/lib/prometheus-agent
AUDIENCE=check.prestigeworldwide.digital
SSH=(ssh -o ConnectTimeout=12 -o BatchMode=yes -i /home/jason/.ssh/rustdesk-hermes.pem ubuntu@52.91.253.34)
SCP=(scp -o ConnectTimeout=12 -o BatchMode=yes -i /home/jason/.ssh/rustdesk-hermes.pem)
mkdir -p "$WALK"
rm -rf "$STORE"
mkdir -m 700 "$STORE"

save() {
  printf '%s' "$2" > "$WALK/$1"
}

http_json() {
  local method="$1" url="$2" body="${3:-}"
  local tmp
  tmp=$(mktemp)
  local code
  if [ -n "$body" ]; then
    code=$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" -H 'content-type: application/json' --data "$body" --max-time 25 "$url" || true)
  else
    code=$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" --max-time 25 "$url" || true)
  fi
  HTTP_CODE="$code"
  HTTP_BODY=$(cat "$tmp")
  rm -f "$tmp"
}

remote() {
  "${SSH[@]}" "$@"
}

remote_check() {
  local out
  out=$(remote "$@")
  printf '%s' "$out"
}

wait_remote_new_gate() {
  local previous="$1" expected="$2" timeout="${3:-40}"
  local deadline last=""
  deadline=$((SECONDS + timeout))
  while [ "$SECONDS" -lt "$deadline" ]; do
    last=$(remote_check "cat $REMOTE/agent-process.stdout 2>/dev/null || true")
    if [ "$last" != "$previous" ]; then
      local tail
      tail=$(printf '%s\n' "$last" | awk 'NF{line=$0} END{print line}')
      if [ "$tail" = "$expected" ]; then
        printf '%s' "$last"
        return 0
      fi
    fi
    sleep 0.25
  done
  echo "timeout waiting for new gate $expected. last=$last" >&2
  exit 1
}

require_same_pid() {
  local pid="$1" when="$2"
  local alive
  alive=$(remote_check "ps -p $pid -o pid=" | tr -d '[:space:]')
  if [ "$alive" != "$pid" ]; then
    local stderr
    stderr=$(remote_check "cat $REMOTE/agent-process.stderr 2>/dev/null || true")
    echo "process pid changed or died $when. expected $pid. stderr=$stderr" >&2
    exit 1
  fi
}

cleanup() {
  if [ -n "${HOST_PID:-}" ]; then
    kill "$HOST_PID" 2>/dev/null || true
    wait "$HOST_PID" 2>/dev/null || true
  fi
  remote "if [ -f $REMOTE/agent-process.pid ]; then kill \$(cat $REMOTE/agent-process.pid) 2>/dev/null || true; fi; if [ -f $REMOTE/fifo-keeper.pid ]; then kill \$(cat $REMOTE/fifo-keeper.pid) 2>/dev/null || true; fi" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo INIT
"$BIN" --data-directory "$STORE" init >/dev/null
save a-init-note.txt "init ran on this machine. Secret files stay under /tmp/prometheus-public-named-act-wimse-a.
"
"$BIN" --data-directory "$STORE" host --listen-address "127.0.0.1:$PORT" >/dev/null 2>&1 &
HOST_PID=$!
for _ in $(seq 1 50); do
  if bash -c "echo >/dev/tcp/127.0.0.1/$PORT" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

http_json GET "$ISSUING/health"
[ "$HTTP_CODE" = 200 ] || { echo "health failed $HTTP_CODE $HTTP_BODY"; exit 1; }
printf '%s\n' "$HTTP_BODY" > "$WALK/a-health.json"

http_json POST "$ISSUING/agent-type" '{"owner":"jason-gale","allowed_intents":["read"],"authorization_limit":"check.prestigeworldwide.digital"}'
echo "AGENT-TYPE $HTTP_CODE"
[ "$HTTP_CODE" = 200 ] || { echo "$HTTP_BODY"; exit 1; }
printf '%s\n' "$HTTP_BODY" > "$WALK/a-agent-type.json"
AGENT_TYPE_ID=$(printf '%s' "$HTTP_BODY" | jq -r .agent_type_id)

birth_one() {
  local label="$1"
  http_json POST "$ISSUING/birth" "$(jq -n --arg id "$AGENT_TYPE_ID" '{agent_type_id:$id,owner:"jason-gale",intent:"read",audience:"check.prestigeworldwide.digital",on_behalf_of:"autonomous"}')"
  echo "BIRTH $label $HTTP_CODE"
  [ "$HTTP_CODE" = 200 ] || { echo "$HTTP_BODY"; exit 1; }
  printf '%s' "$HTTP_BODY"
}

FIRST_JSON=$(birth_one first)
SECOND_JSON=$(birth_one second)
FIRST_ID=$(printf '%s' "$FIRST_JSON" | jq -r .instance_id)
FIRST_CAP=$(printf '%s' "$FIRST_JSON" | jq -r .capability_id)
FIRST_HOLDER=$(printf '%s' "$FIRST_JSON" | jq -r .holder_secret_path)
SECOND_ID=$(printf '%s' "$SECOND_JSON" | jq -r .instance_id)
SECOND_CAP=$(printf '%s' "$SECOND_JSON" | jq -r .capability_id)
SECOND_HOLDER=$(printf '%s' "$SECOND_JSON" | jq -r .holder_secret_path)
jq -n --arg first "$FIRST_ID" --arg second "$SECOND_ID" '{first:$first,second:$second,independent:true,first_on_ramp:"x509-svid",second_on_ramp:"wimse"}' > "$WALK/a-births.json"

http_json GET "$ISSUING/issuer-public"
echo "ISSUER-PUBLIC $HTTP_CODE"
[ "$HTTP_CODE" = 200 ] || { echo "$HTTP_BODY"; exit 1; }
KEY=$(printf '%s' "$HTTP_BODY" | jq -r '.current_issuer_public_key_hex // .public_key_hex')
[ -n "$KEY" ] && [ "$KEY" != null ] || { echo "no public key"; exit 1; }
printf '%s\n' "$HTTP_BODY" | jq '{keys: keys}' > "$WALK/a-issuer-public-keys.json"
save a-issuer-public-key-length.txt "public_key_hex_length=${#KEY}
"
http_json POST "$PUBLIC/issuer-accept" "$(jq -n --arg key "$KEY" '{public_key_hex:$key}')"
echo "ISSUER-ACCEPT $HTTP_CODE"
[ "$HTTP_CODE" = 200 ] || { echo "$HTTP_BODY"; exit 1; }
printf '%s\n' "$HTTP_BODY" | jq --argjson status "$HTTP_CODE" '{http_status:$status,request_keys:["public_key_hex"],response_keys:keys}' > "$WALK/public-issuer-accept.json"

http_json GET "$PUBLIC/.well-known/prometheus-check"
echo "WELL-KNOWN $HTTP_CODE"
[ "$HTTP_CODE" = 200 ] || { echo "$HTTP_BODY"; exit 1; }
printf '%s\n' "$HTTP_BODY" > "$WALK/live-prometheus-check.json"
BIND=$(printf '%s' "$HTTP_BODY" | jq -r .bind)
[ "$BIND" = check.prestigeworldwide.digital ] || { echo "public bind must be check.prestigeworldwide.digital"; exit 1; }
printf '%s' "$HTTP_BODY" | jq -e '.checks | map(.path) | index("/check-svid") and index("/check-wimse")' >/dev/null || { echo "well-known must name both checks"; exit 1; }
VC=$(printf '%s' "$HTTP_BODY" | jq -r .verifier_challenge.path)
[ "$VC" = /verifier-challenge ] || { echo "well-known must name verifier-challenge"; exit 1; }
for verb in /birth /spawn /present-svid /present-wimse /seal-export /previous-key-export; do
  if printf '%s' "$HTTP_BODY" | grep -q "$verb"; then
    echo "public well-known still names write verb $verb"
    exit 1
  fi
done

echo "SCP BINARY"
"${SCP[@]}" "$BIN" "ubuntu@52.91.253.34:$REMOTE/prometheus"
"${SCP[@]}" "$FIRST_HOLDER" "ubuntu@52.91.253.34:$REMOTE/holder.secret"
"${SCP[@]}" "$SECOND_HOLDER" "ubuntu@52.91.253.34:$REMOTE/second-holder.secret"
cat > "$WALK/hermes-start-named-act-wimse.sh" << 'START'
#!/bin/bash
set -euo pipefail
REMOTE=/var/lib/prometheus-agent
if [ -f "$REMOTE/agent-process.pid" ]; then kill "$(cat "$REMOTE/agent-process.pid")" 2>/dev/null || true; fi
if [ -f "$REMOTE/fifo-keeper.pid" ]; then kill "$(cat "$REMOTE/fifo-keeper.pid")" 2>/dev/null || true; fi
rm -f "$REMOTE/agent-process.in" "$REMOTE/agent-process.stdout" "$REMOTE/agent-process.stderr" \
  "$REMOTE/agent-process.pid" "$REMOTE/fifo-keeper.pid" \
  "$REMOTE/tool-allow.txt" "$REMOTE/tool-both.txt" "$REMOTE/tool-named-live.txt" \
  "$REMOTE/tool-named-dead.txt" "$REMOTE/tool-unnamed-after.txt" "$REMOTE/tool-named-dead-wimse.txt"
mkfifo "$REMOTE/agent-process.in"
chmod 600 "$REMOTE/agent-process.in"
nohup bash -c "exec 3<>$REMOTE/agent-process.in; while true; do sleep 3600; done" >/dev/null 2>&1 &
echo $! > "$REMOTE/fifo-keeper.pid"
nohup "$REMOTE/prometheus" runtime-check agent-process \
  --base-url https://check.prestigeworldwide.digital \
  --presentation-json "$REMOTE/first-presentation.json" \
  --certificate-pem "$REMOTE/first-presentation.json.svid.pem" \
  --holder-proof-command "$REMOTE/prometheus holder-sign --holder-secret-path $REMOTE/holder.secret" \
  < "$REMOTE/agent-process.in" > "$REMOTE/agent-process.stdout" 2> "$REMOTE/agent-process.stderr" &
echo $! > "$REMOTE/agent-process.pid"
sleep 0.5
ps -p "$(cat $REMOTE/agent-process.pid)" -o pid=,cmd=
START
"${SCP[@]}" "$WALK/hermes-start-named-act-wimse.sh" "ubuntu@52.91.253.34:$REMOTE/hermes-start-named-act-wimse.sh"
remote "chmod 755 $REMOTE/prometheus $REMOTE/hermes-start-named-act-wimse.sh && chmod 600 $REMOTE/holder.secret $REMOTE/second-holder.secret"
LISTING=$(remote "ls -l $REMOTE && echo --- && test ! -e $REMOTE/issuer.secret && test ! -e $REMOTE/biscuit.secret && echo no-issuer-secret no-biscuit-secret && stat -c 'holder.secret mode=%a' $REMOTE/holder.secret")
save hermes-remote-ls.txt "$LISTING
"
BEFORE=${LISTING%%---*}
if printf "%s" "$BEFORE" | grep -q issuer.secret; then
  echo "issuer.secret must not be on Hermes"
  exit 1
fi
printf '%s' "$LISTING" | grep -q 'holder.secret mode=600' || { echo "holder.secret must be mode 600"; exit 1; }
save hermes-copy-note.txt "Copied prometheus binary and holder secrets to Hermes /var/lib/prometheus-agent before mint. Presentation artifacts are copied after mint. Did not copy issuer.secret. Did not copy biscuit.secret.
"

echo "MINT BOTH PRESENTS LATE"
http_json POST "$ISSUING/challenge" "$(jq -n --arg id "$FIRST_ID" '{instance_id:$id}')"
echo "CHALLENGE FIRST $HTTP_CODE"
[ "$HTTP_CODE" = 200 ] || { echo "$HTTP_BODY"; exit 1; }
FIRST_NONCE=$(printf '%s' "$HTTP_BODY" | jq -r .challenge_nonce)
http_json POST "$ISSUING/present-svid" "$(jq -n --arg id "$FIRST_ID" --arg cap "$FIRST_CAP" --arg holder "$FIRST_HOLDER" --arg nonce "$FIRST_NONCE" '{instance_id:$id,capability_id:$cap,holder_secret_path:$holder,challenge_nonce:$nonce,intent:"read",audience:"check.prestigeworldwide.digital",on_behalf_of:"autonomous"}')"
echo "PRESENT-SVID $HTTP_CODE"
[ "$HTTP_CODE" = 200 ] || { echo "$HTTP_BODY"; exit 1; }
printf '%s' "$HTTP_BODY" | jq -r .presentation_json > "$WALK/first-presentation.json"
printf '%s' "$HTTP_BODY" | jq -r .certificate_pem > "$WALK/first-presentation.json.svid.pem"
printf '%s' "$HTTP_BODY" | jq '{keys: keys}' > "$WALK/a-present-svid-keys.json"

http_json POST "$ISSUING/challenge" "$(jq -n --arg id "$SECOND_ID" '{instance_id:$id}')"
echo "CHALLENGE SECOND $HTTP_CODE"
[ "$HTTP_CODE" = 200 ] || { echo "$HTTP_BODY"; exit 1; }
SECOND_NONCE=$(printf '%s' "$HTTP_BODY" | jq -r .challenge_nonce)
http_json POST "$ISSUING/present-wimse" "$(jq -n --arg id "$SECOND_ID" --arg cap "$SECOND_CAP" --arg holder "$SECOND_HOLDER" --arg nonce "$SECOND_NONCE" '{instance_id:$id,capability_id:$cap,holder_secret_path:$holder,challenge_nonce:$nonce,intent:"read",audience:"check.prestigeworldwide.digital",on_behalf_of:"autonomous"}')"
echo "PRESENT-WIMSE $HTTP_CODE"
[ "$HTTP_CODE" = 200 ] || { echo "$HTTP_BODY"; exit 1; }
printf '%s' "$HTTP_BODY" | jq -r .presentation_json > "$WALK/second-presentation.json"
printf '%s' "$HTTP_BODY" | jq -r .workload_identity_token > "$WALK/second-workload_identity_token"
printf '%s' "$HTTP_BODY" | jq -r .content_digest > "$WALK/second-content_digest"
printf '%s' "$HTTP_BODY" | jq -r .signature_input > "$WALK/second-signature_input"
printf '%s' "$HTTP_BODY" | jq -r .signature > "$WALK/second-signature"
printf '%s' "$HTTP_BODY" | jq '{keys: keys, token_length: (.workload_identity_token|length), content_digest_present: ((.content_digest|length)>0), signature_input_present: ((.signature_input|length)>0), signature_present: ((.signature|length)>0)}' > "$WALK/a-second-present-wimse-keys.json"

for name in first-presentation.json first-presentation.json.svid.pem second-presentation.json second-workload_identity_token second-content_digest second-signature_input second-signature; do
  "${SCP[@]}" "$WALK/$name" "ubuntu@52.91.253.34:$REMOTE/$name"
done
remote "chmod 600 $REMOTE/holder.secret $REMOTE/second-holder.secret && chmod 644 $REMOTE/first-presentation.json $REMOTE/first-presentation.json.svid.pem $REMOTE/second-presentation.json $REMOTE/second-workload_identity_token $REMOTE/second-content_digest $REMOTE/second-signature_input $REMOTE/second-signature"
save hermes-second-copy-note.txt "Copied independent second presentation.json, WIMSE token, content-digest, HTTP Message Signature, and second-holder.secret to Hermes. Did not copy issuer.secret.
"

echo "START DURABLE PROCESS"
START_OUT=$(remote "bash $REMOTE/hermes-start-named-act-wimse.sh") || { echo "failed to start: $START_OUT"; exit 1; }
echo "START $START_OUT"
PID=$(remote_check "cat $REMOTE/agent-process.pid" | tr -d '[:space:]')
[[ "$PID" =~ ^[0-9]+$ ]] || { echo "missing pid $PID"; exit 1; }
save hermes-agent-process.pid "$PID
"
save hermes-agent-process-start.txt "$START_OUT
"
require_same_pid "$PID" "after start"

echo "SEND HONEST INDEPENDENT WIMSE ADD-ACT"
cat > "$WALK/hermes-send-wimse-add-act.sh" << 'ADD'
#!/bin/bash
set -euo pipefail
REMOTE=/var/lib/prometheus-agent
printf '%s\n' "add-act --presentation-json $REMOTE/second-presentation.json --workload-identity-token $REMOTE/second-workload_identity_token --content-digest @$REMOTE/second-content_digest --signature-input @$REMOTE/second-signature_input --signature @$REMOTE/second-signature --holder-proof-command \"$REMOTE/prometheus holder-sign --holder-secret-path $REMOTE/second-holder.secret\"" > "$REMOTE/agent-process.in"
ADD
"${SCP[@]}" "$WALK/hermes-send-wimse-add-act.sh" "ubuntu@52.91.253.34:$REMOTE/hermes-send-wimse-add-act.sh"
PREV=$(remote_check "cat $REMOTE/agent-process.stdout 2>/dev/null || true")
remote "bash $REMOTE/hermes-send-wimse-add-act.sh" >/dev/null
STDOUT_ADDED=$(wait_remote_new_gate "$PREV" ADDED 20)
STDERR_ADDED=$(remote_check "cat $REMOTE/agent-process.stderr 2>/dev/null || true")
save hermes-add-act.stdout "$STDOUT_ADDED
"
save hermes-add-act.stderr "$STDERR_ADDED
"
save add-act-second.line "add-act of independent WIMSE used @-files for signature-input, signature, and content-digest
"
require_same_pid "$PID" "after honest independent WIMSE add-act"
jq -n --arg pid "$PID" '{gate:"ADDED",pid:$pid,same_pid:true,added:"independent WIMSE"}' > "$WALK/hermes-add-act-summary.json"

echo "SEND UNNAMED ALLOW BOTH LIVE"
PREV=$(remote_check "cat $REMOTE/agent-process.stdout 2>/dev/null || true")
remote "echo 'echo TOOL_BOTH > $REMOTE/tool-both.txt' > $REMOTE/agent-process.in" >/dev/null
STDOUT_BOTH=$(wait_remote_new_gate "$PREV" ALLOWED 35)
STDERR_BOTH=$(remote_check "cat $REMOTE/agent-process.stderr 2>/dev/null || true")
save hermes-unnamed-both.stdout "$STDOUT_BOTH
"
save hermes-unnamed-both.stderr "$STDERR_BOTH
"
TOOL_BOTH=$(remote_check "test -f $REMOTE/tool-both.txt && cat $REMOTE/tool-both.txt")
save hermes-tool-both.txt "$TOOL_BOTH
"
printf '%s' "$TOOL_BOTH" | grep -q TOOL_BOTH || { echo "tool did not run while both live: $STDOUT_BOTH $STDERR_BOTH"; exit 1; }
require_same_pid "$PID" "after unnamed both-live ALLOWED"

http_json POST "$ISSUING/kill" "$(jq -n --arg id "$FIRST_ID" '{instance_id:$id,confirm:$id}')"
echo "KILL FIRST $HTTP_CODE"
[ "$HTTP_CODE" = 200 ] || { echo "$HTTP_BODY"; exit 1; }
printf '%s' "$HTTP_BODY" | jq '{instance_id,status}' > "$WALK/a-kill-first.json"
http_json POST "$ISSUING/kill-export" "$(jq -n --arg id "$FIRST_ID" '{instance_id:$id,confirm:$id}')"
echo "KILL-EXPORT FIRST $HTTP_CODE"
[ "$HTTP_CODE" = 200 ] || { echo "$HTTP_BODY"; exit 1; }
printf '%s' "$HTTP_BODY" | jq '{keys: keys}' > "$WALK/kill-export-first-keys.json"
http_json POST "$PUBLIC/kill-accept" "$HTTP_BODY"
echo "KILL-ACCEPT FIRST $HTTP_CODE"
[ "$HTTP_CODE" = 200 ] || { echo "$HTTP_BODY"; exit 1; }
printf '%s\n' "$HTTP_BODY" > "$WALK/public-kill-accept-first.json"

echo "SEND UNNAMED AFTER FIRST DEATH"
PREV=$(remote_check "cat $REMOTE/agent-process.stdout 2>/dev/null || true")
remote "echo 'echo TOOL_UNNAMED_AFTER > $REMOTE/tool-unnamed-after.txt' > $REMOTE/agent-process.in" >/dev/null
STDOUT_UNNAMED=$(wait_remote_new_gate "$PREV" REFUSED 35)
STDERR_UNNAMED=$(remote_check "cat $REMOTE/agent-process.stderr 2>/dev/null || true")
save hermes-unnamed-after.stdout "$STDOUT_UNNAMED
"
save hermes-unnamed-after.stderr "$STDERR_UNNAMED
"
require_same_pid "$PID" "after unnamed refuse following first Decommission"
if remote "test ! -f $REMOTE/tool-unnamed-after.txt"; then
  :
else
  echo "tool ran after unnamed refuse"
  exit 1
fi
REFUSE_TEXT=$(printf '%s\n%s' "$STDOUT_UNNAMED" "$STDERR_UNNAMED" | tr '[:upper:]' '[:lower:]')
case "$REFUSE_TEXT" in
  *"accepted a kill"*|*"kill accept"*) ;;
  *) echo "unnamed refuse must name accepted kill. got: $STDOUT_UNNAMED $STDERR_UNNAMED"; exit 1 ;;
esac
case "$REFUSE_TEXT" in
  *"holder proof command did not write"*|*"a holder signature is required"*) echo "unnamed refuse must name accepted kill, not missing holder. got: $STDOUT_UNNAMED $STDERR_UNNAMED"; exit 1 ;;
esac

echo "SEND NAMED ACT 2 LIVE WIMSE"
PREV=$(remote_check "cat $REMOTE/agent-process.stdout 2>/dev/null || true")
remote "echo 'act 2 echo TOOLLIVE > $REMOTE/tool-named-live.txt' > $REMOTE/agent-process.in" >/dev/null
STDOUT_LIVE=$(wait_remote_new_gate "$PREV" ALLOWED 35)
STDERR_LIVE=$(remote_check "cat $REMOTE/agent-process.stderr 2>/dev/null || true")
save hermes-named-live.stdout "$STDOUT_LIVE
"
save hermes-named-live.stderr "$STDERR_LIVE
"
TOOL_LIVE=$(remote_check "test -f $REMOTE/tool-named-live.txt && cat $REMOTE/tool-named-live.txt")
save hermes-tool-named-live.txt "$TOOL_LIVE
"
printf '%s' "$TOOL_LIVE" | grep -q TOOLLIVE || { echo "named live WIMSE act 2 did not run: $STDOUT_LIVE $STDERR_LIVE"; exit 1; }
require_same_pid "$PID" "after named act 2 ALLOWED"

echo "SEND NAMED ACT 1 DEAD FIRST"
PREV=$(remote_check "cat $REMOTE/agent-process.stdout 2>/dev/null || true")
remote "echo 'act 1 echo TOOLDEAD > $REMOTE/tool-named-dead.txt' > $REMOTE/agent-process.in" >/dev/null
STDOUT_DEAD=$(wait_remote_new_gate "$PREV" REFUSED 35)
STDERR_DEAD=$(remote_check "cat $REMOTE/agent-process.stderr 2>/dev/null || true")
save hermes-named-dead.stdout "$STDOUT_DEAD
"
save hermes-named-dead.stderr "$STDERR_DEAD
"
require_same_pid "$PID" "after named act 1 REFUSED"
if remote "test ! -f $REMOTE/tool-named-dead.txt"; then
  :
else
  echo "named dead act 1 ran the tool"
  exit 1
fi
DEAD_TEXT=$(printf '%s\n%s' "$STDOUT_DEAD" "$STDERR_DEAD" | tr '[:upper:]' '[:lower:]')
case "$DEAD_TEXT" in
  *"accepted a kill"*|*"kill accept"*) ;;
  *) echo "named dead act 1 must name accepted kill: $STDOUT_DEAD $STDERR_DEAD"; exit 1 ;;
esac

echo "SEND FAIL-CLOSED ACT 0"
PREV=$(remote_check "cat $REMOTE/agent-process.stdout 2>/dev/null || true")
remote "echo 'act 0 echo SHOULD_NOT_RUN' > $REMOTE/agent-process.in" >/dev/null
STDOUT_ZERO=$(wait_remote_new_gate "$PREV" REFUSED 20)
STDERR_ZERO=$(remote_check "cat $REMOTE/agent-process.stderr 2>/dev/null || true")
save hermes-act-0.stdout "$STDOUT_ZERO
"
save hermes-act-0.stderr "$STDERR_ZERO
"
case "$(printf '%s' "$STDERR_ZERO" | tr '[:upper:]' '[:lower:]')" in
  *"1"*|*"held"*|*"number"*) ;;
  *) echo "act 0 must name the one-based lock: $STDERR_ZERO"; exit 1 ;;
esac
require_same_pid "$PID" "after act 0 refuse"

echo "SEND FAIL-CLOSED MISSING NUMBER"
PREV=$(remote_check "cat $REMOTE/agent-process.stdout 2>/dev/null || true")
remote "echo 'act' > $REMOTE/agent-process.in" >/dev/null
STDOUT_MISSING=$(wait_remote_new_gate "$PREV" REFUSED 20)
STDERR_MISSING=$(remote_check "cat $REMOTE/agent-process.stderr 2>/dev/null || true")
save hermes-act-missing.stdout "$STDOUT_MISSING
"
save hermes-act-missing.stderr "$STDERR_MISSING
"
case "$(printf '%s' "$STDERR_MISSING" | tr '[:upper:]' '[:lower:]')" in
  *"number"*|*"held"*) ;;
  *) echo "missing act number must be refused: $STDERR_MISSING"; exit 1 ;;
esac
require_same_pid "$PID" "after missing act number refuse"

echo "SEND FAIL-CLOSED INDEX NOT HELD"
PREV=$(remote_check "cat $REMOTE/agent-process.stdout 2>/dev/null || true")
remote "echo 'act 9 echo SHOULD_NOT_RUN' > $REMOTE/agent-process.in" >/dev/null
STDOUT_HELD=$(wait_remote_new_gate "$PREV" REFUSED 20)
STDERR_HELD=$(remote_check "cat $REMOTE/agent-process.stderr 2>/dev/null || true")
save hermes-act-not-held.stdout "$STDOUT_HELD
"
save hermes-act-not-held.stderr "$STDERR_HELD
"
case "$(printf '%s' "$STDERR_HELD" | tr '[:upper:]' '[:lower:]')" in
  *"held"*|*"2"*) ;;
  *) echo "unheld act index must be refused: $STDERR_HELD"; exit 1 ;;
esac
require_same_pid "$PID" "after unheld act refuse"

http_json POST "$ISSUING/kill" "$(jq -n --arg id "$SECOND_ID" '{instance_id:$id,confirm:$id}')"
echo "KILL SECOND WIMSE $HTTP_CODE"
[ "$HTTP_CODE" = 200 ] || { echo "$HTTP_BODY"; exit 1; }
printf '%s' "$HTTP_BODY" | jq '{instance_id,status}' > "$WALK/a-kill-second.json"
http_json POST "$ISSUING/kill-export" "$(jq -n --arg id "$SECOND_ID" '{instance_id:$id,confirm:$id}')"
echo "KILL-EXPORT SECOND $HTTP_CODE"
[ "$HTTP_CODE" = 200 ] || { echo "$HTTP_BODY"; exit 1; }
http_json POST "$PUBLIC/kill-accept" "$HTTP_BODY"
echo "KILL-ACCEPT SECOND $HTTP_CODE"
[ "$HTTP_CODE" = 200 ] || { echo "$HTTP_BODY"; exit 1; }
printf '%s\n' "$HTTP_BODY" > "$WALK/public-kill-accept-second.json"

echo "SEND NAMED DEAD WIMSE ACT 2"
PREV=$(remote_check "cat $REMOTE/agent-process.stdout 2>/dev/null || true")
remote "echo 'act 2 echo TOOLDEADWIMSE > $REMOTE/tool-named-dead-wimse.txt' > $REMOTE/agent-process.in" >/dev/null
STDOUT_DEAD_WIMSE=$(wait_remote_new_gate "$PREV" REFUSED 35)
STDERR_DEAD_WIMSE=$(remote_check "cat $REMOTE/agent-process.stderr 2>/dev/null || true")
save hermes-named-dead-wimse.stdout "$STDOUT_DEAD_WIMSE
"
save hermes-named-dead-wimse.stderr "$STDERR_DEAD_WIMSE
"
require_same_pid "$PID" "after named dead WIMSE act 2 REFUSED"
if remote "test ! -f $REMOTE/tool-named-dead-wimse.txt"; then
  :
else
  echo "named dead WIMSE act 2 ran the tool"
  exit 1
fi
DEAD_WIMSE_TEXT=$(printf '%s\n%s' "$STDOUT_DEAD_WIMSE" "$STDERR_DEAD_WIMSE" | tr '[:upper:]' '[:lower:]')
case "$DEAD_WIMSE_TEXT" in
  *"accepted a kill"*|*"kill accept"*) ;;
  *) echo "named dead WIMSE must name accepted kill: $STDOUT_DEAD_WIMSE $STDERR_DEAD_WIMSE"; exit 1 ;;
esac

jq -n --arg pid "$PID" --arg live "$TOOL_LIVE" '{
  pid:$pid,same_pid:true,first_on_ramp:"x509-svid",second_on_ramp:"wimse",independent:true,
  unnamed_both_live:"ALLOWED",unnamed_after_first_death:"REFUSED",
  named_live_wimse_act_2:"ALLOWED",named_dead_first_act_1:"REFUSED",
  named_dead_wimse_act_2:"REFUSED",fail_closed_act_0:"REFUSED",
  fail_closed_missing_number:"REFUSED",fail_closed_index_not_held:"REFUSED",
  tool_named_live:$live
}' > "$WALK/hermes-named-act-wimse-summary.json"

remote "echo stop > $REMOTE/agent-process.in || true" >/dev/null || true
sleep 0.4
remote "if [ -f $REMOTE/agent-process.pid ]; then kill \$(cat $REMOTE/agent-process.pid) 2>/dev/null || true; fi; if [ -f $REMOTE/fifo-keeper.pid ]; then kill \$(cat $REMOTE/fifo-keeper.pid) 2>/dev/null || true; fi" >/dev/null || true

cat > "$WALK/SEE.txt" << SEE
Public named-act WIMSE independent second Assertion Act walk

Date: 23 August 2026.

This folder is for Jason Gale. These files are public records and artifacts. This folder does not contain issuer.secret, biscuit.secret, holder secrets, or member-two secrets. The issuing store lived under /tmp/prometheus-public-named-act-wimse-a.

Create Agent Principal ran on the operator machine and bound 127.0.0.1 only. Two independent live instances were born. The first Assertion Act was a laboratory X.509-SVID wrap. The second Assertion Act was a WIMSE present. The durable agent process ran on Hermes at 52.91.253.34. The verifier is https://check.prestigeworldwide.digital. Hermes held both Assertion Acts and the holder keys. Hermes did not hold issuer.secret. Hermes is not a second identity store.

prometheus runtime-check agent-process on Hermes started with the first X.509-SVID Assertion Act. add-act of the second independent WIMSE Assertion Act printed ADDED on the same process identifier. An unnamed tool line printed ALLOWED only after both documented checks allowed. After Decommission of the first instance by kill accept, an unnamed tool line on the same process identifier printed REFUSED because this store accepted a kill. A line that named act 2 printed ALLOWED and ran the tool because that WIMSE Assertion Act was still live. A line that named act 1 printed REFUSED because this store accepted a kill. After Decommission of the second instance, a line that named act 2 printed REFUSED because this store accepted a kill. Act 0, a missing act number, and an act number this process does not hold are refused. The process did not restart.

This is not SPIRE. This is not a replica. This is not a public listener for birth. This is not Sanctum.
SEE

echo "WALK_OK pid $PID"
