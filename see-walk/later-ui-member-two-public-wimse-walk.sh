#!/bin/bash
# Rung 100: later UI remote member-secret path, WIMSE public allow then refuse.
# Same HTTP JSON GET / posts. Init on the command line. Host start is a listen command.
# Holder-sign is local. Do not spawn AgentProcess. Do not raise the standing issuer.
# check-wimse body matches later-ui-public-wimse-check-again and later-ui-laboratory-public-wimse.
set -euo pipefail
BIN=/home/jason/Projects/Prometheus/target/release/prometheus
STORE=/tmp/prometheus-later-ui-member-two-public-wimse-20260823
WALK=/home/jason/Projects/Prometheus/see-walk/later-ui-member-two-public-wimse
MEMBER=/home/jason/Projects/prometheus-lab-vpc/mnt-member-two/member-two.secret
MOUNT=/home/jason/Projects/prometheus-lab-vpc/mnt-member-two
SSHFS=/home/jason/.local/bin/sshfs
IDENTITY=/home/jason/.ssh/rustdesk-hermes.pem
STANDING_LAPTOP_MEMBER=/home/jason/Projects/prometheus-lab-vpc/member-two.secret
STANDING_A=/home/jason/Projects/Prometheus/data-a/issuer.json
ISSUING=http://127.0.0.1:18836
PUBLIC=https://check.prestigeworldwide.digital
PORT=18836
AUDIENCE=check.prestigeworldwide.digital
TMP=/tmp/prometheus-later-ui-member-two-public-wimse-curl
mkdir -p "$WALK"
rm -rf "$TMP"
mkdir -m 700 "$TMP"

die() { echo "FAIL: $*" >&2; exit 1; }

http() {
  local method=$1 url=$2 outfile=$3
  local body=${4-}
  if [ -n "$body" ]; then
    curl -sS -X "$method" -H 'content-type: application/json' -d "$body" -o "$outfile" -w '%{http_code}' --max-time 60 "$url"
  else
    curl -sS -X "$method" -o "$outfile" -w '%{http_code}' --max-time 40 "$url"
  fi
}

require() {
  local got=$1 want=$2 label=$3 bodyfile=$4
  if [ "$got" != "$want" ]; then
    die "$label HTTP $got expected $want: $(cat "$bodyfile")"
  fi
}

mount_up() {
  if mountpoint -q "$MOUNT"; then
    return
  fi
  mkdir -p "$MOUNT"
  "$SSHFS" -o "IdentityFile=$IDENTITY" -o StrictHostKeyChecking=accept-new -o reconnect -o ServerAliveInterval=15 \
    ubuntu@10.43.1.186:/home/ubuntu/member-two-custody "$MOUNT"
  local i
  for i in $(seq 1 40); do
    mountpoint -q "$MOUNT" && return
    sleep 0.1
  done
  die "sshfs did not remount $MOUNT"
}

echo PREFLIGHT
[ -x "$BIN" ] || die "missing binary $BIN"
[ -x "$SSHFS" ] || die "missing sshfs $SSHFS"
ping -c 1 -W 3 10.43.1.186 >/dev/null
mount_up
BEFORE_MTIME=$(stat -c %Y "$STANDING_LAPTOP_MEMBER")
STANDING_N=$(jq -r '.threshold_n // 1' "$STANDING_A")
[ "$STANDING_N" = 1 ] || die "standing data-a threshold_n must stay 1"
jq -n --argjson n "$STANDING_N" --argjson m "$BEFORE_MTIME" \
  --arg iso "$(date -d "@$BEFORE_MTIME" '+%Y-%m-%d %H:%M:%S %z')" \
  '{data_a_threshold_n:$n,laptop_member_two_mtime:$m,laptop_member_two_mtime_iso:$iso}' \
  > "$WALK/standing-before.json"

code=$(http GET "$PUBLIC/.well-known/prometheus-check" "$WALK/public-well-known.json")
require "$code" 200 "GET public well-known" "$WALK/public-well-known.json"
jq -e '.bind == "check.prestigeworldwide.digital"' "$WALK/public-well-known.json" >/dev/null \
  || die "public well-known must bind check.prestigeworldwide.digital"
jq -e '.checks | map(.path) | index("/check-wimse")' "$WALK/public-well-known.json" >/dev/null \
  || die "public well-known must name /check-wimse"
jq -e '.checks | map(.path) | index("/check-svid")' "$WALK/public-well-known.json" >/dev/null \
  || die "public well-known must still name /check-svid"
for verb in /birth /present-svid /present-wimse /runtime-check issuer.secret; do
  grep -F -q "$verb" "$WALK/public-well-known.json" && die "public well-known still names write verb $verb"
done
code=$(http GET "$PUBLIC/health" "$WALK/public-health.json")
require "$code" 200 "GET public /health" "$WALK/public-health.json"

rm -rf "$STORE"
mkdir -m 700 "$STORE"
echo INIT
"$BIN" --data-directory "$STORE" init >/dev/null
printf '%s\n' "init ran on hostname 5090. Secret files stay under $STORE. The standing issuer was not used." > "$WALK/a-init-note.txt"

"$BIN" --data-directory "$STORE" host --listen-address "127.0.0.1:${PORT}" >/dev/null 2>&1 &
HOSTPID=$!
CLEANED=0
cleanup() {
  if [ "$CLEANED" = 1 ]; then
    return
  fi
  CLEANED=1
  if kill -0 "$HOSTPID" 2>/dev/null; then
    kill "$HOSTPID" 2>/dev/null || true
    wait "$HOSTPID" 2>/dev/null || true
  fi
  printf '%s\n' "issuing host on 127.0.0.1:${PORT} is stopped" > "$WALK/a-host-stopped.txt"
  if [ -d "$STORE" ]; then
    find "$STORE" -type f -print0 | xargs -0 -r shred -u -- 2>/dev/null || true
    rm -rf "$STORE"
  fi
  rm -rf "$TMP"
  printf '%s\n' "throwaway store $STORE was shredded" > "$WALK/a-store-shredded.txt"
  if [ -e "$STORE" ]; then
    echo "FAIL: throwaway store still exists after shred" >&2
  fi
}
trap cleanup EXIT

ok=0
for _ in $(seq 1 80); do
  if curl -sS -o /dev/null --max-time 1 "$ISSUING/health" >/dev/null 2>&1; then ok=1; break; fi
  sleep 0.1
done
[ "$ok" = 1 ] || die "issuing host did not bind 127.0.0.1:${PORT}"

code=$(http GET "$ISSUING/health" "$WALK/a-health.json")
require "$code" 200 "GET /health" "$WALK/a-health.json"

code=$(http GET "$ISSUING/" "$TMP/root.html")
require "$code" 200 "GET /" "$TMP/root.html"
for marker in \
  'Create Agent Principal' \
  'id="issuing-member-secret-path"' \
  'name="member_secret_path"' \
  'Issuing-store member secret path' \
  'after issuance threshold_n is 2' \
  'Assertion Act' \
  'https://check.prestigeworldwide.digital' \
  'id="emit-wimse"' \
  'workload-identity-token' \
  'function submitCheckWimse(' \
  '/present-wimse' \
  '/check-wimse'
do
  grep -F -q "$marker" "$TMP/root.html" || die "GET / is not the later UI with WIMSE. missing=$marker"
done
grep -F -q 'issuer.secret' "$TMP/root.html" && die "GET / must not name issuer.secret"
grep -F -q 'type="file"' "$TMP/root.html" && die "GET / must not offer a file upload"
{
  echo "issuing GET / is the later user interface with present-wimse"
  echo "listen 127.0.0.1:${PORT}"
  echo "html_bytes $(wc -c < "$TMP/root.html")"
} > "$WALK/a-get-root-proof.txt"

code=$(http GET "$ISSUING/issuer-public" "$TMP/issuer-public.json")
require "$code" 200 "GET /issuer-public" "$TMP/issuer-public.json"
PUBLIC_KEY=$(jq -r '.public_key_hex // .current_issuer_public_key_hex // empty' "$TMP/issuer-public.json")
[ -n "$PUBLIC_KEY" ] || die "issuer-public missing key"
jq '{crypto_profile,public_key_hex_len:(.public_key_hex // .current_issuer_public_key_hex | length),has_public_key:true}' \
  "$TMP/issuer-public.json" > "$WALK/a-issuer-public.json"
printf 'public_key_hex_length=%s\n' "${#PUBLIC_KEY}" > "$WALK/a-issuer-public-key-length.txt"
printf '%s\n' "$PUBLIC_KEY" > "$WALK/a-issuer-public-key.hex"

echo "MEMBER TWO"
jq -n --arg p "$MEMBER" '{member_secret_path:$p}' > "$TMP/member-two-req.json"
code=$(http POST "$ISSUING/member-two" "$TMP/member-two.json" "$(cat "$TMP/member-two-req.json")")
require "$code" 200 "POST /member-two" "$TMP/member-two.json"
MEMBER_PUB=$(jq -r '.public_key_hex // empty' "$TMP/member-two.json")
[ -n "$MEMBER_PUB" ] || die "member-two must return public_key_hex only"
[ -f "$MEMBER" ] || die "kernel did not write member two through the mount"
MODE=$(stat -c %a "$MEMBER")
[ "$MODE" = 600 ] || die "remote member-two.secret mode must be 0600, got $MODE"
jq --argjson st "$code" '{
  http_status:$st,
  public_key_hex_len:(.public_key_hex|length),
  response_keys:(keys),
  secret_bytes_returned:false,
  remote_path_used:true,
  path_is_sshfs_mount:true
}' "$TMP/member-two.json" > "$WALK/a-member-two.json"

echo "ISSUER THRESHOLD"
code=$(http POST "$ISSUING/set-issuer-threshold" "$WALK/a-issuer-threshold.json" '{"confirm":"issuer-threshold","n":2}')
require "$code" 200 "POST /set-issuer-threshold" "$WALK/a-issuer-threshold.json"
[ "$(jq -r .threshold_n "$WALK/a-issuer-threshold.json")" = 2 ] || die "threshold_n must be 2"

echo "AGENT TYPE"
jq -n --arg aud "$AUDIENCE" --arg p "$MEMBER" \
  '{allowed_intents:["read"],authorization_limit:$aud,owner:"jason-gale",member_secret_path:$p}' \
  > "$TMP/agent-type-req.json"
code=$(http POST "$ISSUING/agent-type" "$TMP/agent-type.json" "$(cat "$TMP/agent-type-req.json")")
require "$code" 200 "POST /agent-type" "$TMP/agent-type.json"
AGENT_TYPE_ID=$(jq -r '.agent_type_id // empty' "$TMP/agent-type.json")
[ -n "$AGENT_TYPE_ID" ] || die "agent-type missing id"
jq --argjson st "$code" '{http_status:$st,agent_type_id,allowed_intents}' "$TMP/agent-type.json" > "$WALK/a-agent-type.json"

echo "BIRTH WITHOUT PATH"
jq -n --arg id "$AGENT_TYPE_ID" --arg aud "$AUDIENCE" \
  '{agent_type_id:$id,owner:"jason-gale",intent:"read",audience:$aud,on_behalf_of:"autonomous"}' \
  > "$TMP/birth-no-path.json"
code=$(http POST "$ISSUING/birth" "$TMP/birth-no-path-resp.json" "$(cat "$TMP/birth-no-path.json")")
[ "$code" != 200 ] || die "POST /birth without member_secret_path must refuse after n=2"
REASON=$(jq -r '.reason // .error // empty' "$TMP/birth-no-path-resp.json")
echo "$REASON" | grep -q member_secret_path || die "birth without path must name member_secret_path: $REASON"
jq -n --argjson st "$code" --arg r "$REASON" '{http_status:$st,reason:$r}' > "$WALK/a-birth-refuse-without-path.json"

echo "BIRTH WITH PATH"
jq -n --arg id "$AGENT_TYPE_ID" --arg aud "$AUDIENCE" --arg p "$MEMBER" \
  '{agent_type_id:$id,owner:"jason-gale",intent:"read",audience:$aud,on_behalf_of:"autonomous",member_secret_path:$p}' \
  > "$TMP/birth-req.json"
code=$(http POST "$ISSUING/birth" "$TMP/birth.json" "$(cat "$TMP/birth-req.json")")
require "$code" 200 "POST /birth with remote path" "$TMP/birth.json"
INSTANCE_ID=$(jq -r .instance_id "$TMP/birth.json")
CAPABILITY_ID=$(jq -r .capability_id "$TMP/birth.json")
HOLDER=$(jq -r .holder_secret_path "$TMP/birth.json")
[ -n "$INSTANCE_ID" ] && [ -n "$CAPABILITY_ID" ] && [ -n "$HOLDER" ] || die "birth must return instance, capability, and holder path"
echo "$HOLDER" | grep -q "$STORE" || die "holder secret path must stay on the throwaway store"
jq --argjson st "$code" '{
  http_status:$st,
  instance_id,
  capability_id,
  holder_secret_path_on_throwaway_store:true,
  response_keys:(keys),
  secret_bytes_returned:false
}' "$TMP/birth.json" > "$WALK/a-birth-allow.json"

echo "ISSUER-ACCEPT"
jq -n --arg k "$PUBLIC_KEY" '{public_key_hex:$k}' > "$TMP/issuer-accept-req.json"
code=$(http POST "$PUBLIC/issuer-accept" "$TMP/issuer-accept.json" "$(cat "$TMP/issuer-accept-req.json")")
require "$code" 200 "public POST /issuer-accept" "$TMP/issuer-accept.json"
jq --argjson st "$code" '{
  http_status:$st,
  request_keys:["public_key_hex"],
  response_keys:(keys),
  public_key_hex_length:(.public_key_hex // "" | length)
}' "$TMP/issuer-accept.json" > "$WALK/public-issuer-accept.json"

mint_present() {
  jq -n --arg id "$INSTANCE_ID" --arg p "$MEMBER" '{instance_id:$id,member_secret_path:$p}' > "$TMP/challenge-req.json"
  local code
  code=$(http POST "$ISSUING/challenge" "$TMP/challenge.json" "$(cat "$TMP/challenge-req.json")")
  require "$code" 200 "POST /challenge" "$TMP/challenge.json"
  local nonce
  nonce=$(jq -r '.challenge_nonce // .nonce // empty' "$TMP/challenge.json")
  [ -n "$nonce" ] || die "challenge missing nonce"
  jq -n \
    --arg iid "$INSTANCE_ID" \
    --arg cid "$CAPABILITY_ID" \
    --arg aud "$AUDIENCE" \
    --arg h "$HOLDER" \
    --arg n "$nonce" \
    --arg p "$MEMBER" \
    '{instance_id:$iid,capability_id:$cid,intent:"read",audience:$aud,holder_secret_path:$h,challenge_nonce:$n,on_behalf_of:"autonomous",member_secret_path:$p}' \
    > "$TMP/present-req.json"
  code=$(http POST "$ISSUING/present-wimse" "$TMP/present.json" "$(cat "$TMP/present-req.json")")
  require "$code" 200 "POST /present-wimse" "$TMP/present.json"
  for field in presentation_json workload_identity_token content_digest signature_input signature; do
    [ -n "$(jq -r --arg f "$field" '.[$f] // empty' "$TMP/present.json")" ] || die "present-wimse must return $field"
  done
}

apply_present() {
  jq -r .presentation_json "$TMP/present.json" > "$WALK/presentation.json"
  local sigs
  sigs=$(jq -r '.issuer_signatures | length' "$WALK/presentation.json")
  [ "$sigs" -ge 2 ] || die "present at threshold_n 2 must persist two member signatures, got $sigs"
  SIGS=$sigs
  jq '{keys:(keys)}' "$TMP/present.json" > "$WALK/a-present-wimse-keys.json"
  jq '{
    presentation_json:(.presentation_json|length),
    workload_identity_token:(.workload_identity_token|length),
    content_digest:(.content_digest|length),
    signature_input:(.signature_input|length),
    signature:(.signature|length)
  }' "$TMP/present.json" > "$WALK/a-present-wimse-field-lengths.json"
  local token payload pad decoded sub
  token=$(jq -r .workload_identity_token "$TMP/present.json")
  payload=$(printf '%s' "$token" | cut -d. -f2)
  pad=$(( (4 - ${#payload} % 4) % 4 ))
  payload="${payload}$(printf '%*s' "$pad" | tr ' ' '=')"
  decoded=$(printf '%s' "$payload" | tr '_-' '/+' | base64 -d 2>/dev/null || true)
  printf '%s' "$decoded" | grep -q '"sub":"wimse://prometheus.laboratory/present/' \
    || die "WIT sub must be the present-hash wimse URI"
  printf '%s' "$decoded" | grep -q "$INSTANCE_ID" && die "instance identifier must not live in WIT sub"
  jq -n '{
    sub_prefix:"wimse://prometheus.laboratory/present/",
    sub_is_present_hash_wimse_uri:true,
    iss:"wimse://prometheus.laboratory",
    instance_identifier_in_sub:false
  }' > "$WALK/a-wit-sub.json"
  jq --argjson st 200 --argjson n "$SIGS" '{
    http_status:$st,
    has_presentation_json:true,
    has_workload_identity_token:true,
    has_content_digest:true,
    has_signature_input:true,
    has_signature:true,
    intent:.intent,
    audience:.audience,
    issuer_signature_count:$n,
    secret_bytes_returned:false
  }' "$WALK/presentation.json" > "$WALK/a-present-allow.json"
}

check_wimse_public() {
  local outfile=$1
  local code
  code=$(http POST "$PUBLIC/verifier-challenge" "$TMP/vchal.json" '{}')
  [ "$code" = 200 ] || { echo "$code"; jq -n --arg c "$code" '{result:"refused",reason:("verifier-challenge failed: "+$c)}' > "$outfile"; return; }
  local msg nonce proof
  msg=$(jq -r .challenge_message "$TMP/vchal.json")
  nonce=$(jq -r .challenge_nonce "$TMP/vchal.json")
  proof=$("$BIN" holder-sign --holder-secret-path "$HOLDER" --challenge-message "$msg")
  [ -n "$proof" ] || die "holder-sign must return a proof"
  jq -n \
    --arg pj "$(jq -r .presentation_json "$TMP/present.json")" \
    --arg wit "$(jq -r .workload_identity_token "$TMP/present.json")" \
    --arg cd "$(jq -r .content_digest "$TMP/present.json")" \
    --arg intent "$(jq -r .intent "$WALK/presentation.json")" \
    --arg audience "$(jq -r .audience "$WALK/presentation.json")" \
    --arg proof "$proof" \
    --arg nonce "$nonce" \
    --arg si "$(jq -r .signature_input "$TMP/present.json")" \
    --arg sig "$(jq -r .signature "$TMP/present.json")" \
    '{
      presentation_json:$pj,
      workload_identity_token:$wit,
      content_digest:$cd,
      intent:$intent,
      audience:$audience,
      holder_proof:$proof,
      challenge_nonce:$nonce,
      on_behalf_of:"autonomous",
      signature_input:$si,
      signature:$sig
    }' > "$TMP/check-wimse-req.json"
  http POST "$PUBLIC/check-wimse" "$outfile" "$(cat "$TMP/check-wimse-req.json")"
}

jq -n '{
  keys:[
    "presentation_json",
    "workload_identity_token",
    "content_digest",
    "intent",
    "audience",
    "holder_proof",
    "challenge_nonce",
    "on_behalf_of",
    "signature_input",
    "signature"
  ],
  copied_from:[
    "see-walk/later-ui-public-wimse-check-again-walk.py",
    "see-walk/later-ui-laboratory-public-wimse-walk.py"
  ],
  holder_secret_bytes_sent_to_public_name:false,
  member_secret_bytes_sent_to_public_name:false
}' > "$WALK/public-check-wimse-request-keys.json"

echo PRESENT-WIMSE
mint_present
apply_present

echo "CHECK-WIMSE ALLOW"
ALLOW_CODE=$(check_wimse_public "$TMP/check-allow.json")
ALLOW_RESULT=$(jq -r '.result // .decision // empty' "$TMP/check-allow.json")
if [ "$ALLOW_CODE" != 200 ] || [ "$ALLOW_RESULT" = refused ]; then
  ALLOW_REASON=$(jq -r '.reason // empty' "$TMP/check-allow.json")
  if echo "$ALLOW_REASON" | grep -qi expir; then
    echo "ALLOW expired, remint once"
    mint_present
    apply_present
    ALLOW_CODE=$(check_wimse_public "$TMP/check-allow.json")
    ALLOW_RESULT=$(jq -r '.result // .decision // empty' "$TMP/check-allow.json")
  fi
fi
[ "$ALLOW_CODE" = 200 ] || die "public check-wimse must allow: HTTP $ALLOW_CODE $(cat "$TMP/check-allow.json")"
[ "$ALLOW_RESULT" = allowed ] || [ "$ALLOW_RESULT" = allow ] || [ "$(jq -r '.allowed // false' "$TMP/check-allow.json")" = true ] \
  || die "public check-wimse must allow: $(cat "$TMP/check-allow.json")"
jq --argjson st "$ALLOW_CODE" '{
  http_status:$st,
  result,
  decision,
  reason,
  keys:(keys),
  holder_secret_bytes_sent_to_public_name:false,
  member_secret_bytes_sent_to_public_name:false
}' "$TMP/check-allow.json" > "$WALK/public-check-wimse-allow.json"
echo "ALLOW $ALLOW_CODE $ALLOW_RESULT"

echo KILL
jq -n --arg id "$INSTANCE_ID" --arg p "$MEMBER" '{instance_id:$id,confirm:$id,member_secret_path:$p}' > "$TMP/kill-req.json"
code=$(http POST "$ISSUING/kill" "$TMP/kill.json" "$(cat "$TMP/kill-req.json")")
require "$code" 200 "POST /kill" "$TMP/kill.json"
jq '{instance_id,status,keys:(keys)}' "$TMP/kill.json" > "$WALK/a-kill.json"

echo KILL-EXPORT
code=$(http POST "$ISSUING/kill-export" "$TMP/kill-export.json" "$(cat "$TMP/kill-req.json")")
require "$code" 200 "POST /kill-export" "$TMP/kill-export.json"
jq '{keys:(keys)}' "$TMP/kill-export.json" > "$WALK/kill-export-keys.json"
jq .event "$TMP/kill-export.json" > "$WALK/kill-event.json"
jq .proof "$TMP/kill-export.json" > "$WALK/kill-proof.json"
jq .tree_head "$TMP/kill-export.json" > "$WALK/kill-tree-head.json"

echo KILL-ACCEPT
jq '{event:.event,proof:.proof,tree_head:.tree_head}' "$TMP/kill-export.json" > "$TMP/kill-accept-req.json"
code=$(http POST "$PUBLIC/kill-accept" "$TMP/kill-accept.json" "$(cat "$TMP/kill-accept-req.json")")
require "$code" 200 "public POST /kill-accept" "$TMP/kill-accept.json"
jq --argjson st "$code" '{
  http_status:$st,
  accepted_killed_instance_ids,
  accepted_killed_capability_ids,
  keys:(keys)
}' "$TMP/kill-accept.json" > "$WALK/public-kill-accept.json"

echo "CHECK-WIMSE REFUSE"
REFUSE_CODE=$(check_wimse_public "$TMP/check-refuse.json")
REFUSE_RESULT=$(jq -r '.result // .decision // empty' "$TMP/check-refuse.json")
REFUSE_REASON=$(jq -r '.reason // .error // empty' "$TMP/check-refuse.json")
echo "REFUSE $REFUSE_CODE $REFUSE_REASON"
[ "$REFUSE_RESULT" != allowed ] && [ "$REFUSE_RESULT" != allow ] || die "historical present must refuse after kill-accept"
echo "$REFUSE_REASON" | grep -Eiq 'accepted a kill|kill accept' || die "refuse must name accepted kill: $REFUSE_REASON"
if echo "$REFUSE_REASON" | grep -qi expir; then
  echo "$REFUSE_REASON" | grep -Eiq 'accepted a kill|kill accept' || die "refuse must name accepted kill, not expiry: $REFUSE_REASON"
fi
jq --argjson st "$REFUSE_CODE" --arg r "$REFUSE_REASON" '{
  http_status:$st,
  result,
  reason:$r,
  keys:(keys),
  holder_secret_bytes_sent_to_public_name:false,
  member_secret_bytes_sent_to_public_name:false
}' "$TMP/check-refuse.json" > "$WALK/public-check-wimse-after-kill.json"

AFTER_MTIME=$(stat -c %Y "$STANDING_LAPTOP_MEMBER")
[ "$AFTER_MTIME" = "$BEFORE_MTIME" ] || die "standing laptop member-two.secret mtime moved"
AFTER_N=$(jq -r '.threshold_n // 1' "$STANDING_A")
[ "$AFTER_N" = 1 ] || die "standing data-a threshold_n must stay 1"
COUNTS=$(ssh -i "$IDENTITY" -o StrictHostKeyChecking=accept-new -o BatchMode=yes ubuntu@10.43.1.186 \
  'find /home/ubuntu -name issuer.secret 2>/dev/null | wc -l; find /home/ubuntu/member-two-custody -maxdepth 1 -type f | wc -l')
ISSUER_COUNT=$(printf '%s\n' "$COUNTS" | sed -n '1p' | tr -d ' ')
CUSTODY_FILES=$(printf '%s\n' "$COUNTS" | sed -n '2p' | tr -d ' ')
[ "$ISSUER_COUNT" = 0 ] || die "VPC issuer.secret count must stay 0"
jq -n --argjson n "$AFTER_N" --argjson ic "$ISSUER_COUNT" --argjson cf "$CUSTODY_FILES" '{
  standing_data_a_threshold_n:$n,
  laptop_member_two_mtime_unchanged:true,
  vpc_issuer_secret_count:$ic,
  vpc_custody_file_count:$cf,
  sshfs_mounted:true
}' > "$WALK/a-custody-locks.json"
[ -f "$MEMBER" ] || die "VPC member-two.secret missing after walk; custody dir must stay"
echo "OK later-ui remote path WIMSE public allow then refuse"
