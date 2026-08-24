#!/bin/bash
# Later user interface Check both against the live public check name.
# Small curls. Same JSON GET / posts. Do not spawn AgentProcess.
# Do not copy issuer.secret onto the public host.
set -euo pipefail
BIN=/home/jason/Projects/Prometheus/target/release/prometheus
STORE=/tmp/prometheus-later-ui-public-check-both-a
WALK=/home/jason/Projects/Prometheus/see-walk/later-ui-public-check-both
ISSUING=http://127.0.0.1:18826
PUBLIC=https://check.prestigeworldwide.digital
PORT=18826
AUDIENCE=check.prestigeworldwide.digital
NARROWER=check.prestigeworldwide.digital/child
TMP=/tmp/prometheus-later-ui-public-check-both-curl
mkdir -p "$WALK"
rm -rf "$STORE" "$TMP"
mkdir -m 700 "$STORE"
mkdir -m 700 "$TMP"

die() { echo "FAIL: $*" >&2; exit 1; }

http() {
  local method=$1 url=$2 outfile=$3
  local body=${4-}
  if [ -n "$body" ]; then
    curl -sS -X "$method" -H 'content-type: application/json' -d "$body" -o "$outfile" -w '%{http_code}' --max-time 40 "$url"
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

must_allow() {
  local code=$1 file=$2 label=$3
  [ "$code" = 200 ] || die "$label must allow: HTTP $code $(cat "$file")"
  [ "$(jq -r .result "$file")" = allowed ] || die "$label must allow: $(cat "$file")"
  grep -q issuer.secret "$file" && die "$label body must not name issuer.secret"
}

must_refuse_kill() {
  local code=$1 file=$2 label=$3 cascade=${4-0}
  [ "$code" = 403 ] || die "$label must refuse after operator-pin kill-accept: HTTP $code $(cat "$file")"
  [ "$(jq -r .result "$file")" = refused ] || die "$label must be refused: $(cat "$file")"
  local reason
  reason=$(jq -r '.reason // empty' "$file")
  echo "$reason" | grep -qi expir && die "$label must refuse from accepted kill, not expiry: $reason"
  if [ "$cascade" = 1 ]; then
    echo "$reason" | grep -Eiq 'accepted a kill|kill accept|kill|cascade' || die "$label must name accepted parent death cascade: $reason"
  else
    echo "$reason" | grep -Eiq 'accepted a kill|kill accept' || die "$label must refuse from accepted kill: $reason"
  fi
  grep -q issuer.secret "$file" && die "$label body must not name issuer.secret"
}

echo INIT
"$BIN" --data-directory "$STORE" init >/dev/null
printf '%s\n' "init ran on this machine. Secret files stay under /tmp/prometheus-later-ui-public-check-both-a." > "$WALK/a-init-note.txt"

"$BIN" --data-directory "$STORE" host --listen-address "127.0.0.1:${PORT}" >/dev/null 2>&1 &
HOSTPID=$!
cleanup() {
  if kill -0 "$HOSTPID" 2>/dev/null; then
    kill "$HOSTPID" 2>/dev/null || true
    wait "$HOSTPID" 2>/dev/null || true
  fi
  printf '%s\n' "issuing host on 127.0.0.1:${PORT} is stopped" > "$WALK/a-host-stopped.txt"
  rm -rf "$STORE" "$TMP"
  if [ -e "$STORE" ] || [ -e "$STORE/issuer.secret" ]; then
    die "issuer.secret must not remain under /tmp"
  fi
  printf '%s\n' "Deleted /tmp/prometheus-later-ui-public-check-both-a after the walk. issuer.secret is not left under /tmp from this walk." > "$WALK/tmp-cleaned.txt"
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

code=$(http GET "$ISSUING/" "$WALK/a-get-root.html")
require "$code" 200 "GET /" "$WALK/a-get-root.html"
root="$WALK/a-get-root.html"
for marker in \
  'id="check-base"' \
  'https://check.prestigeworldwide.digital' \
  'Create Agent Principal' \
  '/runtime-check' \
  'id="check-both"' \
  'Check both' \
  'function checkBoth(' \
  'function checkThisActOnly(' \
  'id="check-this-act"' \
  'id="check-act-number"' \
  'Hold two Assertion Acts' \
  'accepted a kill cascade' \
  'named check of the live act' \
  'This page does not store ALLOWED' \
  'Each present is a separate host hit' \
  '/well-known-follow' \
  '/operator-pin' \
  'The path is not sent to the check base' \
  'Spawn a narrower child'
do
  grep -F -q "$marker" "$root" || die "GET / is not the later UI with Check both. missing=$marker"
done
grep -F -q 'issuer.secret' "$root" && die "GET / must not name issuer.secret"
grep -F -q 'type="file"' "$root" && die "GET / must not offer a file upload"
grep -F -q 'fetch("https://' "$root" && die "GET / JS must not CORS-fetch"
grep -F -q 'fetch("http://' "$root" && die "GET / JS must not CORS-fetch"
{
  echo "issuing GET / is the later user interface with Check both and a named check"
  echo "listen 127.0.0.1:${PORT}"
  echo "html_bytes $(wc -c < "$root")"
} > "$WALK/a-get-root-proof.txt"
rm -f "$WALK/a-get-root.html"

code=$(http GET "$PUBLIC/" "$WALK/public-root.json")
require "$code" 200 "public GET /" "$WALK/public-root.json"
role=$(jq -r .role "$WALK/public-root.json")
bind=$(jq -r .bind "$WALK/public-root.json")
[ "$role" = check-only ] && [ "$bind" = check.prestigeworldwide.digital ] || die "public GET / must stay check-only JSON"

echo "PUBLIC HELPER 403"
jq -n --arg b "$PUBLIC" '{check_base:$b,pin:"kill-accept",body:{}}' > "$TMP/op.json"
code=$(http POST "$PUBLIC/operator-pin" "$WALK/public-operator-pin.json" "$(cat "$TMP/op.json")")
require "$code" 403 "public POST /operator-pin" "$WALK/public-operator-pin.json"
grep -q check-only "$WALK/public-operator-pin.json" || die "public POST /operator-pin must stay check-only"

jq -n --arg b "$PUBLIC" '{check_base:$b}' > "$TMP/wk.json"
code=$(http POST "$PUBLIC/well-known-follow" "$WALK/public-well-known-follow.json" "$(cat "$TMP/wk.json")")
require "$code" 403 "public POST /well-known-follow" "$WALK/public-well-known-follow.json"
grep -q check-only "$WALK/public-well-known-follow.json" || die "public POST /well-known-follow must stay check-only"

jq -n --arg b "$PUBLIC" '{check_base:$b,presentation_json:"{}"}' > "$TMP/rc.json"
code=$(http POST "$PUBLIC/runtime-check" "$WALK/public-runtime-check-refused.json" "$(cat "$TMP/rc.json")")
require "$code" 403 "public POST /runtime-check" "$WALK/public-runtime-check-refused.json"
grep -q check-only "$WALK/public-runtime-check-refused.json" || die "public POST /runtime-check must stay check-only"

jq -s '{
  "/operator-pin":{http_status:403,body:.[0]},
  "/well-known-follow":{http_status:403,body:.[1]},
  "/runtime-check":{http_status:403,body:.[2]}
}' "$WALK/public-operator-pin.json" "$WALK/public-well-known-follow.json" "$WALK/public-runtime-check-refused.json" > "$WALK/public-helpers-refused.json"

code=$(http GET "$PUBLIC/.well-known/prometheus-check" "$WALK/public-well-known.json")
require "$code" 200 "public well-known" "$WALK/public-well-known.json"
[ "$(jq -r .bind "$WALK/public-well-known.json")" = check.prestigeworldwide.digital ] || die "public well-known bind must be check.prestigeworldwide.digital"
echo "$(jq -r '.checks[].path' "$WALK/public-well-known.json")" | grep -qx /check-svid || die "public well-known must name /check-svid"
for verb in /birth /spawn /present-svid /present-wimse /runtime-check /seal-export /previous-key-export; do
  grep -F -q "$verb" "$WALK/public-well-known.json" && die "public well-known still names write verb $verb"
done

echo WELL-KNOWN-FOLLOW
code=$(http POST "$ISSUING/well-known-follow" "$WALK/issuing-well-known-follow.json" "$(cat "$TMP/wk.json")")
require "$code" 200 "POST /well-known-follow public" "$WALK/issuing-well-known-follow.json"
[ "$(jq -r .bind "$WALK/issuing-well-known-follow.json")" = check.prestigeworldwide.digital ] || die "well-known-follow bind must be the public name"
grep -E 'issuer\.secret|holder_secret' "$WALK/issuing-well-known-follow.json" && die "well-known-follow must not return secrets"
kill_accept_path=$(jq -r '.operator_pin_paths[] | select(.path|test("kill-accept$")) | .path' "$WALK/issuing-well-known-follow.json")
issuer_accept_path=$(jq -r '.operator_pin_paths[] | select(.path|test("issuer-accept$")) | .path' "$WALK/issuing-well-known-follow.json")
[ "$kill_accept_path" = /kill-accept ] || die "public document kill-accept path was $kill_accept_path"
jq -n --arg b "$PUBLIC" --arg k "$kill_accept_path" --arg i "$issuer_accept_path" '{
  check_base:$b,
  kill_accept_pin_name:"kill-accept",
  kill_accept_path:$k,
  issuer_accept_path:$i,
  note:"GET / resolves these paths from the well-known document. POST /operator-pin then posts that pin name. This walk does not hardcode public /kill-accept as the accept URL."
}' > "$WALK/resolved-operator-pins.json"

code=$(http POST "$ISSUING/agent-type" "$WALK/a-agent-type-raw.json" "$(jq -n --arg aud "$AUDIENCE" '{owner:"jason-gale",allowed_intents:["read"],authorization_limit:$aud}')")
echo "AGENT-TYPE $code"
require "$code" 200 "POST /agent-type" "$WALK/a-agent-type-raw.json"
jq '{agent_type_id:.agent_type_id,keys:(keys|sort)}' "$WALK/a-agent-type-raw.json" > "$WALK/a-agent-type.json"
agent_type_id=$(jq -r .agent_type_id "$WALK/a-agent-type-raw.json")

code=$(http POST "$ISSUING/birth" "$WALK/a-birth-parent-raw.json" "$(jq -n --arg id "$agent_type_id" --arg aud "$AUDIENCE" '{agent_type_id:$id,owner:"jason-gale",intent:"read",audience:$aud,on_behalf_of:"autonomous"}')")
echo "BIRTH PARENT $code"
require "$code" 200 "POST /birth parent" "$WALK/a-birth-parent-raw.json"
jq 'has("holder_secret") and (has("holder_secret_path")|not)' "$WALK/a-birth-parent-raw.json" | grep -q true && die "POST /birth must not return secret bytes"
jq '{instance_id:.instance_id,capability_id:.capability_id,revoke_identifier:.revoke_identifier,holder_secret_path_present:(has("holder_secret_path"))}' "$WALK/a-birth-parent-raw.json" > "$WALK/a-birth-parent.json"
parent_instance_id=$(jq -r .instance_id "$WALK/a-birth-parent-raw.json")
parent_capability_id=$(jq -r .capability_id "$WALK/a-birth-parent-raw.json")
parent_holder=$(jq -r .holder_secret_path "$WALK/a-birth-parent-raw.json")
case "$parent_holder" in
  "$STORE"*) ;;
  *) die "parent holder secret path must stay under the throwaway store" ;;
esac

code=$(http GET "$ISSUING/issuer-public" "$WALK/a-issuer-public-raw.json")
require "$code" 200 "GET /issuer-public" "$WALK/a-issuer-public-raw.json"
jq '{keys:(keys|sort)}' "$WALK/a-issuer-public-raw.json" > "$WALK/a-issuer-public-keys.json"
key=$(jq -r '.current_issuer_public_key_hex // .public_key_hex' "$WALK/a-issuer-public-raw.json")
[ -n "$key" ] && [ "$key" != null ] || die "no public key"
printf 'public_key_hex_length=%s\n' "${#key}" > "$WALK/a-issuer-public-key-length.txt"

echo "OPERATOR-PIN ISSUER-ACCEPT"
jq -n --arg b "$PUBLIC" --arg k "$key" '{check_base:$b,pin:"issuer-accept",body:{public_key_hex:$k}}' > "$TMP/issuer.json"
code=$(http POST "$ISSUING/operator-pin" "$WALK/operator-pin-issuer-accept-raw.json" "$(cat "$TMP/issuer.json")")
echo "ISSUER-ACCEPT $code"
require "$code" 200 "POST /operator-pin issuer-accept" "$WALK/operator-pin-issuer-accept-raw.json"
jq --argjson s "$code" --arg p "$issuer_accept_path" '{http_status:$s,pin:"issuer-accept",resolved_path:$p,request_keys:["check_base","pin","body"],response_keys:(keys|sort)}' "$WALK/operator-pin-issuer-accept-raw.json" > "$WALK/operator-pin-issuer-accept.json"

echo "SPAWN NARROWER CHILD"
code=$(http POST "$ISSUING/challenge" "$TMP/spawn-challenge.json" "$(jq -n --arg id "$parent_instance_id" '{instance_id:$id}')")
require "$code" 200 "POST /challenge spawn" "$TMP/spawn-challenge.json"
nonce=$(jq -r .challenge_nonce "$TMP/spawn-challenge.json")
jq -n --arg pid "$parent_instance_id" --arg cap "$parent_capability_id" --arg hp "$parent_holder" --arg n "$nonce" --arg aud "$NARROWER" '{
  parent_instance_id:$pid,parent_capability_id:$cap,owner:"jason-gale",intent:"read",audience:$aud,holder_secret_path:$hp,challenge_nonce:$n,on_behalf_of:"autonomous"
}' > "$TMP/spawn.json"
code=$(http POST "$ISSUING/spawn" "$WALK/a-spawn-child-raw.json" "$(cat "$TMP/spawn.json")")
echo "SPAWN $code"
require "$code" 200 "POST /spawn narrower child" "$WALK/a-spawn-child-raw.json"
child_instance_id=$(jq -r .instance_id "$WALK/a-spawn-child-raw.json")
child_capability_id=$(jq -r .capability_id "$WALK/a-spawn-child-raw.json")
child_holder=$(jq -r .holder_secret_path "$WALK/a-spawn-child-raw.json")
[ "$child_instance_id" != "$parent_instance_id" ] || die "POST /spawn must write a child instance, not reuse the parent"
jq 'has("holder_secret") and (has("holder_secret_path")|not)' "$WALK/a-spawn-child-raw.json" | grep -q true && die "POST /spawn must not return secret bytes"
case "$child_holder" in
  "$STORE"*) ;;
  *) die "child holder secret path must stay under the throwaway store" ;;
esac
jq --arg p "$parent_instance_id" --arg a "$NARROWER" '{parent_instance_id:$p,instance_id:.instance_id,capability_id:.capability_id,audience:$a,holder_secret_path_present:(has("holder_secret_path")),keys:(keys|sort)}' "$WALK/a-spawn-child-raw.json" > "$WALK/a-spawn-child.json"

mint_svid() {
  local iid=$1 cap=$2 hp=$3 aud=$4 out=$5
  local ccode
  ccode=$(http POST "$ISSUING/challenge" "$TMP/challenge.json" "$(jq -n --arg id "$iid" '{instance_id:$id}')")
  [ "$ccode" = 200 ] || die "POST /challenge HTTP $ccode: $(cat "$TMP/challenge.json")"
  local n
  n=$(jq -r .challenge_nonce "$TMP/challenge.json")
  local pcode
  pcode=$(http POST "$ISSUING/present-svid" "$out" "$(jq -n --arg id "$iid" --arg cap "$cap" --arg hp "$hp" --arg n "$n" --arg aud "$aud" '{
    instance_id:$id,capability_id:$cap,holder_secret_path:$hp,challenge_nonce:$n,intent:"read",audience:$aud,on_behalf_of:"autonomous"
  }')")
  [ "$pcode" = 200 ] || die "POST /present-svid HTTP $pcode: $(cat "$out")"
  grep -E 'holder_secret|issuer\.secret' "$out" && die "POST /present-svid must not return secret bytes"
}

echo "PRESENT PARENT AND CHILD"
mint_svid "$parent_instance_id" "$parent_capability_id" "$parent_holder" "$AUDIENCE" "$TMP/parent-svid.json"
mint_svid "$child_instance_id" "$child_capability_id" "$child_holder" "$NARROWER" "$TMP/child-svid.json"
jq -r .presentation_json "$TMP/parent-svid.json" > "$WALK/parent-presentation.json"
jq -r .certificate_pem "$TMP/parent-svid.json" > "$WALK/parent-presentation.json.svid.pem"
jq -r .presentation_json "$TMP/child-svid.json" > "$WALK/child-presentation.json"
jq -r .certificate_pem "$TMP/child-svid.json" > "$WALK/child-presentation.json.svid.pem"
jq -n --argjson p "$(jq '{keys:(keys|sort)}' "$TMP/parent-svid.json")" --argjson c "$(jq '{keys:(keys|sort)}' "$TMP/child-svid.json")" '{parent:$p.keys,child:$c.keys}' > "$WALK/a-present-svid-keys.json"

jq --arg b "$PUBLIC" --arg hp "$parent_holder" '{check_base:$b,presentation_json:.presentation_json,certificate_pem:.certificate_pem,holder_secret_path:$hp}' "$TMP/parent-svid.json" > "$TMP/parent-runtime.json"
jq --arg b "$PUBLIC" --arg hp "$child_holder" '{check_base:$b,presentation_json:.presentation_json,certificate_pem:.certificate_pem,holder_secret_path:$hp}' "$TMP/child-svid.json" > "$TMP/child-runtime.json"
jq -n --arg b "$PUBLIC" --argjson pk "$(jq 'keys|sort' "$TMP/parent-runtime.json")" --argjson ck "$(jq 'keys|sort' "$TMP/child-runtime.json")" '{
  parent_keys:$pk,child_keys:$ck,check_base:$b,
  holder_secret_path_sent_to_issuing_host:true,
  holder_secret_bytes_sent_to_public_name:false,
  two_runtime_check_hits:true,
  note:"GET / Check both posts this JSON once per present to the loopback issuing host. That host signs the verifier nonce locally. Secret bytes are not uploaded. The path is not sent to the public name."
}' > "$WALK/runtime-check-request-keys.json"

echo "CHECK BOTH ALLOW"
pcode=$(http POST "$ISSUING/runtime-check" "$TMP/parent-allow.json" "$(cat "$TMP/parent-runtime.json")")
ccode=$(http POST "$ISSUING/runtime-check" "$TMP/child-allow.json" "$(cat "$TMP/child-runtime.json")")
if [ "$pcode" != 200 ] || [ "$(jq -r .result "$TMP/parent-allow.json")" != allowed ] || [ "$ccode" != 200 ] || [ "$(jq -r .result "$TMP/child-allow.json")" != allowed ]; then
  echo "ALLOW failed, remint once $pcode $(cat "$TMP/parent-allow.json") $ccode $(cat "$TMP/child-allow.json")"
  mint_svid "$parent_instance_id" "$parent_capability_id" "$parent_holder" "$AUDIENCE" "$TMP/parent-svid.json"
  mint_svid "$child_instance_id" "$child_capability_id" "$child_holder" "$NARROWER" "$TMP/child-svid.json"
  jq -r .presentation_json "$TMP/parent-svid.json" > "$WALK/parent-presentation.json"
  jq -r .certificate_pem "$TMP/parent-svid.json" > "$WALK/parent-presentation.json.svid.pem"
  jq -r .presentation_json "$TMP/child-svid.json" > "$WALK/child-presentation.json"
  jq -r .certificate_pem "$TMP/child-svid.json" > "$WALK/child-presentation.json.svid.pem"
  jq --arg b "$PUBLIC" --arg hp "$parent_holder" '{check_base:$b,presentation_json:.presentation_json,certificate_pem:.certificate_pem,holder_secret_path:$hp}' "$TMP/parent-svid.json" > "$TMP/parent-runtime.json"
  jq --arg b "$PUBLIC" --arg hp "$child_holder" '{check_base:$b,presentation_json:.presentation_json,certificate_pem:.certificate_pem,holder_secret_path:$hp}' "$TMP/child-svid.json" > "$TMP/child-runtime.json"
  pcode=$(http POST "$ISSUING/runtime-check" "$TMP/parent-allow.json" "$(cat "$TMP/parent-runtime.json")")
  ccode=$(http POST "$ISSUING/runtime-check" "$TMP/child-allow.json" "$(cat "$TMP/child-runtime.json")")
fi
must_allow "$pcode" "$TMP/parent-allow.json" "Check both parent POST /runtime-check"
must_allow "$ccode" "$TMP/child-allow.json" "Check both child POST /runtime-check"
jq -n --argjson ps "$pcode" --argjson cs "$ccode" --argjson p "$(cat "$TMP/parent-allow.json")" --argjson c "$(cat "$TMP/child-allow.json")" '{
  parent:{http_status:$ps,result:$p.result,reason:$p.reason,keys:($p|keys|sort)},
  child:{http_status:$cs,result:$c.result,reason:$c.reason,keys:($c|keys|sort)},
  check_both_allowed:true,cached_allowed:false,two_runtime_check_hits:true
}' > "$WALK/runtime-check-both-allow.json"

kill_body=$(jq -n --arg id "$parent_instance_id" '{instance_id:$id,confirm:$id}')
code=$(http POST "$ISSUING/kill" "$WALK/a-kill-parent-raw.json" "$kill_body")
echo "KILL PARENT $code"
require "$code" 200 "POST /kill parent" "$WALK/a-kill-parent-raw.json"
jq '{instance_id:.instance_id,status:.status,keys:(keys|sort)}' "$WALK/a-kill-parent-raw.json" > "$WALK/a-kill-parent.json"

code=$(http POST "$ISSUING/kill-export" "$WALK/kill-export-raw.json" "$kill_body")
echo "KILL-EXPORT $code"
require "$code" 200 "POST /kill-export" "$WALK/kill-export-raw.json"
jq '{keys:(keys|sort)}' "$WALK/kill-export-raw.json" > "$WALK/kill-export-keys.json"

echo "WELL-KNOWN-FOLLOW THEN OPERATOR-PIN KILL-ACCEPT"
code=$(http POST "$ISSUING/well-known-follow" "$TMP/follow-again.json" "$(cat "$TMP/wk.json")")
require "$code" 200 "POST /well-known-follow before kill-accept" "$TMP/follow-again.json"
again_path=$(jq -r '.operator_pin_paths[] | select(.path|test("kill-accept$")) | .path' "$TMP/follow-again.json")
[ "$again_path" = "$kill_accept_path" ] || die "kill-accept path changed between follow and pin: $kill_accept_path vs $again_path"
jq -n --arg b "$PUBLIC" --argjson ev "$(jq .event "$WALK/kill-export-raw.json")" --argjson pr "$(jq .proof "$WALK/kill-export-raw.json")" --argjson th "$(jq .tree_head "$WALK/kill-export-raw.json")" '{
  check_base:$b,pin:"kill-accept",body:{event:$ev,proof:$pr,tree_head:$th}
}' > "$TMP/kill-accept.json"
code=$(http POST "$ISSUING/operator-pin" "$WALK/operator-pin-kill-accept-raw.json" "$(cat "$TMP/kill-accept.json")")
echo "OPERATOR-PIN KILL-ACCEPT $code"
require "$code" 200 "POST /operator-pin kill-accept" "$WALK/operator-pin-kill-accept-raw.json"
jq --argjson s "$code" --arg p "$again_path" '{
  http_status:$s,pin:"kill-accept",resolved_path:$p,
  accepted_killed_instance_ids:.accepted_killed_instance_ids,
  accepted_killed_capability_ids:.accepted_killed_capability_ids,
  keys:(keys|sort),hardcoded_public_kill_accept:false
}' "$WALK/operator-pin-kill-accept-raw.json" > "$WALK/operator-pin-kill-accept.json"

echo "CHECK BOTH AFTER PARENT DECOMMISSION"
pcode=$(http POST "$ISSUING/runtime-check" "$TMP/parent-refuse.json" "$(cat "$TMP/parent-runtime.json")")
ccode=$(http POST "$ISSUING/runtime-check" "$TMP/child-refuse.json" "$(cat "$TMP/child-runtime.json")")
must_refuse_kill "$pcode" "$TMP/parent-refuse.json" "Check both parent after kill-accept" 0
must_refuse_kill "$ccode" "$TMP/child-refuse.json" "Check both child after parent kill-accept" 1
jq -n --argjson ps "$pcode" --argjson cs "$ccode" --argjson p "$(cat "$TMP/parent-refuse.json")" --argjson c "$(cat "$TMP/child-refuse.json")" '{
  parent:{http_status:$ps,result:$p.result,reason:$p.reason,same_present:true},
  child:{http_status:$cs,result:$c.result,reason:$c.reason,same_present:true},
  check_both_allowed:false,cached_allowed:false,two_runtime_check_hits:true,refuse_from_accepted_kill_cascade:true
}' > "$WALK/runtime-check-both-after-decommission.json"

echo "NAMED CHECK OF CHILD AFTER CASCADE"
ncode=$(http POST "$ISSUING/runtime-check" "$TMP/named-child.json" "$(cat "$TMP/child-runtime.json")")
must_refuse_kill "$ncode" "$TMP/named-child.json" "named check of the child after parent kill-accept" 1
jq --argjson s "$ncode" '{
  http_status:$s,result:.result,reason:.reason,act:2,same_child_present:true,cached_allowed:false,refuse_from_accepted_kill_cascade:true,keys:(keys|sort)
}' "$TMP/named-child.json" > "$WALK/named-check-child-after-decommission.json"

echo "PUBLIC CHECK-SVID CHILD AFTER DECOMMISSION"
code=$(http POST "$PUBLIC/verifier-challenge" "$TMP/vchal.json" '{}')
require "$code" 200 "public POST /verifier-challenge" "$TMP/vchal.json"
proof=$("$BIN" holder-sign --holder-secret-path "$child_holder" --challenge-message "$(jq -r .challenge_message "$TMP/vchal.json")" | tr -d '\n')
[ -n "$proof" ] || die "holder-sign must return a proof"
jq -n --argjson pres "$(jq -r .presentation_json "$TMP/child-svid.json")" --arg pem "$(jq -r .certificate_pem "$TMP/child-svid.json")" --arg proof "$proof" --arg nonce "$(jq -r .challenge_nonce "$TMP/vchal.json")" --arg intent "$(jq -r '.presentation_json|fromjson|.intent' "$TMP/child-svid.json")" --arg aud "$(jq -r '.presentation_json|fromjson|.audience' "$TMP/child-svid.json")" '{
  presentation_json:$pres,certificate_pem:$pem,intent:$intent,audience:$aud,holder_proof:$proof,challenge_nonce:$nonce,on_behalf_of:"autonomous"
}' > "$TMP/public-check-svid.json"
code=$(http POST "$PUBLIC/check-svid" "$WALK/public-check-svid-child-after-decommission-raw.json" "$(cat "$TMP/public-check-svid.json")")
[ "$code" = 403 ] || die "public POST /check-svid of the child must refuse after parent kill-accept: HTTP $code $(cat "$WALK/public-check-svid-child-after-decommission-raw.json")"
[ "$(jq -r .result "$WALK/public-check-svid-child-after-decommission-raw.json")" = refused ] || die "public child check-svid must be refused"
preason=$(jq -r '.reason // empty' "$WALK/public-check-svid-child-after-decommission-raw.json")
echo "$preason" | grep -qi expir && die "public child refuse must name accepted kill cascade, not expiry: $preason"
echo "$preason" | grep -Eiq 'accepted a kill|kill accept|kill|cascade' || die "public POST /check-svid of the child must name accepted kill cascade: $preason"
jq --argjson s "$code" '{http_status:$s,result:.result,reason:.reason,holder_secret_bytes_sent_to_public_name:false}' "$WALK/public-check-svid-child-after-decommission-raw.json" > "$WALK/public-check-svid-child-after-decommission.json"
rm -f "$WALK/public-check-svid-child-after-decommission-raw.json" "$WALK/a-agent-type-raw.json" "$WALK/a-birth-parent-raw.json" "$WALK/a-issuer-public-raw.json" "$WALK/a-spawn-child-raw.json" "$WALK/a-kill-parent-raw.json" "$WALK/kill-export-raw.json" "$WALK/operator-pin-issuer-accept-raw.json" "$WALK/operator-pin-kill-accept-raw.json" "$WALK/public-operator-pin.json" "$WALK/public-well-known-follow.json" "$WALK/public-runtime-check-refused.json"

echo "OK later-UI Check both parent-child allow then cascade refuse"
