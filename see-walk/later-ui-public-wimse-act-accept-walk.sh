#!/bin/bash
# Later-UI WIMSE act-accept via operator-pin. Sibling of Rung 79 using Rung 81 helper.
# Small curls. Do not spawn AgentProcess. Do not copy issuer.secret onto the public host.
set -euo pipefail
BIN=/home/jason/Projects/Prometheus/target/release/prometheus
STORE=/tmp/prometheus-later-ui-public-wimse-act-accept-a
WALK=/home/jason/Projects/Prometheus/see-walk/later-ui-public-wimse-act-accept
ISSUING=http://127.0.0.1:18816
PUBLIC=https://check.prestigeworldwide.digital
PORT=18816
AUDIENCE=check.prestigeworldwide.digital
mkdir -p "$WALK"
rm -rf "$STORE"
mkdir -m 700 "$STORE"

die() { echo "FAIL: $*" >&2; exit 1; }

http() {
  local method=$1 url=$2 outfile=$3
  local body=${4-}
  local extra=${5-}
  if [ -n "$body" ]; then
    curl -sS -X "$method" -H 'content-type: application/json' -d "$body" -o "$outfile" -w '%{http_code}' --max-time 40 $extra "$url"
  else
    curl -sS -X "$method" -o "$outfile" -w '%{http_code}' --max-time 40 $extra "$url"
  fi
}

require() {
  local got=$1 want=$2 label=$3 bodyfile=$4
  if [ "$got" != "$want" ]; then
    die "$label HTTP $got expected $want: $(cat "$bodyfile")"
  fi
}

echo INIT
"$BIN" --data-directory "$STORE" init >/dev/null
printf '%s\n' "init ran on this machine. Secret files stay under /tmp/prometheus-later-ui-public-wimse-act-accept-a." > "$WALK/a-init-note.txt"

"$BIN" --data-directory "$STORE" host --listen-address "127.0.0.1:${PORT}" >/dev/null 2>&1 &
HOSTPID=$!
cleanup() {
  if kill -0 "$HOSTPID" 2>/dev/null; then
    kill "$HOSTPID" 2>/dev/null || true
    wait "$HOSTPID" 2>/dev/null || true
  fi
  printf '%s\n' "issuing host on 127.0.0.1:${PORT} is stopped" > "$WALK/a-host-stopped.txt"
  rm -rf "$STORE"
  if [ -e "$STORE" ] || [ -e "$STORE/issuer.secret" ]; then
    die "issuer.secret must not remain under /tmp"
  fi
  printf '%s\n' "Deleted /tmp/prometheus-later-ui-public-wimse-act-accept-a after the walk. issuer.secret is not left under /tmp from this walk." > "$WALK/tmp-cleaned.txt"
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
for marker in 'id="check-base"' 'https://check.prestigeworldwide.digital' 'Create Agent Principal' '/runtime-check' '/present-wimse' '/well-known-follow' '/operator-pin' 'function documentedPinPath(' 'function followWellKnownThenPin(' 'followWellKnownThenPin("act-accept"' 'followWellKnownThenPin("kill-accept"' '/act-export' 'id="act-export-receipt"' 'The holder secret path stays on this host' 'The path is not sent to the check base'; do
  grep -F -q "$marker" "$root" || die "GET / is not the later UI. missing=$marker"
done
grep -F -q 'issuer.secret' "$root" && die "GET / must not name issuer.secret"
grep -F -q 'type="file"' "$root" && die "GET / must not offer a file upload"
grep -F -q 'fetch("https://' "$root" && die "GET / JS must not CORS-fetch"
grep -F -q 'fetch("http://' "$root" && die "GET / JS must not CORS-fetch"
{
  echo "issuing GET / is the later user interface"
  echo "GET / Check WIMSE posts POST /runtime-check with present-wimse fields"
  echo "GET / act-accept follows well-known through POST /operator-pin"
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
jq -n --arg b "$PUBLIC" '{check_base:$b,pin:"act-accept",body:{}}' > /tmp/r83-op.json
code=$(http POST "$PUBLIC/operator-pin" "$WALK/public-operator-pin.json" "$(cat /tmp/r83-op.json)")
require "$code" 403 "public POST /operator-pin" "$WALK/public-operator-pin.json"
grep -q check-only "$WALK/public-operator-pin.json" || die "public POST /operator-pin must stay check-only"

jq -n --arg b "$PUBLIC" '{check_base:$b}' > /tmp/r83-wk.json
code=$(http POST "$PUBLIC/well-known-follow" "$WALK/public-well-known-follow.json" "$(cat /tmp/r83-wk.json)")
require "$code" 403 "public POST /well-known-follow" "$WALK/public-well-known-follow.json"

jq -n --arg b "$PUBLIC" '{check_base:$b,presentation_json:"{}"}' > /tmp/r83-rc.json
code=$(http POST "$PUBLIC/runtime-check" "$WALK/public-runtime-check-refused.json" "$(cat /tmp/r83-rc.json)")
require "$code" 403 "public POST /runtime-check" "$WALK/public-runtime-check-refused.json"

jq -n '{receipt:{result:"allowed"}}' > /tmp/r83-ae.json
code=$(http POST "$PUBLIC/act-export" "$WALK/public-act-export-refused.json" "$(cat /tmp/r83-ae.json)")
require "$code" 403 "public POST /act-export" "$WALK/public-act-export-refused.json"
grep -q check-only "$WALK/public-act-export-refused.json" || die "public POST /act-export must stay check-only"

jq -s '{
  "/operator-pin":{http_status:403,body:.[0]},
  "/well-known-follow":{http_status:403,body:.[1]},
  "/runtime-check":{http_status:403,body:.[2]},
  "/act-export":{http_status:403,body:.[3]}
}' "$WALK/public-operator-pin.json" "$WALK/public-well-known-follow.json" "$WALK/public-runtime-check-refused.json" "$WALK/public-act-export-refused.json" > "$WALK/public-helpers-refused.json"

code=$(http POST "$PUBLIC/act-accept" "$WALK/public-act-accept-empty-raw.json" '{}')
[ "$code" = 403 ] && grep -q check-only "$WALK/public-act-accept-empty-raw.json" && die "public POST /act-accept is check-only 403"
[ "$code" = 400 ] || die "public POST /act-accept empty body must be 400 missing receipt, not $code"
jq --argjson s "$code" '{http_status:$s,body:.,allowed_operator_pin:true,note:"400 missing field receipt means the path is not check-only 403."}' "$WALK/public-act-accept-empty-raw.json" > "$WALK/public-act-accept-empty.json"
rm -f "$WALK/public-act-accept-empty-raw.json"

code=$(http GET "$PUBLIC/instances" "$WALK/public-instances-before-raw.json")
require "$code" 403 "public GET /instances before" "$WALK/public-instances-before-raw.json"
jq --argjson s "$code" '{http_status:$s,body:.}' "$WALK/public-instances-before-raw.json" > "$WALK/public-instances-before.json"
rm -f "$WALK/public-instances-before-raw.json"

echo WELL-KNOWN-FOLLOW
code=$(http POST "$ISSUING/well-known-follow" "$WALK/issuing-well-known-follow.json" "$(cat /tmp/r83-wk.json)")
require "$code" 200 "POST /well-known-follow public" "$WALK/issuing-well-known-follow.json"
follow_bind=$(jq -r .bind "$WALK/issuing-well-known-follow.json")
[ "$follow_bind" = check.prestigeworldwide.digital ] || die "well-known-follow bind must be the public name"
grep -E 'issuer\.secret|holder_secret' "$WALK/issuing-well-known-follow.json" && die "well-known-follow must not return secrets"
for verb in /birth /spawn /present-svid /present-wimse /runtime-check /seal-export /previous-key-export /act-export /kill-export; do
  grep -F -q "$verb" "$WALK/issuing-well-known-follow.json" && die "well-known-follow still names write verb $verb"
done
act_accept_path=$(jq -r '.operator_pin_paths[] | select(.path|test("act-accept$")) | .path' "$WALK/issuing-well-known-follow.json")
kill_accept_path=$(jq -r '.operator_pin_paths[] | select(.path|test("kill-accept$")) | .path' "$WALK/issuing-well-known-follow.json")
issuer_accept_path=$(jq -r '.operator_pin_paths[] | select(.path|test("issuer-accept$")) | .path' "$WALK/issuing-well-known-follow.json")
[ "$act_accept_path" = /act-accept ] || die "public document act-accept path was $act_accept_path"
jq -n --arg b "$PUBLIC" --arg a "$act_accept_path" --arg k "$kill_accept_path" --arg i "$issuer_accept_path" '{
  check_base:$b,
  act_accept_pin_name:"act-accept",
  act_accept_path:$a,
  kill_accept_path:$k,
  issuer_accept_path:$i,
  note:"GET / resolves these paths from the well-known document. POST /operator-pin then posts that pin name. This walk does not hardcode public /act-accept as the accept URL."
}' > "$WALK/resolved-operator-pins.json"

code=$(http POST "$ISSUING/agent-type" "$WALK/a-agent-type-raw.json" "$(jq -n --arg aud "$AUDIENCE" '{owner:"jason-gale",allowed_intents:["read"],authorization_limit:$aud}')")
echo "AGENT-TYPE $code"
require "$code" 200 "POST /agent-type" "$WALK/a-agent-type-raw.json"
jq '{agent_type_id:.agent_type_id,keys:(keys|sort)}' "$WALK/a-agent-type-raw.json" > "$WALK/a-agent-type.json"
agent_type_id=$(jq -r .agent_type_id "$WALK/a-agent-type-raw.json")

code=$(http POST "$ISSUING/birth" "$WALK/a-birth-raw.json" "$(jq -n --arg id "$agent_type_id" --arg aud "$AUDIENCE" '{agent_type_id:$id,owner:"jason-gale",intent:"read",audience:$aud,on_behalf_of:"autonomous"}')")
echo "BIRTH $code"
require "$code" 200 "POST /birth" "$WALK/a-birth-raw.json"
jq 'has("holder_secret") and (has("holder_secret_path")|not)' "$WALK/a-birth-raw.json" | grep -q true && die "POST /birth must not return secret bytes"
jq '{instance_id:.instance_id,capability_id:.capability_id,revoke_identifier:.revoke_identifier,holder_secret_path_present:(has("holder_secret_path"))}' "$WALK/a-birth-raw.json" > "$WALK/a-birth.json"
instance_id=$(jq -r .instance_id "$WALK/a-birth-raw.json")
capability_id=$(jq -r .capability_id "$WALK/a-birth-raw.json")
holder_secret_path=$(jq -r .holder_secret_path "$WALK/a-birth-raw.json")
case "$holder_secret_path" in
  "$STORE"*) ;;
  *) die "holder secret path must stay under the throwaway store" ;;
esac

code=$(http GET "$ISSUING/issuer-public" "$WALK/a-issuer-public-raw.json")
require "$code" 200 "GET /issuer-public" "$WALK/a-issuer-public-raw.json"
jq '{keys:(keys|sort)}' "$WALK/a-issuer-public-raw.json" > "$WALK/a-issuer-public-keys.json"
key=$(jq -r '.current_issuer_public_key_hex // .public_key_hex' "$WALK/a-issuer-public-raw.json")
[ -n "$key" ] && [ "$key" != null ] || die "no public key"
printf 'public_key_hex_length=%s\n' "${#key}" > "$WALK/a-issuer-public-key-length.txt"

echo "OPERATOR-PIN ISSUER-ACCEPT"
jq -n --arg b "$PUBLIC" --arg k "$key" '{check_base:$b,pin:"issuer-accept",body:{public_key_hex:$k}}' > /tmp/r83-issuer.json
code=$(http POST "$ISSUING/operator-pin" "$WALK/operator-pin-issuer-accept-raw.json" "$(cat /tmp/r83-issuer.json)")
echo "ISSUER-ACCEPT $code"
require "$code" 200 "POST /operator-pin issuer-accept" "$WALK/operator-pin-issuer-accept-raw.json"
jq --argjson s "$code" --arg p "$issuer_accept_path" '{http_status:$s,pin:"issuer-accept",resolved_path:$p,request_keys:["check_base","pin","body"],response_keys:(keys|sort)}' "$WALK/operator-pin-issuer-accept-raw.json" > "$WALK/operator-pin-issuer-accept.json"

mint_present() {
  local ch_code
  ch_code=$(http POST "$ISSUING/challenge" /tmp/r83-challenge.json "$(jq -n --arg id "$instance_id" '{instance_id:$id}')")
  [ "$ch_code" = 200 ] || die "POST /challenge HTTP $ch_code: $(cat /tmp/r83-challenge.json)"
  local nonce
  nonce=$(jq -r .challenge_nonce /tmp/r83-challenge.json)
  jq -n --arg id "$instance_id" --arg cap "$capability_id" --arg hp "$holder_secret_path" --arg n "$nonce" --arg aud "$AUDIENCE" '{
    instance_id:$id,capability_id:$cap,holder_secret_path:$hp,challenge_nonce:$n,intent:"read",audience:$aud,on_behalf_of:"autonomous"
  }' > /tmp/r83-present.json
  local pcode
  pcode=$(http POST "$ISSUING/present-wimse" /tmp/r83-wimse.json "$(cat /tmp/r83-present.json)")
  [ "$pcode" = 200 ] || die "POST /present-wimse HTTP $pcode: $(cat /tmp/r83-wimse.json)"
}

echo PRESENT-WIMSE
mint_present
jq -r .presentation_json /tmp/r83-wimse.json > "$WALK/presentation.json"
jq '{keys:(keys|sort)}' /tmp/r83-wimse.json > "$WALK/a-present-wimse-keys.json"
jq '{
  presentation_json:(.presentation_json|length),
  workload_identity_token:(.workload_identity_token|length),
  content_digest:(.content_digest|length),
  signature_input:(.signature_input|length),
  signature:(.signature|length)
}' /tmp/r83-wimse.json > "$WALK/a-present-wimse-field-lengths.json"
grep -E 'holder_secret|issuer\.secret' /tmp/r83-wimse.json && die "POST /present-wimse must not return secret bytes"
jq --arg b "$PUBLIC" --arg hp "$holder_secret_path" '{
  check_base:$b,
  presentation_json:.presentation_json,
  workload_identity_token:.workload_identity_token,
  content_digest:.content_digest,
  signature_input:.signature_input,
  signature:.signature,
  holder_secret_path:$hp
}' /tmp/r83-wimse.json > /tmp/r83-runtime.json
jq --arg b "$PUBLIC" '{
  keys:(keys|sort),
  check_base:$b,
  holder_secret_path_sent_to_issuing_host:true,
  holder_secret_bytes_sent_to_public_name:false,
  note:"GET / posts this JSON to the loopback issuing host. That host signs the verifier nonce locally. Secret bytes are not uploaded. The path is not sent to the public name. WIMSE token, digest, and signature fields are not trimmed."
}' /tmp/r83-runtime.json > "$WALK/runtime-check-request-keys.json"

echo "RUNTIME-CHECK ALLOW"
code=$(http POST "$ISSUING/runtime-check" /tmp/r83-allow.json "$(cat /tmp/r83-runtime.json)")
if [ "$code" != 200 ] || [ "$(jq -r .result /tmp/r83-allow.json)" != allowed ]; then
  echo "ALLOW failed, remint once $code $(cat /tmp/r83-allow.json)"
  mint_present
  jq -r .presentation_json /tmp/r83-wimse.json > "$WALK/presentation.json"
  jq --arg b "$PUBLIC" --arg hp "$holder_secret_path" '{
    check_base:$b,
    presentation_json:.presentation_json,
    workload_identity_token:.workload_identity_token,
    content_digest:.content_digest,
    signature_input:.signature_input,
    signature:.signature,
    holder_secret_path:$hp
  }' /tmp/r83-wimse.json > /tmp/r83-runtime.json
  code=$(http POST "$ISSUING/runtime-check" /tmp/r83-allow.json "$(cat /tmp/r83-runtime.json)")
fi
require "$code" 200 "POST /runtime-check allow" /tmp/r83-allow.json
[ "$(jq -r .result /tmp/r83-allow.json)" = allowed ] || die "first POST /runtime-check must allow"
jq --argjson s "$code" '{http_status:$s,result:.result,reason:.reason,keys:(keys|sort),has_receipt:(.receipt!=null)}' /tmp/r83-allow.json > "$WALK/runtime-check-allow.json"
grep -q issuer.secret /tmp/r83-allow.json && die "allow body must not name issuer.secret"

echo "ISSUING CHECK FOR RECEIPT"
code=$(http POST "$ISSUING/challenge" /tmp/r83-local-ch.json "$(jq -n --arg id "$instance_id" '{instance_id:$id}')")
require "$code" 200 "POST /challenge for local check" /tmp/r83-local-ch.json
nonce=$(jq -r .challenge_nonce /tmp/r83-local-ch.json)
jq -n --arg id "$instance_id" --arg cap "$capability_id" --arg hp "$holder_secret_path" --arg n "$nonce" --arg aud "$AUDIENCE" '{
  instance_id:$id,capability_id:$cap,intent:"read",audience:$aud,holder_secret_path:$hp,challenge_nonce:$n,on_behalf_of:"autonomous"
}' > /tmp/r83-check.json
code=$(http POST "$ISSUING/check" /tmp/r83-local-check.json "$(cat /tmp/r83-check.json)")
require "$code" 200 "issuing POST /check" /tmp/r83-local-check.json
[ "$(jq -r .result /tmp/r83-local-check.json)" = allowed ] || die "issuing POST /check must allow so act-export has a receipt"
jq -e '.receipt|type=="object"' /tmp/r83-local-check.json >/dev/null || die "issuing POST /check must return a signed receipt"
jq --argjson s "$code" '{
  http_status:$s,
  result:.result,
  receipt_keys:(.receipt|keys|sort),
  receipt_result:.receipt.result,
  note:"The public host already allowed this WIMSE act. The issuing store also checked so the receipt stays on the issuing store. Public act-export stays 403."
}' /tmp/r83-local-check.json > "$WALK/a-check-receipt-keys.json"

echo ACT-EXPORT
jq '{receipt:.receipt}' /tmp/r83-local-check.json > /tmp/r83-act-export.json
code=$(http POST "$ISSUING/act-export" /tmp/r83-exported.json "$(cat /tmp/r83-act-export.json)")
echo "ACT-EXPORT $code"
require "$code" 200 "issuing POST /act-export" /tmp/r83-exported.json
for field in receipt proof tree_head; do
  jq -e --arg f "$field" 'has($f)' /tmp/r83-exported.json >/dev/null || die "act-export must return $field"
done
jq -e 'has("presentation")' /tmp/r83-exported.json >/dev/null && die "act-export must not invent a presentation artifact"
jq --argjson s "$code" '{http_status:$s,keys:(keys|sort),receipt_result:(.receipt.result // null)}' /tmp/r83-exported.json > "$WALK/a-act-export-keys.json"
grep -E 'issuer\.secret|holder_secret' /tmp/r83-exported.json && die "act-export must not return secret bytes"
jq '{receipt:.receipt,proof:.proof,tree_head:.tree_head}' /tmp/r83-exported.json > /tmp/r83-act-accept-body.json

echo "WELL-KNOWN-FOLLOW THEN OPERATOR-PIN ACT-ACCEPT"
code=$(http POST "$ISSUING/well-known-follow" /tmp/r83-follow-act.json "$(cat /tmp/r83-wk.json)")
require "$code" 200 "POST /well-known-follow before act-accept" /tmp/r83-follow-act.json
again_act_path=$(jq -r '.operator_pin_paths[] | select(.path|test("act-accept$")) | .path' /tmp/r83-follow-act.json)
[ "$again_act_path" = "$act_accept_path" ] || die "act-accept path changed between follow and pin"
jq -n --arg b "$PUBLIC" --argjson body "$(cat /tmp/r83-act-accept-body.json)" '{check_base:$b,pin:"act-accept",body:$body}' > /tmp/r83-op-act.json
code=$(http POST "$ISSUING/operator-pin" /tmp/r83-act-accept.json "$(cat /tmp/r83-op-act.json)")
echo "OPERATOR-PIN ACT-ACCEPT $code"
require "$code" 200 "POST /operator-pin act-accept" /tmp/r83-act-accept.json
[ "$(jq -r .result /tmp/r83-act-accept.json)" = accepted ] || die "POST /operator-pin act-accept must return accepted"
jq --argjson s "$code" --arg p "$again_act_path" '{
  http_status:$s,pin:"act-accept",resolved_path:$p,result:.result,keys:(keys|sort),wrote_instance:false,hardcoded_public_act_accept:false
}' /tmp/r83-act-accept.json > "$WALK/operator-pin-act-accept.json"
inst=$(jq -r '.instance_id // empty' /tmp/r83-act-accept.json)
[ -z "$inst" ] || die "operator-pin act-accept must write no instance"

code=$(http GET "$PUBLIC/instances" /tmp/r83-inst-after.json)
require "$code" 403 "public GET /instances after act-accept" /tmp/r83-inst-after.json
grep -q check-only /tmp/r83-inst-after.json || die "public GET /instances must stay check-only after act-accept"
jq --argjson s "$code" '{http_status:$s,body:.,note:"Public GET /instances stayed 403. Act-accept wrote no instance record."}' /tmp/r83-inst-after.json > "$WALK/public-instances-after-act-accept.json"

jq '{receipt:.receipt}' /tmp/r83-exported.json > /tmp/r83-ae-after.json
code=$(http POST "$PUBLIC/act-export" /tmp/r83-ae-after-body.json "$(cat /tmp/r83-ae-after.json)")
require "$code" 403 "public POST /act-export after act-accept" /tmp/r83-ae-after-body.json
jq --argjson s "$code" '{http_status:$s,body:.}' /tmp/r83-ae-after-body.json > "$WALK/public-act-export-after-act-accept.json"

jq -n --arg id "$instance_id" '{instance_id:$id,confirm:$id}' > /tmp/r83-kill.json
code=$(http POST "$ISSUING/kill" /tmp/r83-killed.json "$(cat /tmp/r83-kill.json)")
echo "KILL $code"
require "$code" 200 "POST /kill" /tmp/r83-killed.json
jq '{instance_id:.instance_id,status:.status,keys:(keys|sort)}' /tmp/r83-killed.json > "$WALK/a-kill.json"

code=$(http POST "$ISSUING/kill-export" /tmp/r83-kill-exported.json "$(cat /tmp/r83-kill.json)")
echo "KILL-EXPORT $code"
require "$code" 200 "POST /kill-export" /tmp/r83-kill-exported.json
jq '{keys:(keys|sort)}' /tmp/r83-kill-exported.json > "$WALK/kill-export-keys.json"
jq '{event:.event,proof:.proof,tree_head:.tree_head}' /tmp/r83-kill-exported.json > /tmp/r83-kill-accept-body.json

echo "WELL-KNOWN-FOLLOW THEN OPERATOR-PIN KILL-ACCEPT"
code=$(http POST "$ISSUING/well-known-follow" /tmp/r83-follow-kill.json "$(cat /tmp/r83-wk.json)")
require "$code" 200 "POST /well-known-follow before kill-accept" /tmp/r83-follow-kill.json
again_path=$(jq -r '.operator_pin_paths[] | select(.path|test("kill-accept$")) | .path' /tmp/r83-follow-kill.json)
[ "$again_path" = "$kill_accept_path" ] || die "kill-accept path changed between follow and pin"
jq -n --arg b "$PUBLIC" --argjson body "$(cat /tmp/r83-kill-accept-body.json)" '{check_base:$b,pin:"kill-accept",body:$body}' > /tmp/r83-op-kill.json
code=$(http POST "$ISSUING/operator-pin" /tmp/r83-kill-accept.json "$(cat /tmp/r83-op-kill.json)")
echo "OPERATOR-PIN KILL-ACCEPT $code"
require "$code" 200 "POST /operator-pin kill-accept" /tmp/r83-kill-accept.json
jq --argjson s "$code" --arg p "$again_path" '{
  http_status:$s,pin:"kill-accept",resolved_path:$p,
  accepted_killed_instance_ids:.accepted_killed_instance_ids,
  accepted_killed_capability_ids:.accepted_killed_capability_ids,
  keys:(keys|sort),hardcoded_public_kill_accept:false
}' /tmp/r83-kill-accept.json > "$WALK/operator-pin-kill-accept.json"

echo "RUNTIME-CHECK REFUSE"
code=$(http POST "$ISSUING/runtime-check" /tmp/r83-refused.json "$(cat /tmp/r83-runtime.json)")
[ "$code" = 403 ] || die "second POST /runtime-check must refuse after operator-pin kill-accept: HTTP $code $(cat /tmp/r83-refused.json)"
[ "$(jq -r .result /tmp/r83-refused.json)" = refused ] || die "second POST /runtime-check must be refused"
reason=$(jq -r .reason /tmp/r83-refused.json)
echo "$reason" | grep -qiE 'accepted a kill|kill accept' || die "typed-base Check again must refuse from accepted kill: $reason"
jq --argjson s "$code" '{http_status:$s,result:.result,reason:.reason,keys:(keys|sort)}' /tmp/r83-refused.json > "$WALK/runtime-check-after-decommission.json"
grep -q issuer.secret /tmp/r83-refused.json && die "refuse body must not name issuer.secret"

echo "PUBLIC CHECK-WIMSE AFTER DECOMMISSION"
code=$(http POST "$PUBLIC/verifier-challenge" /tmp/r83-vch.json '{}')
require "$code" 200 "public POST /verifier-challenge" /tmp/r83-vch.json
challenge_message=$(jq -r .challenge_message /tmp/r83-vch.json)
challenge_nonce=$(jq -r .challenge_nonce /tmp/r83-vch.json)
proof=$("$BIN" holder-sign --holder-secret-path "$holder_secret_path" --challenge-message "$challenge_message")
[ -n "$proof" ] || die "holder-sign must return a proof"
jq -n \
  --argjson wimse "$(cat /tmp/r83-wimse.json)" \
  --arg proof "$proof" \
  --arg nonce "$challenge_nonce" \
  '{
    presentation_json:$wimse.presentation_json,
    workload_identity_token:$wimse.workload_identity_token,
    content_digest:$wimse.content_digest,
    intent:($wimse.presentation_json|fromjson|.intent),
    audience:($wimse.presentation_json|fromjson|.audience),
    holder_proof:$proof,
    challenge_nonce:$nonce,
    on_behalf_of:"autonomous",
    signature_input:$wimse.signature_input,
    signature:$wimse.signature
  }' > /tmp/r83-public-wimse.json
code=$(http POST "$PUBLIC/check-wimse" /tmp/r83-public-refused.json "$(cat /tmp/r83-public-wimse.json)")
[ "$code" = 403 ] && [ "$(jq -r .result /tmp/r83-public-refused.json)" = refused ] || die "public POST /check-wimse must refuse after operator-pin kill-accept: HTTP $code $(cat /tmp/r83-public-refused.json)"
public_reason=$(jq -r .reason /tmp/r83-public-refused.json)
echo "$public_reason" | grep -qiE 'accepted a kill|kill accept' || die "public POST /check-wimse must name accepted kill: $public_reason"
jq --argjson s "$code" '{
  http_status:$s,result:.result,reason:.reason,
  request_keys:["presentation_json","workload_identity_token","content_digest","intent","audience","holder_proof","challenge_nonce","on_behalf_of","signature_input","signature"],
  holder_secret_bytes_sent_to_public_name:false
}' /tmp/r83-public-refused.json > "$WALK/public-check-wimse-after-decommission.json"

rm -f /tmp/r83-*.json
echo "OK WIMSE operator-pin act-accept allow then refuse"
