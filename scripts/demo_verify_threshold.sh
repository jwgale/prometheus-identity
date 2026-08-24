#!/usr/bin/env bash
# Demonstration: foreign act accept uses verify_threshold_n, not issuance threshold_n.
# Store B does not mint. Member two stays outside store A.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_A="${DEMO_DATA_A:-$ROOT/data-verify-a}"
DATA_B="${DEMO_DATA_B:-$ROOT/data-verify-b}"
if [ -d "$ROOT/../prometheus-lab-vpc" ]; then
  MEMBER_TWO="${MEMBER_TWO_SECRET:-$ROOT/../prometheus-lab-vpc/member-two-verify.secret}"
else
  MEMBER_TWO="${MEMBER_TWO_SECRET:-$ROOT/../member-two-verify.secret}"
fi
rm -rf "$DATA_A" "$DATA_B"
rm -f "$MEMBER_TWO"
mkdir -p "$(dirname "$MEMBER_TWO")"

if [ -x "$ROOT/target/release/prometheus" ]; then
  BIN="$ROOT/target/release/prometheus"
else
  cargo build --release
  BIN="$ROOT/target/release/prometheus"
fi

echo "Initializing store A and store B."
"$BIN" --data-directory "$DATA_A" init >/dev/null
"$BIN" --data-directory "$DATA_B" init >/dev/null

echo "Adding member two outside store A."
"$BIN" --data-directory "$DATA_A" issuer member add --secret-path "$MEMBER_TWO" >/dev/null
"$BIN" --data-directory "$DATA_A" --member-secret "$MEMBER_TWO" issuer threshold --n 2 >/dev/null

python3 - "$DATA_A" << 'PY'
import json, pathlib, sys
data_a = pathlib.Path(sys.argv[1])
issuer = json.loads((data_a / "issuer.json").read_text())
keys = [k.strip() for k in issuer.get("public_keys") or [] if k.strip()]
if len(keys) < 2:
    raise SystemExit("store A must have two member public keys")
print(f"store A has {len(keys)} member public keys")
pathlib.Path("/tmp/prometheus-verify-a-keys.json").write_text(json.dumps(keys))
PY

"$BIN" --data-directory "$DATA_A" --member-secret "$MEMBER_TWO" agent-type add \
  --owner laboratory --intent read --authorization-limit internal \
  --max-delegation-depth 2 --lifetime-seconds 3600 >"$DATA_A/agent-type.json"
AGENT_TYPE_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$DATA_A/agent-type.json")"
"$BIN" --data-directory "$DATA_A" --member-secret "$MEMBER_TWO" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience internal >"$DATA_A/birth.json"
INSTANCE_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["instance"]["id"])' "$DATA_A/birth.json")"
CAPABILITY_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["capability"]["id"])' "$DATA_A/birth.json")"
SECRET="$DATA_A/holders/${INSTANCE_ID}.secret"
"$BIN" --data-directory "$DATA_A" --member-secret "$MEMBER_TWO" challenge --instance "$INSTANCE_ID" >"$DATA_A/challenge.json"
NONCE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["nonce"])' "$DATA_A/challenge.json")"
"$BIN" --data-directory "$DATA_A" --member-secret "$MEMBER_TWO" check \
  --instance "$INSTANCE_ID" --capability "$CAPABILITY_ID" \
  --intent read --audience internal \
  --holder-secret-path "$SECRET" --challenge-nonce "$NONCE" \
  --on-behalf-of autonomous >"$DATA_A/check.json"
RECEIPT_PATH="$DATA_A/allowed_receipt.json"
python3 -c '
import json, pathlib, sys
decision = json.load(open(sys.argv[1]))
assert decision.get("result") == "allowed", decision
pathlib.Path(sys.argv[2]).write_text(json.dumps(decision["receipt"], indent=2) + "\n")
' "$DATA_A/check.json" "$RECEIPT_PATH"
BUNDLE="$DATA_A/act-bundle"
rm -rf "$BUNDLE"
"$BIN" --data-directory "$DATA_A" --member-secret "$MEMBER_TWO" act export --receipt "$RECEIPT_PATH" --output-directory "$BUNDLE" >/dev/null

KEY1="$(python3 -c 'import json; print(json.load(open("/tmp/prometheus-verify-a-keys.json"))[0])')"
KEY2="$(python3 -c 'import json; print(json.load(open("/tmp/prometheus-verify-a-keys.json"))[1])')"

echo "Store B accepts only member one. verify_threshold_n 2 must refuse."
"$BIN" --data-directory "$DATA_B" issuer accept --public-key-hex "$KEY1" >/dev/null
"$BIN" --data-directory "$DATA_B" issuer verify-threshold --n 2 >/dev/null
if "$BIN" --data-directory "$DATA_B" act accept --bundle-directory "$BUNDLE" \
  >/tmp/prometheus-verify-b-one.json 2>/tmp/prometheus-verify-b-one.err; then
  echo "Store B must refuse a two-member bundle when only one key is accepted and verify_threshold_n is 2."
  exit 1
fi
echo "Store B refused with only member one accepted."

echo "Store B accepts member two. Act accept must succeed."
"$BIN" --data-directory "$DATA_B" issuer accept --public-key-hex "$KEY2" >/dev/null
"$BIN" --data-directory "$DATA_B" act accept --bundle-directory "$BUNDLE"
echo "Foreign verify-threshold demonstration passed."
