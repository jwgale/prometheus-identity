#!/usr/bin/env bash
# Demonstration: multi-signature issuance with threshold_n.
# Init stays at n=1. Setting n=2 with one member refuses.
# After a second member, n=2 accepts. Birth with one secret when n=2 refuses.
# Birth with two member secrets succeeds. Stripping one of two signatures refuses evaluate.
# This is multi-signature issuance. This is not a Shamir split of issuer.secret.
# This is not FROST. This is not Federal Information Processing Standard 204
# threshold Module-Lattice Digital Signature Algorithm.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_DIRECTORY="${DEMO_DATA_DIRECTORY:-$ROOT/data-threshold}"
rm -rf "$DATA_DIRECTORY"
cargo build
BIN="$ROOT/target/debug/prometheus"

echo "Initializing the laboratory issuer. threshold_n must be 1."
INIT_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" init)"
python3 -c '
import json, sys
issuer = json.loads(sys.argv[1])
if issuer.get("threshold_n") != 1:
    raise SystemExit("Init must write threshold_n 1.")
print("Init wrote threshold_n 1.")
' "$INIT_JSON"

echo "Setting threshold_n 2 with only one member must refuse."
if "$BIN" --data-directory "$DATA_DIRECTORY" issuer threshold --n 2 >/tmp/prometheus-threshold-refuse.json 2>/tmp/prometheus-threshold-refuse.err; then
  echo "Setting n=2 with one member must refuse."
  exit 1
fi
if ! grep -q "Need two members\|greater than the number of trusted" /tmp/prometheus-threshold-refuse.err; then
  echo "The refuse reason must name the missing second member."
  cat /tmp/prometheus-threshold-refuse.err
  exit 1
fi
echo "n=2 with one member was refused."

echo "Adding a second Module-Lattice Digital Signature Algorithm member."
MEMBER_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" issuer member add)"
python3 -c '
import json, sys
issuer = json.loads(sys.argv[1])
keys = issuer.get("public_keys") or []
if len(keys) < 2:
    raise SystemExit("Member add must install a second public key.")
print("A second member public key is on the issuer record.")
' "$MEMBER_JSON"

MEMBER_SECRETS="$(find "$DATA_DIRECTORY" -maxdepth 1 -name 'issuer-member-*.secret' | wc -l)"
if [ "$MEMBER_SECRETS" -lt 1 ]; then
  echo "Member add must write an issuer-member-*.secret file."
  exit 1
fi

echo "Setting threshold_n 2 after the second member."
THRESH_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" issuer threshold --n 2)"
python3 -c '
import json, sys
issuer = json.loads(sys.argv[1])
if issuer.get("threshold_n") != 2:
    raise SystemExit("threshold --n 2 must persist threshold_n 2.")
print("threshold_n is 2.")
' "$THRESH_JSON"

echo "Lowering threshold_n must refuse."
if "$BIN" --data-directory "$DATA_DIRECTORY" issuer threshold --n 1 >/tmp/prometheus-threshold-lower.json 2>/tmp/prometheus-threshold-lower.err; then
  echo "Lowering threshold_n must refuse."
  exit 1
fi
if ! grep -q "cannot be lowered" /tmp/prometheus-threshold-lower.err; then
  echo "The refuse reason must say the threshold cannot be lowered."
  cat /tmp/prometheus-threshold-lower.err
  exit 1
fi
echo "Lowering threshold_n was refused."

echo "Adding an agent type, then hiding the additional member secret."
AGENT_TYPE_ID="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type add \
  --owner laboratory --intent read --authorization-limit payments \
  --max-delegation-depth 2 --lifetime-seconds 3600 | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
MEMBER_FILE="$(find "$DATA_DIRECTORY" -maxdepth 1 -name 'issuer-member-*.secret' | head -n 1)"
HIDDEN="${MEMBER_FILE}.hidden"
mv "$MEMBER_FILE" "$HIDDEN"

echo "Birth with one secret when n=2 must refuse."
if "$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience payments \
  >/tmp/prometheus-threshold-birth-one.json 2>/tmp/prometheus-threshold-birth-one.err; then
  echo "Birth with one secret when n=2 must refuse."
  exit 1
fi
if ! grep -q "only 1 issuer member secret\|threshold_n value is 2" /tmp/prometheus-threshold-birth-one.err; then
  echo "The refuse reason must name the missing second secret."
  cat /tmp/prometheus-threshold-birth-one.err
  exit 1
fi
echo "Birth with one secret when n=2 was refused."

echo "Restoring the second member secret and birthing with two secrets."
mv "$HIDDEN" "$MEMBER_FILE"
BIRTH_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience payments)"
INSTANCE_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["id"])' "$BIRTH_JSON")"
CAPABILITY_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["capability"]["id"])' "$BIRTH_JSON")"
python3 -c '
import json, sys
birth = json.loads(sys.argv[1])
signatures = birth["capability"].get("issuer_signatures") or []
if len(signatures) < 2:
    raise SystemExit("n=2 birth must persist two member signatures.")
print("Birth with two member secrets succeeded. The capability has two signatures.")
' "$BIRTH_JSON"
SECRET="$DATA_DIRECTORY/holders/${INSTANCE_ID}.secret"

echo "Stripping one of the two signatures. Evaluate must refuse."
python3 -c '
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
capability = json.loads(path.read_text())
signatures = capability.get("issuer_signatures") or []
if len(signatures) < 2:
    raise SystemExit("the stored capability must have two signatures before the strip")
capability["issuer_signatures"] = signatures[:1]
path.write_text(json.dumps(capability, indent=2) + "\n")
print("One of two signatures was stripped from the capability record.")
' "$DATA_DIRECTORY/capabilities/${CAPABILITY_ID}.json"

NONCE="$("$BIN" --data-directory "$DATA_DIRECTORY" challenge --instance "$INSTANCE_ID" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])')"
if "$BIN" --data-directory "$DATA_DIRECTORY" capability verify \
  --capability "$CAPABILITY_ID" --audience payments --intent read \
  --holder-secret-path "$SECRET" --challenge-nonce "$NONCE" \
  --on-behalf-of autonomous >/tmp/prometheus-threshold-verify.json 2>/tmp/prometheus-threshold-verify.err; then
  echo "Evaluate must refuse a record with only one of two signatures."
  exit 1
fi
if ! grep -q "needs 2\|member signatures\|issuer signature" /tmp/prometheus-threshold-verify.err /tmp/prometheus-threshold-verify.json; then
  echo "The refuse reason must name the missing second signature."
  cat /tmp/prometheus-threshold-verify.err
  cat /tmp/prometheus-threshold-verify.json
  exit 1
fi
echo "Evaluate refused the stripped one-of-two signature."
echo "Multi-signature issuance demonstration passed."
