#!/usr/bin/env bash
# Demonstration: member two lives outside the data directory.
# A stolen store without that file cannot birth when threshold_n is 2.
# This is operator custody. This is not a sixth identity record.
# This is not Shamir. This is not FROST.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_DIRECTORY="${DEMO_DATA_DIRECTORY:-$ROOT/data-custody}"
if [ -d "$ROOT/../prometheus-lab-vpc" ]; then
  MEMBER_TWO="${MEMBER_TWO_SECRET:-$ROOT/../prometheus-lab-vpc/member-two.secret}"
else
  MEMBER_TWO="${MEMBER_TWO_SECRET:-$ROOT/../member-two.secret}"
fi
rm -rf "$DATA_DIRECTORY"
rm -f "$MEMBER_TWO"
mkdir -p "$(dirname "$MEMBER_TWO")"

if [ -x "$ROOT/target/release/prometheus" ]; then
  BIN="$ROOT/target/release/prometheus"
else
  cargo build
  BIN="$ROOT/target/debug/prometheus"
fi

echo "Initializing the laboratory issuer."
"$BIN" --data-directory "$DATA_DIRECTORY" init >/dev/null

echo "Adding member two outside the data directory."
"$BIN" --data-directory "$DATA_DIRECTORY" issuer member add --secret-path "$MEMBER_TWO" >/dev/null
if [ ! -f "$MEMBER_TWO" ]; then
  echo "Member two must be written outside the data directory."
  exit 1
fi
if ls "$DATA_DIRECTORY"/issuer-member-*.secret >/dev/null 2>&1; then
  echo "Member two must not also live in the data directory."
  ls "$DATA_DIRECTORY"/issuer-member-*.secret
  exit 1
fi
echo "Member two is outside the data directory."

echo "Setting threshold_n 2 with member two in hand."
"$BIN" --data-directory "$DATA_DIRECTORY" --member-secret "$MEMBER_TWO" issuer threshold --n 2 >/dev/null

AGENT_TYPE_ID="$("$BIN" --data-directory "$DATA_DIRECTORY" --member-secret "$MEMBER_TWO" agent-type add \
  --owner laboratory --intent read --authorization-limit payments \
  --max-delegation-depth 2 --lifetime-seconds 3600 | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"

echo "Birth without member two must refuse."
if "$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience payments \
  >/tmp/prometheus-custody-birth-one.json 2>/tmp/prometheus-custody-birth-one.err; then
  echo "Birth without member two must refuse."
  exit 1
fi
if ! grep -q "only 1 issuer member secret\|threshold_n value is 2" /tmp/prometheus-custody-birth-one.err; then
  echo "The refuse reason must name the missing second secret."
  cat /tmp/prometheus-custody-birth-one.err
  exit 1
fi
echo "Birth without member two was refused."

echo "Birth with member two in hand."
BIRTH_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" --member-secret "$MEMBER_TWO" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience payments)"
python3 -c '
import json, sys
birth = json.loads(sys.argv[1])
signatures = birth["capability"].get("issuer_signatures") or []
if len(signatures) < 2:
    raise SystemExit("n=2 birth must persist two member signatures.")
print("Birth with the outside member secret succeeded. The capability has two signatures.")
' "$BIRTH_JSON"
echo "Member two custody demonstration passed."
