#!/usr/bin/env bash
# Demonstration: a fourth hop fails when max_delegation_depth is 3. Chain records are real.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_DIRECTORY="${DEMO_DATA_DIRECTORY:-$ROOT/data-depth}"
rm -rf "$DATA_DIRECTORY"
cargo build
BIN="$ROOT/target/debug/prometheus"

id_from_json() { python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])'; }

"$BIN" --data-directory "$DATA_DIRECTORY" init >/dev/null
AGENT_TYPE_ID="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type add \
  --owner laboratory --intent read --authorization-limit payments \
  --max-delegation-depth 3 --lifetime-seconds 3600 | id_from_json)"
BIRTH_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience payments)"
CAPABILITY_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["capability"]["id"])' "$BIRTH_JSON")"

HOP1="$("$BIN" --data-directory "$DATA_DIRECTORY" capability attenuate \
  --capability "$CAPABILITY_ID" --audience payments/a | id_from_json)"
HOP2="$("$BIN" --data-directory "$DATA_DIRECTORY" capability attenuate \
  --capability "$HOP1" --audience payments/a/b | id_from_json)"
HOP3="$("$BIN" --data-directory "$DATA_DIRECTORY" capability attenuate \
  --capability "$HOP2" --audience payments/a/b/c | id_from_json)"

python3 -c '
import json, pathlib, sys
data = pathlib.Path(sys.argv[1])
hop3 = sys.argv[2]
chain = json.loads((data / "chains" / (hop3 + ".json")).read_text())
if chain["hop_index"] != 3:
    raise SystemExit("The third hop must have hop_index 3.")
if not chain.get("parent_capability_id"):
    raise SystemExit("The chain record must point to the parent capability.")
print("The chain record for hop 3 is present.")
' "$DATA_DIRECTORY" "$HOP3"

echo "The fourth hop must fail."
if "$BIN" --data-directory "$DATA_DIRECTORY" capability attenuate \
  --capability "$HOP3" --audience payments/a/b/c/d; then
  echo "The fourth hop succeeded, but a failure was required."
  exit 1
fi

echo "The depth demonstration completed successfully."
