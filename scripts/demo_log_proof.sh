#!/usr/bin/env bash
# Demonstration: a local Merkle inclusion proof over the hash-chained issuance log.
# A second store can check one logged mint without copying the whole log.
# This is a local Merkle tree. This is not a public transparency log.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_DIRECTORY="${DEMO_DATA_DIRECTORY:-$ROOT/data-log-proof}"
rm -rf "$DATA_DIRECTORY"
cargo build
BIN="$ROOT/target/debug/prometheus"

"$BIN" --data-directory "$DATA_DIRECTORY" init >/dev/null
AGENT_TYPE_ID="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type add \
  --owner laboratory --intent read --authorization-limit internal \
  --max-delegation-depth 2 --lifetime-seconds 3600 | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"

echo "Birthing one instance. The issuance log must grow."
BIRTH_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience internal)"
python3 -c '
import json, sys
birth = json.loads(sys.argv[1])
if not birth.get("instance", {}).get("id") or not birth.get("capability", {}).get("id"):
    raise SystemExit("Birth must write an instance and a capability.")
print("Birth wrote one instance and the first capability.")
' "$BIRTH_JSON"

echo "Printing the local Merkle root and the leaf count."
ROOT_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" log root)"
OLD_ROOT="$(python3 -c '
import json, sys
root = json.loads(sys.argv[1])
if not root.get("root") or int(root.get("leaf_count") or 0) < 1:
    raise SystemExit("log root must print a Merkle root and a leaf count of at least one.")
print(root["root"])
' "$ROOT_JSON")"
echo "The first Merkle root is $OLD_ROOT"

LINE_HASH="$(python3 -c '
import json, pathlib, sys
log_path = pathlib.Path(sys.argv[1]) / "issuance.log"
for line in log_path.read_text().splitlines():
    if not line.strip():
        continue
    event = json.loads(line)
    if event.get("operation") == "birth_write":
        line_hash = event.get("line_hash")
        if not line_hash:
            raise SystemExit("The birth line must include line_hash.")
        print(line_hash)
        break
else:
    raise SystemExit("The birth line is missing.")
' "$DATA_DIRECTORY")"
echo "The birth line_hash is $LINE_HASH"

PROOF_PATH="$DATA_DIRECTORY/birth_proof.json"
echo "Proving the birth line."
"$BIN" --data-directory "$DATA_DIRECTORY" log prove --line-hash "$LINE_HASH" > "$PROOF_PATH"
python3 -c '
import json, pathlib, sys
proof = json.loads(pathlib.Path(sys.argv[1]).read_text())
if proof.get("line_hash") != sys.argv[2]:
    raise SystemExit("The proof line_hash must be the birth line.")
if "leaf_index" not in proof:
    raise SystemExit("The proof must include leaf_index.")
if "sibling_hashes" not in proof or not isinstance(proof["sibling_hashes"], list):
    raise SystemExit("The proof must include sibling_hashes in order.")
if proof.get("root") != sys.argv[3]:
    raise SystemExit("The proof root must match the current Merkle root.")
print("The inclusion proof names line_hash, leaf_index, sibling_hashes, and root.")
' "$PROOF_PATH" "$LINE_HASH" "$OLD_ROOT"

echo "Checking the inclusion proof against this store root. This check must succeed."
"$BIN" --data-directory "$DATA_DIRECTORY" log check-proof --proof "$PROOF_PATH"

echo "Altering one sibling. The check must fail."
TAMPERED_PATH="$DATA_DIRECTORY/tampered_proof.json"
python3 -c '
import json, pathlib, sys
proof = json.loads(pathlib.Path(sys.argv[1]).read_text())
siblings = list(proof.get("sibling_hashes") or [])
if siblings:
    siblings[0] = "00" * 32
    print("One sibling hash was altered.")
else:
    siblings.append("00" * 32)
    print("A forged sibling hash was inserted into an empty sibling list.")
proof["sibling_hashes"] = siblings
pathlib.Path(sys.argv[2]).write_text(json.dumps(proof, indent=2) + "\n")
' "$PROOF_PATH" "$TAMPERED_PATH"
if "$BIN" --data-directory "$DATA_DIRECTORY" log check-proof --proof "$TAMPERED_PATH"; then
  echo "The inclusion proof verified after a sibling was altered, but a failure was required."
  exit 1
fi
echo "The tampered inclusion proof was refused."

echo "Birthing a second instance. The Merkle root must change."
"$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience internal >/dev/null
NEW_ROOT="$("$BIN" --data-directory "$DATA_DIRECTORY" log root | python3 -c 'import json,sys; print(json.load(sys.stdin)["root"])')"
if [ "$NEW_ROOT" = "$OLD_ROOT" ]; then
  echo "The Merkle root did not change after a second birth."
  exit 1
fi
echo "The new Merkle root is $NEW_ROOT"

echo "Checking the old proof against the old root. This check must succeed."
"$BIN" --data-directory "$DATA_DIRECTORY" log check-proof --proof "$PROOF_PATH" --root "$OLD_ROOT"

echo "Checking the old proof against the new store root. This check must fail."
if "$BIN" --data-directory "$DATA_DIRECTORY" log check-proof --proof "$PROOF_PATH"; then
  echo "The old inclusion proof verified against the new root, but a failure was required."
  exit 1
fi
echo "The old inclusion proof was refused against the new root."

echo "Checking the old proof against the supplied new root. This check must fail."
if "$BIN" --data-directory "$DATA_DIRECTORY" log check-proof --proof "$PROOF_PATH" --root "$NEW_ROOT"; then
  echo "The old inclusion proof verified against the supplied new root, but a failure was required."
  exit 1
fi
echo "The old inclusion proof was refused against the supplied new root."

echo "The local Merkle inclusion proof demonstration completed successfully."
