#!/usr/bin/env bash
# Demonstration: a locally signed Merkle tree head over the hash-chained issuance log.
# A second store can pin "this issuer attested this root at this leaf count".
# This is a locally signed Merkle root. This is not Certificate Transparency.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_DIRECTORY="${DEMO_DATA_DIRECTORY:-$ROOT/data-sign-root}"
rm -rf "$DATA_DIRECTORY"
cargo build
BIN="$ROOT/target/debug/prometheus"

echo "Initializing the laboratory issuer and birthing one instance."
INIT_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" init)"
FIRST_PUBLIC_KEY="$(python3 -c 'import json,sys; issuer=json.loads(sys.argv[1]); print(issuer.get("current_public_key") or issuer["public_keys"][0])' "$INIT_JSON")"
AGENT_TYPE_ID="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type add \
  --owner laboratory --intent read --authorization-limit internal \
  --max-delegation-depth 2 --lifetime-seconds 3600 | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
"$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience internal >/dev/null

TREE_HEAD_PATH="$DATA_DIRECTORY/tree_head.json"
echo "Signing the current local Merkle root."
"$BIN" --data-directory "$DATA_DIRECTORY" log sign-root --output "$TREE_HEAD_PATH"
python3 -c '
import json, pathlib, sys
tree_head = json.loads(pathlib.Path(sys.argv[1]).read_text())
required = ("merkle_root", "leaf_count", "signed_at", "issuer_public_key_hex", "signature_hex")
missing = [name for name in required if not tree_head.get(name) and tree_head.get(name) != 0]
if missing:
    raise SystemExit(f"The signed tree head is missing {missing}.")
if int(tree_head.get("leaf_count") or 0) < 1:
    raise SystemExit("The signed tree head leaf_count must be at least one after birth.")
if tree_head.get("issuer_public_key_hex") != sys.argv[2]:
    raise SystemExit("The signed tree head must name the current issuer public key.")
print("The signed tree head names merkle_root, leaf_count, signed_at, issuer_public_key_hex, and signature_hex.")
' "$TREE_HEAD_PATH" "$FIRST_PUBLIC_KEY"

echo "Checking the signed tree head. This check must succeed."
"$BIN" --data-directory "$DATA_DIRECTORY" log check-root --tree-head "$TREE_HEAD_PATH"

echo "Checking the signed tree head against this store current root. This check must succeed."
"$BIN" --data-directory "$DATA_DIRECTORY" log check-root --tree-head "$TREE_HEAD_PATH" --require-current-root

echo "Altering the Merkle root. The check must fail."
TAMPERED_PATH="$DATA_DIRECTORY/tampered_tree_head.json"
python3 -c '
import json, pathlib, sys
tree_head = json.loads(pathlib.Path(sys.argv[1]).read_text())
tree_head["merkle_root"] = "00" * 32
pathlib.Path(sys.argv[2]).write_text(json.dumps(tree_head, indent=2) + "\n")
print("The Merkle root was altered. The other fields still look valid.")
' "$TREE_HEAD_PATH" "$TAMPERED_PATH"
if "$BIN" --data-directory "$DATA_DIRECTORY" log check-root --tree-head "$TAMPERED_PATH"; then
  echo "The signed tree head verified after the Merkle root was altered, but a failure was required."
  exit 1
fi
echo "The tampered signed tree head was refused."

echo "Rotating the laboratory issuer key."
ROTATED="$("$BIN" --data-directory "$DATA_DIRECTORY" issuer rotate --kill-after-seconds 3600)"
NEW_PUBLIC_KEY="$(python3 -c 'import json,sys; issuer=json.loads(sys.argv[1]); print(issuer.get("current_public_key") or issuer["public_keys"][0])' "$ROTATED")"
if [ "$NEW_PUBLIC_KEY" = "$FIRST_PUBLIC_KEY" ]; then
  echo "Rotate must replace the current public key."
  exit 1
fi

NEW_TREE_HEAD_PATH="$DATA_DIRECTORY/new_tree_head.json"
echo "Signing a new tree head. This signature must use the new key."
"$BIN" --data-directory "$DATA_DIRECTORY" log sign-root --output "$NEW_TREE_HEAD_PATH"
python3 -c '
import json, pathlib, sys
tree_head = json.loads(pathlib.Path(sys.argv[1]).read_text())
if tree_head.get("issuer_public_key_hex") != sys.argv[2]:
    raise SystemExit("The new signed tree head must use the current issuer public key.")
if tree_head.get("issuer_public_key_hex") == sys.argv[3]:
    raise SystemExit("The new signed tree head must not use the previous issuer public key.")
print("The new signed tree head uses the current issuer key only.")
' "$NEW_TREE_HEAD_PATH" "$NEW_PUBLIC_KEY" "$FIRST_PUBLIC_KEY"
"$BIN" --data-directory "$DATA_DIRECTORY" log check-root --tree-head "$NEW_TREE_HEAD_PATH"

echo "Checking the old signed tree head as a historical pin. This check must succeed."
"$BIN" --data-directory "$DATA_DIRECTORY" log check-root --tree-head "$TREE_HEAD_PATH"
echo "The old signed tree head remains a historical pin after rotate."

echo "The locally signed Merkle tree head demonstration completed successfully."
