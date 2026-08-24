#!/usr/bin/env bash
# Demonstration: a local act bundle a second store can accept without becoming a second identity kernel.
# Compose a decision receipt, a Merkle inclusion proof, and a signed tree head.
# This is a local export of three existing artifacts. This is not a global name system.
# This is not SPIFFE federation. This is not Certificate Transparency gossip.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
FIRST_DIRECTORY="${DEMO_FIRST_DATA_DIRECTORY:-$ROOT/data-act-first}"
SECOND_DIRECTORY="${DEMO_SECOND_DATA_DIRECTORY:-$ROOT/data-act-second}"
BUNDLE_DIRECTORY="${DEMO_BUNDLE_DIRECTORY:-$ROOT/data-act-bundle}"
rm -rf "$FIRST_DIRECTORY" "$SECOND_DIRECTORY" "$BUNDLE_DIRECTORY"
cargo build
BIN="$ROOT/target/debug/prometheus"

challenge_nonce() {
  local data_directory="$1"
  local instance_id="$2"
  "$BIN" --data-directory "$data_directory" challenge --instance "$instance_id" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])'
}

echo "Initializing store A and birthing one instance."
FIRST_ISSUER="$("$BIN" --data-directory "$FIRST_DIRECTORY" init)"
FIRST_PUBLIC_KEY="$(python3 -c 'import json,sys; issuer=json.loads(sys.argv[1]); print(issuer.get("current_public_key") or issuer["public_keys"][0])' "$FIRST_ISSUER")"
AGENT_TYPE_ID="$("$BIN" --data-directory "$FIRST_DIRECTORY" agent-type add \
  --owner laboratory --intent read --authorization-limit internal \
  --max-delegation-depth 2 --lifetime-seconds 3600 | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
BIRTH_JSON="$("$BIN" --data-directory "$FIRST_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience internal)"
INSTANCE_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["id"])' "$BIRTH_JSON")"
CAPABILITY_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["capability"]["id"])' "$BIRTH_JSON")"
SECRET="$FIRST_DIRECTORY/holders/${INSTANCE_ID}.secret"

echo "Checking an allowed tool action on store A and saving the signed decision receipt."
ALLOWED_NONCE="$(challenge_nonce "$FIRST_DIRECTORY" "$INSTANCE_ID")"
ALLOWED_JSON="$("$BIN" --data-directory "$FIRST_DIRECTORY" check \
  --instance "$INSTANCE_ID" --capability "$CAPABILITY_ID" \
  --intent read --audience internal \
  --holder-secret-path "$SECRET" --challenge-nonce "$ALLOWED_NONCE" \
  --on-behalf-of autonomous)"
RECEIPT_PATH="${FIRST_DIRECTORY}/allowed_receipt.json"
python3 -c '
import json, pathlib, sys
decision = json.loads(sys.argv[1])
if decision.get("result") != "allowed":
    raise SystemExit("The check must be allowed.")
receipt = decision.get("receipt")
if not isinstance(receipt, dict):
    raise SystemExit("The check must return a signed decision receipt.")
if not receipt.get("signature"):
    raise SystemExit("The receipt must include a signature.")
if not receipt.get("issuance_log_line"):
    raise SystemExit("The receipt must include issuance_log_line.")
pathlib.Path(sys.argv[2]).write_text(json.dumps(receipt, indent=2) + "\n")
print("The allowed receipt was saved.")
' "$ALLOWED_JSON" "$RECEIPT_PATH"

echo "Exporting the act bundle from store A."
"$BIN" --data-directory "$FIRST_DIRECTORY" act export \
  --receipt "$RECEIPT_PATH" \
  --output-directory "$BUNDLE_DIRECTORY"
python3 -c '
import json, pathlib, sys
bundle = pathlib.Path(sys.argv[1])
for name in ("receipt.json", "proof.json", "tree-head.json"):
    path = bundle / name
    if not path.exists():
        raise SystemExit(f"The act bundle is missing {name}.")
receipt = json.loads((bundle / "receipt.json").read_text())
proof = json.loads((bundle / "proof.json").read_text())
tree_head = json.loads((bundle / "tree-head.json").read_text())
line = json.loads(receipt["issuance_log_line"])
if proof.get("line_hash") != line.get("line_hash"):
    raise SystemExit("The proof line_hash must match the receipt bound line.")
if proof.get("root") != tree_head.get("merkle_root"):
    raise SystemExit("The proof root must match the signed tree head merkle_root.")
print("The act bundle holds receipt.json, proof.json, and tree-head.json.")
' "$BUNDLE_DIRECTORY"

echo "Initializing store B and accepting store A public key."
"$BIN" --data-directory "$SECOND_DIRECTORY" init >/dev/null
"$BIN" --data-directory "$SECOND_DIRECTORY" issuer accept --public-key-hex "$FIRST_PUBLIC_KEY"

echo "Store B accepts the act bundle. This check must succeed."
"$BIN" --data-directory "$SECOND_DIRECTORY" act accept --bundle-directory "$BUNDLE_DIRECTORY"
python3 -c '
import pathlib, sys
log = (pathlib.Path(sys.argv[1]) / "issuance.log").read_text()
if log.strip():
    raise SystemExit("Act accept must not write a second issuance.log line.")
instances = pathlib.Path(sys.argv[1]) / "instances"
if any(instances.glob("*.json")):
    raise SystemExit("Act accept must not create instance records.")
print("Store B did not mint and did not write a second issuance.log line.")
' "$SECOND_DIRECTORY"

echo "Altering the receipt result. Store B must refuse the tampered bundle."
TAMPERED_DIRECTORY="${BUNDLE_DIRECTORY}-tampered"
rm -rf "$TAMPERED_DIRECTORY"
cp -a "$BUNDLE_DIRECTORY" "$TAMPERED_DIRECTORY"
python3 -c '
import json, pathlib, sys
path = pathlib.Path(sys.argv[1]) / "receipt.json"
receipt = json.loads(path.read_text())
receipt["result"] = "refused"
path.write_text(json.dumps(receipt, indent=2) + "\n")
print("The receipt result was altered.")
' "$TAMPERED_DIRECTORY"
if "$BIN" --data-directory "$SECOND_DIRECTORY" act accept --bundle-directory "$TAMPERED_DIRECTORY"; then
  echo "The tampered act bundle was accepted, but a failure was required."
  exit 1
fi
echo "The tampered act bundle was refused."

echo "The act bundle demonstration completed successfully."
