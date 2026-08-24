#!/usr/bin/env bash
# Demonstration: a signed presentation document from a live instance and an unexpired capability.
# Present is a document, not a name. This is not a SPIFFE SVID. This is not an X.509 certificate.
# This is not a WIMSE token. This is not a Transaction Token.
# The instance identifier must not become a certificate subject.
# Present requires a one-time challenge. Present is not a bearer document.
# Expiry is covered by the injected-clock unit test an_expired_presentation_refuses.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA_DIRECTORY="${DEMO_DATA_DIRECTORY:-$ROOT/data-present}"
rm -rf "$DATA_DIRECTORY"
cargo build
BIN="$ROOT/target/debug/prometheus"

challenge_nonce() {
  "$BIN" --data-directory "$DATA_DIRECTORY" challenge --instance "$1" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])'
}

echo "Initializing the store and birthing one instance."
"$BIN" --data-directory "$DATA_DIRECTORY" init >/dev/null
AGENT_TYPE_ID="$("$BIN" --data-directory "$DATA_DIRECTORY" agent-type add \
  --owner laboratory --intent read --authorization-limit internal \
  --max-delegation-depth 2 --lifetime-seconds 3600 | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
BIRTH_JSON="$("$BIN" --data-directory "$DATA_DIRECTORY" birth \
  --agent-type "$AGENT_TYPE_ID" --owner laboratory --intent read --audience internal)"
INSTANCE_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["instance"]["id"])' "$BIRTH_JSON")"
CAPABILITY_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["capability"]["id"])' "$BIRTH_JSON")"
SECRET="$DATA_DIRECTORY/holders/${INSTANCE_ID}.secret"
PRESENTATION_PATH="$DATA_DIRECTORY/presentation.json"

echo "Issuing a one-time holder challenge."
NONCE="$(challenge_nonce "$INSTANCE_ID")"

echo "Writing a signed presentation document. This is a document, not a name."
"$BIN" --data-directory "$DATA_DIRECTORY" present \
  --instance "$INSTANCE_ID" \
  --capability "$CAPABILITY_ID" \
  --output "$PRESENTATION_PATH" \
  --holder-secret-path "$SECRET" \
  --challenge-nonce "$NONCE"
python3 -c '
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
presentation = json.loads(path.read_text())
required = (
    "instance_id",
    "agent_type_id",
    "capability_id",
    "on_behalf_of",
    "intent",
    "audience",
    "holder_public_key",
    "issuer_public_key_hex",
    "presented_at",
    "expires_at",
    "signature_hex",
)
for name in required:
    if not presentation.get(name):
        raise SystemExit(f"The presentation is missing {name}.")
if presentation["instance_id"] != sys.argv[2]:
    raise SystemExit("The presentation instance_id must match the live instance.")
if presentation["capability_id"] != sys.argv[3]:
    raise SystemExit("The presentation capability_id must match the named capability.")
print("The presentation document was written. Present is a document, not a name.")
' "$PRESENTATION_PATH" "$INSTANCE_ID" "$CAPABILITY_ID"

echo "Verifying the presentation. This check must succeed."
"$BIN" --data-directory "$DATA_DIRECTORY" present verify --presentation "$PRESENTATION_PATH"

echo "Re-using the spent challenge nonce. This present must fail."
if "$BIN" --data-directory "$DATA_DIRECTORY" present \
  --instance "$INSTANCE_ID" \
  --capability "$CAPABILITY_ID" \
  --output "$DATA_DIRECTORY/spent.json" \
  --holder-secret-path "$SECRET" \
  --challenge-nonce "$NONCE"; then
  echo "The spent challenge was accepted, but a failure was required."
  exit 1
fi
echo "The spent challenge nonce was refused."

echo "Altering the presentation intent. Verify must refuse the tampered document."
TAMPERED_PATH="$DATA_DIRECTORY/presentation-tampered.json"
python3 -c '
import json, pathlib, sys
source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
presentation = json.loads(source.read_text())
presentation["intent"] = "write"
destination.write_text(json.dumps(presentation, indent=2) + "\n")
print("The presentation intent was altered.")
' "$PRESENTATION_PATH" "$TAMPERED_PATH"
if "$BIN" --data-directory "$DATA_DIRECTORY" present verify --presentation "$TAMPERED_PATH"; then
  echo "The tampered presentation was accepted, but a failure was required."
  exit 1
fi
echo "The tampered presentation was refused."

echo "Expiry is covered by the injected-clock unit test an_expired_presentation_refuses."
echo "The unit test does not sleep. now >= expires_at fails closed."

echo "The present demonstration completed successfully."
