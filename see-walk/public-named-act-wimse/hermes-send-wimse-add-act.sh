#!/bin/bash
set -euo pipefail
REMOTE=/var/lib/prometheus-agent
printf '%s\n' "add-act --presentation-json $REMOTE/second-presentation.json --workload-identity-token $REMOTE/second-workload_identity_token --content-digest @$REMOTE/second-content_digest --signature-input @$REMOTE/second-signature_input --signature @$REMOTE/second-signature --holder-proof-command \"$REMOTE/prometheus holder-sign --holder-secret-path $REMOTE/second-holder.secret\"" > "$REMOTE/agent-process.in"
