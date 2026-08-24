#!/bin/bash
set -euo pipefail
REMOTE=/var/lib/prometheus-agent
printf '%s\n' "add-act --presentation-json $REMOTE/child-presentation.json --workload-identity-token $REMOTE/child-workload_identity_token --content-digest @$REMOTE/child-content_digest --signature-input @$REMOTE/child-signature_input --signature @$REMOTE/child-signature --holder-proof-command \"$REMOTE/prometheus holder-sign --holder-secret-path $REMOTE/child-holder.secret\"" > "$REMOTE/agent-process.in"
