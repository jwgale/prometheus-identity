#!/bin/bash
set -euo pipefail
REMOTE=/var/lib/prometheus-agent
if [ -f "$REMOTE/agent-process.pid" ]; then kill "$(cat "$REMOTE/agent-process.pid")" 2>/dev/null || true; fi
if [ -f "$REMOTE/fifo-keeper.pid" ]; then kill "$(cat "$REMOTE/fifo-keeper.pid")" 2>/dev/null || true; fi
rm -f "$REMOTE/agent-process.in" "$REMOTE/agent-process.stdout" "$REMOTE/agent-process.stderr" \
  "$REMOTE/agent-process.pid" "$REMOTE/fifo-keeper.pid" \
  "$REMOTE/tool-allow.txt" "$REMOTE/tool-both.txt" "$REMOTE/tool-named-live.txt" \
  "$REMOTE/tool-named-dead.txt" "$REMOTE/tool-unnamed-after.txt" "$REMOTE/tool-named-dead-wimse.txt"
mkfifo "$REMOTE/agent-process.in"
chmod 600 "$REMOTE/agent-process.in"
nohup bash -c "exec 3<>$REMOTE/agent-process.in; while true; do sleep 3600; done" >/dev/null 2>&1 &
echo $! > "$REMOTE/fifo-keeper.pid"
nohup "$REMOTE/prometheus" runtime-check agent-process \
  --base-url https://check.prestigeworldwide.digital \
  --presentation-json "$REMOTE/first-presentation.json" \
  --certificate-pem "$REMOTE/first-presentation.json.svid.pem" \
  --holder-proof-command "$REMOTE/prometheus holder-sign --holder-secret-path $REMOTE/holder.secret" \
  < "$REMOTE/agent-process.in" > "$REMOTE/agent-process.stdout" 2> "$REMOTE/agent-process.stderr" &
echo $! > "$REMOTE/agent-process.pid"
sleep 0.5
ps -p "$(cat $REMOTE/agent-process.pid)" -o pid=,cmd=
