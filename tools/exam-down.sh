#!/usr/bin/env bash
# Stop everything exam-up.sh started and hand the host back.
#
#   sudo bash tools/exam-down.sh
#
# The exam record is NOT touched. /var/lib/themis/exam.jsonl is the artifact a
# student is entitled to see if their marks are questioned, so nothing here
# deletes it; `themis.state.archive_previous` is what rolls it over for the next
# sitting, deliberately as a separate decision.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AP="$ROOT/netguard/linux/bin/themis-ap"
RUN=/run/themis
PORTAL_PID="$RUN/portal.pid"

[ "$(id -u)" = 0 ] || { echo "exam-down: must run as root" >&2; exit 1; }

# Bracketed so the pattern cannot match this script's own command line.
server_pids() { pgrep -f '[t]hemis\.server' 2>/dev/null; }

echo "stopping the portal and console ..."
if [ -f "$PORTAL_PID" ]; then
  kill "$(cat "$PORTAL_PID")" 2>/dev/null && echo "  stopped the portal"
  rm -f "$PORTAL_PID"
fi
stray=$(server_pids)
if [ -n "$stray" ]; then
  # shellcheck disable=SC2086
  kill $stray 2>/dev/null && echo "  stopped a stray exam server"
fi

echo
echo "stopping the exam network ..."
"$AP" down

echo
echo "the exam record is untouched:"
if [ -f /var/lib/themis/exam.jsonl ]; then
  printf '  /var/lib/themis/exam.jsonl  (%s events)\n' "$(wc -l < /var/lib/themis/exam.jsonl)"
else
  echo "  /var/lib/themis/exam.jsonl  (none yet)"
fi
echo
