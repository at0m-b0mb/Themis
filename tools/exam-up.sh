#!/usr/bin/env bash
# Bring up an entire exam with one command: radio, DHCP, DNS, firewall, the
# name-validating proxy, the student portal and the proctor console.
#
# Why this exists rather than a line in the README. The portal used to be started
# by hand in a terminal, and during a real session it died with that terminal --
# silently, while the network itself stayed up, so the exam looked fine and the
# captive portal simply did not answer. Everything started here is detached with
# setsid and tracked by a pid file, so closing the window you launched it from
# cannot take the exam down.
#
#   sudo bash tools/exam-up.sh
#
# Idempotent: run it again and it restarts whatever is not running.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AP="$ROOT/netguard/linux/bin/themis-ap"
POLICY="$ROOT/netguard/linux/policy.json"
RUN=/run/themis
PORTAL_PID="$RUN/portal.pid"
CONSOLE_PORT="${CONSOLE_PORT:-8081}"

c_g=$'\033[32m'; c_r=$'\033[31m'; c_b=$'\033[1m'; c_0=$'\033[0m'

[ "$(id -u)" = 0 ] || {
  echo "exam-up: must run as root -- the radio, the firewall and port 80 all need it" >&2
  exit 1; }

mkdir -p "$RUN"

# `pgrep -f themis.server` would match THIS script's own command line, because the
# pattern appears in it. The bracket makes the regex match the running server
# without matching the literal text here. (Learned the hard way: a pkill -f with
# the plain pattern killed the shell that was running it, before it could start
# anything.)
server_pids() { pgrep -f '[t]hemis\.server' 2>/dev/null; }

stop_portal() {
  if [ -f "$PORTAL_PID" ]; then
    kill "$(cat "$PORTAL_PID")" 2>/dev/null && echo "  stopped the portal we started earlier"
    rm -f "$PORTAL_PID"
  fi
  local stray; stray=$(server_pids)
  if [ -n "$stray" ]; then
    echo "  stopping a stray exam server: $(echo "$stray" | tr '\n' ' ')"
    # shellcheck disable=SC2086
    kill $stray 2>/dev/null
    sleep 1
  fi
}

printf "${c_b}exam-up${c_0}\n\n"

# Claiming to be idempotent is not the same as being idempotent. `themis-ap up`
# does not evict an hostapd that is already holding the radios, so running this
# on a live setup would fail partway with an error about the interface rather
# than about the cause. Tear down first when something is already running.
if [ -f "$RUN/state.json" ]; then
  printf "${c_b}0. an exam network is already up -- stopping it first${c_0}\n"
  stop_portal
  "$AP" down >/dev/null 2>&1
  echo "  stopped"
  echo
fi

printf "${c_b}1. the exam network${c_0}\n"
if ! "$AP" up; then
  printf "\n${c_r}the network did not come up, so nothing else was started.${c_0}\n" >&2
  printf "Read the preflight output above -- it names the fix.\n" >&2
  exit 1
fi

printf "\n${c_b}2. the student portal and the proctor console${c_0}\n"
stop_portal
cd "$ROOT" || exit 1
# PYTHONUNBUFFERED so portal.log is readable while it matters rather than after
# the process exits. setsid so this survives its launching terminal.
PYTHONUNBUFFERED=1 setsid nohup python3 -m themis.server \
    --policy "$POLICY" --console-port "$CONSOLE_PORT" \
    >"$RUN/portal.log" 2>&1 </dev/null &
echo $! > "$PORTAL_PID"

listening=0
for _ in $(seq 1 40); do
  if ss -lnt 2>/dev/null | grep -qE ':80\b'; then listening=1; break; fi
  if ! kill -0 "$(cat "$PORTAL_PID" 2>/dev/null)" 2>/dev/null; then break; fi
  sleep 0.25
done
if [ "$listening" = 1 ]; then
  echo "  portal listening on port 80, console on 127.0.0.1:$CONSOLE_PORT"
else
  printf "  ${c_r}the portal did not start.${c_0} Last lines of %s:\n" "$RUN/portal.log" >&2
  tail -12 "$RUN/portal.log" 2>/dev/null | sed 's/^/    /' >&2
  printf "  The network is up, but students would get no sign-in page.\n" >&2
  exit 1
fi

printf "\n${c_b}3. what is running${c_0}\n"
python3 - "$POLICY" "$CONSOLE_PORT" <<'PY'
import json, sys
pol = json.loads(open(sys.argv[1]).read())
console = sys.argv[2]
mode = ("blocklist" if pol.get("proxy_mode") == "block"
        else "allowlist" if pol.get("profile") == "proxy" else pol.get("profile"))
print(f"  ssid         {pol.get('ssid')}")
print(f"  passphrase   {pol.get('passphrase')}")
print(f"  mode         {mode}")
radios = pol.get("radios") or [{"interface": pol.get("ap_interface"),
                                "channel": pol.get("channel")}]
for r in radios:
    ch = int(r.get("channel", 0))
    band = "2.4" if ch <= 14 else "5"
    print(f"  radio        {r.get('interface')}  {band} GHz  ch {ch}")
key = "block_dns_names" if mode == "blocklist" else "allow_dns_names"
names = [n for n in (pol.get(key) or []) if not str(n).startswith("_")]
label = "blocked" if mode == "blocklist" else "reachable"
print(f"  {label:<12} {', '.join(names) or '(nothing)'}")
print()
print(f"  students     http://{pol.get('server_ip')}/")
print(f"  console      http://127.0.0.1:{console}/   (loopback only)")
print(f"  record       /var/lib/themis/exam.jsonl")
print(f"  refusals     /run/themis/proxy-decisions.log")
PY

printf "\n  ${c_g}Up.${c_0}  Verify it refuses what you think it does:\n"
printf "      sudo bash tools/verify_blocking.sh\n"
printf "  Stop everything:\n"
printf "      sudo bash tools/exam-down.sh\n\n"
