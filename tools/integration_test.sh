#!/usr/bin/env bash
# End-to-end test of everything downstream of the radio.
#
# hostapd needs real hardware, but ASSOCIATION is the only part that does. Every
# step after it -- DHCP, the DNS sinkhole, the port-80 redirect, the captive-portal
# probes, registration, MAC resolution, the console, and the firewall's refusals --
# runs over ordinary IP and can be tested properly.
#
# So: a veth pair stands in for the radio link, and a network namespace plays the
# student's laptop. The exam side runs the real generated nftables ruleset, the real
# dnsmasq, and the real portal. Nothing is mocked.
#
# Run as root on Linux:  sudo bash tools/integration_test.sh
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NS=student
AP_IF=exam0
STU_IF=stu0
SRV=10.83.0.1
PASS=0 FAIL=0

ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; [ $# -gt 1 ] && printf '        %s\n' "$2"; FAIL=$((FAIL+1)); }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }
sx()   { ip netns exec $NS "$@"; }   # run as the student

cleanup() {
  head_ "cleanup"
  [ -f /run/themis/portal.pid ] && kill "$(cat /run/themis/portal.pid)" 2>/dev/null
  pkill -f 'themis.server' 2>/dev/null
  [ -f /run/themis/dnsmasq.pid ] && kill "$(cat /run/themis/dnsmasq.pid)" 2>/dev/null
  nft flush ruleset 2>/dev/null
  ip netns del $NS 2>/dev/null
  ip link del $AP_IF 2>/dev/null
  echo "  torn down"
}
trap cleanup EXIT

head_ "setting up a fake radio link"
ip link del $AP_IF 2>/dev/null
ip netns del $NS 2>/dev/null
ip link add $AP_IF type veth peer name $STU_IF || { echo "veth failed"; exit 1; }
ip netns add $NS
mkdir -p /etc/netns/$NS && printf "nameserver %s\n" "$SRV" > /etc/netns/$NS/resolv.conf
ip link set $STU_IF netns $NS
ip addr add $SRV/24 dev $AP_IF
ip link set $AP_IF up
sx ip link set $STU_IF up
sx ip link set lo up
STU_MAC=$(sx cat /sys/class/net/$STU_IF/address)
echo "  exam side $AP_IF = $SRV   student $STU_IF = $STU_MAC"

head_ "rendering the real configs for this interface"
python3 - "$ROOT" "$AP_IF" <<'PY'
import json, sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
root, iface = Path(sys.argv[1]), sys.argv[2]
ap = SourceFileLoader("ap", str(root/"netguard/linux/bin/themis-ap")).load_module()
pol = json.loads((root/"netguard/linux/policy.json").read_text())
pol.update({"ap_interface": iface, "passphrase": "integration-test-passphrase"})
Path("/run/themis").mkdir(parents=True, exist_ok=True)
for name, text in ap.render(pol).items():
    Path("/run/themis", name).write_text(text)
(root/"/tmp/itest-policy.json").write_text(json.dumps(pol, indent=2)) if False else None
Path("/tmp/itest-policy.json").write_text(json.dumps(pol, indent=2))
print("  rendered hostapd.conf, nftables.conf, dnsmasq.conf")
PY

head_ "loading the firewall and DHCP/DNS"
if nft -f /run/themis/nftables.conf 2>/tmp/nfterr; then ok "nftables ruleset loaded"; else bad "nftables refused the ruleset" "$(cat /tmp/nfterr)"; exit 1; fi
dnsmasq -C /run/themis/dnsmasq.conf 2>/tmp/dnserr && ok "dnsmasq started" || { bad "dnsmasq would not start" "$(cat /tmp/dnserr)"; exit 1; }
sleep 1

head_ "starting the portal"
( cd "$ROOT" && python3 -m themis.server --policy /tmp/itest-policy.json \
    --journal /var/lib/themis/itest.jsonl --port 80 --console-port 8081 \
    >/run/themis/portal.log 2>&1 & echo $! > /run/themis/portal.pid )
sleep 2
if kill -0 "$(cat /run/themis/portal.pid)" 2>/dev/null; then ok "portal is running"; else bad "portal died" "$(tail -5 /run/themis/portal.log)"; exit 1; fi

head_ "1. the student gets an address (DHCP)"
timeout 25 ip netns exec $NS dhclient -v -1 $STU_IF >/tmp/dh.log 2>&1
STU_IP=$(sx ip -4 -br addr show $STU_IF | awk '{print $3}' | cut -d/ -f1)
if [ -n "$STU_IP" ]; then ok "leased $STU_IP"; else bad "no DHCP lease" "$(tail -8 /tmp/dh.log)"; fi
grep -q "$STU_MAC" /run/themis/dhcp.leases 2>/dev/null && ok "lease file records the student's MAC" || bad "MAC missing from the lease file"

printf "nameserver %s\n" "$SRV" > /etc/netns/$NS/resolv.conf 2>/dev/null || true

head_ "2. DNS is a sinkhole with no way out"
R=$(sx getent hosts google.com 2>/dev/null | awk '{print $1}')
[ "$R" = "$SRV" ] && ok "google.com resolves to the portal ($R)" || bad "google.com resolved to '$R', expected $SRV"
R=$(sx getent hosts chat.openai.com 2>/dev/null | awk '{print $1}')
[ "$R" = "$SRV" ] && ok "chat.openai.com resolves to the portal" || bad "AI endpoint resolved to '$R'"

head_ "3. HTTP to any address lands on the portal (the redirect)"
C=$(sx curl -s -o /tmp/body -w '%{http_code}' --max-time 8 http://93.184.216.34/ 2>/dev/null)
if [ "$C" = "200" ] && grep -qi 'exam network' /tmp/body; then ok "http://93.184.216.34/ was redirected to the sign-in page"
else bad "a raw IP did not reach the portal (code $C)" "$(head -c 120 /tmp/body 2>/dev/null)"; fi

head_ "4. the OS captive-portal probes do not look like success"
for u in /hotspot-detect.html /generate_204 /connecttest.txt /ncsi.txt; do
  C=$(sx curl -s -o /dev/null -w '%{http_code}' --max-time 8 "http://captive.example.com$u" 2>/dev/null)
  [ "$C" = "302" ] && ok "$u -> 302 (sign-in sheet will appear)" || bad "$u returned $C, expected 302"
done

head_ "5. everything else fails FAST, not after a hang"
START=$(date +%s%N)
sx curl -s -o /dev/null --max-time 10 https://example.com/ 2>/dev/null
MS=$(( ($(date +%s%N) - START) / 1000000 ))
[ "$MS" -lt 3000 ] && ok "https refused in ${MS}ms (reset, not a 30s spinner)" || bad "https took ${MS}ms -- looks like a drop, not a reject"
START=$(date +%s%N)
sx curl -s -o /dev/null --max-time 10 "http://$SRV:22/" 2>/dev/null
MS=$(( ($(date +%s%N) - START) / 1000000 ))
[ "$MS" -lt 3000 ] && ok "ssh port refused in ${MS}ms" || bad "ssh port took ${MS}ms"

head_ "6. the student registers, and the MAC is resolved from the network"
C=$(sx curl -s -o /tmp/reg -w '%{http_code}' --max-time 8 \
      -X POST -d "student_id=jhu4242&name=Integration+Test&seat=7" "http://$SRV/register" 2>/dev/null)
[ "$C" = "302" ] && ok "registration accepted" || bad "registration returned $C" "$(head -c 200 /tmp/reg)"
sleep 1
if curl -s --max-time 5 http://127.0.0.1:8081/api/state | grep -q "$STU_MAC"; then
  ok "the console shows the student bound to $STU_MAC"
else bad "the console did not resolve the student's MAC"; fi
curl -s --max-time 5 http://127.0.0.1:8081/api/state | grep -q 'Integration Test' \
  && ok "the student's name appears on the console" || bad "name missing from the console"

head_ "7. a returning student sees their own page, not the form"
sx curl -s --max-time 8 "http://$SRV/" > /tmp/home 2>/dev/null
grep -qi 'You are connected' /tmp/home && ok "returning device gets its own page" || bad "returning device was shown the sign-in form again"

head_ "8. the proctor console is NOT reachable from the exam network"
C=$(sx curl -s -o /dev/null -w '%{http_code}' --max-time 6 "http://$SRV:8081/" 2>/dev/null)
[ "$C" = "000" ] && ok "console refused from the student side (it lists every name and device)" \
                 || bad "the console answered a student with HTTP $C"
C=$(sx curl -s -o /dev/null -w '%{http_code}' --max-time 6 "http://$SRV:8081/api/state" 2>/dev/null)
[ "$C" = "000" ] && ok "console API refused from the student side" || bad "console API answered a student: $C"
C=$(sx curl -s -o /dev/null -w '%{http_code}' --max-time 6 "http://$SRV:8080/" 2>/dev/null)
[ "$C" = "000" ] && ok "operator panel refused from the student side" || bad "operator panel answered a student: $C"

head_ "9. presence sampling notices the student"
sleep 11
if curl -s --max-time 5 http://127.0.0.1:8081/api/state | python3 -c "
import json,sys
d=json.load(sys.stdin)
on=[s for s in d['students'] if s['online']]
sys.exit(0 if on else 1)"; then ok "the student shows as on the network"; else bad "presence never saw the student"; fi
SRC=$(curl -s --max-time 5 http://127.0.0.1:8081/api/state | python3 -c "import json,sys; print(json.load(sys.stdin).get('presence_source'))")
[ "$SRC" = "leases" ] && ok "presence source reported honestly as '$SRC' (no hostapd here)" \
                      || bad "presence source was '$SRC'"

head_ "10. the record is intact and reviewable"
python3 - <<'PY'
import sys; sys.path.insert(0, "/src" if False else ".")
from themis.journal import Journal
v = Journal("/var/lib/themis/itest.jsonl").verify()
print(("  PASS  " if v.ok else "  FAIL  ") + v.summary())
raise SystemExit(0 if v.ok else 1)
PY
[ $? -eq 0 ] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))

head_ "RESULT"
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
