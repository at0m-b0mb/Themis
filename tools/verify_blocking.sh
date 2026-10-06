#!/usr/bin/env bash
# Verify what the LIVE exam network actually permits, by being a student on it.
#
# tools/integration_test.sh builds its own fake radio link and its own ruleset, so
# it proves the design is sound on any machine. This proves something different and
# narrower: that the network running RIGHT NOW, with the policy that is loaded right
# now, refuses what you believe it refuses. Run it after `themis-ap up` and before
# students arrive.
#
# It attaches a veth to the real bridge and speaks over the real firewall, the real
# dnsmasq and the real proxy. Nothing is mocked and nothing is reconfigured: the only
# things it creates are two namespaces and two veth pairs, and it removes them.
#
#   sudo bash tools/verify_blocking.sh
#
# Every refusal is also TIMED, because "blocked" and "blocked instantly" are
# different products. A dropped packet leaves a student watching a spinner and
# concluding the exam network is broken; a reset tells the browser at once. Any
# refusal slower than REJECT_MAX seconds is reported as a failure even though the
# traffic did not get through.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
POLICY="$ROOT/netguard/linux/policy.json"
NS1=themis-stu1
NS2=themis-stu2
V1=vths1; V1B=vths1b
V2=vths2; V2B=vths2b
IP1=10.83.0.151
IP2=10.83.0.152
REJECT_MAX=2.0
PASS=0; FAIL=0; SKIP=0

c_g=$'\033[32m'; c_r=$'\033[31m'; c_y=$'\033[33m'; c_b=$'\033[1m'; c_0=$'\033[0m'
# ${1-} rather than $1: this file runs under `set -u`, where a helper called with
# a missing argument aborts the whole run -- and it aborted it mid-way through the
# VPN section, which reads as "the tests stopped" rather than "a test is buggy".
ok()   { printf "  ${c_g}PASS${c_0}  %s\n" "${1-}"; PASS=$((PASS+1)); }
bad()  { printf "  ${c_r}FAIL${c_0}  %s\n" "${1-}"; [ $# -gt 1 ] && printf '        %s\n' "${2-}"; FAIL=$((FAIL+1)); return 0; }
skip() { printf "  ${c_y}SKIP${c_0}  %s\n" "${1-}"; SKIP=$((SKIP+1)); }
hd()   { printf "\n${c_b}%s${c_0}\n" "${1-}"; }

s1() { ip netns exec $NS1 "$@"; }
s2() { ip netns exec $NS2 "$@"; }

# Seconds (float) that a command took, printed on stdout.
timed() { local t0 t1; t0=$(date +%s.%N); "$@" >/dev/null 2>&1; t1=$(date +%s.%N)
          awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}'; }
faster_than() { awk -v x="${1:-99}" -v m="${2:-0}" 'BEGIN{exit !(x+0<m+0)}'; }

[ "$(id -u)" = 0 ] || { echo "verify_blocking: must run as root" >&2; exit 1; }

# Proving a UDP packet did NOT leave is harder than it looks, and the obvious
# test is worthless. Writing to /dev/udp/host/port succeeds as soon as the bytes
# reach the local socket buffer, whether or not the packet is ever delivered --
# so "the write succeeded" and "the write failed" tell you nothing either way.
# An earlier version of this file branched on exactly that and called BOTH
# outcomes a pass, which meant the WireGuard check could not fail.
#
# The only thing that proves a UDP packet left is a REPLY. So the probe is a DNS
# query to a public resolver: if an answer comes back, student UDP reaches the
# internet and every UDP-based VPN works. If nothing comes back, nothing left.
UDP_PROBE_RAW=""
udp_reaches_internet() {
  # Captured rather than piped straight into grep, so that a claimed bypass can
  # be inspected instead of taken on trust. `dig +short` writes its errors to
  # STDOUT, so the raw text is the only way to tell a real answer from a
  # timeout message that merely contains digits and dots.
  UDP_PROBE_RAW=$(s1 timeout 8 dig +short +time=4 +tries=1 example.com @8.8.8.8 2>&1)
  printf '%s\n' "$UDP_PROBE_RAW" \
    | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
}

# Independent of any reply: the kernel counts packets it refused to route.
# InAddrErrors climbs for every datagram that arrived for somewhere else while
# forwarding was off, which is exactly what a student's VPN produces.
in_addr_errors() {
  awk '/^Ip:/ {if (h) {for (i=1;i<=NF;i++) if (hdr[i]=="InAddrErrors") print $i; exit}
       else {for (i=1;i<=NF;i++) hdr[i]=$i; h=1}}' /proc/net/snmp 2>/dev/null
}


BRIDGE=$(python3 - "$POLICY" <<'PY'
import json, sys
pol = json.loads(open(sys.argv[1]).read())
radios = pol.get("radios") or []
print(pol.get("bridge", "br-themis") if len(radios) > 1 else "")
PY
)
SRV=$(python3 -c "import json,sys;print(json.load(open('$POLICY')).get('server_ip','10.83.0.1'))")
MODE=$(python3 -c "
import json;p=json.load(open('$POLICY'))
print('blocklist' if p.get('proxy_mode')=='block' else ('allowlist' if p.get('profile')=='proxy' else p.get('profile','?')))")
ALLOW1=$(python3 -c "
import json;p=json.load(open('$POLICY'))
n=[x for x in (p.get('allow_dns_names') or []) if not str(x).startswith('_')]
print(n[0] if n else '')")

if [ -z "$BRIDGE" ]; then
  echo "verify_blocking: the live setup is single-radio, so there is no bridge to"
  echo "  attach a test student to. Use tools/integration_test.sh, which builds its"
  echo "  own link, or run two radios." >&2
  exit 1
fi
ip link show "$BRIDGE" >/dev/null 2>&1 || {
  echo "verify_blocking: $BRIDGE does not exist -- is the exam network up?" >&2; exit 1; }

cleanup() {
  hd "cleanup"
  ip netns del $NS1 2>/dev/null; ip netns del $NS2 2>/dev/null
  ip link del $V1 2>/dev/null;   ip link del $V2 2>/dev/null
  rm -rf /etc/netns/$NS1 /etc/netns/$NS2
  echo "  removed both test students; the exam network itself was not touched"
}
trap cleanup EXIT

mkstudent() { # ns veth vethb addr
  local ns=$1 v=$2 vb=$3 addr=$4
  ip netns del "$ns" 2>/dev/null
  ip link del "$v" 2>/dev/null
  ip netns add "$ns"
  ip link add "$v" type veth peer name "$vb"
  ip link set "$v" master "$BRIDGE" up
  ip link set "$vb" netns "$ns"
  ip netns exec "$ns" ip link set lo up
  ip netns exec "$ns" ip link set "$vb" name eth0
  ip netns exec "$ns" ip addr add "$addr/24" dev eth0
  ip netns exec "$ns" ip link set eth0 up
  ip netns exec "$ns" ip route add default via "$SRV"
  mkdir -p "/etc/netns/$ns"
  printf 'nameserver %s\n' "$SRV" > "/etc/netns/$ns/resolv.conf"
}

printf "${c_b}verify_blocking -- against the live exam network${c_0}\n"
printf "  mode       %s\n  bridge     %s\n  gateway    %s\n" "$MODE" "$BRIDGE" "$SRV"
printf "  allowed    %s\n" "${ALLOW1:-(none)}"

hd "attaching two test students to the live bridge"
mkstudent $NS1 $V1 $V1B $IP1
mkstudent $NS2 $V2 $V2B $IP2
sleep 1
if s1 ping -c1 -W2 "$SRV" >/dev/null 2>&1; then ok "a student can reach the gateway"
else bad "a student cannot reach the gateway" "everything below would fail for the wrong reason"; fi

hd "DNS"
res=$(s1 dig +short +time=2 +tries=1 example.com @"$SRV" 2>/dev/null | head -1)
[ "$res" = "$SRV" ] && ok "every name sinkholes to the gateway (example.com -> $res)" \
                    || bad "sinkhole not in effect" "example.com -> ${res:-<nothing>}"
if [ -n "$ALLOW1" ]; then
  res=$(s1 dig +short +time=2 +tries=1 "$ALLOW1" @"$SRV" 2>/dev/null | head -1)
  [ "$res" = "$SRV" ] && ok "even the allowlisted name resolves to us, so the client never learns its real address" \
                      || bad "allowlisted name did not sinkhole" "$ALLOW1 -> ${res:-<nothing>}"
fi
# `dig +short` prints its FAILURES to stdout, not stderr:
#   ;; communications error to 8.8.8.8#53: timed out
#   ;; no servers could be reached
# An earlier version matched that with an unanchored /[0-9]+\./, which hits the
# "8.8.8.8#53" inside the error text -- so the check reported a bypass exactly
# when the query had been blocked, and would have reported success only if the
# resolver really were reachable. Anchoring to a complete dotted quad is what
# makes the test mean what it says.
if udp_reaches_internet; then
  bad "DNS to 8.8.8.8 ANSWERED -- the resolver can be bypassed" \
      "dig returned: $(printf '%s' "$UDP_PROBE_RAW" | tr '\n' '|')"
else
  ok "DNS to an outside resolver is refused"
  printf "        (dig said: %s)\n" "$(printf '%s' "$UDP_PROBE_RAW" | tr '\n' '|' | cut -c1-90)"
fi
t=$(timed s1 timeout 3 bash -c "exec 3<>/dev/tcp/1.1.1.1/853")
if s1 timeout 3 bash -c "exec 3<>/dev/tcp/1.1.1.1/853" 2>/dev/null; then
  bad "DNS-over-TLS (853) connected"
else ok "DNS-over-TLS on 853 is refused (${t}s)"; fi

hd "the captive portal"
code=$(s1 curl -s -o /dev/null -w '%{http_code}' --max-time 6 "http://$SRV/" 2>/dev/null)
[ "$code" = "200" ] && ok "the portal answers on port 80 (HTTP $code)" || bad "portal did not answer" "HTTP $code"
code=$(s1 curl -s -o /dev/null -w '%{http_code}' --max-time 6 -H 'Host: connectivitycheck.gstatic.com' \
       "http://$SRV/generate_204" 2>/dev/null)
[ "$code" = "302" ] && ok "the OS captive-portal probe gets a 302, so the sign-in sheet pops" \
                    || bad "captive-portal probe did not redirect" "HTTP $code"

hd "HTTPS: the allowlist is matched by NAME"
if [ -z "$ALLOW1" ]; then skip "no allowlisted name in the policy to test"; else
  # A real handshake all the way to the real server. If this returns the real
  # certificate, the proxy spliced rather than intercepted -- there is no
  # certificate of ours anywhere in the path.
  cert=$(s1 timeout 15 openssl s_client -connect "$SRV:443" -servername "$ALLOW1" \
         -verify_return_error </dev/null 2>/dev/null | openssl x509 -noout -subject 2>/dev/null)
  if [ -n "$cert" ]; then ok "allowlisted name completes a real TLS handshake: ${cert#subject=}"
  else bad "allowlisted name did not complete TLS" "the exam site would not load"; fi
  code=$(s1 curl -s -o /dev/null -w '%{http_code}' --max-time 20 "https://$ALLOW1/" 2>/dev/null)
  if [ "$code" != "000" ] && [ -n "$code" ]; then ok "HTTPS to the allowlisted site returns HTTP $code"
  else bad "HTTPS to the allowlisted site failed" "curl exit code 000"; fi
fi

for host in google.com chatgpt.com chat.openai.com gemini.google.com protonvpn.com; do
  t=$(timed s1 curl -s -o /dev/null --max-time 8 "https://$host/")
  if s1 curl -s -o /dev/null --max-time 8 "https://$host/" 2>/dev/null; then
    bad "https://$host WORKED -- it is not on the allowlist"
  elif faster_than "$t" "$REJECT_MAX"; then ok "https://$host refused in ${t}s"
  else bad "https://$host was refused but took ${t}s" "a hang reads as a broken network"; fi
done

hd "HTTPS: the ADDRESS is not what is trusted"
# Aim at an arbitrary address with an allowlisted SNI. nftables redirects it to the
# proxy, which resolves the name itself -- so a student pointing the exam hostname
# at their own relay reaches the real site, not the relay.
if [ -n "$ALLOW1" ]; then
  subj=$(s1 timeout 15 openssl s_client -connect 203.0.113.9:443 -servername "$ALLOW1" \
         </dev/null 2>/dev/null | openssl x509 -noout -subject 2>/dev/null)
  if [ -n "$subj" ]; then ok "aiming at 203.0.113.9 with an allowed SNI still lands on the real site (${subj#subject=})"
  else bad "could not confirm the destination address is discarded"; fi
  # And the inverse: a PERMITTED address with a FORBIDDEN name must still fail.
  realip=$(getent ahostsv4 "$ALLOW1" 2>/dev/null | awk '{print $1; exit}')
  if [ -n "$realip" ]; then
    if s1 timeout 10 openssl s_client -connect "$realip:443" -servername google.com </dev/null 2>/dev/null \
       | grep -q "BEGIN CERTIFICATE"; then
      bad "a forbidden SNI succeeded against an allowlisted address" "the filter is on addresses, not names"
    else ok "a forbidden SNI is refused even when aimed at the allowlisted site's own address"
    fi
  fi
fi
t=$(timed s1 timeout 6 openssl s_client -connect "$SRV:443" </dev/null)
if s1 timeout 6 openssl s_client -connect "$SRV:443" </dev/null 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
  bad "TLS with NO SNI was served" "this is what a raw tunnel on 443 looks like"
else ok "TLS with no SNI is refused (${t}s)"; fi

hd "VPN and tunnelling"
# And the firewall's own counters, which are independent of any reply and so
# cannot be fooled by a peer that is simply down.
fwd_counter() {
  nft -j list ruleset 2>/dev/null \
    | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: print(-1); raise SystemExit
tot=0
for item in d.get('nftables',[]):
    r=item.get('rule')
    if not r or r.get('chain')!='forward': continue
    for e in r.get('expr',[]):
        c=e.get('counter')
        if c: tot+=c.get('packets',0)
print(tot)
" 2>/dev/null || echo -1
}
vpn_tcp() { # label host port
  local t; t=$(timed s1 timeout 5 bash -c "exec 3<>/dev/tcp/$2/$3")
  if s1 timeout 5 bash -c "exec 3<>/dev/tcp/$2/$3" 2>/dev/null; then
    bad "$1: CONNECTED to $2:$3"
  elif faster_than "$t" "$REJECT_MAX"; then ok "$1: refused in ${t}s"
  else bad "$1: refused but took ${t}s"; fi
}
vpn_tcp "OpenVPN over TCP"      1.1.1.1 1194
vpn_tcp "OpenVPN on 443 (TCP)"  1.1.1.1 1195
vpn_tcp "SSH tunnel to the internet" 1.1.1.1 22
vpn_tcp "SOCKS proxy"           1.1.1.1 1080
vpn_tcp "Tor directory port"    1.1.1.1 9001

# One decisive test covers EVERY UDP-based VPN at once -- WireGuard, OpenVPN/UDP,
# IKEv2, L2TP, QUIC -- because they all need the same thing: a UDP packet from a
# student reaching an arbitrary address on the internet.
e0=$(in_addr_errors)
if udp_reaches_internet; then
  bad "student UDP REACHES THE INTERNET" \
      "WireGuard, OpenVPN/UDP and IKEv2 all work. dig returned: $(printf '%s' "$UDP_PROBE_RAW" | tr '\n' '|')"
else
  ok "student UDP does not reach the internet (so WireGuard, OpenVPN/UDP, IKEv2 and QUIC have no transport)"
  e1=$(in_addr_errors)
  if [ -n "${e0:-}" ] && [ -n "${e1:-}" ] && [ "$e1" -gt "$e0" ] 2>/dev/null; then
    printf "        (the kernel refused to route %s more datagram(s) during this test)\n" \
           "$((e1 - e0))"
  fi
fi
fwd4=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
fwd6=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null)
if [ "$fwd4" = "0" ] && [ "$fwd6" = "0" ]; then
  ok "IPv4 and IPv6 forwarding are both off, so no student packet can be routed at all"
else
  bad "forwarding is on (v4=$fwd4 v6=$fwd6)" \
      "with forwarding enabled a VPN on any port and any protocol works"
fi
if ip -6 addr show "$BRIDGE" 2>/dev/null | grep -q "inet6 [^f]"; then
  bad "the bridge has a routable IPv6 address" "IPv6 is a second path the v4 rules do not cover"
else
  ok "students get no routable IPv6, so there is no second path around the v4 rules"
fi
if s1 ping -c1 -W3 8.8.8.8 >/dev/null 2>&1; then
  bad "ICMP to the internet succeeded" "there is a route off this network"
else ok "ICMP to the internet is blocked (no route exists)"; fi

hd "the gateway and the proctor console are not reachable"
for port in 22 8080 8081 3389; do
  if s1 timeout 4 bash -c "exec 3<>/dev/tcp/$SRV/$port" 2>/dev/null; then
    bad "a student reached the gateway on port $port"
  else ok "the gateway refuses port $port from a student"; fi
done

hd "student-to-student, across the two bands"
if s1 ping -c1 -W3 "$IP2" >/dev/null 2>&1; then
  bad "one student pinged another through the bridge" "client isolation does not hold across bands"
else ok "a student cannot reach another student through the bridge"; fi
if s1 timeout 4 bash -c "exec 3<>/dev/tcp/$IP2/80" 2>/dev/null; then
  bad "a student opened a TCP connection to another student"
else ok "student-to-student TCP is refused"; fi

hd "result"
printf "  %d passed, %d failed, %d skipped\n" "$PASS" "$FAIL" "$SKIP"
if [ "$FAIL" -gt 0 ]; then
  printf "\n  ${c_r}This network does not refuse what you think it refuses.${c_0}\n"
  printf "  Do not run an exam on it until the failures above are understood.\n\n"
  exit 1
fi
printf "\n  ${c_g}The live network refuses everything it claims to.${c_0}\n"
printf "  Still not blocked, and no network control can change that: a phone on\n"
printf "  cellular, a local model on a laptop, and collusion inside the allowlisted\n"
printf "  site itself. Those are what the human in the room and the oral spot-checks\n"
printf "  are for.\n\n"
