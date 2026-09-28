# Exam network setup — TL-WR1502X + macOS gateway

## Why this shape

The TL-WR1502X is Realtek-based and **will never run OpenWrt**, so it cannot
hold a real egress policy. Stock firmware gives you parental controls, not a
firewall. So the router is demoted to a dumb radio and your Mac becomes the
gateway, where the policy lives in files you can read and diff.

```
 28 student laptops
        │  WiFi (WPA2/3, AP isolation ON)
        ▼
 TL-WR1502X  ── Access Point mode, its own DHCP OFF ──┐
                                                       │ Ethernet
                                                       ▼
 Your Mac  ·  USB-C ethernet adapter = en7
            ·  10.83.0.1
            ·  dnsmasq   → DHCP + sinkhole DNS
            ·  pf        → default-deny, exam server only
            ·  Themis    → the exam itself, served locally
            ·  WiFi OFF, ip forwarding = 0   ← this is the air gap
```

No uplink means there is nothing to filter. "Blocked" is not a rule that could
be misconfigured; it is the absence of a route.

## Hardware you need

- The TL-WR1502X.
- A USB-C ethernet adapter — you already have one: the ASIX **AX88179B** that
  macOS enumerates as `en7`. (`en4`–`en6` are virtual adapters from your VMware
  work, not physical ports.)
- A short ethernet cable.

### Why not the Mac's own Wi-Fi, and why not the Alfa adapters

Both were considered and both are ruled out on facts, not preference:

| Option | Verdict |
|---|---|
| Mac's built-in Wi-Fi as the AP (Internet Sharing) | **No.** macOS Internet Sharing caps at ~10 clients; 19 students will not fit. It also runs Apple's own `bootpd` for DHCP and its own NAT, which collide with dnsmasq and the pf ruleset here. |
| Alfa AWUS1900 (RTL8814AU) | **No.** Realtek's macOS kexts are x86_64-only and cannot load on an ARM64 kernel. No arm64 kext or DriverKit driver exists. |
| Alfa AWUS036AXML (MT7921AU) | **No**, for the same reason, plus: macOS has no `hostapd` and offers no AP mode to third-party adapters at all. |
| **TL-WR1502X as a dumb AP** | **Yes.** Purpose-built radio, within capacity at 19, and it holds no policy — which is the point. |

The Alfa adapters are excellent hardware; they are simply unusable as an access
point on an Apple Silicon Mac. They would need a Linux host — see
[IDENTITY.md](IDENTITY.md) for the one design where that is worth doing.

## 1. Router configuration

Mode selector → **Access Point (AP)**. Not Router, not Hotspot, not Repeater.
AP mode takes a wired uplink and bridges it to WiFi, which is exactly what we
want: the Mac becomes the brain.

Then, in the web UI:

| Setting | Value | Why |
|---|---|---|
| Mode | Access Point | Bridges wired ↔ wireless; no NAT of its own |
| **DHCP server** | **OFF** | The Mac serves DHCP. Two servers racing = chaos |
| SSID | `EXAM-ONLY` | Unambiguous. Do not hide it — students must find it |
| Security | WPA2/WPA3-PSK | **Rotate the password every exam** and write it on the board |
| **AP / client isolation** | **ON** | Stops student↔student directly in the radio |
| Guest network | OFF | A second unfiltered path |
| WPS | OFF | Push-button association bypasses your password |
| Band | Use both 2.4 + 5 GHz | 28 clients on one band will hurt |

Verify DHCP is really off: join the SSID from a phone before starting the Mac
side. If you get an IP address, the router is still serving DHCP.

## 2. Mac configuration

```bash
brew install dnsmasq
```

Find the adapter and put it in `policy.json` as `exam_interface`:

```bash
ifconfig -l                      # plug the adapter in, run again, spot the new name
```

Confirm the air gap, then check the machine is fit:

```bash
sudo sysctl -w net.inet.ip.forwarding=0
sudo netguard/bin/themis-net preflight
```

Preflight refuses to continue if forwarding is on while the profile is
`airgap` — with forwarding on, students could route out through the Mac and the
guarantee is a fiction. Turn the Mac's WiFi off too; it is the one machine whose
uplink could leak.

```bash
sudo netguard/bin/themis-net render     # inspect the configs, change nothing
sudo netguard/bin/themis-net up         # start it
sudo netguard/bin/themis-net status     # what it can honestly claim
sudo netguard/bin/themis-net down       # restore the previous network state
```

`down` restores `/etc/pf.conf` and disables pf if it was off beforehand, so the
Mac goes back to how you found it.

## 3. Dry run with the real class size — do not skip this

**19 students is within a TL-WR1502X's comfortable range** (an AX1500 pocket router
is usually fine to roughly 20 associations), so this is no longer the knife-edge it
would have been at 28. It is still the single most likely thing to go wrong on the
day, because association failures during a graded exam are an availability incident
affecting real students.

Run a dress rehearsal with all 19 laptops associating at once, on a day that does
not matter. Watch for association failures and DHCP timeouts, not just throughput.

Have a paper fallback for every exam. A network problem must never become a grading
dispute.

## 4. What students should be told, before the day

Say all of it plainly — this is a privacy course, and the setup is defensible
precisely because it hides nothing:

- The exam runs on a local network with no internet access.
- DNS queries and DHCP leases on that network are logged for the exam duration.
- The exam page sends a heartbeat; if your device leaves the network, that gap
  is recorded and a proctor may ask you about it.
- **Nothing is installed on your laptop. Nothing inspects your device. No
  camera, no microphone, no screen capture.**
- Logs are deleted after grades are final. (Pick the date. Honour it.)
