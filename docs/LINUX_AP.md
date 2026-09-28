# Exam AP on Kali (or any Linux) with the AWUS036AXML

This is the primary implementation. It is also the portable one: `hostapd` +
`dnsmasq` + `nftables` runs on any Linux host, which is what makes Themis
adoptable somewhere that isn't your laptop. The macOS path in
[NETWORK_SETUP.md](NETWORK_SETUP.md) is kept as a tested fallback.

```
 19 student laptops
        │  WiFi 6, 5 GHz, ch 36, WPA2 + client isolation
        ▼
 ALFA AWUS036AXML  (mt7921u, AP mode)
        │  USB passthrough
        ▼
 Kali VM  ·  hostapd   the radio + real association/disassociation events
           ·  dnsmasq   DHCP + sinkhole DNS (no upstream at all)
           ·  nftables  default-deny, nothing forwarded
           ·  Themis    portal, registration, console, journal
        │
        ▼
    no uplink   ← this is why VPN and Tor are impossible, not merely blocked
```

## Use the AWUS036AXML, not the AWUS1900

| Adapter | Chipset | Verdict |
|---|---|---|
| **AWUS036AXML** | MT7921AU | **Use this.** `mt7921u` is in the mainline kernel — USB since 5.18, **AP mode since 5.19**, part of mt76. Nothing to compile. |
| AWUS1900 | RTL8814AU | Avoid. Needs an out-of-tree DKMS driver that rebuilds on every kernel update and breaks when it doesn't. Not something to have in the path of a graded exam. |

## Three traps, all enforced by `themis-ap preflight`

1. **Bluetooth crashes the Wi-Fi.** On kernel 6.6+ the BT subsystem causes sporadic
   `mt7921u` crashes, and the AWUS036AXML has BT 5.2 on the same chip. Preflight
   *fails* if `btusb` or `btmtk` is loaded.
2. **No DFS channels in AP mode.** The radio simply will not start. Stay on
   36–48 or 149–165 (US). Preflight rejects anything else.
3. **NetworkManager will tear down the AP.** It grabs the interface and fights
   hostapd; this is the single most common reason a hand-rolled AP "randomly"
   stops working. Preflight fails until the interface is unmanaged.

## Setup

### 1. Pass the adapter through to the VM

UTM, VMware Fusion and Parallels all support USB passthrough on Apple Silicon.
Attach the AWUS036AXML to the Kali VM, then confirm inside the VM:

```bash
lsusb | grep -i mediatek
ip link                                    # note the interface name, e.g. wlan1
cat /sys/class/net/wlan1/device/driver/module/drivers/*/module 2>/dev/null
basename $(readlink -f /sys/class/net/wlan1/device/driver)    # expect: mt7921u
```

### 2. Close the traps

```bash
sudo apt update && sudo apt install -y hostapd dnsmasq nftables iw rfkill

sudo cp netguard/linux/templates/blacklist-themis-bt.conf /etc/modprobe.d/
sudo systemctl disable --now bluetooth
sudo modprobe -r btusb btmtk        # or reboot

sudo nmcli device set wlan1 managed no
sudo rfkill unblock all

# hostapd and dnsmasq must not also be running as system services -- themis-ap
# starts its own with its own configs.
sudo systemctl disable --now hostapd dnsmasq

sudo sysctl -w net.ipv4.ip_forward=0          # airgap: no route out, for anyone
```

Confirm the radio will actually do AP mode:

```bash
iw list | grep -A 10 "Supported interface modes"      # expect "* AP"
```

### 3. Configure and run

Set the interface and mint a fresh passphrase. Run it with no argument and it
lists the radios it can see, marking the one on the in-tree driver:

```bash
sudo netguard/linux/bin/themis-ap configure              # lists candidates
sudo netguard/linux/bin/themis-ap configure wlan0        # sets it, rotates the passphrase
```

The passphrase is regenerated on every run, deliberately — last term's should not
open this term's exam network. Write the printed one on the board. Preflight
refuses to start while it is still the placeholder.

```bash
sudo netguard/linux/bin/themis-ap preflight    # do this first, and read it
sudo netguard/linux/bin/themis-ap render       # inspect the configs, change nothing
sudo netguard/linux/bin/themis-ap up
sudo netguard/linux/bin/themis-ap status       # what it can honestly claim
sudo netguard/linux/bin/themis-ap down
```

`up` refuses to touch anything if preflight fails, and refuses to load an nftables
ruleset that `nft -c` rejects.

### Note: the ruleset is exclusive

The generated `nftables.conf` begins with `flush ruleset`, so it replaces every
nftables rule on the host. That is correct for a VM dedicated to being an exam AP
and wrong for a machine doing anything else. Do not run this on a host you care
about the firewall of.

## What you get that the travel router could not

- **Disconnects are facts, not inferences.** hostapd reports association and
  disassociation the instant they happen, with the station MAC and a reason code.
  `themis-sta-hook` writes each one into the hash-chained journal. Polling DHCP
  leases could only notice, seconds later, that a device had stopped answering.
- **Client isolation at the radio** (`ap_isolate=1`), with the nftables `forward`
  chain dropping everything as a second layer.
- **WPA2-Enterprise is reachable.** Flip `enterprise.enabled` in the policy and
  hostapd's built-in EAP server gives every student their own credential, so
  identity is bound to a MAC cryptographically at association, before any web
  request happens. See [IDENTITY.md](IDENTITY.md). Not for the first run.

## Still true, and still worth saying out loud

A local LLM on a student's laptop emits no packets, and a phone on cellular never
touches this network. No amount of control over the radio changes either. Those
are handled by the two people in the room and by oral spot-checks.
