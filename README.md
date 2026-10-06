<p align="center">
  <img src="images/themis-wordmark.svg" alt="Themis" width="420">
</p>

<p align="center">
  <em>Exam integrity for university courses, built on controls that actually hold —<br>
  and honest about the ones that don't.</em>
</p>

<p align="center">
  <a href="https://github.com/at0m-b0mb/Themis/releases"><img alt="version" src="https://img.shields.io/badge/version-0.2.0-9A7B28?style=flat-square"></a>
  <img alt="tests" src="https://img.shields.io/badge/tests-193%20passing-2F6B41?style=flat-square">
  <img alt="dependencies" src="https://img.shields.io/badge/dependencies-stdlib%20only-6B6554?style=flat-square">
  <a href="LICENSE"><img alt="licence" src="https://img.shields.io/badge/licence-MIT-6B6554?style=flat-square"></a>
</p>

---

Named for the goddess of fair judgement. Fairness runs both directions here: a
student is entitled to an exam that isn't rigged, and to not be surveilled to
sit it.

## The design claim

Commercial proctoring puts controls on the student's own machine, which is the
one place they cannot be enforced. A local AI model emits no packets. A phone in
a lap is off-machine entirely. An agent on an untrusted laptop can be killed,
sandboxed, or fed a fake answer. So the industry ships webcam gaze detection
with documented racial bias, flags disabled and neurodivergent students, and
buys a signal that doesn't survive contact with a determined cheater.

Themis moves every control to hardware the institution owns, and states its
limits on the face of every exam it delivers.

**Design invariant: no Themis component inspects a student's device.** No
process enumeration, no filesystem scanning, no camera, no microphone, no screen
capture, no keystroke biometrics. Not disabled by default — absent. A capability
that exists will be switched on by the first adopter who wants it.

## What works today

`netguard/` — the exam network. A travel router demoted to a dumb access point,
with your Mac as a software-defined gateway: `dnsmasq` for DHCP and sinkhole
DNS, `pf` for default-deny, and the exam served locally over an air gap.

```bash
brew install dnsmasq
sudo sysctl -w net.inet.ip.forwarding=0
sudo netguard/bin/themis-net preflight    # is this machine fit to host an exam?
sudo netguard/bin/themis-net render       # write the configs, change nothing
sudo netguard/bin/themis-net up
sudo netguard/bin/themis-net status       # what this setup can honestly claim
sudo netguard/bin/themis-net down         # restore the previous network state
```

Two profiles:

- **`airgap`** — no uplink at all. Online lookup and cloud AI are not filtered,
  they are *unreachable*. Requires the exam to be served locally. Use this.
- **`allowlist`** — a named set of domains resolves upstream. Needed if the quiz
  lives in cloud Canvas. Weaker, and `status` says so: pf resolves names at load
  time, and a permitted domain can relay others.


## Install on the exam host (Kali or any Linux)

```bash
git clone https://github.com/at0m-b0mb/Themis.git
cd Themis
sudo apt update && sudo apt install -y hostapd dnsmasq nftables iw rfkill
```

No Python packages to install — everything is stdlib, on purpose.

```bash
python3 -m unittest discover -s tests          # 180 unit tests, no hardware needed
sudo bash tools/integration_test.sh            # 24 end-to-end checks, no hardware needed
sudo bash tools/verify_blocking.sh             # what the LIVE network refuses, right now
```

The integration suite is the one worth running before you trust this. `hostapd`
needs real hardware, but **association is the only part that does** — so a veth pair
stands in for the radio link and a network namespace plays a student's laptop, over
the real generated firewall, the real dnsmasq and the real portal. It checks that a
student gets an address, that every name resolves to the sign-in page, that HTTP to
a raw IP is redirected there too, that each OS captive-portal probe returns 302,
that everything else is refused in milliseconds rather than hanging, that
registration resolves the MAC from the network rather than trusting the client, that
the proctor console is unreachable from the student side, and that the record
verifies afterwards.

## One command, or one screen

```bash
sudo python3 -m themis.operator      # a panel on 127.0.0.1:8080, loopback only
```

Detects the adapters, assigns the bands, picks the mode, edits the lists, starts
and stops the exam. It shells out to the same `themis-ap` you would run by hand,
so the panel and the terminal cannot disagree about what is running.

The panel's most useful screen is **Refused so far**: every name a student's
device asked for and did not get, most frequent first, with a button to allow it.
A site the exam genuinely needs announces itself there the first time someone
hits it, so the list is built from real traffic rather than guessed at in
advance. Mapping a real JHU Canvas login — Canvas, then a Shibboleth IdP, then
Entra, then a FIDO bridge on a *different* Microsoft hostname — took four rounds
of exactly that.

From a terminal instead:

```bash
sudo bash tools/exam-up.sh           # radios, DHCP, DNS, firewall, proxy, portal
sudo bash tools/verify_blocking.sh   # prove it refuses what you think it refuses
sudo bash tools/exam-down.sh         # hand the host back; the record is untouched
```

## Three modes, which are three different guarantees

| | |
|---|---|
| **`airgap`** | No uplink. Online lookup, cloud AI, VPN and Tor are not filtered, they are *unreachable*. The exam is served locally. The only mode that proves rather than claims. |
| **`allowlist`** | Only the named sites work. Everything else is refused in milliseconds. |
| **`blocklist`** | The web works except the named sites. Much weaker — a site you did not think of is a site that works — but it is what an open-book paper needs. |

The two filtered modes do not use an address allowlist, because that is not a
control. `canvas.jhu.edu` is four rotating Cloudflare addresses shared with every
other tenant, so pinning addresses goes stale *and* lets a student reach those
tenants by changing the TLS SNI. Instead `themis/proxy.py` reads the SNI from the
ClientHello, checks the **name**, and then resolves that name **itself** — the
client never chooses the destination address. Aim `canvas.jhu.edu` at your own
relay and you reach Canvas, not the relay.

It does not terminate TLS. No certificate, no decryption, nothing in the path can
read a student's traffic: after the ClientHello is checked the sockets are
spliced byte for byte and the browser validates the real server's certificate.

**And nothing is forwarded.** `ip_forward` stays `0` and the forward chain is
empty, so no student packet is ever routed anywhere. The proxy is the only
process that egresses. That is why a self-hosted VPN on an arbitrary address and
port — WireGuard, OpenVPN, IKEv2, or something homemade on 443 — has nothing to
reach. Verified against a real device: Tailscale's control plane and DERP relays
are refused, and a WireGuard tunnel reports "connected" while moving zero bytes.

## Two bands means two adapters

One radio has one transceiver and tunes to one frequency, so 2.4 GHz and 5 GHz at
once is two radios — which is all a dual-band router is. With two, Themis bridges
them: one SSID, one passphrase, one subnet, one portal, and the student's device
picks the band.

```bash
sudo netguard/linux/bin/themis-ap autoconfigure
```

Finds every adapter, asks each **phy** which channels it may legally beacon on,
assigns one to 2.4 GHz and one to 5 GHz, fixes the regulatory domain and takes
the radios off NetworkManager. With one adapter it picks 2.4 GHz, because every
device ever built can see it and a student whose laptop cannot find the network
cannot sit the exam.

Bridging two radios would quietly undo client isolation — `ap_isolate` only
separates two students on the *same* radio — so a `bridge`-family drop closes
the path between bands.

Then set `ap_interface` and a fresh `passphrase` in `netguard/linux/policy.json`
and run preflight. **Read what it says before doing anything else** — it checks
the three traps that will otherwise bite you during an exam:

```bash
sudo netguard/linux/bin/themis-ap preflight
```

Full walkthrough, including the USB passthrough and the Bluetooth blacklist:
[docs/LINUX_AP.md](docs/LINUX_AP.md).

### See the console without any hardware

```bash
python3 tools/demo_journal.py /tmp/demo.jsonl
python3 -m themis.server --policy netguard/linux/policy.json \
        --journal /tmp/demo.jsonl --review --console-port 8899
```

Open <http://127.0.0.1:8899/>. That generates a 19-student, 90-minute exam and
opens it read-only — nothing is written, so it is also exactly how you reopen a
real exam's record afterwards.

Each tile shows the student, whether their device is on the network, any gaps
with timestamp *bounds* rather than false precision, and **what the network was
asked for**: the site currently being reached, how many requests were allowed and
refused, and the recent hostnames with counts. A student working shows
`canvas.jhu.edu` and some background chatter from their phone; a student reaching
for an AI tool shows dozens of refusals to one name, which is visible at a glance
across 28 tiles.

That phrasing is exact and the console uses it on screen. The proxy splices TLS
without terminating it, so a **hostname is the most that can ever be known** —
the page opened on an allowed site, what was typed into it and what came back are
invisible, and no amount of future work here will change that. A tile reading
`canvas.jhu.edu` means the device requested Canvas, not that the student is
working, and a refusal does not mean anyone tried to cheat: a phone reaches for
iCloud on its own. These are questions worth asking, never answers.

## What is honestly out of reach

| | |
|---|---|
| Local AI model on a student laptop | **Cannot be blocked.** Runs offline, emits nothing. |
| Phone on cellular | **Cannot be blocked.** Never touches your network. |
| Switching to another WiFi | **Detected, not prevented.** Jamming it violates §333 of the Communications Act — the FCC fined Marriott $600k and Hilton/MC Dean $750k for exactly that. |
| Collusion inside a site you allowed | **Cannot be blocked.** Canvas's own Inbox and discussions are a student-to-student channel carried inside a connection you deliberately permitted. |

These are handled by a human in the room and by **oral spot-checks** — five
minutes per student, which at a class of 28 is ~2.5 hours and zero engineering.
A student who cannot explain their own answer is caught by the only control that
scales against a tool able to write any answer.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Layout

```
netguard/
  policy.json           the whole policy, one readable file
  bin/themis-net        gateway CLI (stdlib only, no dependencies)
  templates/            pf + dnsmasq sources, rendered not hand-edited
docs/
  THREAT_MODEL.md       what is provable, what is refused, and why
  NETWORK_SETUP.md      TL-WR1502X + macOS recipe, incl. the 28-client warning
```

## Roadmap

- [x] Exam network: air-gapped gateway, two profiles, assurance labelling
- [x] Dual-band: two radios bridged under one SSID, isolation held across bands
- [x] Name-validating proxy: allowlist/blocklist by SNI, no TLS interception
- [x] Operator panel: adapter detection, mode, list editing, live refusals
- [x] Live verification: `tools/verify_blocking.sh` against the running network
- [x] Exam server + proctor console: live tiles, radio-reported presence,
      per-student view of what the network was asked for
- [ ] Per-student parameterised items → QTI 1.2 export (imports into Canvas,
      Moodle, Blackboard with no admin approval — the lowest-friction path to
      adoption by other universities)
- [ ] Per-student flags for practical/CTF questions
- [ ] Post-hoc collusion statistics over exported results
- [ ] LTI 1.3 tool for grade passback, once the above is proven in a real exam

## Status

**v0.2.0.** Proven end to end against real hardware, and not yet proven at class
scale. Both of those matter, so be specific about which is which.

What has actually been run: two MT7921U adapters bridged under one SSID on 2.4
and 5 GHz; real devices associating on both bands; a complete JHU Canvas login
through Shibboleth, Entra and a FIDO passkey bridge; Canvas rendering and its
file service reachable; and a live blocking check in which a forbidden SNI was
refused *even when aimed at Canvas's own IP address*, while an allowed SNI aimed
at an arbitrary address still landed on real Canvas. Tailscale's control plane
and DERP relays, Perplexity, ChatGPT, Claude and Grammarly were all refused on
genuine device traffic, and a WireGuard tunnel reported "connected" while moving
zero bytes.

What has **not** been run: 28 laptops at once, a real submission at the moment
students hit submit, and coverage from the back of the actual room. Those are the
three things the dress rehearsal in `docs/NETWORK_SETUP.md` exists to find, and
none of them can be inferred from a bench test.

Before it counts for marks:

```bash
sudo bash tools/verify_blocking.sh    # what the LIVE network refuses, right now
```
