<p align="center">
  <img src="docs/assets/themis-wordmark.svg" alt="Themis" width="430">
</p>

<p align="center">
  <strong>Exam integrity built on controls that actually hold —<br>
  and honest about the ones that don't.</strong>
</p>

<p align="center">
  <a href="https://at0m-b0mb.github.io/Themis/">Project page</a> ·
  <a href="docs/THREAT_MODEL.md">Threat model</a> ·
  <a href="docs/LINUX_AP.md">Setup guide</a> ·
  <a href="docs/RELEASE-v0.2.0.md">Release notes</a>
</p>

<p align="center">
  <img alt="version" src="https://img.shields.io/badge/version-0.2.0-9A7B28?style=flat-square">
  <img alt="tests" src="https://img.shields.io/badge/tests-193%20passing-2F6B41?style=flat-square">
  <img alt="dependencies" src="https://img.shields.io/badge/dependencies-Python%20stdlib%20only-6B6554?style=flat-square">
  <a href="LICENSE"><img alt="licence" src="https://img.shields.io/badge/licence-MIT-6B6554?style=flat-square"></a>
</p>

---

Named for the goddess of fair judgement. Fairness runs both directions here: a
student is entitled to an exam that isn't rigged, **and** to not be surveilled to
sit it.

```bash
git clone https://github.com/at0m-b0mb/Themis.git && cd Themis
sudo apt install -y hostapd dnsmasq nftables iw rfkill

sudo ./exam            # repair whatever is in the way, then run the exam
```

That one command sets the regulatory domain, takes the radios off
NetworkManager, clears the leftovers of a previous run, starts two radios under
one SSID, and brings up the firewall, the name-validating proxy, the student
portal and the proctor console. Every repair it makes is one that has already
stopped an exam from starting.

---

## Contents

- [The design claim](#the-design-claim) · [How it filters](#filtering-by-name-not-by-address) · [Three modes](#three-modes-three-different-guarantees)
- [Two bands](#two-bands-means-two-adapters) · [What the proctor sees](#what-the-proctor-sees) · [The honest limits](#what-is-honestly-out-of-reach)
- [Commands](#commands) · [Layout](#layout) · [Verifying it](#verifying-it) · [Status](#status) · [Roadmap](#roadmap)

## The design claim

Commercial proctoring puts controls on the student's own machine, which is the
one place they cannot be enforced. A local AI model emits no packets. A phone in
a lap is off-machine entirely. An agent on an untrusted laptop can be killed,
sandboxed, or fed a fake answer. So the industry ships webcam gaze detection
with documented racial bias, flags disabled and neurodivergent students, and buys
a signal that doesn't survive contact with a determined cheater.

> **Themis moves every control onto hardware the institution owns, and states its
> limits on the face of every exam it delivers.**

**Design invariant: no Themis component inspects a student's device.** No process
enumeration, no filesystem scanning, no camera, no microphone, no screen capture,
no keystroke biometrics. Not disabled by default — *absent*. A capability that
exists will be switched on by the first adopter who wants it.

## Filtering by name, not by address

An address allowlist is not a control. A university's Canvas is four rotating CDN
addresses shared with every other tenant on that CDN — so pinning them goes stale
**and** lets a student reach those tenants by changing the TLS SNI. Filtering in
two layers that disagree (DNS permits *names*, nftables permits *addresses*) is
worse than either alone.

Themis reads the SNI from the handshake, checks the **name**, then resolves that
name **itself**. The client never chooses the destination address:

| A student tries | What happens |
|---|---|
| `canvas.example.edu` | allowed, spliced to whatever that name really resolves to |
| `chatgpt.com` | refused in milliseconds — a TCP reset, not a hang |
| allowed SNI aimed at *their own relay* | reaches the real site; their address is discarded |
| forbidden SNI aimed at *the exam site's own IP* | refused; the address was never what was trusted |
| TLS with no SNI at all | refused — this is what a raw tunnel on 443 looks like |

**It does not terminate TLS.** No certificate, no decryption; the sockets are
spliced byte for byte and the browser validates the real server. Nothing here can
read a student's traffic, and no future work will change that.

**And nothing is forwarded.** `ip_forward` stays `0` and the forward chain is
empty, so the proxy is the only process that egresses. That is why a self-hosted
VPN on an arbitrary address and port has nothing to reach — WireGuard, OpenVPN,
IKEv2 or something homemade on 443 alike.

## Three modes, three different guarantees

| Mode | What it means |
|---|---|
| **`airgap`** | No uplink at all. Online lookup, cloud AI, VPN and Tor are not filtered — they are *unreachable*. The exam is served locally. The only mode that **proves** rather than claims. |
| **`allowlist`** | Only the named sites work; everything else is refused instantly, **by name**, so it survives the CDN rotating. |
| **`blocklist`** | The web works except the named sites. Much weaker — a site you did not think of is a site that works, including every AI front-end launched between now and the exam. |

Switch modes and edit the lists from the operator panel. **Saving reloads the
proxy in place** — nobody is disconnected, so a site the exam genuinely needs can
be added mid-exam.

## Two bands means two adapters

One radio has one transceiver and tunes to one frequency, so 2.4 GHz and 5 GHz at
once is *two radios* — which is all a dual-band router is. With two adapters
Themis bridges them: **one SSID, one passphrase, one subnet, one portal**, and the
student's device picks the band.

```bash
sudo netguard/linux/bin/themis-ap autoconfigure
```

Finds every adapter, asks each **phy** which channels it may legally beacon on,
assigns one to 2.4 GHz and one to 5 GHz, fixes the regulatory domain and takes
the radios off NetworkManager. With one adapter it picks 2.4 GHz, because every
device ever built can see it and a student whose laptop cannot find the network
cannot sit the exam.

> Bridging two radios would quietly undo client isolation — `ap_isolate` only
> separates students on the *same* radio — so a `bridge`-family drop closes the
> path between bands.

## What the proctor sees

```bash
python3 tools/demo_journal.py /tmp/demo.jsonl
python3 -m themis.server --policy netguard/linux/policy.json \
        --journal /tmp/demo.jsonl --review --console-port 8899
```

Open <http://127.0.0.1:8899/> for a 19-student, 90-minute exam, read-only —
nothing is written, so it is also exactly how you reopen a real exam's record
afterwards.

Each tile shows the student, whether their device is on the network, any gaps
with timestamp **bounds** rather than false precision, and **what the network was
asked for**: the site currently being reached, how many requests were allowed and
refused, and the recent hostnames with counts.

> **"Asked for", not "is doing"** — and the console says so on screen. The proxy
> splices TLS without terminating it, so a **hostname is the most that can ever be
> known**. The page opened on an allowed site, what was typed into it and what came
> back are invisible. A tile reading `canvas.example.edu` means the device
> requested Canvas, not that the student is working; a refusal does not mean anyone
> cheated, because a phone reaches for iCloud on its own. **These are questions
> worth asking, never answers.**

## What is honestly out of reach

| Route | Verdict | Why |
|---|---|---|
| Online answer lookup | **blocked** | Refused by name, so it does not go stale when the CDN rotates |
| Cloud AI | **blocked** | Their names are not allowlisted; no address to pin and none to miss |
| Self-hosted VPN, any port | **blocked** | No student packet is ever forwarded; the proxy connects to a name it resolved itself |
| VPN over TLS with a forged SNI | **blocked** | The destination address the client chose is discarded |
| DNS tunnelling | **impossible** | The resolver has no upstream, so there is no exit |
| **Local AI on their laptop** | **not blocked** | Runs offline, emits no traffic. Invisible to any network control |
| **Phone on cellular** | **not blocked** | Never touches this network. Jamming it violates §333 of the Communications Act — the FCC fined Marriott $600k and Hilton/MC Dean $750k |
| **Collusion inside an allowed site** | **not blocked** | Carried inside a connection you deliberately permitted |
| Leaving for another network | *detected* | The radio reports the disassociation. Preventing it would be illegal |

Those last three are handled by a human in the room and by **oral spot-checks** —
five minutes per student, which at a class of 28 is ~2.5 hours and zero
engineering. A student who cannot explain their own answer is caught by the only
control that scales against a tool able to write any answer.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Commands

```bash
sudo ./exam                  # repair what is in the way, then run the exam
sudo ./exam doctor           # find and fix the problems; start nothing
sudo ./exam doctor --dry-run # say what it would change, change nothing
sudo ./exam status           # what is running
sudo ./exam stop             # stop, and hand the host back
sudo ./exam panel            # repair, then open the operator panel
```

The panel lives on `127.0.0.1:8080`, loopback only. It detects adapters, picks
the mode, edits the lists, and shows **Refused so far** — every name a student's
device asked for and did not get, with an *Allow this* button. That is how an
allowlist gets built from real traffic instead of guesswork.

<details>
<summary>Running the pieces by hand</summary>

```bash
sudo netguard/linux/bin/themis-ap autoconfigure   # detect adapters, assign bands
sudo netguard/linux/bin/themis-ap preflight       # is this host fit to host an exam?
sudo netguard/linux/bin/themis-ap up              # radio, DHCP, DNS, firewall, proxy
sudo netguard/linux/bin/themis-ap status          # what it can honestly claim
sudo netguard/linux/bin/themis-ap down            # restore the previous network state

sudo bash tools/exam-up.sh                        # the same, plus the portal
sudo bash tools/exam-down.sh
```

`./exam` shells out to exactly these, so the app and the terminal can never
disagree about what is running.
</details>

## Layout

```
exam                      one command: repair the host, then run the exam
themis/
  server.py               the captive portal and the proctor console
  proxy.py                the name-validating proxy (reads SNI, resolves it itself)
  operator.py             the panel on 127.0.0.1:8080
  journal.py              append-only, hash-chained exam record
  roster.py               registrations, presence, gaps, anomalies
  activity.py             what the network was asked for, per student
  leases.py  state.py  views.py
netguard/linux/
  policy.json             the whole policy, one readable file
  bin/themis-ap           the AP: preflight, autoconfigure, render, up/down
  bin/themis-sta-hook     association events, straight into the journal
  templates/              hostapd + dnsmasq + nftables sources, rendered not edited
netguard/
  bin/themis-net          the macOS/pf gateway (the original, kept for that host)
tools/
  exam-up.sh exam-down.sh starting and stopping, detached from any terminal
  verify_blocking.sh      what the LIVE network refuses, right now
  integration_test.sh     end-to-end over a veth pair, no radio needed
  demo_journal.py         a fake exam, to see the console without hardware
  pre-commit              refuses to commit a live exam passphrase
docs/                     threat model, setup, identity, and the project page
```

## Verifying it

```bash
python3 -m unittest discover -s tests   # 193 unit tests, no hardware needed
sudo bash tools/integration_test.sh     # end to end over a veth pair
sudo bash tools/verify_blocking.sh      # against the LIVE network, right now
```

`hostapd` needs real hardware, but **association is the only part that does** — so
a veth pair stands in for the radio link and a network namespace plays a
student's laptop, over the real generated firewall, the real dnsmasq and the real
portal.

`verify_blocking.sh` is different and is the one to run before an exam: it
attaches a test student to the **running** bridge and checks what that network
actually refuses — including that a forbidden SNI is rejected even when aimed at
the exam site's own address, and that student UDP cannot reach the internet (so
WireGuard, OpenVPN/UDP and IKEv2 have no transport). Every refusal is **timed**,
because "blocked" and "blocked instantly" are different products: a dropped packet
leaves a student watching a spinner and concluding the network is broken.

## Status

**v0.2.0 — proven end to end on real hardware, not yet proven at class scale.**
Both halves of that matter.

**Run:** two MT7921U adapters bridged under one SSID on 2.4 and 5 GHz, with real
devices on both bands; a complete university SSO login through Shibboleth, Entra
and a FIDO passkey bridge; Canvas rendering and its file service reachable; a
forbidden SNI refused *even when aimed at Canvas's own IP address*; Tailscale's
control plane and DERP relays, Perplexity, ChatGPT, Claude and Grammarly all
refused on genuine device traffic; and a WireGuard tunnel reporting "connected"
while moving zero bytes.

**Not run:** 28 laptops at once, a real submission at the moment a student hits
submit, and coverage from the back of the actual room. None of those can be
inferred from a bench test — do the dress rehearsal in
[docs/NETWORK_SETUP.md](docs/NETWORK_SETUP.md) before it counts for marks.

## Roadmap

- [x] Exam network: air-gapped gateway, three modes, assurance labelling
- [x] Dual-band: two radios bridged under one SSID, isolation held across bands
- [x] Name-validating proxy: allowlist/blocklist by SNI, no TLS interception
- [x] Operator panel: adapter detection, mode, list editing, live refusals
- [x] Proctor console: live tiles, radio-reported presence, per-student activity
- [x] Live verification against the running network
- [x] One-command repair-and-start
- [ ] Per-student parameterised items → QTI 1.2 export (imports into Canvas,
      Moodle and Blackboard with no admin approval — the lowest-friction path to
      adoption by other universities)
- [ ] Per-student flags for practical/CTF questions
- [ ] Post-hoc collusion statistics over exported results
- [ ] LTI 1.3 tool for grade passback, once the above is proven in a real exam

## Licence

MIT — see [LICENSE](LICENSE).
