# v0.2.0 — dual-band, filtering by name, and a console that says what it knows

Proven end to end against real hardware and a real JHU Canvas login. Not yet
proven at class scale. Both halves of that sentence matter.

## What is new

**Two bands, one network.** One radio has one transceiver and tunes to one
frequency, so 2.4 GHz and 5 GHz at once is two radios — which is all a dual-band
router is. With two adapters Themis bridges them: one SSID, one passphrase, one
subnet, one portal, and the student's device picks the band. `themis-ap
autoconfigure` finds every adapter, asks each **phy** which channels it may
legally beacon on, and assigns the bands.

**Egress filtered by NAME, not by address.** The old `allowlist` profile filtered
in two layers that disagree with each other: dnsmasq permits names, nftables
permits addresses. For a CDN-hosted exam site that is both fragile and porous —
`canvas.jhu.edu` is four rotating Cloudflare addresses shared with every other
tenant, so pinning them goes stale **and** lets a student reach those tenants by
changing the TLS SNI. `themis/proxy.py` reads the SNI, checks the name, then
**resolves that name itself**, so the client never chooses the destination
address. Point `canvas.jhu.edu` at your own relay and you reach Canvas.

It does not terminate TLS. No certificate, no decryption; the sockets are spliced
byte for byte and the browser validates the real server.

**Nothing is forwarded.** `ip_forward` stays `0` and the forward chain is empty,
so the proxy is the only process that egresses — which is why a self-hosted VPN
on an arbitrary address and port has nothing to reach.

**Three modes**, selectable from the operator panel: air-gapped, allowlist,
blocklist. Lists are editable in the panel and apply within ~2 seconds without
restarting anything or disconnecting anyone.

**A proctor console that shows what the network was asked for**, per student: the
site currently being reached, counts of allowed and refused requests, and the
recent hostnames. A student working shows `canvas.jhu.edu`; a student reaching
for an AI tool shows dozens of refusals to one name.

**An operator panel** with adapter detection, mode selection, list editing, a
live status bar, and a **Refused so far** table with an *Allow this* button —
which is how an allowlist gets built from real traffic instead of guesswork.

## Verified on hardware, not inferred

- Two MT7921U adapters bridged under one SSID, devices associating on both bands
- A complete JHU Canvas login: Shibboleth → Entra → a FIDO passkey bridge → Canvas
- A forbidden SNI refused **even when aimed at Canvas's own IP address**
- An allowed SNI aimed at an arbitrary address still landing on real Canvas
- Tailscale's control plane and DERP relays, Perplexity, ChatGPT, Claude and
  Grammarly all refused on genuine device traffic
- A WireGuard tunnel reporting "connected" while moving zero bytes

## Bugs fixed

A 138-agent adversarial audit confirmed 18 defects. Eleven are fixed here. The
ones that would have been felt during a sitting:

| | |
|---|---|
| **Start the exam archived the LIVE journal** | with no server-side guard, and the button stayed enabled for the whole exam because `ap_running()` only looked for `hostapd.pid` while a dual-radio exam writes `hostapd-<iface>.pid`. One click renamed the record out from under the running portal, which opened a fresh chain at seq 0 — every registration gone, and `verify()` reporting the new chain as perfectly intact. |
| **Presence polled one radio** | so every 2.4 GHz student read as absent for the whole exam — recorded as `source="hostapd"`, i.e. authoritative rather than degraded. |
| **ARP filtered on `wlan0`** | while the exam address lives on the bridge, so no registration could ever be corroborated and the anomalies panel filled with one card per student. |
| **`/report.txt` was forgeable** | a student's name containing a newline reads as another student's entry, and the hash chain verifies as intact over it. Flattened at the renderer, because events already written cannot be edited. |
| **Presence sampling died silently** | one transient journal write error ended sampling for the rest of the exam while the console said "live". |
| **`max_num_sta` was 25** | against a documented class of 28. The 26th laptop gets a generic "cannot connect", indistinguishable from a no-show. |
| **Regulatory domain unchecked** | preflight checked DFS but not the regdomain, which is `00` on a fresh boot — under which no 5 GHz AP channel is legal. hostapd failed at `up` with a bare nl80211 error. |
| **`ht_capab` hardcoded `[HT40+]`** | wrong on channels 40/48/153/161, on 165, and on all of 2.4 GHz. |
| **The journal was split in two** | `themis-ap` wrote to `/run/themis` while the station hook wrote to `/var/lib/themis`. One hash chain, two files — and `/run` is tmpfs, so half the record died on reboot. |
| **A second `up`** | passed both hostapd health checks on the previous run's artifacts and reported success while the new hostapd was already dead. |
| **No read timeout** | on the student listener, and the console shares that process. |

## Documentation that was not true

- `THREAT_MODEL.md` and `NETWORK_SETUP.md` described a **heartbeat sent by the
  exam page**. It has never existed. It appeared in the disclosure students read
  before signing in — the worst possible place, since the entire argument of this
  project is that controls belong on institution hardware and not on the
  student's machine.
- `LINUX_AP.md` said the nftables forward chain backs up client isolation. The
  code, the threat model and a dedicated test all say otherwise.
- The student disclosure still said "there is no internet connection here, so
  nothing can be reached", which stopped being true when allowlist mode shipped.

## Tests: 127 → 193

Including SNI parsing against real ClientHellos with truncation fuzzing, name
matching (`evil-canvas.jhu.edu` must not satisfy `canvas.jhu.edu`), band
arithmetic, dual-radio rendering, and that archiving a live journal loses the
roster while still verifying as intact.

Two existing tests built their fixtures by copying the live `policy.json`, so
once the mode changed they asserted airgap properties against a proxy config —
one had only ever passed by matching the word "masquerade" inside a comment.
Every test file also had `unittest.main()` in the middle, so running one directly
executed only the classes above it and exited 0.

## Still not blocked, and cannot be

A phone on cellular, a local AI model on a student's laptop, and collusion inside
a site you have allowed. Jamming the first is illegal, the second emits no
packets, and the third is carried inside a connection you deliberately permitted.
Oral spot-checks are the control that covers all three, and the console says so
on its own face.

## Before it counts for marks

```bash
sudo bash tools/verify_blocking.sh
```

Three things cannot be inferred from a bench test and are exactly what the dress
rehearsal is for: **28 laptops at once**, **a real submission at the moment a
student hits submit**, and **coverage from the back of the actual room**.
