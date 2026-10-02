# Themis threat model

## The one idea

**Policy is only enforceable on hardware whose owner enforces it.**

A control that runs on a student's own laptop asks an untrusted machine to
report honestly about itself. It never will, and the effort spent pretending
otherwise is the entire failure mode of the commercial proctoring industry.

Themis therefore puts every control on the **network you own** and on **the
humans in the room**, and puts nothing on the student's device.

## What the exam network can prove

Profile `airgap`, students on the exam SSID, two staff present:

| Vector | Status | Why |
|---|---|---|
| Web search for answers | **Blocked** | No route off the exam network exists. Not filtered — absent. |
| Cloud AI (ChatGPT, Claude, Gemini) | **Blocked** | Same. No egress path to permit or deny. |
| Answer sharing over exam WiFi | **Blocked at the radio** | hostapd `ap_isolate`. The firewall does *not* back this up: traffic between two clients of one AP is relayed inside the radio at layer 2 and never reaches the IP forward hook. If `ap_isolate` is off, nothing else catches it. |
| Pre-staged answers on a USB stick | Not blocked | Out of scope for a network control. |
| **Local AI model on their laptop** | **Not blocked** | A 4 GB model runs fully offline and emits no packets. No network control can see it. |
| **Phone on cellular** | **Not blocked** | Never touches your network. |
| **Switching to another WiFi** | **Detected, not prevented** | Heartbeat gap is logged with a timestamp. Preventing it is illegal — see below. |

The last three rows are the honest limit. They are handled by people, not code.

## Attacks by students against the exam network itself

The threat model above is about a student getting information *out*. These are
about a student attacking the network the exam runs on, which is a different thing
and was missed in the first cut.

| Attack | Status |
|---|---|
| **Deauthenticating classmates** to disrupt the exam | Mitigated by 802.11w (`pmf`). Without it, deauth frames are unauthenticated and any student with a laptop can knock the others off — and every one of those reads as a genuine drop in the proctor console, which is the part that makes it nasty. Default is PMF *optional*, which protects every client that supports it; PMF *required* protects all of them but refuses clients that do not. |
| **Decrypting a classmate's traffic** off the air | WPA2-PSK gives all 19 students the same key, so AP isolation does not stop passive decryption. WPA3-SAE gives each session its own key. Default is transition mode: SAE for clients that support it, PSK for those that do not. |
| **Offline dictionary attack on the passphrase** | The passphrase is 16 characters from `secrets.token_urlsafe(12)` and rotates every exam. Under SAE it is not subject to offline attack at all. |
| **Logging into the gateway** | The nftables input chain is `policy drop` and admits only DHCP, DNS to the server, and the portal's TCP ports — all of them to the server address alone. No SSH, no remote access, nothing else reachable from the exam network. Pinned by tests. |
| **MAC spoofing another student's device** | Not prevented. The device-to-student binding is an assertion under WPA2/WPA3-PSK; only WPA2-Enterprise makes it cryptographic. See [IDENTITY.md](IDENTITY.md). |

The honest residual: everything in this table except the last row assumes the
student is attacking over the air. A student who is simply *quiet* — a local model,
a phone on cellular — is unaffected by any of it.

## Two things Themis deliberately does not do

### 1. It does not jam, deauth, or interfere with other networks

Transmitting deauthentication frames to stop students joining another AP or a
phone hotspot violates **§333 of the Communications Act**. The FCC fined
Marriott **$600,000** for precisely this, and Hilton/MC Dean **$750,000**. It is
a federal matter, not a policy preference, and it would expose the university.

*Instead:* the exam page sends a heartbeat. If a client leaves the exam network
the heartbeat stops, and the proctor console shows which seat went dark, when,
and for how long. You have a TA and an instructor in the room — a red tile is
all they need to walk over. Detection plus a human beats prevention that
doesn't exist.

### 2. It does not scan student devices

No process enumeration, no filesystem scanning, no "is Ollama installed"
check, no camera, no microphone, no screen capture, no keystroke biometrics.

Two reasons, and the second is the stronger one:

- It does not work. Renaming a binary defeats it.
- It is the most invasive thing in this space, and it would make Themis the
  thing this course exists to critique.

On institution-owned lab machines the same goal is met by **not granting install
rights**, which is both stronger and harmless.

## The layer that actually resists AI

Network controls cannot stop a local model. Item design mostly cannot either —
a current LLM will solve a freshly generated crypto or forensics question. Two
things do:

1. **Per-student flags.** Derive each student's expected answer from their ID so
   a shared answer is *wrong*, not merely *detectable*. Defeats collusion
   outright and surveils nobody.
2. **Oral spot-checks.** Five minutes per student, sampled or universal. At 28
   students that is ~2.5 hours and zero engineering. A student who cannot
   explain their own answer is caught by the only control that scales against a
   tool that can write any answer.

Post-hoc pair statistics (identical *wrong* answers, timing correlation) run on
data you already hold, and report *a pair worth looking at* — never a verdict.

## Assurance labelling

`themis-net status` prints the table above for the loaded profile, every time.
Any exam Themis delivers is labelled with the assurance level it actually
achieved. A quiz run on the `allowlist` profile must not be described as
air-gapped, and Themis will not let you claim it was.
