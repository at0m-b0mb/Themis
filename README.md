# Themis

Exam integrity for university courses, built on controls that actually hold —
and honest about the ones that don't.

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

## What is honestly out of reach

| | |
|---|---|
| Local AI model on a student laptop | **Cannot be blocked.** Runs offline, emits nothing. |
| Phone on cellular | **Cannot be blocked.** Never touches your network. |
| Switching to another WiFi | **Detected, not prevented.** Jamming it violates §333 of the Communications Act — the FCC fined Marriott $600k and Hilton/MC Dean $750k for exactly that. |

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
- [ ] Exam server + proctor console: 28 live tiles, heartbeat gap detection
- [ ] Per-student parameterised items → QTI 1.2 export (imports into Canvas,
      Moodle, Blackboard with no admin approval — the lowest-friction path to
      adoption by other universities)
- [ ] Per-student flags for practical/CTF questions
- [ ] Post-hoc collusion statistics over exported results
- [ ] LTI 1.3 tool for grade passback, once the above is proven in a real exam

## Status

Pre-release. The network layer is written and both pf profiles validate under
`pfctl -n`, but **nothing here has been run against 28 real laptops yet.** Do
the dress rehearsal in `docs/NETWORK_SETUP.md` before it counts for marks.
