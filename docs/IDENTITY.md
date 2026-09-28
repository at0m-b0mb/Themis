# Binding a device to a student

## The problem

A MAC address is not an identity. Every modern platform randomizes its MAC per
SSID by default, the randomized value is user-changeable, and nothing about it is
tied to a person. What a MAC gives us is a handle that is *stable for one exam on
one SSID* — enough to say "same device as five minutes ago", never enough to say
"this device belongs to that student".

So the binding has to be established deliberately. There are two ways to do it and
they differ enormously in strength.

---

## Tier 1 — Captive portal (what Themis implements)

Student joins `EXAM-ONLY`. Every DNS name resolves to the exam server, so the first
web request lands on a registration page. They enter their student ID and name; the
server resolves their source IP to a MAC via [themis/leases.py](../themis/leases.py)
and records the binding in the hash-chained journal.

**What it proves:** a device with this MAC claimed to be this student at this time,
and stayed (or did not stay) on the network for these intervals.

**What it does not prove:** that the person at the keyboard is that student. The
binding is an *assertion by the student*, not an authentication. Specifically:

- A student can register under another student's ID.
- A student can register twice from two devices.
- Nothing stops a device registering as a student who is not in the room.

**What makes it adequate anyway, in this specific room:** 19 students, a TA and an
instructor present, and a console that shows every registration live. Duplicate IDs,
a registration for an absent student, and two devices claiming one ID are all
visible immediately to someone who can see who is actually sitting there. The
portal is not the control; the portal plus a proctor is the control.

Themis therefore flags rather than decides: duplicate student IDs, more devices
than registered students, and MAC/ARP conflicts all surface on the console for a
human to resolve.

---

## Tier 2 — WPA2-Enterprise (the strong version, not yet built)

Instead of asking who they are after they join, make them prove it *to join*.

Each student gets a unique credential. `hostapd` runs with its own built-in EAP
server — no FreeRADIUS needed:

```
eap_server=1
eap_user_file=/etc/hostapd/exam.eap_user
wpa_key_mgmt=WPA-EAP
ap_isolate=1
```

with one line per student in the EAP user file. Association then logs identity ↔
MAC ↔ timestamp **cryptographically, at association time, before a single web
request happens**. A student cannot associate as somebody else without that
person's credential, and every disconnect and reconnect carries a proven identity
rather than an asserted one.

This is strictly stronger than the portal, and it is what makes the project
credible for a class of 200 where no proctor can see everyone.

### This is where the Alfa adapters earn their place

`hostapd` does not exist on macOS, and macOS offers no AP mode to third-party
adapters — so Tier 2 cannot run on the exam Mac. It needs a Linux host, and the
AWUS1900 and AWUS036AXML are well supported there.

| Host | Verdict |
|---|---|
| **Raspberry Pi 4/5 + an Alfa adapter** | Best option. Native Linux, cheap, stable, nothing else competing for the radio. Recommended if Tier 2 is wanted. |
| Linux VM on the Mac + USB passthrough | Works, and is the documented path for these adapters on Apple Silicon — but it puts a VM, USB passthrough, and hostapd in the critical path on exam day. More moving parts than a graded exam deserves. |
| The exam Mac itself | Impossible. No hostapd, no third-party AP mode, and the Realtek/MediaTek kexts are x86_64-only so they will not load on an ARM64 kernel at all. |

---

## Recommendation for this course

**Ship Tier 1.** At 19 students with two staff in the room, a captive portal whose
anomalies are visible live to a human is proportionate, and it introduces no new
hardware on the day the exam actually happens.

**Treat Tier 2 as the adoption story.** It is the answer to "how would this work at
another university with 200 students and no line of sight", and it is a genuinely
better design — just not one worth debugging the morning of a midterm.

Do not build Tier 2 for the first run. Build it after Tier 1 has survived a real
exam, on a Raspberry Pi, with the Alfa adapter you already own.
