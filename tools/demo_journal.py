#!/usr/bin/env python3
"""Generate a realistic exam journal for development and screenshots.

Screenshots and design work use THIS, never a real class. No real student name,
ID or device address should ever leave a real exam host.

    python3 tools/demo_journal.py /tmp/demo.jsonl
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from themis.journal import Journal

# Deterministic: the same journal every run, so a visual diff between two design
# passes is a design difference and not a data difference.
NAMES = [
    "Amara Osei", "Ben Halvorsen", "Chen Wei", "Daniela Rossi", "Ewan Murray",
    "Fatima Al-Rashid", "Grace Okonkwo", "Hiroshi Tanaka", "InesВарга",
    "Jonas Lindqvist", "Kavya Raman", "Liam O'Connell", "Marta Kowalczyk",
    "Nadia Haddad", "Omar Diallo", "Priya Venkatesan", "Quentin Dubois",
    "Rosa Iglesias", "Sunil Batra",
]

T0 = 1_759_000_000.0        # fixed epoch
STEP = 10.0                  # presence sample interval
DURATION = 90 * 60           # a 90-minute exam


def mac(i: int) -> str:
    # Locally-administered range, so nothing here collides with real hardware.
    return f"02:00:5e:{i:02x}:{(i * 7) % 256:02x}:{(i * 13) % 256:02x}"


def main(out: Path) -> int:
    if out.exists():
        out.unlink()

    # Collect first, then append in timestamp order. Appending as we generate put a
    # late registration ahead of earlier presence samples, and Journal.verify()
    # correctly called that out -- a real chain must never go backwards in time.
    pending: list[tuple[float, str, dict]] = []
    def at(ts: float, kind: str, data: dict):
        pending.append((ts, kind, data))

    at(T0, "exam_open", {"ssid": "EXAM-ONLY", "profile": "airgap", "student_port": 80})

    students = []
    for i, name in enumerate(NAMES):
        sid = f"jhu{4100 + i}"
        # Students trickle in over the first four minutes, as they actually do.
        when = T0 + 20 + i * 12
        # One student's gateway had not yet ARPed them when they signed in: a real,
        # innocent situation that the console flags as uncorroborated.
        src = "lease_only" if i == 7 else "both_agree"
        at(when, "register", {"student_id": sid, "name": name, "seat": str(i + 1),
                              "mac": mac(i), "ip": f"10.83.0.{50 + i}",
                              "resolution_source": src, "user_agent": "Mozilla/5.0"})
        students.append([sid, mac(i), when])

    # One student's MAC rotated and they signed in again -- flagged as a duplicate,
    # with "their MAC rotated or they swapped laptops" as the innocent reading.
    rotated_at = T0 + 1500
    at(rotated_at, "register", {"student_id": students[3][0], "name": NAMES[3],
                                "seat": "4", "mac": "02:00:5e:ff:ff:01",
                                "ip": "10.83.0.90", "resolution_source": "both_agree"})

    # Absence windows, in sample indices. Each is a different real-world story.
    absences = {
        2:  [(120, 124)],                 # 40s -- a lid closed briefly
        5:  [(200, 206), (310, 318)],     # twice, a few minutes apart
        9:  [(60, 61)],                   # one sample: jitter, must NOT be a gap
        11: [(400, 540)],                 # left and never came back
        14: [(250, 262)],                 # two minutes
    }

    for n in range(int(DURATION / STEP)):
        ts = T0 + 60 + n * STEP
        present = []
        for i, (sid, m, joined) in enumerate(students):
            if ts < joined:
                continue
            # After the rotation, student 3 is seen under the new address.
            eff = "02:00:5e:ff:ff:01" if (i == 3 and ts >= rotated_at) else m
            if not any(lo <= n < hi for lo, hi in absences.get(i, [])):
                present.append(eff)
        at(ts, "presence_sample", {"macs": sorted(present)})

    at(T0 + 60 + DURATION, "exam_close", {})

    j = Journal(out)
    for ts, kind, data in sorted(pending, key=lambda e: e[0]):
        j.append(kind, data, ts=ts)

    v = j.verify()
    print(f"wrote {out}")
    print(f"  {v.count} events, {v.summary()}")
    print(f"  head {j.head}")
    return 0 if v.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/themis-demo.jsonl")))
