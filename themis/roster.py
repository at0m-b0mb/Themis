"""Who registered, who is on the network now, and who went away.

Everything here is DERIVED from the journal -- this module holds no state of its
own, so the console and the after-the-fact review always agree, and a reviewer can
recompute any claim from the raw log with `cat`.

Two honesty rules are built into the types rather than left to the caller:

  A gap is a RANGE, not a number. Presence is sampled, so when a device stops
  answering we know only that it left sometime between the last sample that saw it
  and the first that did not. Reporting "gone 3m12s" as a fact would be a fiction
  precise to the poll interval. Gap.duration_bounds() returns (min, max), and the
  console prints both.

  A single missed sample is not a gap. Wi-Fi jitter, a sleeping radio and a
  browser throttling a hidden tab all drop one poll. A gap must persist past
  min_gap_seconds before it is called anything at all.

This module flags; it never concludes. Duplicate IDs, extra devices and identity
conflicts are surfaced for a human standing in the room, because every one of them
has an innocent explanation as well as a suspicious one.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from themis.journal import Event, Journal

# A gap must outlast this to be reported. One missed 10s poll is jitter; half a
# minute of silence is something a proctor may want to glance at.
DEFAULT_MIN_GAP_SECONDS = 30.0


@dataclass(frozen=True)
class Registration:
    student_id: str
    name: str
    mac: str
    ip: str
    at: float
    resolution_source: str  # from themis.leases.Resolution.source
    seat: str | None = None

    @property
    def identity_was_corroborated(self) -> bool:
        """True when DHCP and ARP agreed about the MAC at registration time.

        Not a statement about the PERSON -- the portal can only ever record an
        assertion by whoever was at the keyboard. See docs/IDENTITY.md.
        """
        return self.resolution_source == "both_agree"


@dataclass(frozen=True)
class Gap:
    """A period a registered device stopped answering.

    last_seen_at .. missing_from brackets the departure; missing_from .. back_at
    brackets the return. Neither endpoint is known exactly, which is why duration
    is a range.
    """

    last_seen_at: float
    missing_from: float
    back_at: float | None  # None: never came back before the exam closed
    missed_samples: int

    def duration_bounds(self, closed_at: float | None = None) -> tuple[float, float]:
        end = self.back_at if self.back_at is not None else closed_at
        if end is None:
            return (0.0, 0.0)
        return (max(0.0, end - self.missing_from), max(0.0, end - self.last_seen_at))

    def describe(self, closed_at: float | None = None) -> str:
        lo, hi = self.duration_bounds(closed_at)
        tail = "" if self.back_at is not None else ", did not return"
        return f"between {lo:.0f}s and {hi:.0f}s{tail}"


@dataclass
class Presence:
    student_id: str
    mac: str
    first_seen: float | None = None
    last_seen: float | None = None
    samples_present: int = 0
    samples_total: int = 0
    gaps: list[Gap] = field(default_factory=list)

    @property
    def online_now(self) -> bool:
        """Present in the most recent sample. Computed by build_roster, which knows
        which sample was last."""
        return self._online

    _online: bool = False

    def total_absence_bounds(self, closed_at: float | None = None) -> tuple[float, float]:
        los, his = 0.0, 0.0
        for g in self.gaps:
            lo, hi = g.duration_bounds(closed_at)
            los += lo
            his += hi
        return (los, his)


@dataclass
class Anomaly:
    """Something a human should look at. Never a verdict."""

    kind: str
    detail: str
    student_ids: list[str] = field(default_factory=list)
    innocent_explanation: str = ""


@dataclass
class Roster:
    registrations: dict[str, Registration] = field(default_factory=dict)
    presence: dict[str, Presence] = field(default_factory=dict)
    anomalies: list[Anomaly] = field(default_factory=list)
    opened_at: float | None = None
    closed_at: float | None = None
    sample_count: int = 0

    @property
    def online(self) -> list[str]:
        return sorted(sid for sid, p in self.presence.items() if p.online_now)

    @property
    def offline(self) -> list[str]:
        return sorted(sid for sid, p in self.presence.items() if not p.online_now)

    def flagged(self) -> list[str]:
        """Students with at least one reportable gap. For the proctor's eye, not
        for a grade."""
        return sorted(sid for sid, p in self.presence.items() if p.gaps)


def build_roster(
    source: Journal | list[Event],
    *,
    min_gap_seconds: float = DEFAULT_MIN_GAP_SECONDS,
) -> Roster:
    events = list(source.read()) if isinstance(source, Journal) else list(source)
    r = Roster()

    samples: list[tuple[float, set[str]]] = []
    for ev in events:
        if ev.kind == "exam_open":
            r.opened_at = ev.ts
            # Clear the PREVIOUS sitting's close. Left set, it points at an
            # instant already in the past, and every still-open gap is then
            # measured against it and clamps to zero -- so a student who has
            # been gone twenty minutes is reported to the proctor as "gone 0s".
            # Reached whenever the portal is restarted, which server.py's own
            # docstring documents as a normal thing to do.
            r.closed_at = None
        elif ev.kind == "exam_close":
            r.closed_at = ev.ts
        elif ev.kind == "register":
            d = ev.data
            sid = str(d.get("student_id", "")).strip()
            if not sid:
                continue
            reg = Registration(
                student_id=sid,
                name=str(d.get("name", "")),
                mac=str(d.get("mac", "")),
                ip=str(d.get("ip", "")),
                at=ev.ts,
                resolution_source=str(d.get("resolution_source", "unknown")),
                seat=d.get("seat"),
            )
            if sid in r.registrations:
                prev = r.registrations[sid]
                r.anomalies.append(Anomaly(
                    kind="duplicate_registration",
                    detail=f"{sid} registered twice: {prev.mac} then {reg.mac}",
                    student_ids=[sid],
                    innocent_explanation="they reconnected after their MAC rotated, or swapped laptops",
                ))
            r.registrations[sid] = reg
        elif ev.kind == "presence_sample":
            macs = {str(m) for m in (ev.data.get("macs") or [])}
            samples.append((ev.ts, macs))

    r.sample_count = len(samples)

    # One MAC claimed by more than one student.
    by_mac: dict[str, list[str]] = {}
    for sid, reg in r.registrations.items():
        if reg.mac:
            by_mac.setdefault(reg.mac, []).append(sid)
    for mac, sids in by_mac.items():
        if len(sids) > 1:
            r.anomalies.append(Anomaly(
                kind="shared_mac",
                detail=f"{mac} registered by {len(sids)} students: {', '.join(sorted(sids))}",
                student_ids=sorted(sids),
                innocent_explanation="two students shared one laptop, or a MAC was reassigned between sessions",
            ))

    # Registrations whose identity was not corroborated by both sources.
    for sid, reg in r.registrations.items():
        if not reg.identity_was_corroborated:
            r.anomalies.append(Anomaly(
                kind="uncorroborated_registration",
                detail=f"{sid}: DHCP and ARP did not agree at registration ({reg.resolution_source})",
                student_ids=[sid],
                innocent_explanation="the gateway had simply not talked to the device yet when they registered",
            ))

    for sid, reg in r.registrations.items():
        r.presence[sid] = _presence_for(reg, samples, min_gap_seconds)

    return r


def _presence_for(
    reg: Registration,
    samples: list[tuple[float, set[str]]],
    min_gap_seconds: float,
) -> Presence:
    p = Presence(student_id=reg.student_id, mac=reg.mac)
    # Only samples taken at or after registration can say anything about them.
    relevant = [(ts, macs) for ts, macs in samples if ts >= reg.at]
    p.samples_total = len(relevant)

    last_present_ts: float | None = None
    pending: dict | None = None  # an absence being accumulated

    for ts, macs in relevant:
        here = reg.mac in macs
        if here:
            p.samples_present += 1
            if p.first_seen is None:
                p.first_seen = ts
            p.last_seen = ts
            if pending is not None:
                span = ts - pending["missing_from"]
                # Only an absence that outlasted the threshold is a gap at all.
                if span >= min_gap_seconds:
                    p.gaps.append(Gap(
                        last_seen_at=pending["last_seen_at"],
                        missing_from=pending["missing_from"],
                        back_at=ts,
                        missed_samples=pending["missed"],
                    ))
                pending = None
            last_present_ts = ts
        else:
            # Absence before they were ever seen is not a departure.
            if last_present_ts is None:
                continue
            if pending is None:
                pending = {"last_seen_at": last_present_ts, "missing_from": ts, "missed": 1}
            else:
                pending["missed"] += 1

    if pending is not None:
        final_ts = relevant[-1][0]
        if final_ts - pending["missing_from"] >= min_gap_seconds or pending["missed"] > 1:
            p.gaps.append(Gap(
                last_seen_at=pending["last_seen_at"],
                missing_from=pending["missing_from"],
                back_at=None,
                missed_samples=pending["missed"],
            ))

    p._online = bool(relevant) and reg.mac in relevant[-1][1]
    return p
