"""What the exam NETWORK was asked for, attributed to the student who asked.

This is the one place the proctor console can answer "what is this student
actually doing", and it is worth being precise about what that means here.

What this is
------------
The proxy already decides every HTTPS connection by name and writes the decision
down: a timestamp, the client address, the hostname requested, and whether it was
allowed or refused. That record exists because a refusal is evidence and because
an allowlist has to be discoverable from real traffic. This module does nothing
more than group those existing lines by student.

What this is NOT
----------------
It is not device inspection, and it cannot become it. There is no agent, no
process list, no filesystem, no screen, no keystrokes. It cannot see *inside* a
connection either: the proxy splices TLS without terminating it, so the page a
student opened on an allowed site, what they typed into it, and what came back
are all invisible here and always will be. The honest description is "which
names this network was asked for", not "what the student is doing" -- and the
console says so on the screen rather than letting a reader assume the stronger
thing.

Why that distinction is load-bearing: a proctor looking at a tile that says
`canvas.jhu.edu` learns that the device asked for Canvas. It does not tell them
the student is working, and a tile showing a refusal does not tell them the
student tried to cheat -- a phone in someone's pocket reaches for iCloud on its
own. The counts below are a question worth asking, never an answer.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

# Overridable so the demo console can show this feature without a live exam, and
# so a test can point at a fixture instead of a path that needs root to create.
DECISIONS_LOG = Path(os.environ.get("THEMIS_DECISIONS_LOG",
                                    "/run/themis/proxy-decisions.log"))

# "2026-10-05 22:42:06 blocked  10.83.0.70   sso.canvaslms.com  not on the ..."
_LINE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}) +"
    r"(?P<verdict>allowed|blocked|failed) +"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) +"
    r"(?P<host>\S+)"
)
# The hostname came off the wire in a student's ClientHello, so it is validated
# here rather than trusted. "(no SNI)" and anything malformed is counted but
# never rendered as a name.
_HOST_OK = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")

# Reading the whole file every refresh is wasteful once an exam has produced a
# few hundred thousand decisions, and an exam is three hours of background
# chatter from 28 devices. Only the tail is ever interesting on a live console.
MAX_BYTES = 4_000_000


@dataclass
class Site:
    host: str
    allowed: int = 0
    blocked: int = 0
    last_ts: float = 0.0

    @property
    def total(self) -> int:
        return self.allowed + self.blocked


@dataclass
class Activity:
    sites: dict[str, Site] = field(default_factory=dict)
    allowed_total: int = 0
    blocked_total: int = 0
    unnamed: int = 0            # TLS with no SNI, or a malformed name
    last_ts: float = 0.0

    def top(self, n: int = 6, *, blocked: bool | None = None) -> list[Site]:
        rows = list(self.sites.values())
        if blocked is True:
            rows = [s for s in rows if s.blocked]
        elif blocked is False:
            rows = [s for s in rows if s.allowed]
        rows.sort(key=lambda s: (-s.last_ts, -s.total))
        return rows[:n]

    @property
    def latest_allowed(self) -> str | None:
        got = self.top(1, blocked=False)
        return got[0].host if got else None


def _parse_ts(date: str, clock: str) -> float:
    try:
        return time.mktime(time.strptime(f"{date} {clock}", "%Y-%m-%d %H:%M:%S"))
    except (ValueError, OverflowError):
        return 0.0


def read_activity(path: Path | str = DECISIONS_LOG, *,
                  since: float | None = None) -> dict[str, Activity]:
    """Group the proxy's decisions by client address.

    Returns {ip: Activity}. A missing or unreadable log is an empty result, not
    an error: the console must still render when the proxy is not running, which
    is every air-gapped exam.
    """
    p = Path(path)
    try:
        size = p.stat().st_size
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            if size > MAX_BYTES:
                fh.seek(size - MAX_BYTES)
                fh.readline()               # discard the partial first line
            lines = fh.readlines()
    except OSError:
        return {}

    by_ip: dict[str, Activity] = {}
    for line in lines:
        m = _LINE.match(line)
        if not m:
            continue
        ts = _parse_ts(m.group("date"), m.group("time"))
        if not ts:
            # The pattern checks the SHAPE of a timestamp, not its values, so a
            # corrupt line like "2026-13-45 99:99:99" matches and then fails to
            # parse. Counting it anyway invents a client dated to the epoch,
            # which shows up on the console as a student nobody can account for.
            continue
        if since is not None and ts < since:
            continue
        act = by_ip.setdefault(m.group("ip"), Activity())
        act.last_ts = max(act.last_ts, ts)

        host = m.group("host").lower().rstrip(".")
        verdict = m.group("verdict")
        if verdict == "allowed":
            act.allowed_total += 1
        elif verdict == "blocked":
            act.blocked_total += 1

        if not _HOST_OK.match(host) or len(host) > 253:
            act.unnamed += 1
            continue
        site = act.sites.get(host)
        if site is None:
            site = act.sites[host] = Site(host=host)
        if verdict == "allowed":
            site.allowed += 1
        elif verdict == "blocked":
            site.blocked += 1
        site.last_ts = max(site.last_ts, ts)
    return by_ip


def current_ips(leases, registrations) -> dict[str, str]:
    """student_id -> the address that student is on NOW.

    A registration records the address the student had when they signed in, and
    DHCP hands out a different one after a renewal or a reconnect. Attributing
    activity by the stale address silently shows a student doing nothing -- or,
    worse, shows them doing whatever the next device to get that address did.
    So the lease table wins when it has an answer, keyed on the MAC, which does
    not change.
    """
    by_mac = {}
    for l in leases:
        if getattr(l, "mac", None) and getattr(l, "ip", None):
            by_mac[l.mac.lower()] = l.ip
    out = {}
    for sid, reg in registrations.items():
        mac = (getattr(reg, "mac", "") or "").lower()
        out[sid] = by_mac.get(mac) or getattr(reg, "ip", "") or ""
    return out
