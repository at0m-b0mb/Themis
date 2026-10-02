"""An append-only, hash-chained record of what happened during an exam.

This is the artifact the TA reviews by hand afterwards, and it is the thing a
student is entitled to see if their marks are questioned. Both of those demand the
same property: nobody -- including the TA, including a later version of this
program -- can quietly change what it says.

Each event commits to the one before it. Editing, deleting, reordering, or
back-dating any event breaks the chain from that point on, and verify() reports
the exact sequence number where it broke. This does not make the log secret and it
does not prove the log is complete; a chain can be truncated at the tail or never
have recorded an event in the first place. It proves only that what remains has not
been altered since it was written. That is a narrow claim, and it is the honest one.

Deliberately plain JSON Lines: a student or a department reviewer can read it with
`cat`, and nothing about verifying it requires this program to still exist.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

try:
    import fcntl
except ImportError:            # not POSIX
    fcntl = None               # type: ignore

GENESIS = "0" * 64


def _canonical(obj) -> str:
    """Stable serialisation, so a hash computed now matches one computed later."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def event_hash(seq: int, ts: float, kind: str, data: dict, prev: str) -> str:
    # Fields are length-prefixed rather than merely separated: without this,
    # ("a|b", "c") and ("a", "b|c") would hash identically and two different
    # event streams could share a chain.
    parts = [str(seq), f"{ts:.6f}", kind, _canonical(data), prev]
    payload = "|".join(f"{len(p)}:{p}" for p in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Event:
    seq: int
    ts: float
    kind: str
    data: dict
    prev: str
    hash: str

    def recompute(self) -> str:
        return event_hash(self.seq, self.ts, self.kind, self.data, self.prev)

    @property
    def intact(self) -> bool:
        return self.hash == self.recompute()

    def to_json(self) -> str:
        return _canonical({
            "seq": self.seq, "ts": self.ts, "kind": self.kind,
            "data": self.data, "prev": self.prev, "hash": self.hash,
        })

    @classmethod
    def from_dict(cls, d: dict) -> "Event":
        return cls(seq=int(d["seq"]), ts=float(d["ts"]), kind=str(d["kind"]),
                   data=d.get("data") or {}, prev=str(d["prev"]), hash=str(d["hash"]))


@dataclass
class Verdict:
    """The result of checking a chain. Never a bare boolean -- a reviewer needs to
    know *where* it broke, not merely that it did."""

    ok: bool
    count: int
    problems: list[str] = field(default_factory=list)
    broke_at: int | None = None

    def summary(self) -> str:
        if self.ok:
            return f"chain intact over {self.count} event(s)"
        where = f" at seq {self.broke_at}" if self.broke_at is not None else ""
        return f"CHAIN BROKEN{where}: " + "; ".join(self.problems)


class Journal:
    """Append-only event log. Opening an existing file resumes its chain."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq, self._head = self._tail()

    def _tail(self) -> tuple[int, str]:
        last = None
        for ev in self.read():
            last = ev
        return (last.seq, last.hash) if last else (-1, GENESIS)

    def append(self, kind: str, data: dict | None = None, *, ts: float | None = None) -> Event:
        """Append one event, safely against other processes writing the same file.

        There are genuinely two writers during an exam: this server, and the
        hostapd event hook, which hostapd_cli spawns as a FRESH process per
        association. An in-memory head cached across appends goes stale the instant
        the other writer commits, and the chain then breaks on its own -- a real
        exam producing a record that reads as tampered-with, which is worse than
        having no chain at all. (There is a test that reproduces exactly that.)

        So the head is re-derived from the file under an exclusive lock, every
        time. The whole file is re-read to do it: at exam scale that is a few
        hundred kilobytes per append, and being obviously correct is worth more
        here than the arithmetic saved by a backward seek.
        """
        payload = data or {}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a+", encoding="utf-8") as fh:
            if fcntl is not None:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                seq, prev = self._tail()          # authoritative: read under the lock
                seq += 1
                stamp = time.time() if ts is None else ts
                ev = Event(seq=seq, ts=stamp, kind=kind, data=payload, prev=prev,
                           hash=event_hash(seq, stamp, kind, payload, prev))
                # Flush and fsync every event: a laptop that loses power mid-exam
                # must not lose the record of who was present, and a half-written
                # final line is exactly what read() is built to tolerate.
                fh.write(ev.to_json() + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            finally:
                if fcntl is not None:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        self._seq, self._head = seq, ev.hash
        return ev

    def read(self):
        """Yield every well-formed event. A torn final line is skipped, not raised
        on -- the console reads this file while it is being written."""
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield Event.from_dict(json.loads(line))
                except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                    continue

    def verify(self) -> Verdict:
        problems: list[str] = []
        broke_at: int | None = None
        expected_prev, expected_seq, count, last_ts = GENESIS, 0, 0, None

        for ev in self.read():
            count += 1
            if ev.seq != expected_seq:
                problems.append(f"expected seq {expected_seq}, found {ev.seq} (event missing or reordered)")
                broke_at = broke_at if broke_at is not None else ev.seq
            if ev.prev != expected_prev:
                problems.append(f"seq {ev.seq} does not follow the previous event")
                broke_at = broke_at if broke_at is not None else ev.seq
            if not ev.intact:
                problems.append(f"seq {ev.seq} contents were altered after it was written")
                broke_at = broke_at if broke_at is not None else ev.seq
            if last_ts is not None and ev.ts < last_ts:
                # Not fatal on its own -- clocks can step -- but a reviewer must see it.
                problems.append(f"seq {ev.seq} is time-stamped before the event preceding it")
            expected_prev, expected_seq, last_ts = ev.hash, ev.seq + 1, ev.ts

        return Verdict(ok=not problems, count=count, problems=problems, broke_at=broke_at)

    def events(self, kind: str | None = None) -> list[Event]:
        return [e for e in self.read() if kind is None or e.kind == kind]

    @property
    def head(self) -> str:
        """Current chain tip, read from the file rather than from memory -- another
        process may have appended since we last did.

        Worth writing on the board at the end of an exam: published before any
        review begins, it pins the record you will review."""
        return self._tail()[1]
