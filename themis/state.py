"""Where Themis keeps things, and why the split matters.

/run/themis      ephemeral, and correctly so: pid files, rendered configs, DHCP
                 leases, the saved nftables ruleset. All of it is meaningless once
                 the machine reboots, and /run being tmpfs is exactly right for it.

/var/lib/themis  the exam record. This is NOT ephemeral. It is the artifact a
                 student is entitled to see if their marks are questioned, and the
                 one a department might review months later.

The journal used to live in /run/themis alongside the pid files, which meant the
entire record of who was present evaporated on reboot -- silently, and precisely
when someone finally came asking about it.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

RUN_DIR = Path("/run/themis")           # ephemeral by design
DATA_DIR = Path("/var/lib/themis")      # the record, which must survive a reboot

ACTIVE_JOURNAL = DATA_DIR / "exam.jsonl"


def ensure_dirs() -> None:
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        # The record carries student names and device addresses. Operators only.
        os.chmod(DATA_DIR, 0o750)
    except OSError:
        pass


def archive_previous(journal: Path = ACTIVE_JOURNAL) -> Path | None:
    """Move a finished exam aside so a new one starts on a clean chain.

    Appending a second exam onto the first would make one chain spanning two
    sittings, so a question about one exam could not be answered without handing
    over the other one's record too.

    Returns the archived path, or None if there was nothing to archive.
    """
    if not journal.exists() or journal.stat().st_size == 0:
        return None
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(journal.stat().st_mtime))
    dest = journal.with_name(f"exam-{stamp}.jsonl")
    n = 1
    while dest.exists():
        n += 1
        dest = journal.with_name(f"exam-{stamp}-{n}.jsonl")
    journal.rename(dest)
    return dest
