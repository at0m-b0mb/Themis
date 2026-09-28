"""Who is on the exam network, from two independent sources.

A MAC address is a LABEL, never an identity. Every modern platform randomizes its
MAC per SSID by default, and a user can change it at will. What a MAC gives us is
a handle that is *stable for the duration of one exam on one SSID* -- enough to say
"this is the same device as five minutes ago", and never enough to say "this device
belongs to that person". The device-to-student binding is established by an explicit
registration step; see themis/roster.py.

Two sources are read because disagreement between them is itself a signal:

  dnsmasq leases  what the DHCP server handed out, with timestamps
  ARP table       what this gateway has actually been talking to

A lease and an ARP entry that disagree about the MAC behind an IP means either a
stale cache or a device claiming an address that was not leased to it. The caller
gets told which, and decides. This module never concludes anything on its own.
"""

from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

DEFAULT_LEASE_FILE = Path("/var/run/themis/dhcp.leases")

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
# `arp -an` prints: ? (10.83.0.51) at a4:83:e7:1b:2c:3d on en7 ifscope [ethernet]
_ARP_RE = re.compile(
    r"\((?P<ip>\d+\.\d+\.\d+\.\d+)\)\s+at\s+(?P<mac>[0-9a-fA-F:]+)"
)


def normalise_mac(raw: str) -> str | None:
    """Lowercase colon-form, or None if it is not a full MAC.

    `arp` prints short octets (a4:83:e7:1b:2c:3 for ...03) and incomplete entries
    as 'incomplete', so this is a filter as much as a formatter.
    """
    s = raw.strip().lower()
    if not s or "incomplete" in s:
        return None
    parts = s.split(":")
    if len(parts) != 6:
        return None
    try:
        padded = ":".join(f"{int(p, 16):02x}" for p in parts)
    except ValueError:
        return None
    return padded if _MAC_RE.match(padded) else None


@dataclass(frozen=True)
class Lease:
    mac: str
    ip: str
    hostname: str | None
    expires: int  # unix epoch, 0 for an infinite lease

    def expired(self, now: float | None = None) -> bool:
        if self.expires == 0:
            return False
        return (now if now is not None else time.time()) > self.expires


def read_leases(path: Path | str = DEFAULT_LEASE_FILE) -> list[Lease]:
    """Parse a dnsmasq lease file.

    Format is one lease per line:
        <expiry-epoch> <mac> <ip> <hostname|*> <client-id|*>

    Malformed lines are skipped rather than raised on: this is read live, while
    dnsmasq is rewriting the file, and a torn final line must not take down the
    proctor console mid-exam.
    """
    p = Path(path)
    if not p.exists():
        return []
    out: list[Lease] = []
    for line in p.read_text(errors="replace").splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        try:
            expires = int(fields[0])
        except ValueError:
            continue
        mac = normalise_mac(fields[1])
        if mac is None:
            continue
        ip = fields[2]
        if ip.count(".") != 3:
            continue
        hostname = fields[3] if len(fields) > 3 and fields[3] != "*" else None
        out.append(Lease(mac=mac, ip=ip, hostname=hostname, expires=expires))
    return out


def arp_table(interface: str | None = None) -> dict[str, str]:
    """ip -> mac, as this gateway has actually observed it."""
    cmd = ["/usr/sbin/arp", "-an"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if p.returncode != 0:
        return {}
    table: dict[str, str] = {}
    for line in p.stdout.splitlines():
        if interface and f" on {interface} " not in line:
            continue
        m = _ARP_RE.search(line)
        if not m:
            continue
        mac = normalise_mac(m.group("mac"))
        if mac:
            table[m.group("ip")] = mac
    return table


@dataclass(frozen=True)
class Resolution:
    """What we can say about the device behind an IP, and how sure we are."""

    ip: str
    mac: str | None
    source: str  # both_agree | lease_only | arp_only | conflict | unknown
    lease_mac: str | None = None
    arp_mac: str | None = None

    @property
    def trustworthy(self) -> bool:
        """True only when both sources independently agree.

        Deliberately strict. A caller binding a device to a student's name should
        want both, and should ask a human when it cannot have them.
        """
        return self.source == "both_agree"

    def explain(self) -> str:
        return {
            "both_agree": "DHCP lease and ARP agree",
            "lease_only": "leased, but this gateway has not talked to it yet",
            "arp_only": "seen on the wire with no matching lease -- static IP, or an address it was not given",
            "conflict": f"DHCP leased {self.lease_mac} but ARP sees {self.arp_mac} -- stale cache, or one device using another's address",
            "unknown": "no lease and no ARP entry for this address",
        }[self.source]


def resolve(
    ip: str,
    *,
    lease_file: Path | str = DEFAULT_LEASE_FILE,
    interface: str | None = None,
    now: float | None = None,
    _leases: list[Lease] | None = None,
    _arp: dict[str, str] | None = None,
) -> Resolution:
    """Resolve an IP to a MAC using both sources, reporting which agreed.

    The underscore-prefixed parameters exist so tests can inject both sources
    without a live network.
    """
    leases = _leases if _leases is not None else read_leases(lease_file)
    arp = _arp if _arp is not None else arp_table(interface)

    live = [l for l in leases if l.ip == ip and not l.expired(now)]
    # Last line wins: dnsmasq appends, so the newest entry for an IP is the
    # current one when an old lease has not been reaped yet.
    lease_mac = live[-1].mac if live else None
    arp_mac = arp.get(ip)

    if lease_mac and arp_mac:
        source = "both_agree" if lease_mac == arp_mac else "conflict"
        mac = lease_mac if source == "both_agree" else None
    elif lease_mac:
        source, mac = "lease_only", lease_mac
    elif arp_mac:
        source, mac = "arp_only", arp_mac
    else:
        source, mac = "unknown", None

    return Resolution(ip=ip, mac=mac, source=source, lease_mac=lease_mac, arp_mac=arp_mac)
