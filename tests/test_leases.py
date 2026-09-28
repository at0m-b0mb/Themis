"""Tests for themis.leases -- the device-resolution layer.

The point of these is not coverage, it is the invariant that this module never
concludes more than it knows: a conflict or a single-source answer must never
come back as trustworthy.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from themis.leases import Lease, normalise_mac, read_leases, resolve  # noqa: E402

NOW = 1_759_000_000  # fixed so lease expiry is deterministic


class TestNormaliseMac(unittest.TestCase):
    def test_lowercases_and_pads_short_octets(self):
        # `arp -an` prints a4:83:e7:1b:2c:3 for a trailing 0x03.
        self.assertEqual(normalise_mac("A4:83:E7:1B:2C:3"), "a4:83:e7:1b:2c:03")

    def test_already_canonical_is_unchanged(self):
        self.assertEqual(normalise_mac("a4:83:e7:1b:2c:3d"), "a4:83:e7:1b:2c:3d")

    def test_rejects_non_macs(self):
        for bad in ("", "   ", "incomplete", "a4:83:e7:1b:2c", "a4:83:e7:1b:2c:3d:4e",
                    "zz:83:e7:1b:2c:3d", "10.83.0.5"):
            with self.subTest(bad=bad):
                self.assertIsNone(normalise_mac(bad))


class TestReadLeases(unittest.TestCase):
    def _write(self, body: str) -> Path:
        p = Path(self.enterContext(__import__("tempfile").TemporaryDirectory())) / "dhcp.leases"
        p.write_text(body)
        return p

    def test_parses_a_normal_file(self):
        p = self._write(
            f"{NOW + 3600} a4:83:e7:1b:2c:3d 10.83.0.51 seat-01 01:a4:83:e7:1b:2c:3d\n"
            f"{NOW + 3600} b8:27:eb:00:11:22 10.83.0.52 * *\n"
        )
        leases = read_leases(p)
        self.assertEqual(len(leases), 2)
        self.assertEqual(leases[0].hostname, "seat-01")
        self.assertIsNone(leases[1].hostname, "a '*' hostname should become None")

    def test_skips_malformed_lines_without_raising(self):
        # dnsmasq is rewriting this file live; a torn last line must not crash
        # the proctor console mid-exam.
        p = self._write(
            f"{NOW + 60} a4:83:e7:1b:2c:3d 10.83.0.51 ok *\n"
            "garbage\n"
            "notanumber a4:83:e7:1b:2c:3e 10.83.0.52 x *\n"
            f"{NOW + 60} not-a-mac 10.83.0.53 x *\n"
            f"{NOW + 60} a4:83:e7:1b:2c:3f not-an-ip x *\n"
            f"{NOW + 60}\n"
        )
        self.assertEqual([l.ip for l in read_leases(p)], ["10.83.0.51"])

    def test_missing_file_is_empty_not_an_error(self):
        self.assertEqual(read_leases("/nonexistent/themis/dhcp.leases"), [])

    def test_expiry(self):
        past = Lease("a4:83:e7:1b:2c:3d", "10.83.0.51", None, NOW - 1)
        future = Lease("a4:83:e7:1b:2c:3d", "10.83.0.51", None, NOW + 1)
        forever = Lease("a4:83:e7:1b:2c:3d", "10.83.0.51", None, 0)
        self.assertTrue(past.expired(NOW))
        self.assertFalse(future.expired(NOW))
        self.assertFalse(forever.expired(NOW), "0 means an infinite lease")


class TestResolve(unittest.TestCase):
    MAC_A = "a4:83:e7:1b:2c:3d"
    MAC_B = "b8:27:eb:00:11:22"

    def _resolve(self, leases, arp, ip="10.83.0.51"):
        return resolve(ip, now=NOW, _leases=leases, _arp=arp)

    def test_both_sources_agree_is_the_only_trustworthy_answer(self):
        r = self._resolve([Lease(self.MAC_A, "10.83.0.51", None, NOW + 60)],
                          {"10.83.0.51": self.MAC_A})
        self.assertEqual(r.source, "both_agree")
        self.assertEqual(r.mac, self.MAC_A)
        self.assertTrue(r.trustworthy)

    def test_conflict_yields_no_mac_and_is_not_trustworthy(self):
        # One device using an address leased to another looks exactly like this.
        r = self._resolve([Lease(self.MAC_A, "10.83.0.51", None, NOW + 60)],
                          {"10.83.0.51": self.MAC_B})
        self.assertEqual(r.source, "conflict")
        self.assertIsNone(r.mac, "a conflict must not resolve to either candidate")
        self.assertFalse(r.trustworthy)
        self.assertIn(self.MAC_A, r.explain())
        self.assertIn(self.MAC_B, r.explain())

    def test_single_source_answers_are_reported_but_not_trusted(self):
        lease_only = self._resolve([Lease(self.MAC_A, "10.83.0.51", None, NOW + 60)], {})
        self.assertEqual(lease_only.source, "lease_only")
        self.assertEqual(lease_only.mac, self.MAC_A)
        self.assertFalse(lease_only.trustworthy)

        arp_only = self._resolve([], {"10.83.0.51": self.MAC_A})
        self.assertEqual(arp_only.source, "arp_only")
        self.assertEqual(arp_only.mac, self.MAC_A)
        self.assertFalse(arp_only.trustworthy)

    def test_unknown_address(self):
        r = self._resolve([], {})
        self.assertEqual(r.source, "unknown")
        self.assertIsNone(r.mac)
        self.assertFalse(r.trustworthy)

    def test_expired_lease_is_not_used(self):
        r = self._resolve([Lease(self.MAC_A, "10.83.0.51", None, NOW - 1)], {})
        self.assertEqual(r.source, "unknown")

    def test_newest_lease_wins_when_an_old_one_lingers(self):
        # dnsmasq appends; a reaped-late old lease must not shadow the current one.
        r = self._resolve(
            [Lease(self.MAC_A, "10.83.0.51", None, NOW + 10),
             Lease(self.MAC_B, "10.83.0.51", None, NOW + 60)],
            {"10.83.0.51": self.MAC_B},
        )
        self.assertEqual(r.mac, self.MAC_B)
        self.assertEqual(r.source, "both_agree")

    def test_every_source_has_an_explanation(self):
        for src in ("both_agree", "lease_only", "arp_only", "conflict", "unknown"):
            with self.subTest(source=src):
                from themis.leases import Resolution
                r = Resolution(ip="10.83.0.51", mac=None, source=src,
                               lease_mac=self.MAC_A, arp_mac=self.MAC_B)
                self.assertTrue(r.explain(), f"{src} must be explainable to a proctor")


if __name__ == "__main__":
    unittest.main(verbosity=2)
