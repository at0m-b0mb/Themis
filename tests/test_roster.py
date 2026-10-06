"""Tests for themis.roster.

These exist mainly to pin the two honesty rules: a gap is a RANGE, and one missed
sample is not a gap. Both protect a student who did nothing wrong.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from themis.journal import Event, event_hash  # noqa: E402
from themis.roster import build_roster  # noqa: E402

T0 = 1_759_000_000.0
MAC_A, MAC_B = "a4:83:e7:1b:2c:3d", "b8:27:eb:00:11:22"


def ev(seq, ts, kind, data):
    return Event(seq=seq, ts=ts, kind=kind, data=data, prev="x",
                 hash=event_hash(seq, ts, kind, data, "x"))


def build(regs, sample_macs, *, step=10.0, min_gap=30.0, open_at=0.0, close_at=None):
    """regs: [(sid, mac, offset)]; sample_macs: list of sets, one per poll."""
    events, seq = [], 0
    events.append(ev(seq, T0 + open_at, "exam_open", {})); seq += 1
    for sid, mac, off in regs:
        events.append(ev(seq, T0 + off, "register",
                         {"student_id": sid, "name": sid.upper(), "mac": mac,
                          "ip": "10.83.0.51", "resolution_source": "both_agree"}))
        seq += 1
    for i, macs in enumerate(sample_macs):
        events.append(ev(seq, T0 + 10.0 + i * step, "presence_sample",
                         {"macs": sorted(macs)}))
        seq += 1
    if close_at is not None:
        events.append(ev(seq, T0 + close_at, "exam_close", {}))
    return build_roster(events, min_gap_seconds=min_gap)


class TestRegistration(unittest.TestCase):
    def test_records_the_binding(self):
        r = build([("s01", MAC_A, 5)], [{MAC_A}])
        self.assertIn("s01", r.registrations)
        self.assertEqual(r.registrations["s01"].mac, MAC_A)
        self.assertTrue(r.registrations["s01"].identity_was_corroborated)

    def test_duplicate_registration_is_flagged_with_an_innocent_reading(self):
        r = build([("s01", MAC_A, 5), ("s01", MAC_B, 6)], [{MAC_B}])
        kinds = [a.kind for a in r.anomalies]
        self.assertIn("duplicate_registration", kinds)
        dup = next(a for a in r.anomalies if a.kind == "duplicate_registration")
        self.assertTrue(dup.innocent_explanation,
                        "every anomaly must carry the innocent reading too")

    def test_two_students_on_one_mac_is_flagged(self):
        r = build([("s01", MAC_A, 5), ("s02", MAC_A, 6)], [{MAC_A}])
        self.assertIn("shared_mac", [a.kind for a in r.anomalies])

    def test_uncorroborated_registration_is_flagged(self):
        e = [ev(0, T0, "exam_open", {}),
             ev(1, T0 + 5, "register", {"student_id": "s01", "name": "S01", "mac": MAC_A,
                                        "ip": "10.83.0.51", "resolution_source": "lease_only"})]
        r = build_roster(e)
        self.assertIn("uncorroborated_registration", [a.kind for a in r.anomalies])


class TestPresence(unittest.TestCase):
    def test_continuous_presence_has_no_gaps(self):
        r = build([("s01", MAC_A, 5)], [{MAC_A}] * 10)
        p = r.presence["s01"]
        self.assertEqual(p.gaps, [])
        self.assertTrue(p.online_now)
        self.assertEqual(p.samples_present, 10)

    def test_one_missed_sample_is_jitter_not_a_gap(self):
        # 10s poll, 30s threshold: a single miss spans 10s and must be ignored.
        r = build([("s01", MAC_A, 5)], [{MAC_A}, {MAC_A}, set(), {MAC_A}, {MAC_A}])
        self.assertEqual(r.presence["s01"].gaps, [],
                         "a single dropped poll must never be called a gap")

    def test_sustained_absence_is_a_gap(self):
        r = build([("s01", MAC_A, 5)],
                  [{MAC_A}, {MAC_A}] + [set()] * 5 + [{MAC_A}])
        gaps = r.presence["s01"].gaps
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0].missed_samples, 5)
        self.assertIsNotNone(gaps[0].back_at)

    def test_gap_duration_is_a_range_not_a_number(self):
        r = build([("s01", MAC_A, 5)],
                  [{MAC_A}, {MAC_A}] + [set()] * 5 + [{MAC_A}])
        g = r.presence["s01"].gaps[0]
        lo, hi = g.duration_bounds()
        self.assertLess(lo, hi, "the bracket must be a real range, not a point")
        self.assertAlmostEqual(hi - lo, 10.0, places=3,
                               msg="uncertainty should equal one poll interval")
        self.assertIn("between", g.describe())

    def test_never_returned_is_reported_as_such(self):
        r = build([("s01", MAC_A, 5)], [{MAC_A}, {MAC_A}] + [set()] * 6)
        g = r.presence["s01"].gaps[0]
        self.assertIsNone(g.back_at)
        self.assertIn("did not return", g.describe(closed_at=T0 + 200))

    def test_absence_before_first_sighting_is_not_a_departure(self):
        # Student registers, then their laptop takes a while to answer. They never
        # left, so there is nothing to report.
        r = build([("s01", MAC_A, 5)], [set(), set(), {MAC_A}, {MAC_A}])
        self.assertEqual(r.presence["s01"].gaps, [])

    def test_samples_before_registration_are_ignored(self):
        r = build([("s01", MAC_A, 100)], [{MAC_A}] * 3)  # all samples precede reg
        self.assertEqual(r.presence["s01"].samples_total, 0)

    def test_online_and_offline_split(self):
        r = build([("s01", MAC_A, 5), ("s02", MAC_B, 5)],
                  [{MAC_A, MAC_B}, {MAC_A}])
        self.assertEqual(r.online, ["s01"])
        self.assertEqual(r.offline, ["s02"])

    def test_multiple_gaps_accumulate_as_a_range(self):
        r = build([("s01", MAC_A, 5)],
                  [{MAC_A}] + [set()] * 4 + [{MAC_A}] + [set()] * 4 + [{MAC_A}])
        p = r.presence["s01"]
        self.assertEqual(len(p.gaps), 2)
        lo, hi = p.total_absence_bounds()
        self.assertLess(lo, hi)
        self.assertIn("s01", r.flagged())


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestReopenedExamClearsTheStaleClose(unittest.TestCase):
    """Restarting the portal writes exam_close and then exam_open.

    If the close is not cleared, every still-open gap is measured against an
    instant already in the past and clamps to zero -- so the proctor is told a
    student who has been gone twenty minutes has been gone 0s. Restarting the
    portal mid-exam is documented as a normal thing to do, so an operator
    reaches this on purpose.
    """

    def test_exam_open_clears_a_previous_close(self):
        r = build_roster([
            ev(0, T0, "exam_open", {}),
            ev(1, T0 + 60, "exam_close", {}),
            ev(2, T0 + 120, "exam_open", {}),
        ])
        self.assertIsNone(r.closed_at, "a reopened exam is not a closed one")
        self.assertEqual(r.opened_at, T0 + 120)

    def test_a_genuine_close_is_still_recorded(self):
        r = build_roster([ev(0, T0, "exam_open", {}),
                          ev(1, T0 + 60, "exam_close", {})])
        self.assertEqual(r.closed_at, T0 + 60)

    def test_a_gap_after_reopening_is_not_reported_as_zero(self):
        # The symptom an operator actually sees: a student missing from every
        # sample after the restart must not read as "gone 0s".
        events = [ev(0, T0, "exam_open", {}),
                  ev(1, T0 + 5, "register",
                     {"student_id": "s1", "name": "S1", "mac": MAC_A,
                      "ip": "10.83.0.51", "resolution_source": "both_agree"}),
                  ev(2, T0 + 10, "presence_sample", {"macs": [MAC_A]}),
                  ev(3, T0 + 20, "exam_close", {}),
                  ev(4, T0 + 30, "exam_open", {})]
        seq = 5
        for i in range(8):                       # eight polls with nobody seen
            events.append(ev(seq, T0 + 40 + i * 10.0, "presence_sample", {"macs": []}))
            seq += 1
        r = build_roster(events, min_gap_seconds=30.0)
        self.assertIsNone(r.closed_at)
        gaps = [g for pres in r.presence.values() for g in pres.gaps]
        self.assertTrue(gaps, "the student stopped appearing; that is a gap")
        longest = max(g.duration_bounds(r.closed_at or (T0 + 120))[1] for g in gaps)
        self.assertGreater(longest, 30.0,
                           "a gap measured against a stale close clamps to zero")
