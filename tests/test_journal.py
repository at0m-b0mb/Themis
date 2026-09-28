"""Tests for themis.journal.

The claim under test is narrow and must stay narrow: the chain proves nothing was
ALTERED, and it does not prove the log is COMPLETE. Both halves are tested, because
overclaiming here would mislead a reviewer looking at a student's marks.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from themis.journal import GENESIS, Journal, event_hash  # noqa: E402


class JournalCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.path = self.dir / "exam.jsonl"

    def populate(self, n=4):
        j = Journal(self.path)
        for i in range(n):
            j.append("heartbeat", {"student": f"s{i:02d}", "seat": i}, ts=1_759_000_000 + i)
        return j

    def lines(self):
        return self.path.read_text().strip().splitlines()

    def rewrite(self, lines):
        self.path.write_text("\n".join(lines) + "\n")


class TestAppendAndVerify(JournalCase):
    def test_fresh_chain_starts_at_genesis(self):
        j = Journal(self.path)
        ev = j.append("exam_open", {"exam": "midterm"})
        self.assertEqual(ev.seq, 0)
        self.assertEqual(ev.prev, GENESIS)
        self.assertTrue(j.verify().ok)

    def test_clean_chain_verifies(self):
        j = self.populate(5)
        v = j.verify()
        self.assertTrue(v.ok, v.summary())
        self.assertEqual(v.count, 5)
        self.assertIn("intact", v.summary())

    def test_reopening_resumes_the_chain(self):
        first = self.populate(3)
        head, seq = first.head, 2
        second = Journal(self.path)
        ev = second.append("register", {"student": "s99"})
        self.assertEqual(ev.seq, seq + 1)
        self.assertEqual(ev.prev, head, "a reopened journal must continue, not restart")
        self.assertTrue(second.verify().ok)

    def test_empty_journal_verifies_vacuously(self):
        self.assertTrue(Journal(self.path).verify().ok)


class TestTamperDetection(JournalCase):
    def test_edited_payload_is_caught(self):
        self.populate(4)
        rows = [json.loads(l) for l in self.lines()]
        rows[2]["data"]["seat"] = 999          # change a value, leave the hash alone
        self.rewrite([json.dumps(r, sort_keys=True, separators=(",", ":")) for r in rows])
        v = Journal(self.path).verify()
        self.assertFalse(v.ok)
        self.assertEqual(v.broke_at, 2)
        self.assertIn("altered", v.summary())

    def test_recomputed_hash_still_breaks_the_chain(self):
        # The sophisticated tamper: edit the payload AND fix that event's own hash.
        # It must still fail, because the next event commits to the old hash.
        self.populate(4)
        rows = [json.loads(l) for l in self.lines()]
        rows[1]["data"]["seat"] = 999
        rows[1]["hash"] = event_hash(rows[1]["seq"], rows[1]["ts"], rows[1]["kind"],
                                     rows[1]["data"], rows[1]["prev"])
        self.rewrite([json.dumps(r, sort_keys=True, separators=(",", ":")) for r in rows])
        v = Journal(self.path).verify()
        self.assertFalse(v.ok, "re-hashing one event must not launder the edit")
        self.assertEqual(v.broke_at, 2, "the break surfaces at the FOLLOWING event")

    def test_deleted_middle_event_is_caught(self):
        self.populate(5)
        rows = self.lines()
        del rows[2]
        self.rewrite(rows)
        v = Journal(self.path).verify()
        self.assertFalse(v.ok)
        self.assertEqual(v.broke_at, 3)

    def test_reordered_events_are_caught(self):
        self.populate(5)
        rows = self.lines()
        rows[1], rows[3] = rows[3], rows[1]
        self.rewrite(rows)
        self.assertFalse(Journal(self.path).verify().ok)

    def test_backdated_timestamp_is_reported(self):
        self.populate(3)
        rows = [json.loads(l) for l in self.lines()]
        rows[2]["ts"] = rows[0]["ts"] - 500
        rows[2]["hash"] = event_hash(rows[2]["seq"], rows[2]["ts"], rows[2]["kind"],
                                     rows[2]["data"], rows[2]["prev"])
        self.rewrite([json.dumps(r, sort_keys=True, separators=(",", ":")) for r in rows])
        v = Journal(self.path).verify()
        self.assertFalse(v.ok)
        self.assertTrue(any("time-stamped before" in p for p in v.problems), v.problems)

    def test_truncated_tail_still_verifies__a_documented_limit(self):
        # THE honest limit: lopping events off the END leaves a valid chain. The
        # chain proves nothing was altered; it cannot prove nothing was removed
        # from the tail. Publishing the head hash when the exam closes is what
        # closes this gap, not the chain itself.
        self.populate(6)
        self.rewrite(self.lines()[:3])
        v = Journal(self.path).verify()
        self.assertTrue(v.ok, "truncation is NOT detectable by the chain alone")
        self.assertEqual(v.count, 3)

    def test_torn_final_line_is_tolerated(self):
        # The console reads this file while it is being appended to.
        j = self.populate(3)
        with self.path.open("a") as fh:
            fh.write('{"seq": 3, "ts": 175900')  # power cut mid-write
        self.assertTrue(Journal(self.path).verify().ok)
        self.assertEqual(len(list(j.read())), 3)


class TestHashConstruction(JournalCase):
    def test_field_boundaries_cannot_be_shifted(self):
        # Without length-prefixing, ("a|b","c") and ("a","b|c") would collide and
        # two different event streams could share a chain.
        a = event_hash(0, 1.0, "kind", {"x": "a|b"}, GENESIS)
        b = event_hash(0, 1.0, "kind", {"x": "a"}, GENESIS)
        self.assertNotEqual(a, b)
        self.assertNotEqual(event_hash(0, 1.0, "a|b", {}, GENESIS),
                            event_hash(0, 1.0, "a", {"|b": ""}, GENESIS))

    def test_key_order_does_not_change_the_hash(self):
        self.assertEqual(event_hash(1, 2.0, "k", {"a": 1, "b": 2}, GENESIS),
                         event_hash(1, 2.0, "k", {"b": 2, "a": 1}, GENESIS))


if __name__ == "__main__":
    unittest.main(verbosity=2)
