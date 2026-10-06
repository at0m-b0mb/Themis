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

import os  # noqa: E402
from themis import journal, state  # noqa: E402
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


class TestConcurrentWriters(JournalCase):
    """Two processes really do write this file during an exam: the server, and the
    hostapd event hook that hostapd_cli spawns fresh per association.

    Before the lock, that broke the chain ON ITS OWN -- a real exam producing a
    record that read as tampered-with. That is worse than having no chain, because
    it discredits genuine evidence and the student's record along with it.
    """

    def test_threads_sharing_a_cached_head_do_not_break_the_chain(self):
        import threading
        server = Journal(self.path)          # long-lived, caches its head
        server.append("exam_open", {})
        ts = []
        for i in range(10):
            ts.append(threading.Thread(target=lambda i=i: Journal(self.path).append("sta_connected", {"i": i})))
            ts.append(threading.Thread(target=lambda i=i: server.append("presence_sample", {"i": i})))
        for t in ts: t.start()
        for t in ts: t.join()
        v = Journal(self.path).verify()
        self.assertTrue(v.ok, v.summary())
        self.assertEqual(v.count, 21, "every append must land, none lost to the race")

    def test_separate_processes_do_not_break_the_chain(self):
        import subprocess, sys as _sys
        root = Path(__file__).resolve().parent.parent
        Journal(self.path).append("exam_open", {})
        src = (f'import sys; sys.path.insert(0, {str(root)!r})\n'
               'from themis.journal import Journal\n'
               f'Journal({str(self.path)!r}).append("sta_connected", {{"m": sys.argv[1]}})\n')
        procs = [subprocess.Popen([_sys.executable, "-c", src, str(i)]) for i in range(8)]
        for p in procs:
            self.assertEqual(p.wait(timeout=30), 0)
        v = Journal(self.path).verify()
        self.assertTrue(v.ok, v.summary())
        self.assertEqual(v.count, 9)

    def test_head_is_read_from_the_file_not_from_memory(self):
        # Another process appending must be visible to a Journal opened earlier,
        # or the head published at the end of an exam names the wrong record.
        a = Journal(self.path)
        a.append("exam_open", {})
        stale = a.head
        Journal(self.path).append("register", {"student_id": "s01"})
        self.assertNotEqual(a.head, stale, "head must reflect the file, not a cache")
        self.assertEqual(a.head, Journal(self.path).head)


class TestRecordIsNotEphemeral(unittest.TestCase):
    def test_the_default_journal_is_not_on_tmpfs(self):
        # It lived in /run/themis next to the pid files, so the whole record of who
        # was present evaporated on reboot -- silently, and exactly when someone
        # finally came asking about it.
        import sys as _sys
        _sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from themis.state import ACTIVE_JOURNAL, RUN_DIR
        self.assertNotIn("/run", str(ACTIVE_JOURNAL),
                         "the exam record must not live on tmpfs")
        self.assertIn("/var/lib", str(ACTIVE_JOURNAL))
        self.assertIn("/run", str(RUN_DIR), "pids and configs SHOULD be ephemeral")

    def test_archive_moves_a_finished_exam_aside(self):
        import sys as _sys, tempfile as _tf
        _sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from themis.state import archive_previous
        d = Path(_tf.mkdtemp()) / "exam.jsonl"
        self.assertIsNone(archive_previous(d), "nothing to archive is not an error")
        Journal(d).append("exam_open", {})
        dest = archive_previous(d)
        self.assertIsNotNone(dest)
        self.assertTrue(dest.exists())
        self.assertFalse(d.exists(), "the new exam must start on a clean chain")


class TestStartExamNeverArchivesALiveRecord(unittest.TestCase):
    """The panel's "Start the exam" archives the journal as its FIRST action.

    Doing that while a portal is appending renames the file out from under the
    writer, which then opens a fresh chain at seq 0. Every student registered so
    far vanishes from the console, verify() reports the new two-event chain as
    perfectly intact, and nothing anywhere records that a record was lost. The
    button was wrongly enabled for entire dual-band exams, so this was reachable
    by an operator doing nothing unusual.
    """

    def _controller(self, run_dir: Path):
        from themis import operator as op
        ctl = op.Controller.__new__(op.Controller)
        ctl.portal = None
        ctl.last = {}
        return ctl, op

    def test_it_refuses_while_a_portal_is_alive(self):
        import os
        from unittest import mock
        run = Path(tempfile.mkdtemp())
        ctl, op = self._controller(run)
        with mock.patch.object(op, "RUN_DIR", run), \
             mock.patch.object(ctl.__class__, "ap_running", lambda self: False), \
             mock.patch.object(ctl.__class__, "portal_running", lambda self: True):
            ok, msg = op.Controller.start_exam(ctl)
        self.assertFalse(ok)
        self.assertIn("NOT touched", msg)

    def test_it_refuses_while_the_radio_is_up(self):
        from unittest import mock
        run = Path(tempfile.mkdtemp())
        ctl, op = self._controller(run)
        with mock.patch.object(op, "RUN_DIR", run), \
             mock.patch.object(ctl.__class__, "ap_running", lambda self: True), \
             mock.patch.object(ctl.__class__, "portal_running", lambda self: False):
            ok, msg = op.Controller.start_exam(ctl)
        self.assertFalse(ok)
        self.assertIn("already running", msg)

    def test_ap_running_sees_a_per_radio_pid_file(self):
        from unittest import mock
        from themis import operator as op
        run = Path(tempfile.mkdtemp())
        (run / "hostapd-wlan1.pid").write_text(str(os.getpid()))
        ctl = op.Controller.__new__(op.Controller)
        with mock.patch.object(op, "RUN_DIR", run):
            self.assertTrue(op.Controller.ap_running(ctl),
                            "dual-band writes hostapd-<iface>.pid, never hostapd.pid")

    def test_archiving_a_live_journal_would_lose_the_roster(self):
        """The damage itself, so the guard above is anchored to a real harm."""
        d = Path(tempfile.mkdtemp())
        jp = d / "exam.jsonl"
        j = journal.Journal(jp)
        j.append("exam_open", {})
        for sid in ("s01", "s02", "s03"):
            j.append("register", {"student_id": sid, "mac": f"aa:bb:cc:00:00:{sid[-1]}"})
        before = len(list(j.read()))
        state.archive_previous(jp)
        j.append("presence_sample", {"macs": []})      # the still-running portal
        reopened = journal.Journal(jp)
        after = list(reopened.read())
        self.assertEqual(before, 4)
        self.assertEqual(len(after), 1, "the roster is gone from the active journal")
        self.assertEqual(after[0].seq, 0, "and the chain silently restarted at zero")
        self.assertTrue(reopened.verify().ok,
                        "while still verifying as intact -- which is exactly why "
                        "this needs a guard up front rather than an integrity "
                        "check afterwards")


if __name__ == "__main__":
    unittest.main(verbosity=2)
