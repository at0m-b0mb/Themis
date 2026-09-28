"""Tests for the portal and console.

This is the one module where a mistake is a security bug rather than a wrong
answer: it takes attacker-supplied strings over the network and renders them back
to a proctor. So the things pinned here are the refusals -- what the server will
NOT do -- more than the happy path.
"""

import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from themis import server as srv  # noqa: E402
from themis.journal import Journal  # noqa: E402
from themis.leases import Resolution  # noqa: E402
from themis.roster import build_roster  # noqa: E402

POLICY = {"ssid": "EXAM-ONLY", "profile": "airgap", "server_ip": "10.83.0.1",
          "ap_interface": None, "lease_file": "/nonexistent"}


class Harness(unittest.TestCase):
    """A real HTTP server on an ephemeral loopback port, with MAC resolution stubbed."""

    resolution = Resolution(ip="127.0.0.1", mac="a4:83:e7:1b:2c:3d", source="both_agree")

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.ctx = srv.Context(dict(POLICY), self.dir / "exam.jsonl")

        test = self
        class H(srv.StudentHandler):
            ctx = self.ctx
            def _resolve(self):
                return test.resolution
        class C(srv.ConsoleHandler):
            ctx = self.ctx

        self.student = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.console = ThreadingHTTPServer(("127.0.0.1", 0), C)
        # poll_interval defaults to 0.5s, and shutdown() blocks until the loop
        # notices -- 1s of teardown per test across two servers.
        for s in (self.student, self.console):
            threading.Thread(target=s.serve_forever, kwargs={"poll_interval": 0.01},
                             daemon=True).start()
        self.sport = self.student.server_address[1]
        self.cport = self.console.server_address[1]

    def tearDown(self):
        for s in (self.student, self.console):
            s.shutdown()
            s.server_close()      # without this the listening sockets leak

    def get(self, path, port=None, redirect=True):
        url = f"http://127.0.0.1:{port or self.sport}{path}"
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k): return None
        opener = urllib.request.build_opener() if redirect else urllib.request.build_opener(NoRedirect)
        try:
            r = opener.open(url, timeout=5)
            return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def post(self, path, fields, redirect=False):
        url = f"http://127.0.0.1:{self.sport}{path}"
        data = urllib.parse.urlencode(fields).encode()
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k): return None
        opener = urllib.request.build_opener() if redirect else urllib.request.build_opener(NoRedirect)
        try:
            r = opener.open(url, data=data, timeout=5)
            return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def register(self, sid="s01", name="Ada Lovelace", seat="3"):
        self.ctx._recent.clear()   # the rate limiter is per-IP and all tests share one
        return self.post("/register", {"student_id": sid, "name": name, "seat": seat})


class TestCaptivePortalBehaviour(Harness):
    def test_os_probe_urls_are_redirected_not_satisfied(self):
        # If these succeed, the OS decides it has internet and never shows the
        # sign-in sheet -- the portal would simply never appear.
        for probe in ("/hotspot-detect.html", "/generate_204", "/connecttest.txt",
                      "/ncsi.txt", "/canonical.html", "/success.txt"):
            with self.subTest(probe=probe):
                status, _ = self.get(probe, redirect=False)
                self.assertEqual(status, 302, f"{probe} must not look like success")

    def test_unknown_paths_get_the_blocked_page(self):
        status, body = self.get("/anything/else")
        self.assertEqual(status, 200)
        self.assertIn("Not available during the exam", body)
        self.assertIn("no route off this network", body)

    def test_blocked_page_says_vpns_cannot_help(self):
        _, body = self.get("/some/site")
        self.assertIn("including a VPN", body)


class TestRegistration(Harness):
    def test_unregistered_device_gets_the_form(self):
        status, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("Student ID", body)
        self.assertIn("Nothing is installed on your computer", body,
                      "the disclosure must be on the page the student actually reads")

    def test_valid_registration_is_journalled(self):
        status, _ = self.register()
        self.assertEqual(status, 302)
        regs = self.ctx.journal.events("register")
        self.assertEqual(len(regs), 1)
        self.assertEqual(regs[0].data["student_id"], "s01")
        self.assertEqual(regs[0].data["mac"], "a4:83:e7:1b:2c:3d")

    def test_client_cannot_supply_its_own_mac(self):
        # A browser can claim anything; only an observation counts.
        self.ctx._recent.clear()
        self.post("/register", {"student_id": "s02", "name": "Mallory",
                                "mac": "00:00:00:00:00:01"})
        rec = self.ctx.journal.events("register")[0].data
        self.assertEqual(rec["mac"], "a4:83:e7:1b:2c:3d",
                         "a client-supplied MAC must be ignored entirely")

    def test_registered_device_sees_its_own_page(self):
        self.register(name="Ada Lovelace")
        status, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("You are connected", body)
        self.assertIn("Ada Lovelace", body)

    def test_bad_student_ids_are_rejected(self):
        for bad in ("", "a", "x" * 40, "has space", "semi;colon", "../etc/passwd"):
            with self.subTest(sid=bad):
                status, _ = self.register(sid=bad)
                self.assertEqual(status, 400, f"{bad!r} should not be accepted")
        self.assertEqual(self.ctx.journal.events("register"), [])

    def test_empty_name_is_rejected(self):
        self.assertEqual(self.register(name="")[0], 400)

    def test_rate_limited_per_ip(self):
        self.ctx._recent.clear()
        first = self.post("/register", {"student_id": "s10", "name": "A"})
        second = self.post("/register", {"student_id": "s11", "name": "B"})
        self.assertEqual(first[0], 302)
        self.assertEqual(second[0], 429, "back-to-back registrations must be throttled")

    def test_post_to_anything_else_is_not_a_registration(self):
        self.assertEqual(self.post("/elsewhere", {"student_id": "s99", "name": "X"})[0], 404)


class TestRefusesToGuess(Harness):
    def test_unresolvable_device_is_refused_not_guessed(self):
        # Recording a binding against the wrong device is worse than asking the
        # student to raise their hand.
        self.resolution = Resolution(ip="127.0.0.1", mac=None, source="unknown")
        status, body = self.register()
        self.assertEqual(status, 409)
        self.assertIn("cannot identify your device", body)
        self.assertEqual(self.ctx.journal.events("register"), [],
                         "nothing may be written when the device is unknown")

    def test_conflicting_sources_are_also_refused(self):
        self.resolution = Resolution(ip="127.0.0.1", mac=None, source="conflict",
                                     lease_mac="a4:83:e7:1b:2c:3d",
                                     arp_mac="b8:27:eb:00:11:22")
        self.assertEqual(self.register()[0], 409)
        self.assertEqual(self.ctx.journal.events("register"), [])


class TestEscaping(Harness):
    PAYLOAD = '<script>alert(1)</script>'

    def test_name_is_escaped_on_the_student_page(self):
        self.register(name=self.PAYLOAD)
        _, body = self.get("/")
        self.assertNotIn(self.PAYLOAD, body)
        self.assertIn("&lt;script&gt;", body)

    def test_name_is_escaped_on_the_console(self):
        self.register(name=self.PAYLOAD)
        _, body = self.get("/", port=self.cport)
        self.assertNotIn(self.PAYLOAD, body)
        self.assertIn("&lt;script&gt;", body)

    def test_blocked_page_escapes_the_host_header(self):
        # The Host header is fully attacker-controlled and gets rendered back.
        req = urllib.request.Request(f"http://127.0.0.1:{self.sport}/x",
                                     headers={"Host": f"127.0.0.1:{self.sport}"})
        body = urllib.request.urlopen(req, timeout=5).read().decode()
        self.assertNotIn("<script>", body)


class TestConsole(Harness):
    def test_console_lists_registered_students(self):
        self.register(sid="s01", name="Ada Lovelace")
        _, body = self.get("/", port=self.cport)
        self.assertIn("Ada Lovelace", body)
        self.assertIn("s01", body)

    def test_console_states_that_it_decides_nothing(self):
        _, body = self.get("/", port=self.cport)
        self.assertIn("decides nothing", body)

    def test_dump_is_machine_readable_and_reports_the_chain(self):
        self.register()
        status, body = self.get("/dump.json", port=self.cport)
        self.assertEqual(status, 200)
        d = json.loads(body)
        self.assertIn("intact", d["chain"])
        self.assertEqual(len(d["head"]), 64)
        self.assertTrue(any(e["kind"] == "register" for e in d["events"]))

    def test_console_binds_loopback_only(self):
        self.assertEqual(self.console.server_address[0], "127.0.0.1",
                         "the console must not be reachable from the exam network")


class TestPresenceSampling(Harness):
    def test_sample_records_the_observed_macs(self):
        self.register()
        self.ctx.observe_macs = lambda: {"a4:83:e7:1b:2c:3d"}
        stop = threading.Event()
        t = threading.Thread(target=srv.presence_loop, args=(self.ctx, 0.05, stop), daemon=True)
        t.start()
        stop.wait(0.3); stop.set(); t.join(timeout=2)
        samples = self.ctx.journal.events("presence_sample")
        self.assertTrue(samples)
        self.assertIn("a4:83:e7:1b:2c:3d", samples[0].data["macs"])
        self.assertTrue(build_roster(self.ctx.journal).presence["s01"].online_now)

    def test_sampling_failure_does_not_stop_the_loop(self):
        calls = {"n": 0}
        def flaky():
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("hostapd went away")
            return {"a4:83:e7:1b:2c:3d"}
        self.ctx.observe_macs = flaky
        stop = threading.Event()
        t = threading.Thread(target=srv.presence_loop, args=(self.ctx, 0.05, stop), daemon=True)
        t.start()
        stop.wait(0.4); stop.set(); t.join(timeout=2)
        self.assertGreater(calls["n"], 1, "a failed sample must not kill sampling")
        self.assertTrue(self.ctx.journal.events("presence_sample"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
