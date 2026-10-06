"""Tests for the portal and console.

This is the one module where a mistake is a security bug rather than a wrong
answer: it takes attacker-supplied strings over the network and renders them back
to a proctor. So the things pinned here are the refusals -- what the server will
NOT do -- more than the happy path.
"""

import json
import time
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

    def test_name_is_escaped_in_the_console_api(self):
        # The console's script interpolates these values into innerHTML, so the
        # escaping has to happen server-side, in the JSON itself.
        self.register(name=self.PAYLOAD)
        _, body = self.get("/api/state", port=self.cport)
        self.assertNotIn(self.PAYLOAD, body)
        d = json.loads(body)
        self.assertIn("&lt;script&gt;", d["students"][0]["name"])

    def test_blocked_page_escapes_the_host_header(self):
        # The Host header is fully attacker-controlled and gets rendered back.
        req = urllib.request.Request(f"http://127.0.0.1:{self.sport}/x",
                                     headers={"Host": f"127.0.0.1:{self.sport}"})
        body = urllib.request.urlopen(req, timeout=5).read().decode()
        self.assertNotIn("<script>", body)


class TestConsole(Harness):
    def test_api_lists_registered_students(self):
        self.register(sid="s01", name="Ada Lovelace", seat="3")
        status, body = self.get("/api/state", port=self.cport)
        self.assertEqual(status, 200)
        d = json.loads(body)
        self.assertEqual(d["counts"]["registered"], 1)
        st = d["students"][0]
        self.assertEqual(st["name"], "Ada Lovelace")
        self.assertEqual(st["student_id"], "s01")
        self.assertEqual(st["seat"], "3")
        self.assertTrue(d["chain_ok"])
        self.assertEqual(len(d["head"]), 64)

    def test_console_shell_renders_without_data(self):
        status, body = self.get("/", port=self.cport)
        self.assertEqual(status, 200)
        self.assertIn("Proctor console", body)
        self.assertIn("/api/state", body, "the shell must know where to fetch state")

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
        self.ctx.observe_macs = lambda: ({"a4:83:e7:1b:2c:3d"}, "hostapd")
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
            return {"a4:83:e7:1b:2c:3d"}, "hostapd"
        self.ctx.observe_macs = flaky
        stop = threading.Event()
        t = threading.Thread(target=srv.presence_loop, args=(self.ctx, 0.05, stop), daemon=True)
        t.start()
        stop.wait(0.4); stop.set(); t.join(timeout=2)
        self.assertGreater(calls["n"], 1, "a failed sample must not kill sampling")
        self.assertTrue(self.ctx.journal.events("presence_sample"))


class TestConsoleApiAndReport(Harness):
    """The API feeds a script that writes into innerHTML, and the report is read by
    people who are not looking at this program. Both have to be right."""

    def test_every_api_string_is_html_escaped(self):
        self.register(sid="s01", name='Bobby <b>Tables</b> & "co"', seat="<i>4</i>")
        d = json.loads(self.get("/api/state", port=self.cport)[1])
        st = d["students"][0]
        for field in ("name", "seat", "student_id", "mac"):
            self.assertNotIn("<", st[field], f"{field} reached the API unescaped")
        self.assertIn("&amp;", st["name"])

    def test_anomaly_text_is_escaped_too(self):
        self.register(sid="s01", name="<script>a</script>")
        self.resolution = Resolution(ip="127.0.0.1", mac="b8:27:eb:00:11:22",
                                     source="lease_only")
        self.register(sid="s02", name="Second")
        d = json.loads(self.get("/api/state", port=self.cport)[1])
        self.assertTrue(d["anomalies"], "an uncorroborated registration should flag")
        for a in d["anomalies"]:
            self.assertNotIn("<script>", a["detail"])
            self.assertTrue(a["innocent"], "an anomaly with no innocent reading is an accusation")

    def test_counts_reflect_presence(self):
        self.register(sid="s01", name="A")
        self.ctx.journal.append("presence_sample", {"macs": ["a4:83:e7:1b:2c:3d"]})
        d = json.loads(self.get("/api/state", port=self.cport)[1])
        self.assertEqual(d["counts"]["online"], 1)
        self.assertEqual(d["counts"]["offline"], 0)

    def test_elapsed_clock_needs_an_open_event(self):
        self.register()
        self.assertEqual(json.loads(self.get("/api/state", port=self.cport)[1])["elapsed"], "\u2014")
        self.ctx.journal.append("exam_open", {}, ts=time.time() - 3725)
        # exam_open arriving late still anchors the clock when the roster is rebuilt.
        el = json.loads(self.get("/api/state", port=self.cport)[1])["elapsed"]
        self.assertRegex(el, r"^\d\d:\d\d:\d\d$")

    def test_report_explains_how_to_read_itself(self):
        self.register(sid="s01", name="Ada Lovelace")
        status, body = self.get("/report.txt", port=self.cport)
        self.assertEqual(status, 200)
        self.assertIn("HOW TO READ THIS", body)
        self.assertIn("a gap is a RANGE", body)
        self.assertIn("A gap is not misconduct", body)
        self.assertIn("Ada Lovelace", body)
        self.assertIn("chain head", body)

    def test_report_warns_that_truncation_is_undetectable(self):
        body = self.get("/report.txt", port=self.cport)[1]
        self.assertIn("cannot prove none was removed", body)

    def test_api_reports_a_broken_chain_rather_than_hiding_it(self):
        self.register(sid="s01", name="Ada Lovelace")
        path = self.ctx.journal.path
        before = path.read_text()
        self.assertIn("Ada Lovelace", before, "precondition: the name is on disk")

        # Edit a recorded name after the fact, as someone altering the record would.
        path.write_text(before.replace("Ada Lovelace", "Grace Hopper"))

        d = json.loads(self.get("/api/state", port=self.cport)[1])
        self.assertFalse(d["chain_ok"], "a tampered chain must be reported, not hidden")
        self.assertIn("BROKEN", d["chain"].upper())
        self.assertIn("altered", d["chain"])

        # And the console's own report must carry the same warning, since that is
        # the file a student or a reviewer actually reads.
        self.assertIn("CHAIN BROKEN", self.get("/report.txt", port=self.cport)[1])


class TestPresenceSourceIsHonest(Harness):
    """If hostapd dies mid-exam, presence falls back to DHCP leases -- which last
    hours. Without saying so, the console would show 19 calm green tiles over a dead
    radio. The source travels with every sample."""

    def test_sample_records_where_it_came_from(self):
        self.register()
        self.ctx.observe_macs = lambda: ({"a4:83:e7:1b:2c:3d"}, "hostapd")
        stop = threading.Event()
        t = threading.Thread(target=srv.presence_loop, args=(self.ctx, 0.05, stop), daemon=True)
        t.start(); stop.wait(0.3); stop.set(); t.join(timeout=2)
        self.assertEqual(self.ctx.journal.events("presence_sample")[0].data["source"], "hostapd")

    def test_degradation_is_reported_when_an_ap_was_expected(self):
        self.ctx.ap_interface = "wlan0"
        self.register()
        self.ctx.journal.append("presence_sample", {"macs": [], "source": "leases"})
        d = json.loads(self.get("/api/state", port=self.cport)[1])
        self.assertTrue(d["presence_degraded"])
        self.assertEqual(d["presence_source"], "leases")

    def test_leases_are_not_degraded_when_there_is_no_ap(self):
        # On a host with no AP interface, leases are simply the source, not a fault.
        self.ctx.ap_interface = None
        self.register()
        self.ctx.journal.append("presence_sample", {"macs": [], "source": "leases"})
        d = json.loads(self.get("/api/state", port=self.cport)[1])
        self.assertFalse(d["presence_degraded"])

    def test_hostapd_source_is_not_degraded(self):
        self.ctx.ap_interface = "wlan0"
        self.register()
        self.ctx.journal.append("presence_sample", {"macs": [], "source": "hostapd"})
        d = json.loads(self.get("/api/state", port=self.cport)[1])
        self.assertFalse(d["presence_degraded"])


class TestActivityAttribution(unittest.TestCase):
    """What the NETWORK was asked for, grouped by the student who asked.

    Names only, and never page contents: the proxy splices TLS rather than
    terminating it, so a hostname is the most this can ever know. The console
    says "asked for" rather than "is doing" for that reason.
    """

    def _log(self, lines):
        p = Path(tempfile.mkdtemp()) / "decisions.log"
        p.write_text("\n".join(lines) + "\n")
        return p

    def test_groups_by_client_and_counts_both_verdicts(self):
        from themis.activity import read_activity
        p = self._log([
            "2026-10-05 22:00:01 allowed  10.83.0.70      canvas.jhu.edu  on the exam allowlist",
            "2026-10-05 22:00:02 allowed  10.83.0.70      canvas.jhu.edu  on the exam allowlist",
            "2026-10-05 22:00:03 blocked  10.83.0.70      chatgpt.com  not on the exam allowlist",
            "2026-10-05 22:00:04 blocked  10.83.0.71      www.perplexity.ai  not on the exam allowlist",
        ])
        a = read_activity(p)
        self.assertEqual(sorted(a), ["10.83.0.70", "10.83.0.71"])
        self.assertEqual(a["10.83.0.70"].allowed_total, 2)
        self.assertEqual(a["10.83.0.70"].blocked_total, 1)
        self.assertEqual(a["10.83.0.70"].sites["canvas.jhu.edu"].allowed, 2)
        self.assertEqual(a["10.83.0.70"].latest_allowed, "canvas.jhu.edu")

    def test_a_hostname_off_the_wire_is_validated_not_trusted(self):
        # The host comes from a student's ClientHello, and the console puts it on
        # screen. Anything that is not a hostname is counted but never named.
        from themis.activity import read_activity
        p = self._log([
            "2026-10-05 22:00:01 blocked  10.83.0.70      (no  SNI)",
            "2026-10-05 22:00:02 blocked  10.83.0.70      <script>alert(1)</script>  x",
            "2026-10-05 22:00:03 blocked  10.83.0.70      ok.example.com  x",
        ])
        a = read_activity(p)["10.83.0.70"]
        self.assertEqual(sorted(a.sites), ["ok.example.com"])
        self.assertEqual(a.unnamed, 2)
        self.assertEqual(a.blocked_total, 3, "refusals still count even when unnamed")

    def test_a_missing_log_is_empty_not_an_error(self):
        # Every air-gapped exam runs with no proxy at all; the console must still
        # render rather than fail to load.
        from themis.activity import read_activity
        self.assertEqual(read_activity(Path("/nonexistent/decisions.log")), {})

    def test_malformed_lines_are_skipped(self):
        from themis.activity import read_activity
        p = self._log(["garbage", "", "2026-13-45 99:99:99 allowed 1.2.3.4 x  y",
                       "2026-10-05 22:00:01 allowed  10.83.0.70      canvas.jhu.edu  ok"])
        a = read_activity(p)
        self.assertEqual(list(a), ["10.83.0.70"])

    def test_the_current_address_wins_over_the_registered_one(self):
        """DHCP hands out a new address after a renewal.

        Attributing by the stale one shows a student doing nothing -- or, worse,
        shows them doing whatever the next device to get that address did.
        """
        from themis.activity import current_ips
        from types import SimpleNamespace
        regs = {"s1": SimpleNamespace(mac="aa:bb:cc:00:00:01", ip="10.83.0.50")}
        leases = [SimpleNamespace(mac="aa:bb:cc:00:00:01", ip="10.83.0.99")]
        self.assertEqual(current_ips(leases, regs)["s1"], "10.83.0.99")
        self.assertEqual(current_ips([], regs)["s1"], "10.83.0.50",
                         "and the registered address is the fallback")


if __name__ == "__main__":
    unittest.main(verbosity=2)
