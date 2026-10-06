"""Tests for the name-validating proxy.

The proxy is the only path off the exam network, so these pin the two properties
the whole design rests on:

  * a name is matched as a NAME -- 'evil-canvas.jhu.edu' must not satisfy an
    entry for 'canvas.jhu.edu', and that is one character away from being wrong;
  * anything that is not a readable ClientHello is refused, because that is
    exactly what a raw tunnel on port 443 looks like.

The SNI parser reads attacker-controlled length fields, so it is also fuzzed
against truncation and nonsense. A parser that reads past its buffer here would
be reachable by any student on the network.
"""

import socket
import ssl
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from themis.proxy import (          # noqa: E402
    HelloIncomplete, NotTLS, decide, host_matches, parse_sni,
)


def real_client_hello(server_name: str) -> bytes:
    """A genuine ClientHello from the stdlib TLS stack.

    Hand-rolled bytes would only prove the parser agrees with whatever this file
    believes the format to be. Making Python actually offer a handshake means the
    fixture is produced by a real implementation.
    """
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    captured = {}

    def accept():
        conn, _ = listener.accept()
        conn.settimeout(3)
        buf = b""
        # Read the way the handler does: until the SNI parses, because a long
        # name pushes the ClientHello across more than one segment.
        while len(buf) < 16384:
            try:
                parse_sni(buf)
                break
            except HelloIncomplete:
                pass
            except NotTLS:
                break
            try:
                chunk = conn.recv(65536)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
        captured["hello"] = buf
        conn.close()

    t = threading.Thread(target=accept)
    t.start()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection(("127.0.0.1", port))
    try:
        ctx.wrap_socket(sock, server_hostname=server_name)
    except OSError:
        pass            # the peer never replies; we only want the ClientHello
    t.join(5)
    listener.close()
    return captured.get("hello", b"")


class TestSniParsing(unittest.TestCase):
    def test_reads_the_name_a_real_client_sent(self):
        for name in ("canvas.jhu.edu", "login.microsoftonline.com",
                     "a.b.c.d.example.com"):
            with self.subTest(name=name):
                self.assertEqual(parse_sni(real_client_hello(name)), name)

    def test_a_long_name_still_parses(self):
        # 3 x 60-char labels: legal, and large enough that the hello arrives in
        # more than one read on some systems.
        name = ".".join(["x" * 60] * 3) + ".example.com"
        self.assertEqual(parse_sni(real_client_hello(name)), name)

    def test_truncation_says_incomplete_rather_than_guessing(self):
        hello = real_client_hello("canvas.jhu.edu")
        for cut in (1, 3, 5, 40, len(hello) - 1):
            with self.subTest(cut=cut):
                with self.assertRaises(HelloIncomplete):
                    parse_sni(hello[:cut])

    def test_non_tls_is_refused(self):
        # Every one of these is something a student could aim at port 443, and
        # the last two are what a tunnel trying to look like nothing looks like.
        for label, data in (
            ("http", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
            ("ssh", b"SSH-2.0-OpenSSH_9.6\r\n"),
            ("openvpn-tcp", bytes([0, 14, 0x38, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0])),
            ("zeros", b"\x00" * 300),
            ("tls-header-then-junk", b"\x16\x03\x01\x00\x10" + b"\x01" * 16),
            ("absurd-record-length", b"\x16\x03\x01\xff\xff" + b"\x01" * 100),
        ):
            with self.subTest(label=label):
                with self.assertRaises((NotTLS, HelloIncomplete)):
                    parse_sni(data)

    def test_a_hello_without_sni_is_none_not_an_error(self):
        # Distinguishable from "not TLS": one is refused as unparseable, the
        # other is a valid handshake that simply cannot be checked. Both are
        # rejected by the handler, but for different reasons it logs separately.
        # Lengths computed, not written by hand: a hardcoded one that disagrees
        # with the bytes makes the parser raise, and the test then "proves"
        # something about a malformed hello rather than about a missing SNI.
        body = (b"\x03\x03" + b"\x00" * 32   # version + random
                + b"\x00"                    # legacy_session_id: empty
                + b"\x00\x02\x13\x01"        # one cipher suite
                + b"\x01\x00"                # compression: null
                + b"\x00\x00")               # extensions block, empty
        ch = b"\x01" + len(body).to_bytes(3, "big") + body
        rec = b"\x16\x03\x01" + len(ch).to_bytes(2, "big") + ch
        self.assertIsNone(parse_sni(rec))

    def test_truncated_lengths_inside_the_hello_do_not_read_past_the_buffer(self):
        """Every length here comes from the wire, so each is fuzzed short."""
        hello = real_client_hello("canvas.jhu.edu")
        body = hello[5:]
        for n in range(4, min(len(body), 120)):
            rec = b"\x16\x03\x01" + n.to_bytes(2, "big") + body[:n]
            try:
                parse_sni(rec)
            except (NotTLS, HelloIncomplete):
                pass
            except Exception as e:          # noqa: BLE001
                self.fail(f"truncating to {n} raised {type(e).__name__}: {e}")


class TestNameMatching(unittest.TestCase):
    ALLOW = ["canvas.jhu.edu"]

    def test_exact_and_subdomain_match(self):
        for host in ("canvas.jhu.edu", "CANVAS.JHU.EDU", "canvas.jhu.edu.",
                     "files.canvas.jhu.edu"):
            with self.subTest(host=host):
                self.assertTrue(host_matches(host, self.ALLOW))

    def test_a_prefix_is_not_a_subdomain(self):
        # The whole point of anchoring the suffix on a dot. Without it, anyone
        # who can register this name reaches the exam network.
        self.assertFalse(host_matches("evil-canvas.jhu.edu", self.ALLOW))

    def test_a_parent_domain_is_not_matched(self):
        self.assertFalse(host_matches("jhu.edu", self.ALLOW))
        self.assertFalse(host_matches("instructure.com", ["jhu.instructure.com"]))

    def test_the_name_cannot_be_a_suffix_of_an_attacker_domain(self):
        self.assertFalse(host_matches("canvas.jhu.edu.evil.net", self.ALLOW))

    def test_separate_microsoft_hosts_are_separate(self):
        # login.microsoft.com is NOT a subdomain of login.microsoftonline.com,
        # and the real login chain needs both -- so getting this wrong either
        # breaks the exam or opens a host nobody intended.
        self.assertFalse(host_matches("login.microsoft.com",
                                      ["login.microsoftonline.com"]))
        self.assertTrue(host_matches("login.microsoft.com", ["login.microsoft.com"]))

    def test_empty_and_missing_names_never_match(self):
        for host in ("", None, ".", ".."):
            with self.subTest(host=host):
                self.assertFalse(host_matches(host, self.ALLOW))

    def test_an_empty_allowlist_matches_nothing(self):
        self.assertFalse(host_matches("canvas.jhu.edu", []))
        self.assertFalse(host_matches("canvas.jhu.edu", None))


class TestDecide(unittest.TestCase):
    ALLOW = ["canvas.jhu.edu"]
    BLOCK = ["chatgpt.com", "perplexity.ai"]

    def test_allow_mode_permits_only_the_list(self):
        self.assertTrue(decide("canvas.jhu.edu", "allow", self.ALLOW, self.BLOCK)[0])
        for host in ("google.com", "chatgpt.com", "login.microsoft.com"):
            with self.subTest(host=host):
                self.assertFalse(decide(host, "allow", self.ALLOW, self.BLOCK)[0])

    def test_block_mode_permits_everything_but_the_list(self):
        for host in ("google.com", "canvas.jhu.edu", "notchatgpt.com"):
            with self.subTest(host=host):
                self.assertTrue(decide(host, "block", self.ALLOW, self.BLOCK)[0])
        for host in ("chatgpt.com", "sub.chatgpt.com", "perplexity.ai"):
            with self.subTest(host=host):
                self.assertFalse(decide(host, "block", self.ALLOW, self.BLOCK)[0])

    def test_an_empty_allowlist_in_allow_mode_refuses_everything(self):
        # Fail CLOSED. An empty list must not be read as "no restrictions".
        self.assertFalse(decide("canvas.jhu.edu", "allow", [], [])[0])

    def test_an_empty_blocklist_in_block_mode_permits_everything(self):
        # And fail OPEN here, which is the honest reading of "block these" with
        # nothing listed -- preflight warns about it rather than guessing.
        self.assertTrue(decide("anything.example.com", "block", [], [])[0])

    def test_the_reason_is_reported_not_just_the_verdict(self):
        # The verdict string goes into the exam record, where "blocked" without
        # which rule applied is not reviewable.
        for mode, host in (("allow", "google.com"), ("block", "chatgpt.com")):
            _, why = decide(host, mode, self.ALLOW, self.BLOCK)
            self.assertTrue(why.strip(), "a refusal must say which rule applied")


if __name__ == "__main__":
    unittest.main()
