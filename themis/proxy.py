"""The only way off the exam network, and it validates names rather than addresses.

Why this exists
---------------
Profile 'allowlist' filters egress in two layers that disagree with each other:
dnsmasq permits NAMES, nftables permits ADDRESSES. For a CDN-hosted service --
which is every Canvas instance; jhu.instructure.com is four rotating CloudFront
addresses -- that pairing is both fragile and porous:

  * the address set goes stale the moment the CDN rotates, and the exam then
    fails closed on the one service it was supposed to allow;
  * every other tenant of that CDN shares those addresses, so a student who
    changes the TLS SNI reaches them through a rule that looks like it says
    "Canvas only";
  * a self-hosted VPN listening on 443 is indistinguishable from a web server,
    so an address allowlist wide enough to include a CDN is wide enough to
    include somebody's relay sitting on it.

This proxy replaces that with one layer that filters the thing we actually mean.
A student's TLS connection arrives here (DNS sinkholes every name to this host,
and nftables redirects any stray HTTPS to it as well). We read the SNI out of the
ClientHello, check it against the allowlist, and then -- the load-bearing part --
**resolve that name ourselves** and connect to what it resolves to. The client
never chooses the destination address. So:

  * SNI not on the list  -> the connection is reset, immediately, not hung;
  * SNI on the list but aimed at a student's own server -> we ignore where they
    aimed and connect to the real name, so their server is simply never reached;
  * no SNI at all, or not TLS -> reset. That is what a raw VPN on 443 looks like.

What it deliberately does NOT do
--------------------------------
It does not terminate TLS. There is no certificate, no decryption, and nothing
here can read a student's traffic: after the ClientHello is validated the two
sockets are spliced byte-for-byte, and the browser completes a normal handshake
with the real server and validates the real certificate. That keeps the design
invariant -- no Themis component inspects a student's device or their content --
and it also means no trusted root has to be pushed to 19 unknown laptops, which
would not work anyway.

Its ceiling, stated plainly
---------------------------
  * A relay hosted *at an allowlisted name* defeats it. With only
    jhu.instructure.com permitted that means somebody would have to host it
    inside JHU's Canvas, but Canvas's own messaging is a student-to-student
    channel and no network control can see it. See docs/THREAT_MODEL.md.
  * Encrypted ClientHello (ECH) would hide the SNI. It is not negotiable here
    because it is advertised through DNS HTTPS/SVCB records and our resolver
    answers none -- but that is a consequence of the sinkhole, not of this
    program, so preflight checks it rather than assuming it.
  * A phone on cellular and a local model on a laptop are untouched, exactly as
    everywhere else in this project.
"""

from __future__ import annotations

import argparse
import json
import selectors
import socket
import socketserver
import struct
import sys
import threading
import time
from pathlib import Path

try:
    from themis.journal import Journal
except ImportError:                                    # running from the repo root
    from journal import Journal                        # type: ignore

# A ClientHello is normally well under 1 KiB, but a client offering many
# extensions and a post-quantum key share can exceed 4 KiB and may arrive split
# across several TCP segments. Read up to this much while looking for the SNI.
MAX_HELLO = 16384
HELLO_TIMEOUT = 5.0            # seconds to wait for a complete ClientHello
CONNECT_TIMEOUT = 8.0          # seconds to reach the upstream server
IDLE_TIMEOUT = 300.0           # a spliced connection idle this long is dropped
CHUNK = 65536

# One journal event per (client, name) per this many seconds. Without it, a
# laptop whose background apps retry every few seconds would bury the record of
# what a student actually did under thousands of identical lines.
JOURNAL_DEDUP_WINDOW = 60.0


# --------------------------------------------------------------------------- #
# TLS ClientHello parsing. Enough of the format to find one extension, and no
# more -- this never decrypts anything.

class HelloIncomplete(Exception):
    """Not enough bytes yet. Read more and try again."""


class NotTLS(Exception):
    """This is not a TLS ClientHello and never will be."""


def _u16(b: bytes, i: int) -> int:
    return struct.unpack_from("!H", b, i)[0]


def parse_sni(data: bytes) -> str | None:
    """The SNI host from a TLS ClientHello.

    Returns the lowercased name, or None when the handshake is a valid
    ClientHello that simply carries no SNI extension. Raises HelloIncomplete if
    more bytes are needed, NotTLS if this cannot become a ClientHello.

    Every length here is read from attacker-controlled bytes, so each one is
    bounds-checked against what we actually hold. A malformed record must raise,
    never read past the buffer and never loop.
    """
    if len(data) < 5:
        raise HelloIncomplete
    if data[0] != 0x16:                       # not handshake -> not TLS at all
        raise NotTLS
    if data[1] != 0x03:                       # not SSL 3.x / TLS 1.x record
        raise NotTLS
    rec_len = _u16(data, 3)
    if rec_len == 0 or rec_len > MAX_HELLO:
        raise NotTLS
    if len(data) < 5 + rec_len:
        raise HelloIncomplete
    body = data[5:5 + rec_len]

    if len(body) < 4:
        raise NotTLS
    if body[0] != 0x01:                       # not ClientHello
        raise NotTLS
    hs_len = int.from_bytes(body[1:4], "big")
    ch = body[4:4 + hs_len]
    if len(ch) < hs_len:
        # The ClientHello is fragmented across records. We do not reassemble
        # multi-record handshakes: refusing is safe and no real client does it.
        raise NotTLS

    p = 2 + 32                                # client_version + random
    if p + 1 > len(ch):
        raise NotTLS
    p += 1 + ch[p]                            # legacy_session_id
    if p + 2 > len(ch):
        raise NotTLS
    p += 2 + _u16(ch, p)                      # cipher_suites
    if p + 1 > len(ch):
        raise NotTLS
    p += 1 + ch[p]                            # compression_methods
    if p + 2 > len(ch):
        return None                           # no extensions block: no SNI
    ext_end = min(len(ch), p + 2 + _u16(ch, p))
    p += 2

    while p + 4 <= ext_end:
        etype = _u16(ch, p)
        elen = _u16(ch, p + 2)
        p += 4
        if p + elen > ext_end:
            raise NotTLS
        if etype == 0x0000:                   # server_name
            ext = ch[p:p + elen]
            if len(ext) < 5:
                raise NotTLS
            list_end = min(len(ext), 2 + _u16(ext, 0))
            q = 2
            while q + 3 <= list_end:
                name_type = ext[q]
                nlen = _u16(ext, q + 1)
                q += 3
                if q + nlen > list_end:
                    raise NotTLS
                if name_type == 0:            # host_name
                    try:
                        return ext[q:q + nlen].decode("ascii").lower().rstrip(".")
                    except UnicodeDecodeError:
                        raise NotTLS
                q += nlen
            return None
        p += elen
    return None


# --------------------------------------------------------------------------- #

def host_matches(host: str, names) -> bool:
    """Exact name, or a subdomain of one.

    Suffix matching is anchored on a dot so that an entry for 'canvas.jhu.edu'
    cannot be satisfied by 'evil-canvas.jhu.edu' -- which would otherwise be a
    one-character bypass that reads as correct.
    """
    h = (host or "").lower().rstrip(".")
    if not h:
        return False
    for pat in names or ():
        p = str(pat).lower().lstrip("*").lstrip(".").rstrip(".")
        if p and (h == p or h.endswith("." + p)):
            return True
    return False


# Kept as the old name so existing callers and tests do not break.
def host_allowed(host: str, allow) -> bool:
    return host_matches(host, allow)


def decide(host: str, mode: str, allow, block) -> tuple[bool, str]:
    """(permitted, why). The only policy decision in this program.

    Two directions, and they are not symmetrical. An allowlist is a statement
    about what the exam needs; a blocklist is a guess about what a student might
    try, and every site nobody thought of is permitted by it. The verdict string
    goes into the journal, so it says which rule applied, not merely yes or no.
    """
    if mode == "block":
        if host_matches(host, block):
            return False, "on the exam blocklist"
        return True, "not on the blocklist"
    if host_matches(host, allow):
        return True, "on the exam allowlist"
    return False, "not on the exam allowlist"


def _reset(sock) -> None:
    """Close with a TCP RST instead of a FIN.

    A dropped packet leaves a student watching a spinner for thirty seconds and
    concluding the exam network is broken. A reset tells the browser at once,
    which is also what makes the operating system's captive-portal detection fire
    instead of silently retrying.
    """
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                        struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _splice(a: socket.socket, b: socket.socket) -> None:
    """Copy bytes both ways until either side is done. Nothing is inspected."""
    for s in (a, b):
        s.settimeout(None)
    sel = selectors.DefaultSelector()
    sel.register(a, selectors.EVENT_READ, b)
    sel.register(b, selectors.EVENT_READ, a)
    live = 2
    try:
        while live:
            events = sel.select(timeout=IDLE_TIMEOUT)
            if not events:
                return                        # idle too long
            for key, _ in events:
                src, dst = key.fileobj, key.data
                try:
                    chunk = src.recv(CHUNK)
                except OSError:
                    return
                if not chunk:
                    try:
                        sel.unregister(src)
                    except (KeyError, ValueError):
                        pass
                    live -= 1
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue
                try:
                    dst.sendall(chunk)
                except OSError:
                    return
    finally:
        sel.close()


class _Recorder:
    """Writes what was allowed and refused, and keeps the journal readable.

    The journal is the artifact a TA reviews and a student is entitled to see, so
    it records decisions, not traffic: a name and a verdict, never content.
    """

    def __init__(self, journal: Journal | None, logfile: Path | None):
        self.journal = journal
        self.logfile = logfile
        self._lock = threading.Lock()
        self._last: dict[tuple[str, str], tuple[float, int]] = {}

    def _line(self, text: str) -> None:
        if not self.logfile:
            return
        try:
            with self.logfile.open("a", encoding="utf-8") as fh:
                fh.write(text + "\n")
        except OSError:
            pass

    def record(self, kind: str, client: str, host: str | None, detail: str) -> None:
        name = host or "(no SNI)"
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self._line(f"{stamp} {kind:<8} {client:<15} {name}  {detail}")
        if not self.journal:
            return
        key = (client, name)
        now = time.time()
        with self._lock:
            seen_at, repeats = self._last.get(key, (0.0, 0))
            if now - seen_at < JOURNAL_DEDUP_WINDOW:
                self._last[key] = (seen_at, repeats + 1)
                return
            self._last[key] = (now, 0)
        try:
            self.journal.append(f"net.{kind}", {
                "client": client, "host": name, "detail": detail,
                "repeats_suppressed": repeats,
            })
        except OSError:
            pass


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        cfg = self.server.themis                     # type: ignore[attr-defined]
        rec: _Recorder = cfg["recorder"]
        client_ip = self.client_address[0]
        sock = self.request

        # --- read just enough to find the SNI ---
        buf = b""
        sock.settimeout(HELLO_TIMEOUT)
        host = None
        try:
            while True:
                try:
                    host = parse_sni(buf)
                    break
                except HelloIncomplete:
                    pass
                except NotTLS:
                    rec.record("blocked", client_ip, None,
                               "not a TLS ClientHello -- a raw tunnel on 443 looks "
                               "exactly like this")
                    return _reset(sock)
                if len(buf) >= MAX_HELLO:
                    rec.record("blocked", client_ip, None, "ClientHello too large")
                    return _reset(sock)
                chunk = sock.recv(CHUNK)
                if not chunk:
                    rec.record("blocked", client_ip, None,
                               "closed before sending a ClientHello")
                    return _reset(sock)
                buf += chunk
        except (socket.timeout, TimeoutError):
            rec.record("blocked", client_ip, None, "no ClientHello within "
                       f"{HELLO_TIMEOUT:g}s")
            return _reset(sock)
        except OSError:
            return _reset(sock)

        if host is None:
            rec.record("blocked", client_ip, None,
                       "TLS without SNI -- cannot be checked, so it is refused")
            return _reset(sock)

        permitted, why = decide(host, cfg["mode"], cfg["allow"], cfg["block"])
        if not permitted:
            rec.record("blocked", client_ip, host, why)
            return _reset(sock)

        # --- resolve the NAME ourselves. This is the control. ---
        # The client's chosen destination address is discarded: if a student
        # points jhu.instructure.com at their own relay, we still connect to
        # whatever the real name resolves to, so the relay is never reached.
        try:
            upstream = socket.create_connection((host, cfg["upstream_port"]),
                                                timeout=CONNECT_TIMEOUT)
        except socket.gaierror as e:
            rec.record("failed", client_ip, host, f"allowlisted but did not resolve: {e}")
            return _reset(sock)
        except OSError as e:
            rec.record("failed", client_ip, host, f"allowlisted but unreachable: {e}")
            return _reset(sock)

        peer = upstream.getpeername()[0]
        rec.record("allowed", client_ip, host, f"{why}; spliced to {peer}")
        try:
            upstream.sendall(buf)                    # replay the ClientHello
            _splice(sock, upstream)
        except OSError:
            pass
        finally:
            for s in (upstream, sock):
                try:
                    s.close()
                except OSError:
                    pass


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    # A class of 19 with background apps retrying produces bursts; a short
    # backlog turns those into connection failures that look like the network
    # rather than like the policy.
    request_queue_size = 128


def serve(*, bind: str, port: int, allow, block, mode: str, upstream_port: int,
          journal_path: Path | None, logfile: Path | None,
          policy_path: Path | None = None) -> int:
    journal = Journal(journal_path) if journal_path else None
    rec = _Recorder(journal, logfile)
    srv = _Server((bind, port), _Handler)
    srv.themis = {                                   # type: ignore[attr-defined]
        "allow": list(allow), "block": list(block), "mode": mode,
        "upstream_port": upstream_port, "recorder": rec,
    }

    def reload_lists(_sig=None, _frm=None) -> None:
        """Re-read the lists from the policy on SIGHUP.

        A domain the exam genuinely needs will be discovered the first time a
        student hits it, which is mid-exam. Requiring a restart to add it would
        mean dropping every student off the network to fix a one-line omission,
        so the lists are swapped in place instead. The mode is deliberately NOT
        reloaded: switching between allow and block while an exam is running is
        a different decision and should be a deliberate restart.
        """
        if not policy_path:
            return
        try:
            pol = json.loads(policy_path.read_text())
        except (OSError, json.JSONDecodeError) as e:
            print(f"  reload failed, keeping the lists in force: {e}", file=sys.stderr)
            return
        def names(key):
            return [n for n in (pol.get(key) or []) if not str(n).startswith("_")]
        cfg = srv.themis                             # type: ignore[attr-defined]
        cfg["allow"], cfg["block"] = names("allow_dns_names"), names("block_dns_names")
        which = "blocked" if cfg["mode"] == "block" else "allowed"
        shown = cfg["block"] if cfg["mode"] == "block" else cfg["allow"]
        print(f"  reloaded: {which} = {', '.join(shown) or '(empty)'}", flush=True)

    try:
        import signal
        signal.signal(signal.SIGHUP, reload_lists)
    except (ImportError, ValueError, OSError):
        pass

    def _watch_policy() -> None:
        """Reload whenever the policy file changes on disk.

        A signal is easy to forget and easy to send to the wrong pid, and
        forgetting it produces the most confusing failure available here: the
        file says the site is allowed, the operator panel says it is allowed,
        and the student is still refused -- with nothing anywhere reporting a
        disagreement. Watching the mtime closes that gap, so editing the list by
        any route takes effect within a couple of seconds whether or not anybody
        remembers to signal anything.
        """
        last = None
        while True:
            try:
                stamp = policy_path.stat().st_mtime
            except OSError:
                stamp = None
            if stamp is not None and last is not None and stamp != last:
                print("  policy.json changed on disk", flush=True)
                reload_lists()
            last = stamp
            time.sleep(2.0)

    if policy_path:
        threading.Thread(target=_watch_policy, daemon=True).start()
    print(f"themis-proxy on {bind}:{port}")
    if mode == "block":
        print(f"  mode         BLOCKLIST -- everything works except the names below")
        print(f"  blocked      {', '.join(block) or '(nothing: the whole web is open)'}")
    else:
        print(f"  mode         ALLOWLIST -- only the names below work")
        print(f"  allowed      {', '.join(allow) or '(nothing -- everything is refused)'}")
    print(f"  upstream     port {upstream_port}, resolved here and not by the client")
    if logfile:
        print(f"  decisions    {logfile}")
    if journal_path:
        print(f"  journal      {journal_path}")
    print()
    print("  Names are checked, addresses are not trusted, and TLS is not")
    print("  terminated -- no certificate is involved and no content is read.")
    if policy_path:
        print(f"  Watching {policy_path.name}: list changes apply within ~2s,")
        print(f"  with no restart and nobody disconnected. SIGHUP also works.")
    print()
    try:
        srv.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        print("\nthemis-proxy stopped.")
    finally:
        srv.server_close()
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="themis.proxy", description=__doc__.split("\n")[0])
    ap.add_argument("--policy", type=Path, required=True)
    ap.add_argument("--bind", default=None,
                    help="default: the policy's server_ip, so this is unreachable "
                         "from the uplink")
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--upstream-port", type=int, default=443)
    ap.add_argument("--journal", type=Path, default=None)
    ap.add_argument("--log", type=Path, default=None)
    args = ap.parse_args(argv)

    try:
        pol = json.loads(args.policy.read_text())
    except (OSError, json.JSONDecodeError) as e:
        print(f"themis-proxy: cannot read policy: {e}", file=sys.stderr)
        return 2

    def _names(key):
        return [n for n in (pol.get(key) or []) if not str(n).startswith("_")]

    allow, block = _names("allow_dns_names"), _names("block_dns_names")
    mode = "block" if pol.get("proxy_mode") == "block" else "allow"
    if mode == "allow" and not allow:
        print("themis-proxy: allow_dns_names is empty, so this would refuse every\n"
              "              connection including the exam site. If that is what you\n"
              "              want, use mode 'airgap' -- it makes the same guarantee\n"
              "              without a process that has to keep running.", file=sys.stderr)
        return 2

    return serve(bind=args.bind or pol.get("server_ip", "127.0.0.1"),
                 port=args.port or int(pol.get("proxy_port", 443)),
                 allow=allow, block=block, mode=mode,
                 upstream_port=args.upstream_port,
                 journal_path=args.journal, logfile=args.log,
                 policy_path=args.policy)


if __name__ == "__main__":
    raise SystemExit(main())
