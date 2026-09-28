"""The captive portal, the exam page, and the proctor console.

Run with:  sudo python3 -m themis.server --policy netguard/linux/policy.json

Two listeners, deliberately:

  0.0.0.0:80 (and 8080)   students. The portal and the exam page.
  127.0.0.1:8081          the proctor console. Bound to loopback, so it is not
                          merely hidden from the exam network but unreachable
                          from it -- and nftables does not permit that port
                          either. Two independent reasons, because the console
                          lists every student's name and device.

Rules this module holds to:

  The client never tells us its MAC. It is resolved from the request's source
  address via themis.leases, using two sources that must agree. A browser can
  claim anything; a DHCP lease and an ARP entry are observations.

  Nothing here decides anything about a student. It records, it flags, and it
  shows a human what it saw.
"""

from __future__ import annotations

import argparse
import json
import re
import socketserver
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from themis import views
from themis.journal import Journal
from themis.leases import hostapd_stations, read_leases, resolve
from themis.roster import build_roster

# Student IDs end up in filenames, logs and HTML. Keep them boring.
SID_RE = re.compile(r"^[A-Za-z0-9._-]{2,32}$")
NAME_MAX = 80
SEAT_MAX = 16

# The URLs operating systems fetch to decide whether a network is "online". They
# must NOT succeed, or the OS silently concludes it has internet and never shows
# the sign-in sheet.
CAPTIVE_PROBES = {
    "/hotspot-detect.html",      # Apple
    "/library/test/success.html",  # Apple (older)
    "/generate_204",             # Android / Chrome
    "/gen_204",
    "/connecttest.txt",          # Windows
    "/ncsi.txt",
    "/canonical.html",           # Ubuntu / NetworkManager
    "/success.txt",              # Firefox
}

PRESENCE_INTERVAL = 10.0


class Context:
    """Shared, thread-safe-enough state. Writes go to the journal, which is the
    single source of truth; this object holds only configuration and a lock."""

    def __init__(self, policy: dict, journal_path: Path):
        self.policy = policy
        self.journal = Journal(journal_path)
        self.lock = threading.Lock()
        self.ap_interface = policy.get("ap_interface") or policy.get("exam_interface")
        self.lease_file = Path(policy.get("lease_file", "/run/themis/dhcp.leases"))
        self._recent: dict[str, float] = {}   # ip -> last registration attempt

    def registered_ids(self) -> dict[str, dict]:
        return {e.data.get("student_id"): e.data
                for e in self.journal.events("register") if e.data.get("student_id")}

    def registration_for_mac(self, mac: str) -> dict | None:
        found = None
        for e in self.journal.events("register"):
            if e.data.get("mac") == mac:
                found = e.data          # latest wins
        return found

    def rate_limited(self, ip: str, window: float = 2.0) -> bool:
        now = time.time()
        last = self._recent.get(ip, 0.0)
        self._recent[ip] = now
        return (now - last) < window

    def observe_macs(self) -> set[str]:
        """Who is on the network right now.

        hostapd is authoritative when available -- a station in its list is
        associated at this instant. It returning None means we could not ask, which
        is different from "nobody is here", so we fall back rather than journal an
        empty sample and manufacture 19 simultaneous disconnections.
        """
        if self.ap_interface:
            sta = hostapd_stations(self.ap_interface)
            if sta is not None:
                return sta
        now = time.time()
        return {l.mac for l in read_leases(self.lease_file) if not l.expired(now)}


class StudentHandler(BaseHTTPRequestHandler):
    server_version = "Themis"
    sys_version = ""
    ctx: Context = None  # set by serve()

    def log_message(self, fmt, *args):
        pass  # the journal and dnsmasq's own log are the record; stderr noise is not

    # -- helpers ----------------------------------------------------------- #

    def _send(self, body: str, status: int = 200, ctype: str = "text/html; charset=utf-8"):
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        # The portal is the only thing this network serves; no external anything.
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def _redirect(self, to: str = "/"):
        self.send_response(302)
        self.send_header("Location", to)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    @property
    def client_ip(self) -> str:
        return self.client_address[0]

    def _resolve(self):
        return resolve(self.client_ip,
                       lease_file=self.ctx.lease_file,
                       interface=self.ctx.ap_interface)

    # -- routes ------------------------------------------------------------ #

    def do_GET(self):
        path = urlparse(self.path).path
        if path in CAPTIVE_PROBES:
            # Answer a captive-portal probe with a redirect so the OS pops the
            # sign-in sheet instead of deciding the network is online.
            return self._redirect("/")
        if path == "/":
            return self._home()
        if path == "/healthz":
            return self._send("ok", ctype="text/plain; charset=utf-8")
        return self._send(views.blocked_page(self.headers.get("Host")), status=200)

    do_HEAD = do_GET

    def _home(self):
        r = self._resolve()
        reg = self.ctx.registration_for_mac(r.mac) if r.mac else None
        if reg:
            return self._send(views.registered_page(
                name=reg.get("name", ""), student_id=reg.get("student_id", ""),
                mac=r.mac,
                code_block=(
                    '<p class="note" style="margin-bottom:.4rem">Your integrity code</p>'
                    '<div class="code">issued when the exam opens</div>'
                ),
            ))
        return self._send(views.register_page(mac=r.mac, resolution=r.explain()))

    def do_POST(self):
        if urlparse(self.path).path != "/register":
            return self._send(views.blocked_page(), status=404)

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > 8192:
            return self._send(views.register_page(error="Could not read that form."), status=400)
        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))

        sid = (form.get("student_id", [""])[0] or "").strip()
        name = (form.get("name", [""])[0] or "").strip()
        seat = (form.get("seat", [""])[0] or "").strip()[:SEAT_MAX] or None

        if self.ctx.rate_limited(self.client_ip):
            return self._send(views.register_page(error="Slow down a moment, then try again."),
                              status=429)
        if not SID_RE.match(sid):
            return self._send(views.register_page(
                error="Student ID should be 2–32 letters, digits, dot, dash or underscore."),
                status=400)
        if not (1 <= len(name) <= NAME_MAX):
            return self._send(views.register_page(error="Please enter your full name."),
                              status=400)

        r = self._resolve()
        if r.mac is None:
            # Refuse rather than guess. A binding recorded against the wrong device
            # is worse than a student raising their hand.
            return self._send(views.register_page(
                error="This network cannot identify your device yet — wait a few "
                      "seconds and try again, or tell the proctor.",
                resolution=r.explain()), status=409)

        with self.ctx.lock:
            self.ctx.journal.append("register", {
                "student_id": sid, "name": name, "seat": seat,
                "mac": r.mac, "ip": self.client_ip,
                "resolution_source": r.source,
                "user_agent": (self.headers.get("User-Agent") or "")[:200],
            })
        return self._redirect("/")


class ConsoleHandler(BaseHTTPRequestHandler):
    server_version = "Themis"
    sys_version = ""
    ctx: Context = None

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        path = urlparse(self.path).path
        # Defence in depth: bound to loopback, blocked by nftables, and checked here.
        if self.client_address[0] not in ("127.0.0.1", "::1"):
            self.send_response(403); self.send_header("Content-Length", "0"); self.end_headers()
            return
        roster = build_roster(self.ctx.journal)
        if path == "/dump.json":
            body = json.dumps({
                "chain": self.ctx.journal.verify().summary(),
                "head": self.ctx.journal.head,
                "events": [json.loads(e.to_json()) for e in self.ctx.journal.read()],
            }, indent=2)
            raw = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        body = views.console_page(roster=roster, now=time.time(), ap_info=self.ctx.policy)
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)


def presence_loop(ctx: Context, interval: float, stop: threading.Event):
    while not stop.wait(interval):
        try:
            macs = ctx.observe_macs()
        except Exception:
            continue  # a sampling failure must never take the portal down
        with ctx.lock:
            ctx.journal.append("presence_sample", {"macs": sorted(macs)})


def serve(policy: dict, *, journal_path: Path, student_port: int,
          console_port: int, interval: float) -> int:
    ctx = Context(policy, journal_path)
    StudentHandler.ctx = ctx
    ConsoleHandler.ctx = ctx

    socketserver.TCPServer.allow_reuse_address = True
    student = ThreadingHTTPServer(("0.0.0.0", student_port), StudentHandler)
    console = ThreadingHTTPServer(("127.0.0.1", console_port), ConsoleHandler)

    with ctx.lock:
        ctx.journal.append("exam_open", {
            "ssid": policy.get("ssid"), "profile": policy.get("profile"),
            "student_port": student_port,
        })

    stop = threading.Event()
    threads = [
        threading.Thread(target=student.serve_forever, daemon=True),
        threading.Thread(target=console.serve_forever, daemon=True),
        threading.Thread(target=presence_loop, args=(ctx, interval, stop), daemon=True),
    ]
    for t in threads:
        t.start()

    print(f"Themis serving")
    print(f"  students   http://{policy.get('server_ip', '0.0.0.0')}:{student_port}/")
    print(f"  console    http://127.0.0.1:{console_port}/   (loopback only)")
    print(f"  journal    {journal_path}")
    print(f"  sampling   every {interval:.0f}s")
    print("  Ctrl-C to close the exam\n")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        with ctx.lock:
            ev = ctx.journal.append("exam_close", {})
        student.shutdown(); console.shutdown()
        print(f"\nexam closed. chain head: {ev.hash}")
        print("Write that hash down before you review anything — published up front,")
        print("it pins the record and closes the one gap the chain cannot: truncation.")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="themis.server", description=__doc__)
    ap.add_argument("--policy", required=True, type=Path)
    ap.add_argument("--journal", type=Path, default=Path("/run/themis/exam.jsonl"))
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--console-port", type=int, default=8081)
    ap.add_argument("--interval", type=float, default=PRESENCE_INTERVAL)
    args = ap.parse_args(argv)

    try:
        policy = json.loads(args.policy.read_text())
    except (OSError, json.JSONDecodeError) as e:
        print(f"themis.server: cannot read {args.policy}: {e}", file=sys.stderr)
        return 1
    return serve(policy, journal_path=args.journal, student_port=args.port,
                 console_port=args.console_port, interval=args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
