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
from themis.state import ACTIVE_JOURNAL, ensure_dirs
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
    """The proctor's view. Loopback-only, and nftables does not permit the port
    either -- two independent reasons, because this lists every student's name and
    device."""

    server_version = "Themis"
    sys_version = ""
    ctx: Context = None

    def log_message(self, fmt, *args):
        pass

    def _body(self, raw: bytes, ctype: str):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def do_GET(self):
        # Defence in depth: bound to loopback, blocked by nftables, checked here.
        if self.client_address[0] not in ("127.0.0.1", "::1"):
            self.send_response(403); self.send_header("Content-Length", "0"); self.end_headers()
            return

        path = urlparse(self.path).path
        if path == "/api/state":
            return self._body(json.dumps(self._state()).encode(),
                              "application/json; charset=utf-8")
        if path == "/dump.json":
            return self._body(self._dump().encode(), "application/json; charset=utf-8")
        if path == "/report.txt":
            return self._body(self._report().encode(), "text/plain; charset=utf-8")
        return self._body(views.console_page(policy=self.ctx.policy).encode(),
                          "text/html; charset=utf-8")

    do_HEAD = do_GET

    # -- payloads ---------------------------------------------------------- #

    def _state(self) -> dict:
        roster = build_roster(self.ctx.journal)
        verdict = self.ctx.journal.verify()
        end = roster.closed_at or time.time()

        # Values below are interpolated into innerHTML by the console's script, so
        # they are escaped HERE. A student's own name is the injection vector.
        students = []
        for sid in sorted(roster.registrations):
            reg = roster.registrations[sid]
            pres = roster.presence.get(sid)
            lo, hi = pres.total_absence_bounds(end) if pres else (0.0, 0.0)
            # "Left and never came back" is the single most important state on this
            # page, so it is a fact in the payload rather than something the front
            # end has to infer from a gap count.
            never_back = bool(pres and pres.gaps and pres.gaps[-1].back_at is None)
            students.append({
                "student_id": views.esc(sid),
                "name": views.esc(reg.name),
                "mac": views.esc(reg.mac),
                "seat": views.esc(reg.seat) if reg.seat else "",
                "online": bool(pres and pres.online_now),
                "gaps": len(pres.gaps) if pres else 0,
                "gap_lo": round(lo),
                "gap_hi": round(hi),
                "never_returned": never_back,
                "last_seen": (time.strftime("%H:%M", time.localtime(pres.last_seen))
                              if pres and pres.last_seen else ""),
            })

        elapsed = "—"
        if roster.opened_at:
            secs = int(end - roster.opened_at)
            elapsed = f"{secs // 3600:02d}:{secs % 3600 // 60:02d}:{secs % 60:02d}"

        return {
            "counts": {
                "registered": len(roster.registrations),
                "online": len(roster.online),
                "offline": len(roster.offline),
                "flagged": len(roster.flagged()),
                "anomalies": len(roster.anomalies),
                "samples": roster.sample_count,
            },
            "students": students,
            "anomalies": [{
                "kind": views.esc(a.kind.replace("_", " ")),
                "detail": views.esc(a.detail),
                "innocent": views.esc(a.innocent_explanation),
            } for a in roster.anomalies],
            "chain": views.esc(verdict.summary()),
            "chain_ok": verdict.ok,
            "head": views.esc(self.ctx.journal.head),
            "elapsed": elapsed,
        }

    def _dump(self) -> str:
        v = self.ctx.journal.verify()
        return json.dumps({
            "chain": v.summary(),
            "chain_ok": v.ok,
            "head": self.ctx.journal.head,
            "events": [json.loads(e.to_json()) for e in self.ctx.journal.read()],
        }, indent=2)

    def _report(self) -> str:
        """The plain-text record a human reads when deciding what a gap meant.

        Written to be read by someone who is NOT looking at this program: a student
        querying their marks, or a department reviewing the decision.
        """
        roster = build_roster(self.ctx.journal)
        v = self.ctx.journal.verify()
        end = roster.closed_at or time.time()
        L = []
        w = L.append
        w("THEMIS EXAM RECORD")
        w("=" * 64)
        w(f"ssid              {self.ctx.policy.get('ssid')}")
        w(f"profile           {self.ctx.policy.get('profile')}")
        if roster.opened_at:
            w(f"opened            {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(roster.opened_at))}")
        w(f"closed            {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(roster.closed_at)) if roster.closed_at else 'still open'}")
        w(f"presence samples  {roster.sample_count}")
        w(f"record integrity  {v.summary()}")
        w(f"chain head        {self.ctx.journal.head}")
        w("")
        w("HOW TO READ THIS")
        w("-" * 64)
        w("Presence is sampled, so a gap is a RANGE, not an exact number: the device")
        w("left somewhere between the last sample that saw it and the first that did")
        w("not. A single missed sample is not counted at all -- Wi-Fi drops, radios")
        w("sleep, and browsers throttle background tabs.")
        w("")
        w("A gap is not misconduct. It is a question worth asking. Nothing in this")
        w("file is a mark, and nothing here decided anything.")
        w("")
        w("STUDENTS")
        w("-" * 64)
        # A student who signed in more than once is only tracked under their LATEST
        # device, so their earlier stretch is not in the numbers below. That has to
        # be said in their own entry -- a reviewer reading one student does not
        # necessarily read the anomaly list at the bottom.
        earlier: dict[str, list[str]] = {}
        for e in self.ctx.journal.events("register"):
            sid_ = e.data.get("student_id")
            if sid_:
                earlier.setdefault(sid_, []).append(
                    f"{e.data.get('mac')} at {time.strftime('%H:%M:%S', time.localtime(e.ts))}")

        for sid in sorted(roster.registrations):
            reg = roster.registrations[sid]
            p = roster.presence.get(sid)
            w(f"{reg.name}  ({sid})" + (f"  seat {reg.seat}" if reg.seat else ""))
            w(f"    device        {reg.mac}  [{reg.resolution_source}]")
            w(f"    signed in     {time.strftime('%H:%M:%S', time.localtime(reg.at))}")
            if len(earlier.get(sid, [])) > 1:
                w(f"    NOTE          signed in {len(earlier[sid])} times; the figures below")
                w(f"                  cover only the latest device. All sign-ins:")
                for line in earlier[sid]:
                    w(f"                    {line}")
            if not p or not p.samples_total:
                w("    presence      no samples covered this registration")
            else:
                w(f"    seen in       {p.samples_present}/{p.samples_total} samples")
                if not p.gaps:
                    w("    gaps          none")
                else:
                    lo, hi = p.total_absence_bounds(end)
                    w(f"    gaps          {len(p.gaps)}, totalling between {lo:.0f}s and {hi:.0f}s")
                    for i, g in enumerate(p.gaps, 1):
                        t = time.strftime("%H:%M:%S", time.localtime(g.missing_from))
                        w(f"      {i}. from ~{t}, {g.describe(end)}")
            w("")
        if roster.anomalies:
            w("WORTH A LOOK")
            w("-" * 64)
            for a in roster.anomalies:
                w(f"[{a.kind}] {a.detail}")
                w(f"    innocent reading: {a.innocent_explanation}")
            w("")
        w("=" * 64)
        w("Publish the chain head above before reviewing anything. The chain proves")
        w("no event was altered; it cannot prove none was removed from the end.")
        return "\n".join(L) + "\n"


def presence_loop(ctx: Context, interval: float, stop: threading.Event):
    while not stop.wait(interval):
        try:
            macs = ctx.observe_macs()
        except Exception:
            continue  # a sampling failure must never take the portal down
        with ctx.lock:
            ctx.journal.append("presence_sample", {"macs": sorted(macs)})


def review(policy: dict, *, journal_path: Path, console_port: int) -> int:
    """Reopen a finished exam's record, read-only.

    No student listener, no presence sampling, and -- the point -- not a single
    event appended. Reviewing a record must not modify it, or the chain head the
    exam closed with would no longer match what you are looking at.
    """
    ctx = Context(policy, journal_path)
    ConsoleHandler.ctx = ctx
    v = ctx.journal.verify()

    socketserver.TCPServer.allow_reuse_address = True
    console = ThreadingHTTPServer(("127.0.0.1", console_port), ConsoleHandler)
    threading.Thread(target=console.serve_forever, kwargs={"poll_interval": 0.2},
                     daemon=True).start()

    print("Themis review (read-only -- nothing is written)")
    print(f"  console    http://127.0.0.1:{console_port}/")
    print(f"  journal    {journal_path}")
    print(f"  record     {v.summary()}")
    print(f"  head       {ctx.journal.head}")
    print("  Ctrl-C to stop\n")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        console.shutdown(); console.server_close()
    return 0


def serve(policy: dict, *, journal_path: Path, student_port: int,
          console_port: int, interval: float) -> int:
    ensure_dirs()
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
    ap.add_argument("--journal", type=Path, default=ACTIVE_JOURNAL)
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--console-port", type=int, default=8081)
    ap.add_argument("--interval", type=float, default=PRESENCE_INTERVAL)
    ap.add_argument("--review", action="store_true",
                    help="reopen a finished exam's record read-only: console only, "
                         "no student listener, no sampling, nothing written")
    args = ap.parse_args(argv)

    try:
        policy = json.loads(args.policy.read_text())
    except (OSError, json.JSONDecodeError) as e:
        print(f"themis.server: cannot read {args.policy}: {e}", file=sys.stderr)
        return 1
    if args.review:
        return review(policy, journal_path=args.journal,
                      console_port=args.console_port)
    return serve(policy, journal_path=args.journal, student_port=args.port,
                 console_port=args.console_port, interval=args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
