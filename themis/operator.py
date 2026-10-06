"""One screen that runs the whole exam. No commands to remember.

    sudo python3 -m themis.operator

Opens a control panel on 127.0.0.1:8080 that drives everything: the host checks,
the radio, DHCP and DNS, the firewall, the captive portal, and the proctor
console. On exam morning it should be one command and then buttons.

Two things about how this is built, both deliberate:

  It shells out to the SAME tools you would run by hand -- netguard/linux/bin/themis-ap
  and `python3 -m themis.server` -- rather than reimplementing them. There is one
  implementation of "bring up the exam network", so the panel and the terminal can
  never disagree, and anything you learn here still applies if you drop to a shell.

  It runs as root, so it is bound to loopback only and every action is a fixed
  entry in a table below. Nothing from a request is ever interpolated into a
  command: the only free-form input is an interface name, and that is checked
  against the interfaces the kernel actually reports before it goes anywhere.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from themis import views

ROOT = Path(__file__).resolve().parent.parent
THEMIS_AP = ROOT / "netguard" / "linux" / "bin" / "themis-ap"
POLICY = ROOT / "netguard" / "linux" / "policy.json"
from themis.state import ACTIVE_JOURNAL, DATA_DIR, RUN_DIR, archive_previous, ensure_dirs

JOURNAL = ACTIVE_JOURNAL

CONSOLE_PORT = 8081
PORTAL_PORT = 80

IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")

# What a teacher chooses between. These map onto policy fields in themis-ap, and
# the mapping lives there -- this only has to know the names it may pass on.
MODES = ("airgap", "allowlist", "blocklist")


def _run(cmd: list[str], timeout: float = 120.0) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout:.0f}s: {' '.join(cmd)}"
    except OSError as e:
        return 127, f"could not run {' '.join(cmd)}: {e}"
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError) as e:
        return isinstance(e, PermissionError)
    return True


class Controller:
    """Owns the exam's moving parts. One lock, because two clicks at once on a
    'start exam' button must not race the radio."""

    def __init__(self):
        self.lock = threading.Lock()
        self.portal: subprocess.Popen | None = None
        self.last: dict = {"action": None, "ok": None, "output": ""}

    # -- observations ------------------------------------------------------ #

    def policy(self) -> dict:
        try:
            return json.loads(POLICY.read_text())
        except (OSError, json.JSONDecodeError):
            return {}

    def ap_running(self) -> bool:
        pf = RUN_DIR / "hostapd.pid"
        if not pf.exists():
            return False
        try:
            return _pid_alive(int(pf.read_text().strip()))
        except (ValueError, OSError):
            return False

    def portal_running(self) -> bool:
        return self.portal is not None and self.portal.poll() is None

    def interfaces(self) -> list[dict]:
        out = []
        net = Path("/sys/class/net")
        if not net.is_dir():
            return out
        for d in sorted(net.iterdir()):
            if not (d / "phy80211").exists():
                continue
            try:
                drv = (d / "device" / "driver").resolve().name
            except OSError:
                drv = "?"
            out.append({"name": d.name, "driver": drv, "preferred": drv == "mt7921u"})
        return out

    def preflight(self) -> dict:
        rc, txt = _run([sys.executable, str(THEMIS_AP), "preflight", "--json"], timeout=60)
        try:
            return json.loads(txt[txt.index("{"):txt.rindex("}") + 1])
        except (ValueError, json.JSONDecodeError):
            return {"ok": [], "warn": [], "ready": False, "blocking": 1,
                    "fail": [{"level": "fail",
                              "message": f"could not run preflight (exit {rc}):\n{txt.strip()[:400]}"}]}

    def mode(self) -> str:
        pol = self.policy()
        if pol.get("profile") == "proxy":
            return "blocklist" if pol.get("proxy_mode") == "block" else "allowlist"
        if pol.get("profile") == "allowlist":
            return "allowlist-legacy"
        return "airgap"

    def _names(self, key) -> list[str]:
        return [n for n in (self.policy().get(key) or []) if not str(n).startswith("_")]

    def _stations(self, iface: str, multi: bool) -> list[str]:
        pidf = RUN_DIR / (f"hostapd-{iface}.pid" if multi else "hostapd.pid")
        if not iface or not pidf.exists() or not shutil.which("hostapd_cli"):
            return []
        _rc, txt = _run(["hostapd_cli", "-i", iface, "list_sta"], timeout=5)
        return [l.strip() for l in txt.splitlines()
                if re.match(r"^[0-9a-f:]{17}$", l.strip().lower())]

    def radios(self) -> list[dict]:
        """Per radio, because one number cannot say whether BOTH bands came up.

        "12 associated" is no help if the 2.4 GHz side silently died: the figure
        that proves it is that band's own station count.
        """
        pol = self.policy()
        raw = pol.get("radios") or [{"interface": pol.get("ap_interface", ""),
                                     "channel": pol.get("channel", 0),
                                     "channel_width_mhz": pol.get("channel_width_mhz", 20)}]
        multi = len(raw) > 1
        out = []
        for r in raw:
            iface = str(r.get("interface") or "")
            ch = int(r.get("channel") or 0)
            pidf = RUN_DIR / (f"hostapd-{iface}.pid" if multi else "hostapd.pid")
            out.append({
                "interface": iface, "channel": ch,
                "width": int(r.get("channel_width_mhz") or 20),
                "band": "2.4" if ch <= 14 else "5",
                "running": pidf.exists(),
                "stations": self._stations(iface, multi),
            })
        return out

    def refusals(self, limit: int = 30) -> list[dict]:
        """Names the proxy has refused, most frequent first.

        This is the panel's most useful screen and the reason it exists: a site
        the exam genuinely needs announces itself here the first time a student
        hits it, so the allowlist is discovered from real traffic instead of
        guessed at in advance. Mapping a JHU Canvas login took four rounds of
        exactly this, by hand, in a terminal.
        """
        log = RUN_DIR / "proxy-decisions.log"
        try:
            lines = log.read_text(errors="replace").splitlines()[-6000:]
        except OSError:
            return []
        allow = set(self._names("allow_dns_names"))
        block = set(self._names("block_dns_names"))
        counts: dict[str, int] = {}
        when: dict[str, str] = {}
        for line in lines:
            parts = line.split()
            if len(parts) < 5 or parts[2] != "blocked":
                continue
            host = parts[4].lower()
            if not HOST_RE.match(host):      # "(no SNI)" and anything malformed
                continue
            counts[host] = counts.get(host, 0) + 1
            when[host] = f"{parts[0]} {parts[1]}"
        rows = [{"host": h, "count": c, "last": when[h],
                 "on_allow": h in allow, "on_block": h in block}
                for h, c in counts.items()]
        rows.sort(key=lambda r: (-r["count"], r["host"]))
        return rows[:limit]

    def state(self) -> dict:
        pol = self.policy()
        pf = self.preflight()
        return {
            "preflight": pf,
            "ap_running": self.ap_running(),
            "portal_running": self.portal_running(),
            "proxy_running": (RUN_DIR / "proxy.pid").exists(),
            "interfaces": self.interfaces(),
            "radios": self.radios(),
            "mode": self.mode(),
            "allow": self._names("allow_dns_names"),
            "block": self._names("block_dns_names"),
            "refusals": self.refusals(),
            "policy": {
                "ssid": pol.get("ssid", "?"),
                "profile": pol.get("profile", "?"),
                "channel": pol.get("channel", "?"),
                "interface": pol.get("ap_interface", ""),
                "bridge": pol.get("bridge") if (pol.get("radios") or []) else None,
                "passphrase_set": pol.get("passphrase") != "CHANGE-ME-EVERY-EXAM",
                "passphrase": pol.get("passphrase", ""),
            },
            "console_port": CONSOLE_PORT,
            "last": self.last,
            "root": os.geteuid() == 0,
        }

    # -- actions ----------------------------------------------------------- #

    def configure(self, interface: str) -> tuple[bool, str]:
        # The only free-form input in the whole panel. Shape-check it, then require
        # that the kernel actually reports it as a radio, before it reaches argv.
        if not IFACE_RE.match(interface):
            return False, f"{interface!r} is not a valid interface name"
        if interface not in {i["name"] for i in self.interfaces()}:
            return False, (f"{interface!r} is not a wireless interface on this host. "
                           f"Pass the adapter through and reload this page.")
        rc, txt = _run([sys.executable, str(THEMIS_AP), "configure", interface])
        return rc == 0, txt

    def autoconfigure(self) -> tuple[bool, str]:
        """Detect what is plugged in and write a policy that matches it."""
        rc, txt = _run([sys.executable, str(THEMIS_AP), "autoconfigure",
                        "--keep-passphrase"], timeout=180)
        return rc == 0, txt

    def rotate_passphrase(self) -> tuple[bool, str]:
        rc, txt = _run([sys.executable, str(THEMIS_AP), "autoconfigure"], timeout=180)
        return rc == 0, txt

    def set_mode(self, mode: str) -> tuple[bool, str]:
        # Checked against a fixed tuple before it can reach argv. The only other
        # free-form input in this panel is an interface name, which is checked
        # against the interfaces the kernel reports.
        if mode not in MODES:
            return False, f"unknown mode {mode!r}"
        rc, txt = _run([sys.executable, str(THEMIS_AP), "set-mode", mode])
        return rc == 0, txt

    def set_list(self, which: str, text: str) -> tuple[bool, str]:
        """Replace a list from the textarea.

        Written to a file and handed to themis-ap rather than passed as
        arguments: it keeps teacher-typed text out of argv entirely, and it means
        the SAME validator runs whether the list came from this panel or from the
        command line. There is one definition of "is that a hostname".
        """
        if which not in ("allow", "block"):
            return False, f"unknown list {which!r}"
        if len(text) > 100_000:
            return False, "that list is implausibly large -- refusing to write it"
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        tmp = RUN_DIR / f"{which}list.txt"
        tmp.write_text(text)
        rc, txt = _run([sys.executable, str(THEMIS_AP), "set-list", which, str(tmp)])
        if rc != 0:
            return False, txt
        ok2, note = self.reload_proxy()
        return True, txt + ("\n" + note if note else "")

    def allow_name(self, host: str) -> tuple[bool, str]:
        """Add one refused name to the allowlist, from the refusals table.

        The name is not trusted because it appeared in a log: it is shape-checked
        here and validated again by themis-ap, and the log line it came from was
        itself written from a student-supplied SNI.
        """
        host = str(host or "").strip().lower()
        if not HOST_RE.match(host) or len(host) > 253:
            return False, f"{host[:60]!r} is not a hostname"
        current = self._names("allow_dns_names")
        if host in current:
            return True, f"{host} is already on the allowlist"
        return self.set_list("allow", "\n".join(current + [host]) + "\n")

    def reload_proxy(self) -> tuple[bool, str]:
        """Make the proxy re-read the lists WITHOUT dropping the exam.

        A domain the exam needs is discovered the first time a student hits it,
        which is mid-exam. Restarting to add it would disconnect every student to
        fix a one-line omission.
        """
        pidf = RUN_DIR / "proxy.pid"
        if not pidf.exists():
            return True, "(the proxy is not running, so there was nothing to reload)"
        try:
            os.kill(int(pidf.read_text().strip()), signal.SIGHUP)
        except (ProcessLookupError, ValueError, OSError) as e:
            return False, f"could not signal the proxy: {e}"
        return True, "the proxy reloaded its lists; nobody was disconnected"

    def ap_up(self) -> tuple[bool, str]:
        rc, txt = _run([sys.executable, str(THEMIS_AP), "up"], timeout=180)
        return rc == 0, txt

    def ap_down(self) -> tuple[bool, str]:
        rc, txt = _run([sys.executable, str(THEMIS_AP), "down"], timeout=120)
        return rc == 0, txt

    def portal_start(self) -> tuple[bool, str]:
        if self.portal_running():
            return True, "portal already running"
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        log = (RUN_DIR / "portal.log").open("a")
        try:
            self.portal = subprocess.Popen(
                [sys.executable, "-m", "themis.server",
                 "--policy", str(POLICY), "--journal", str(JOURNAL),
                 "--port", str(PORTAL_PORT), "--console-port", str(CONSOLE_PORT)],
                cwd=str(ROOT), stdout=log, stderr=log)
        except OSError as e:
            return False, f"could not start the portal: {e}"
        # Give it long enough to fail loudly (a taken port, a bad policy) rather
        # than reporting success for a process that is already gone.
        time.sleep(1.5)
        if self.portal.poll() is not None:
            tail = (RUN_DIR / "portal.log").read_text(errors="replace")[-600:]
            self.portal = None
            return False, f"the portal exited immediately:\n{tail}"
        return True, f"portal listening on :{PORTAL_PORT}, console on :{CONSOLE_PORT}"

    def portal_stop(self) -> tuple[bool, str]:
        if not self.portal_running():
            return True, "portal was not running"
        assert self.portal is not None
        self.portal.send_signal(signal.SIGINT)   # writes exam_close, then exits
        try:
            self.portal.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.portal.kill()
            self.portal.wait(timeout=5)
            return True, "portal did not stop cleanly and was killed -- the journal " \
                         "may have no exam_close event"
        self.portal = None
        return True, "portal stopped"

    def start_exam(self) -> tuple[bool, str]:
        ensure_dirs()
        # A new sitting starts on a clean chain. Appending onto the previous exam
        # would make one chain spanning two of them, so a question about either
        # could not be answered without handing over the other one's record.
        archived = archive_previous(JOURNAL)
        pre = f"archived the previous exam record to {archived}\n" if archived else ""
        ok, txt = self.ap_up()
        txt = pre + txt
        if not ok:
            return False, txt
        ok2, txt2 = self.portal_start()
        if not ok2:
            # Do not leave a radio broadcasting an exam SSID with nothing serving it;
            # a student who associates would get a network that goes nowhere.
            _, undo = self.ap_down()
            return False, f"{txt}\n\nportal failed, so the network was taken back down:\n{txt2}\n{undo}"
        return True, f"{txt}\n{txt2}"

    def stop_exam(self) -> tuple[bool, str]:
        _, a = self.portal_stop()
        ok, b = self.ap_down()
        return ok, f"{a}\n{b}"

    ACTIONS = {
        "configure": None,          # these take arguments and are handled below
        "set_mode": None,
        "set_list": None,
        "allow_name": None,
        "autoconfigure": "autoconfigure",
        "rotate_passphrase": "rotate_passphrase",
        "reload_proxy": "reload_proxy",
        "up": "ap_up",
        "down": "ap_down",
        "portal_start": "portal_start",
        "portal_stop": "portal_stop",
        "start_exam": "start_exam",
        "stop_exam": "stop_exam",
    }

    def dispatch(self, action: str, payload: dict) -> dict:
        with self.lock:
            if action == "configure":
                ok, out = self.configure(str(payload.get("interface", "")))
            elif action == "set_mode":
                ok, out = self.set_mode(str(payload.get("mode", "")))
            elif action == "set_list":
                ok, out = self.set_list(str(payload.get("which", "")),
                                        str(payload.get("text", "")))
            elif action == "allow_name":
                ok, out = self.allow_name(str(payload.get("host", "")))
            elif action in self.ACTIONS and self.ACTIONS[action]:
                ok, out = getattr(self, self.ACTIONS[action])()
            else:
                return {"ok": False, "output": f"unknown action {action!r}"}
            self.last = {"action": action, "ok": ok, "output": out}
            return {"ok": ok, "output": out}


class Handler(BaseHTTPRequestHandler):
    server_version = "Themis"
    sys_version = ""
    ctl: Controller = None

    def log_message(self, fmt, *args):
        pass

    def _guard(self) -> bool:
        # This process is root. Loopback only, and checked per request.
        if self.client_address[0] not in ("127.0.0.1", "::1"):
            self.send_response(403); self.send_header("Content-Length", "0"); self.end_headers()
            return False
        return True

    def _send(self, raw: bytes, ctype: str, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def do_GET(self):
        if not self._guard():
            return
        path = urlparse(self.path).path
        if path == "/api/state":
            return self._send(json.dumps(self.ctl.state()).encode(),
                              "application/json; charset=utf-8")
        return self._send(views.operator_page().encode(), "text/html; charset=utf-8")

    do_HEAD = do_GET

    def do_POST(self):
        if not self._guard():
            return
        if urlparse(self.path).path != "/api/action":
            return self._send(b'{"ok":false,"output":"no such endpoint"}',
                              "application/json; charset=utf-8", 404)
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        try:
            payload = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            payload = {}
        result = self.ctl.dispatch(str(payload.get("action", "")), payload)
        return self._send(json.dumps(result).encode(), "application/json; charset=utf-8")


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="themis.operator", description=__doc__)
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args(argv)

    if sys.platform != "linux":
        print("themis.operator runs on the Linux exam host.", file=sys.stderr)
        return 1
    if os.geteuid() != 0:
        print("themis.operator must run as root -- it brings up a radio, a DHCP\n"
              "server and a firewall:\n\n    sudo python3 -m themis.operator\n",
              file=sys.stderr)
        return 1

    Handler.ctl = Controller()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print("Themis operator")
    print(f"  open   http://127.0.0.1:{args.port}/")
    print("  This panel is reachable only from this machine.")
    print("  Ctrl-C to close it (it does NOT stop a running exam).\n")
    try:
        srv.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        srv.shutdown(); srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
