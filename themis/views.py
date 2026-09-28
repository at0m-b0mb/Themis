"""HTML for the portal and the proctor console.

Plain server-rendered pages, no framework and no client-side build. A student on a
locked-down network should get something that works in any browser, and a page
whose whole source they can read is the right register for a mechanism they are
entitled to understand.

Every interpolation goes through esc(). Student names and IDs are attacker-supplied
strings that get rendered back to a proctor, so this is the one place in the project
where a mistake is an injection bug rather than a wrong answer.
"""

from __future__ import annotations

from html import escape


def esc(v) -> str:
    return escape(str(v), quote=True)


# Warm white and gold, light by default, true black in dark mode -- no navy.
CSS = """
:root{
  --bg:#fbfaf7; --panel:#fffefb; --ink:#1a1814; --muted:#6d675d;
  --line:#e6e1d6; --gold:#9a7b28; --gold-soft:#f3ecd9;
  --ok:#2f6b41; --warn:#8a5a12; --bad:#8c2f2f;
  --radius:10px;
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]){
    --bg:#000; --panel:#0c0b0a; --ink:#f2efe8; --muted:#9a938a;
    --line:#241f19; --gold:#d8b45c; --gold-soft:#1a1409;
    --ok:#6fbf87; --warn:#d9a441; --bad:#e08585;
  }
}
:root[data-theme="dark"]{
  --bg:#000; --panel:#0c0b0a; --ink:#f2efe8; --muted:#9a938a;
  --line:#241f19; --gold:#d8b45c; --gold-soft:#1a1409;
  --ok:#6fbf87; --warn:#d9a441; --bad:#e08585;
}
*{box-sizing:border-box}
body{
  margin:0; background:var(--bg); color:var(--ink);
  font:16px/1.55 ui-serif,Georgia,"Times New Roman",serif;
  -webkit-font-smoothing:antialiased;
}
.wrap{max-width:46rem; margin:0 auto; padding:3rem 16px 4rem}
.wide{max-width:72rem}
h1{font-size:1.6rem; letter-spacing:-.01em; margin:0 0 .3rem; font-weight:600}
h2{font-size:1.05rem; margin:2rem 0 .6rem; font-weight:600}
.sub{color:var(--muted); margin:0 0 2rem; font-size:.95rem}
.rule{height:1px; background:var(--line); border:0; margin:1.6rem 0}
.card{
  background:var(--panel); border:1px solid var(--line);
  border-radius:var(--radius); padding:1.4rem 1.5rem; margin:0 0 1.1rem;
}
label{display:block; font-size:.8rem; letter-spacing:.04em; text-transform:uppercase;
  color:var(--muted); margin:0 0 .35rem}
input[type=text]{
  width:100%; padding:.7rem .8rem; font:inherit; color:var(--ink);
  background:var(--bg); border:1px solid var(--line); border-radius:8px;
}
input[type=text]:focus{outline:2px solid var(--gold); outline-offset:1px; border-color:var(--gold)}
.field{margin:0 0 1rem}
button{
  font:inherit; font-weight:600; padding:.7rem 1.4rem; cursor:pointer;
  color:#fff; background:var(--gold); border:1px solid var(--gold); border-radius:8px;
}
button:hover{filter:brightness(1.07)}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.code{
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
  font-size:1.5rem; letter-spacing:.12em; padding:.9rem 1rem; text-align:center;
  background:var(--gold-soft); border:1px solid var(--gold); border-radius:8px;
  color:var(--ink); word-break:break-all;
}
table{width:100%; border-collapse:collapse; font-size:.9rem}
th,td{text-align:left; padding:.5rem .6rem; border-bottom:1px solid var(--line)}
th{font-size:.72rem; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); font-weight:600}
tr:last-child td{border-bottom:0}
.pill{display:inline-block; font-size:.72rem; font-weight:600; padding:.15rem .5rem;
  border-radius:999px; border:1px solid currentColor}
.on{color:var(--ok)} .off{color:var(--bad)} .flag{color:var(--warn)}
.note{font-size:.88rem; color:var(--muted)}
.disclose{background:var(--gold-soft); border-left:3px solid var(--gold);
  padding:.9rem 1.1rem; border-radius:0 8px 8px 0; font-size:.9rem; margin:0 0 1.4rem}
.disclose ul{margin:.5rem 0 0; padding-left:1.1rem}
.err{color:var(--bad); font-size:.9rem; margin:0 0 1rem}
.foot{margin-top:2.5rem; font-size:.8rem; color:var(--muted)}
@media (max-width:520px){ .wrap{padding:2rem 16px 3rem} h1{font-size:1.35rem} }
"""


def page(title: str, body: str, *, wide: bool = False) -> str:
    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)}</title>
<style>{CSS}</style>
</head><body><div class="wrap{' wide' if wide else ''}">{body}</div></body></html>"""


# --- student-facing -------------------------------------------------------- #

DISCLOSURE = """
<div class="disclose">
  <strong>What this network records, and what it does not.</strong>
  <ul>
    <li>Your device's network address, the name you enter below, and the times your
        device joins or leaves this network.</li>
    <li>Which names your device asked this network to look up. There is no internet
        connection here, so nothing can be reached.</li>
    <li><strong>Nothing is installed on your computer. Nothing looks at what is on
        it or running on it. No camera, no microphone, no screen recording.</strong></li>
    <li>If your device drops off, that is recorded — but it is never marked against
        you automatically. A person reads the record, and you get to explain.</li>
  </ul>
</div>
"""


def register_page(*, error: str | None = None, mac: str | None = None,
                  resolution: str | None = None) -> str:
    err = f'<p class="err">{esc(error)}</p>' if error else ""
    seen = ""
    if mac:
        seen = (f'<p class="note">This network sees your device as '
                f'<span class="mono">{esc(mac)}</span>.</p>')
    elif resolution:
        seen = (f'<p class="note">This network cannot yet identify your device '
                f'({esc(resolution)}). Tell the proctor if this page will not accept you.</p>')
    return page("Exam network — sign in", f"""
<h1>Exam network</h1>
<p class="sub">Sign in so the proctor can see you are connected.</p>
{DISCLOSURE}
{err}
<form method="POST" action="/register" class="card">
  <div class="field">
    <label for="sid">Student ID</label>
    <input type="text" id="sid" name="student_id" autocomplete="off"
           autocapitalize="off" spellcheck="false" required maxlength="32">
  </div>
  <div class="field">
    <label for="name">Full name</label>
    <input type="text" id="name" name="name" autocomplete="off"
           spellcheck="false" required maxlength="80">
  </div>
  <div class="field">
    <label for="seat">Seat or row <span style="text-transform:none">(optional)</span></label>
    <input type="text" id="seat" name="seat" autocomplete="off" maxlength="16">
  </div>
  <button type="submit">Sign in</button>
</form>
{seen}
<p class="foot">Themis · this page has no internet access by design</p>
""")


def registered_page(*, name: str, student_id: str, mac: str, code_block: str) -> str:
    return page("Exam network — connected", f"""
<h1>You are connected</h1>
<p class="sub">{esc(name)} · {esc(student_id)}</p>
<div class="card">
  <p class="note" style="margin-top:0">Device seen as <span class="mono">{esc(mac)}</span></p>
  {code_block}
</div>
<p class="note">Keep this page open for the whole exam. If your connection drops,
rejoin <strong>EXAM-ONLY</strong> and return to this page — then tell the proctor,
so the gap is explained rather than guessed at.</p>
<p class="foot">Themis · no internet access by design</p>
""")


def blocked_page(host: str | None = None) -> str:
    what = f' <span class="mono">{esc(host)}</span>' if host else ""
    return page("Not available during the exam", f"""
<h1>Not available during the exam</h1>
<p class="sub">This network has no internet connection.</p>
<div class="card">
  <p style="margin:0">Your device tried to reach{what or " a site outside this network"}.
  There is no route off this network, so nothing outside it can be reached — by any
  application, including a VPN.</p>
</div>
<p class="note">The attempt is recorded in the exam log. That is not, by itself,
treated as anything: browsers and apps request things on their own constantly.</p>
<p><a href="/" style="color:var(--gold)">Back to the exam page</a></p>
<p class="foot">Themis</p>
""")


# --- proctor-facing -------------------------------------------------------- #

def console_page(*, roster, now: float, ap_info: dict) -> str:
    rows = []
    for sid in sorted(roster.registrations):
        reg = roster.registrations[sid]
        p = roster.presence.get(sid)
        if p and p.online_now:
            state = '<span class="pill on">on</span>'
        else:
            state = '<span class="pill off">off</span>'
        gaps = len(p.gaps) if p else 0
        if gaps:
            lo, hi = p.total_absence_bounds(roster.closed_at or now)
            gap_cell = (f'<span class="pill flag">{gaps}</span> '
                        f'<span class="note">{lo:.0f}–{hi:.0f}s</span>')
        else:
            gap_cell = '<span class="note">—</span>'
        rows.append(
            f"<tr><td>{esc(reg.name)}</td><td class='mono'>{esc(sid)}</td>"
            f"<td class='mono note'>{esc(reg.mac)}</td>"
            f"<td>{esc(reg.seat or '')}</td><td>{state}</td><td>{gap_cell}</td></tr>"
        )
    table = ("<table><thead><tr><th>Name</th><th>ID</th><th>Device</th><th>Seat</th>"
             "<th>Now</th><th>Gaps</th></tr></thead><tbody>"
             + ("".join(rows) or "<tr><td colspan=6 class='note'>nobody registered yet</td></tr>")
             + "</tbody></table>")

    anoms = "".join(
        f"<div class='card'><strong>{esc(a.kind.replace('_',' '))}</strong>"
        f"<p style='margin:.4rem 0 .3rem'>{esc(a.detail)}</p>"
        f"<p class='note' style='margin:0'>Innocent reading: {esc(a.innocent_explanation)}</p></div>"
        for a in roster.anomalies
    ) or "<p class='note'>none</p>"

    return page("Themis — proctor console", f"""
<h1>Proctor console</h1>
<p class="sub">{esc(ap_info.get('ssid','?'))} ·
  {len(roster.registrations)} registered ·
  {len(roster.online)} online ·
  {len(roster.flagged())} with gaps ·
  {roster.sample_count} presence samples</p>

<h2>Students</h2>
{table}

<h2>Worth a look</h2>
<p class="note">Flags, not findings. Every one has an innocent reading as well as a
suspicious one, and you are the one who can see the room.</p>
{anoms}

<hr class="rule">
<p class="note"><strong>This console decides nothing.</strong> It has no marks in it
and no way to fail anybody. A gap is shown as a range because presence is sampled:
a device is only known to have left somewhere between the last sample that saw it
and the first that did not.</p>
<p class="foot">Themis · reachable only from this machine</p>
""", wide=True)
