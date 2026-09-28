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

CONSOLE_CSS = """
.bar{display:flex; align-items:baseline; gap:1rem; flex-wrap:wrap; margin:0 0 .3rem}
.bar h1{margin:0}
.live{display:inline-flex; align-items:center; gap:.4rem; font-size:.78rem;
  color:var(--muted); letter-spacing:.04em; text-transform:uppercase}
.dot{width:7px; height:7px; border-radius:50%; background:var(--ok); display:inline-block}
.dot.stale{background:var(--warn)}
@media (prefers-reduced-motion:no-preference){
  .beat{animation:beat 2s ease-in-out infinite}
  @keyframes beat{0%,100%{opacity:1}50%{opacity:.25}}
}
.stats{display:grid; grid-template-columns:repeat(auto-fit,minmax(8.2rem,1fr));
  gap:.7rem; margin:1.4rem 0 2rem}
.stat{background:var(--panel); border:1px solid var(--line); border-radius:var(--radius);
  padding:.9rem 1rem}
.stat .n{font-size:1.9rem; line-height:1; font-variant-numeric:tabular-nums; font-weight:600}
.stat .k{font-size:.72rem; text-transform:uppercase; letter-spacing:.06em;
  color:var(--muted); margin-top:.35rem}
.stat.alert .n{color:var(--warn)}
.stat.bad .n{color:var(--bad)}

.grid{display:grid; grid-template-columns:repeat(auto-fill,minmax(15rem,1fr)); gap:.7rem}
.who{background:var(--panel); border:1px solid var(--line); border-left:3px solid var(--ok);
  border-radius:var(--radius); padding:.85rem 1rem; display:flex; flex-direction:column; gap:.2rem}
.who.off{border-left-color:var(--bad)}
.who.gapped{border-left-color:var(--warn)}
.who .nm{font-weight:600; letter-spacing:-.005em}
.who .id{font-size:.78rem; color:var(--muted)}
.who .dev{font-size:.7rem; color:var(--muted); font-family:ui-monospace,Menlo,monospace}
.who .st{display:flex; align-items:center; gap:.4rem; margin-top:.35rem; font-size:.78rem}
.who .st b{font-weight:600}
.on-t{color:var(--ok)} .off-t{color:var(--bad)} .gap-t{color:var(--warn)}
.seat{margin-left:auto; font-size:.7rem; color:var(--muted); border:1px solid var(--line);
  border-radius:5px; padding:.05rem .35rem}

.chain{display:flex; gap:.6rem; align-items:flex-start; font-size:.85rem;
  background:var(--gold-soft); border-left:3px solid var(--gold);
  padding:.75rem 1rem; border-radius:0 8px 8px 0; margin:0 0 1.4rem}
.chain.broken{background:transparent; border-left-color:var(--bad); color:var(--bad)}
.head{font-family:ui-monospace,Menlo,monospace; font-size:.72rem; word-break:break-all;
  color:var(--muted)}
.empty{color:var(--muted); padding:1.2rem 0}
.actions{display:flex; gap:.6rem; margin:0 0 1.6rem; flex-wrap:wrap}
.btn2{font:inherit; font-size:.85rem; padding:.45rem .9rem; cursor:pointer; color:var(--ink);
  background:var(--panel); border:1px solid var(--line); border-radius:7px; text-decoration:none}
.btn2:hover{border-color:var(--gold); color:var(--gold)}
@media (max-width:560px){ .grid{grid-template-columns:1fr} }
"""

CONSOLE_JS = """
let lastOk = Date.now();
let lastPayload = null;   // re-rendering identical data just makes the page flash
let failed = false;

// Seconds are unreadable past a minute or two, and this is read at a glance from
// across a room.
function dur(a, b){
  const unit = v => v < 120 ? `${Math.round(v)}s` : `${Math.round(v/60)} min`;
  if (Math.abs(b - a) < 1) return unit(a);
  return (b < 120) ? `${Math.round(a)}\u2013${Math.round(b)}s`
                   : `${Math.round(a/60)}\u2013${Math.round(b/60)} min`;
}

function card(s){
  const cls = !s.online ? 'off' : (s.gaps ? 'gapped' : '');
  let state, gap;
  if (s.never_returned){
    state = `<span class="off-t"><b>left</b> at ${s.last_seen}, did not return</span>`;
    gap   = `<span class="off-t">gone ${dur(s.gap_lo, s.gap_hi)}</span>`;
  } else if (!s.online){
    state = `<span class="off-t"><b>off</b> the network now</span>`;
    gap   = s.gaps ? `<span class="gap-t">${s.gaps} gap${s.gaps>1?'s':''}, ${dur(s.gap_lo,s.gap_hi)} total</span>`
                   : `<span style="color:var(--muted)">last seen ${s.last_seen||'\u2014'}</span>`;
  } else if (s.gaps){
    state = `<span class="gap-t"><b>on</b> \u00b7 came back</span>`;
    gap   = `<span class="gap-t">${s.gaps} gap${s.gaps>1?'s':''}, ${dur(s.gap_lo,s.gap_hi)} total</span>`;
  } else {
    state = `<span class="on-t"><b>on</b> the network</span>`;
    gap   = `<span style="color:var(--muted)">no gaps</span>`;
  }
  const seat = s.seat ? `<span class="seat">seat ${s.seat}</span>` : '';
  return `<div class="who ${cls}">
    <div class="nm">${s.name}${seat}</div>
    <div class="id">${s.student_id} \u00b7 <span class="dev">${s.mac}</span></div>
    <div class="st">${state}</div>
    <div class="st">${gap}</div>
  </div>`;
}

function render(d){
  document.getElementById('stats').innerHTML = [
    ['registered', d.counts.registered, ''],
    ['on the network', d.counts.online, ''],
    ['off right now', d.counts.offline, d.counts.offline ? 'bad' : ''],
    ['with gaps', d.counts.flagged, d.counts.flagged ? 'alert' : ''],
    ['to look at', d.counts.anomalies, d.counts.anomalies ? 'alert' : ''],
    ['samples', d.counts.samples, ''],
  ].map(([k,n,c]) => `<div class="stat ${c}"><div class="n">${n}</div><div class="k">${k}</div></div>`).join('');

  // Attention first: off the network, then gapped, then alphabetical. A proctor
  // scanning this in a room should not have to hunt.
  const order = s => s.never_returned ? 0 : (!s.online ? 1 : (s.gaps ? 2 : 3));
  const rows = d.students.slice().sort((a,b) => order(a)-order(b) || a.name.localeCompare(b.name));
  document.getElementById('grid').innerHTML = rows.length
    ? rows.map(card).join('')
    : '<p class="empty">Nobody has signed in yet.</p>';

  document.getElementById('anoms').innerHTML = d.anomalies.length
    ? d.anomalies.map(a => `<div class="card"><strong>${a.kind}</strong>
        <p style="margin:.4rem 0 .3rem">${a.detail}</p>
        <p class="note" style="margin:0">Innocent reading: ${a.innocent}</p></div>`).join('')
    : '<p class="note">Nothing flagged.</p>';

  const c = document.getElementById('chain');
  c.className = 'chain' + (d.chain_ok ? '' : ' broken');
  c.innerHTML = `<div><strong>${d.chain_ok ? 'Record intact' : 'RECORD BROKEN'}</strong>
    <div>${d.chain}</div><div class="head">head ${d.head}</div></div>`;

  document.getElementById('clock').textContent = d.elapsed;
}

async function tick(){
  try{
    const r = await fetch('/api/state', {cache:'no-store'});
    if(!r.ok) throw new Error(r.status);
    const text = await r.text();
    // Wholesale innerHTML replacement every 2s makes the console visibly flash.
    // Most ticks change nothing, so only re-render when the payload actually moved.
    if (text !== lastPayload){
      render(JSON.parse(text));
      // Only after a SUCCESSFUL render. Setting this first meant one thrown error
      // sent every later tick down the else branch, freezing the console for good
      // while it still said "live".
      lastPayload = text;
    } else {
      document.getElementById('clock').textContent = JSON.parse(text).elapsed;
    }
    lastOk = Date.now();
    failed = false;
  }catch(e){
    console.error('themis console tick failed:', e);
    failed = true;
  }
  const stale = failed || (Date.now() - lastOk > 6000);
  const dot = document.getElementById('beat');
  dot.className = 'dot beat' + (stale ? ' stale' : '');
  // A console that is broken must never look fine. This is the same rule the rest
  // of the project follows: say what you actually know.
  document.getElementById('livetext').textContent =
    failed ? 'not updating' : (stale ? 'reconnecting' : 'live');
}
tick(); setInterval(tick, 2000);
"""


def console_page(*, policy: dict) -> str:
    """The shell. All the numbers arrive from /api/state, so the page never goes
    stale silently -- if polling stops, the indicator says so rather than showing
    an old roster as if it were current."""
    ssid = esc(policy.get("ssid", "?"))
    ch = esc(policy.get("channel", "?"))
    prof = esc(policy.get("profile", "?"))
    ident = ("WPA2-Enterprise · identity proven at association"
             if (policy.get("enterprise") or {}).get("enabled")
             else "WPA2-PSK · identity asserted at sign-in")
    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Themis — proctor console</title>
<style>{CSS}{CONSOLE_CSS}</style>
</head><body><div class="wrap wide">

<div class="bar">
  <h1>Proctor console</h1>
  <span class="live"><span class="dot beat" id="beat"></span><span id="livetext">live</span></span>
  <span class="live" style="margin-left:auto">elapsed <span id="clock" class="mono">—</span></span>
</div>
<p class="sub">{ssid} · channel {ch} · profile {prof} · {esc(ident)}</p>

<div class="chain" id="chain"><div>checking the record…</div></div>

<div class="stats" id="stats"></div>

<div class="actions">
  <a class="btn2" href="/dump.json" download="themis-exam.json">Download the full record</a>
  <a class="btn2" href="/report.txt" target="_blank">Per-student report</a>
</div>

<h2>Students</h2>
<div class="grid" id="grid"></div>

<h2>Worth a look</h2>
<p class="note">Flags, not findings. Every one has an innocent reading as well as a
suspicious one, and you are the one who can see the room.</p>
<div id="anoms"></div>

<hr class="rule">
<p class="note"><strong>This console decides nothing.</strong> There are no marks in
it and no way to fail anybody. Gaps are shown as a range because presence is
sampled: a device is only known to have left somewhere between the last sample that
saw it and the first that did not.</p>
<p class="foot">Themis · reachable only from this machine</p>

<script>{CONSOLE_JS}</script>
</div></body></html>"""
