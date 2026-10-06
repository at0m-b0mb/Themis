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
    <li>Which site names your device asks this network for, whether each one was
        allowed or refused, and when. The proctor can see that list next to your
        name. It is names only: this network does not decrypt anything, so what
        you open on an allowed site, what you type into it, and what it sends
        back are not visible here.</li>
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

CONSOLE_CSS += """
/* What the network was asked for, per student. */
.net{margin-top:.55rem; padding-top:.5rem; border-top:1px solid var(--line)}
.netline{font-size:.82rem}
.netline .got{color:var(--ok)}
.netline b{font-family:ui-monospace,Menlo,monospace; font-weight:600}
.netline .muted, .net .muted{color:var(--muted)}
.netcount{font-size:.74rem; color:var(--muted); margin-top:.1rem;
  font-variant-numeric:tabular-nums}
ul.sites{list-style:none; margin:.4rem 0 0; padding:0; font-size:.74rem;
  font-family:ui-monospace,Menlo,monospace}
ul.sites li{display:flex; gap:.5rem; align-items:baseline; padding:.1rem 0}
ul.sites li .h{flex:1 1 auto; overflow:hidden; text-overflow:ellipsis;
  white-space:nowrap}
ul.sites li .n{flex:0 0 auto; font-variant-numeric:tabular-nums}
ul.sites li .t{flex:0 0 auto; color:var(--muted)}
ul.sites li.got .h{color:var(--ink)}
ul.sites li.ref .h{color:var(--muted)}
ul.sites li.ref .n{color:var(--warn)}
ul.sites li.got .n{color:var(--ok)}
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

  // What the NETWORK was asked for. Deliberately worded as "asked for" and not
  // "is doing": the proxy splices TLS without terminating it, so a hostname is
  // the most that can ever be known here. A tile saying canvas.jhu.edu means
  // the device requested Canvas, not that the student is working -- and a
  // refusal does not mean they tried to cheat, because a phone reaches for
  // iCloud on its own. Writing the stronger claim on screen would invite a
  // reader to treat a question as an answer.
  let net = '';
  if (s.asked_for || s.allowed_n || s.refused_n){
    const rows = (s.sites||[]).map(x =>
      `<li class="${x.blocked && !x.allowed ? 'ref' : 'got'}">`
      + `<span class="h">${x.host}</span>`
      + `<span class="n">${x.allowed ? x.allowed + '\u2713' : ''}`
      + `${x.blocked ? ' ' + x.blocked + '\u2717' : ''}</span>`
      + `<span class="t">${x.at}</span></li>`).join('');
    net = `<div class="net">
      <div class="netline">${s.asked_for
          ? `<span class="got">reaching <b>${s.asked_for}</b></span>`
          : `<span class="muted">nothing reached yet</span>`}</div>
      <div class="netcount">${s.allowed_n} allowed \u00b7 ${s.refused_n} refused</div>
      ${rows ? `<ul class="sites">${rows}</ul>` : ''}
    </div>`;
  }

  return `<div class="who ${cls}">
    <div class="nm">${s.name}${seat}</div>
    <div class="id">${s.student_id} \u00b7 <span class="dev">${s.mac}</span>${
      s.ip ? ` \u00b7 <span class="dev">${s.ip}</span>` : ''}</div>
    <div class="st">${state}</div>
    <div class="st">${gap}</div>
    ${net}
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

  const warn = document.getElementById('degraded');
  if (d.presence_degraded){
    warn.style.display = 'block';
    warn.innerHTML = '<strong>Not hearing from the radio.</strong> These tiles are now '
      + 'based on DHCP leases, which last hours — a student who has left may still show '
      + 'as present. Check that hostapd is still running before trusting anything below.';
  } else { warn.style.display = 'none'; }

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

<div class="chain broken" id="degraded" style="display:none"></div>
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


# --- operator control panel ------------------------------------------------ #

OPERATOR_CSS = """
.step{background:var(--panel); border:1px solid var(--line); border-radius:var(--radius);
  padding:1.2rem 1.4rem; margin:0 0 .9rem; border-left:3px solid var(--line)}
.step.done{border-left-color:var(--ok)}
.step.now{border-left-color:var(--gold)}
.step.blocked{border-left-color:var(--bad)}
.step h3{margin:0 0 .15rem; font-size:1rem; font-weight:600; display:flex;
  align-items:center; gap:.5rem}
.step .num{display:inline-flex; align-items:center; justify-content:center;
  width:1.4rem; height:1.4rem; border-radius:50%; font-size:.75rem; font-weight:600;
  background:var(--gold-soft); color:var(--gold); border:1px solid var(--gold);
  font-family:ui-monospace,Menlo,monospace}
.step.done .num{background:var(--ok); color:var(--bg); border-color:var(--ok)}
.step p.h{margin:.1rem 0 .9rem; color:var(--muted); font-size:.88rem}
.checks{list-style:none; padding:0; margin:.2rem 0 0; font-size:.88rem}
.checks li{padding:.28rem 0 .28rem 1.4rem; position:relative; white-space:pre-wrap}
.checks li:before{position:absolute; left:0; font-weight:700}
.checks li.ok:before{content:"\\2713"; color:var(--ok)}
.checks li.warn:before{content:"!"; color:var(--warn)}
.checks li.fail:before{content:"\\2717"; color:var(--bad)}
.checks li.fail{color:var(--bad)}
.checks li.warn{color:var(--warn)}
.row{display:flex; gap:.6rem; align-items:center; flex-wrap:wrap; margin-top:.7rem}
select{font:inherit; padding:.55rem .7rem; border-radius:8px; color:var(--ink);
  background:var(--bg); border:1px solid var(--line)}
.big{font-size:1rem; padding:.85rem 1.8rem}
.ghost{background:var(--panel); color:var(--ink); border-color:var(--line)}
.ghost:hover{border-color:var(--gold); color:var(--gold); filter:none}
.danger{background:var(--bad); border-color:var(--bad)}
button[disabled]{opacity:.4; cursor:not-allowed; filter:none}
.kv{display:grid; grid-template-columns:auto 1fr; gap:.25rem 1rem; font-size:.88rem;
  margin:.5rem 0 0}
.kv dt{color:var(--muted)}
.kv dd{margin:0; font-family:ui-monospace,Menlo,monospace}
.out{white-space:pre-wrap; font-family:ui-monospace,Menlo,monospace; font-size:.76rem;
  background:var(--bg); border:1px solid var(--line); border-radius:8px;
  padding:.7rem .85rem; margin:.8rem 0 0; max-height:16rem; overflow:auto; color:var(--muted)}
.out.bad{border-color:var(--bad); color:var(--bad)}
.badge{font-size:.72rem; font-weight:600; padding:.12rem .5rem; border-radius:999px;
  border:1px solid currentColor; margin-left:auto}
.badge.up{color:var(--ok)} .badge.downb{color:var(--muted)}
.working{display:none; font-size:.85rem; color:var(--gold); margin-top:.6rem}
.working.on{display:block}

/* --- radios, one card each: a single station count cannot say whether BOTH
       bands came up, and a dead 2.4 GHz side is invisible in a total. --- */
.radios{display:grid; gap:.5rem; margin:.6rem 0 0}
.radio{display:flex; align-items:center; gap:.7rem; padding:.6rem .8rem;
  border:1px solid var(--line); border-radius:8px; background:var(--bg);
  font-size:.88rem}
.radio .band{font-family:ui-monospace,Menlo,monospace; font-weight:600;
  color:var(--gold); min-width:4.2rem}
.radio .iface{font-family:ui-monospace,Menlo,monospace; color:var(--muted);
  min-width:4rem}
.radio .dot{width:.5rem; height:.5rem; border-radius:50%; background:var(--muted)}
.radio.on .dot{background:var(--ok)}
.radio .sta{margin-left:auto; color:var(--muted); font-size:.82rem}

/* --- mode: three genuinely different guarantees, not three settings --- */
.modes{display:grid; gap:.5rem; margin:.4rem 0 0}
.mode{text-align:left; display:block; width:100%; padding:.75rem .9rem;
  border:1px solid var(--line); border-radius:8px; background:var(--bg);
  color:var(--ink); cursor:pointer; font:inherit}
.mode:hover{border-color:var(--gold)}
.mode.sel{border-color:var(--gold); background:var(--gold-soft)}
.mode b{display:block; font-size:.95rem; margin-bottom:.15rem}
.mode span{display:block; color:var(--muted); font-size:.82rem; line-height:1.45}
.mode.sel span{color:var(--ink)}

textarea{width:100%; min-height:9rem; font:.84rem/1.5 ui-monospace,Menlo,monospace;
  padding:.7rem .85rem; border-radius:8px; color:var(--ink); background:var(--bg);
  border:1px solid var(--line); resize:vertical}
textarea:focus{outline:none; border-color:var(--gold)}

/* --- refusals: the discovery tool. A site the exam needs announces itself
       here the first time a student hits it. --- */
table.ref{width:100%; border-collapse:collapse; font-size:.84rem; margin:.5rem 0 0}
table.ref th{text-align:left; font-weight:600; color:var(--muted); font-size:.78rem;
  padding:.3rem .5rem; border-bottom:1px solid var(--line)}
table.ref td{padding:.32rem .5rem; border-bottom:1px solid var(--line);
  vertical-align:middle}
table.ref td.host{font-family:ui-monospace,Menlo,monospace; word-break:break-all}
table.ref td.n{color:var(--muted); text-align:right; font-variant-numeric:tabular-nums}
table.ref td.act{text-align:right; white-space:nowrap}
table.ref tr.allowed td.host{color:var(--ok)}
.btn2{font:inherit; font-size:.78rem; padding:.25rem .6rem; border-radius:6px;
  background:var(--panel); color:var(--ink); border:1px solid var(--line);
  cursor:pointer}
.btn2:hover{border-color:var(--gold); color:var(--gold)}
.empty{color:var(--muted); font-size:.85rem; margin:.6rem 0 0}

/* --- the one line an operator glances at mid-exam --- */
.statusbar{position:sticky; top:0; z-index:5; margin:0 0 1rem;
  background:var(--panel); border:1px solid var(--line); border-radius:var(--radius);
  padding:.6rem .9rem; display:flex; align-items:center; gap:.4rem .9rem;
  flex-wrap:wrap; backdrop-filter:blur(8px)}
.statusbar .pill{display:inline-flex; align-items:center; gap:.4rem;
  font-size:.82rem; color:var(--muted)}
.statusbar .pill b{color:var(--ink); font-family:ui-monospace,Menlo,monospace;
  font-weight:600}
.statusbar .live{width:.5rem; height:.5rem; border-radius:50%;
  background:var(--muted); flex:none}
.statusbar.up .live{background:var(--ok); box-shadow:0 0 0 3px color-mix(in srgb, var(--ok) 25%, transparent)}
/* max-width:max-content is the load-bearing part. When the bar wraps, this ends
   up alone on its line and is stretched to the full width -- a pill that is no
   longer pill-shaped. flex:0 0 auto does NOT prevent it; measured in a browser,
   the element went 673px -> 98px only once max-content was set. */
.statusbar .mode{margin-left:auto; flex:0 0 auto; align-self:center;
  max-width:max-content;
  font-size:.74rem; font-weight:600; letter-spacing:.04em; text-transform:uppercase;
  color:var(--gold); border:1px solid var(--gold); border-radius:999px;
  padding:.15rem .6rem; white-space:nowrap}

@media (max-width:640px){
  .statusbar{position:static}
  .statusbar .mode{margin-left:0}
  .radio{flex-wrap:wrap; gap:.3rem .7rem}
  .radio .sta{margin-left:0; width:100%}
  table.ref td.act{display:block; text-align:left; padding-top:0}
  .row{flex-direction:column; align-items:stretch}
  .row button, .row a{width:100%; text-align:center}
}
"""

OPERATOR_JS = """
let busy = false;
let editing = {allow:false, block:false};

function esc(s){ const d=document.createElement('div'); d.textContent=s==null?'':s; return d.innerHTML; }

function checks(pf){
  const li = (c,l) => `<li class="${l}">${esc(c.message)}</li>`;
  return '<ul class="checks">'
    + (pf.fail||[]).map(c=>li(c,'fail')).join('')
    + (pf.warn||[]).map(c=>li(c,'warn')).join('')
    + (pf.ok||[]).map(c=>li(c,'ok')).join('')
    + '</ul>';
}

const MODES = [
  ['airgap', 'Air-gapped',
   'No uplink at all. Online lookup, cloud AI, VPN and Tor are not filtered \u2014 they are unreachable. The exam must be served from this machine. The only mode that can prove rather than claim.'],
  ['allowlist', 'Allowlist \u2014 only these sites work',
   'Everything else is refused instantly. Matched by NAME, so it survives the CDN rotating and cannot be reached by aiming at an allowed address with a different SNI. Use this when the quiz lives in cloud Canvas.'],
  ['blocklist', 'Blocklist \u2014 the web works except these',
   'Much weaker: a site you did not think of is a site that works, and that includes every AI front-end launched between now and the exam. Use it for an open-book paper, not a closed one.'],
];

function radios(s){
  if (!s.radios || !s.radios.length) return '<p class="empty">No radio configured yet.</p>';
  return '<div class="radios">' + s.radios.map(r =>
    `<div class="radio ${r.running?'on':''}"><span class="dot"></span>`
    + `<span class="band">${esc(r.band)} GHz</span>`
    + `<span class="iface">${esc(r.interface)}</span>`
    + `<span>ch ${esc(r.channel)} \u00b7 ${esc(r.width)} MHz</span>`
    + `<span class="sta">${r.running ? esc(r.stations.length)+' station(s)' : 'not running'}</span>`
    + `</div>`).join('') + '</div>';
}

function statusbar(s){
  const live = s.ap_running && s.portal_running;
  const total = (s.radios||[]).reduce((n,r)=>n + (r.stations||[]).length, 0);
  const bands = (s.radios||[]).filter(r=>r.running).map(r=>r.band+' GHz').join(' + ') || 'none';
  const el = document.getElementById('statusbar');
  el.className = 'statusbar' + (live ? ' up' : '');
  el.innerHTML = `<span class="pill"><span class="live"></span>`
    + `<b>${esc(s.policy.ssid)}</b></span>`
    + `<span class="pill">${live ? 'running' : 'stopped'}</span>`
    + `<span class="pill">bands <b>${esc(bands)}</b></span>`
    + `<span class="pill">students <b>${esc(total)}</b></span>`
    + `<span class="mode">${esc(s.mode === 'allowlist-legacy' ? 'legacy' : s.mode)}</span>`;
}

function refusals(s){
  const rows = s.refusals || [];
  if (!s.proxy_running) return '<p class="empty">The proxy is not running, so nothing is being refused yet. In air-gapped mode nothing is reachable at all, so nothing is logged here.</p>';
  if (!rows.length) return '<p class="empty">Nothing refused yet. Once students join, whatever their devices reach for that is not permitted will appear here.</p>';
  return '<table class="ref"><thead><tr><th>name a student asked for</th>'
    + '<th style="text-align:right">tries</th><th>last</th><th></th></tr></thead><tbody>'
    + rows.map(r =>
      `<tr class="${r.on_allow?'allowed':''}"><td class="host">${esc(r.host)}</td>`
      + `<td class="n">${esc(r.count)}</td>`
      + `<td class="n">${esc((r.last||'').slice(11))}</td>`
      + `<td class="act">${r.on_allow ? '<span class="sta">allowed</span>'
          : `<button class="btn2" data-allow="${esc(r.host)}">Allow this</button>`}</td></tr>`
    ).join('') + '</tbody></table>';
}

function render(s){
  const pol = s.policy, pf = s.preflight;
  const configured = !!(s.radios && s.radios.length && s.radios[0].interface) && pol.passphrase_set;
  const live = s.ap_running && s.portal_running;
  const mode = s.mode;
  const listed = mode === 'blocklist' ? 'block' : 'allow';

  const s1 = document.getElementById('s1');
  s1.className = 'step ' + (pf.ready ? 'done' : 'blocked');
  document.getElementById('s1body').innerHTML = checks(pf) +
    (pf.ready ? '' : '<p class="note" style="margin:.8rem 0 0">Fix the items above, then re-check. '
      + 'Each one is something that would otherwise surface during the exam.</p>');

  const s2 = document.getElementById('s2');
  s2.className = 'step ' + (configured ? 'done' : (pf.ready ? 'now' : ''));
  document.getElementById('s2body').innerHTML = radios(s) + (configured
    ? `<dl class="kv"><dt>network</dt><dd>${esc(pol.ssid)}</dd>`
      + `<dt>password</dt><dd>${esc(pol.passphrase)}</dd>`
      + (pol.bridge ? `<dt>bridge</dt><dd>${esc(pol.bridge)} \u2014 both bands are one network</dd>` : '')
      + `</dl>`
      + '<p class="note" style="margin:.6rem 0 0">Write the password on the board. '
      + 'Detect again after plugging in another adapter: one radio can only beacon on '
      + 'one band, so two bands needs two of them.</p>'
    : '<p class="note" style="margin:.6rem 0 0">Not set up yet. Detect adapters to begin.</p>');

  const s3 = document.getElementById('s3');
  s3.className = 'step ' + (mode ? 'done' : '');
  document.getElementById('modes').innerHTML = MODES.map(([k,t,d]) =>
    `<button class="mode ${mode===k?'sel':''}" data-mode="${k}"><b>${esc(t)}</b><span>${esc(d)}</span></button>`
  ).join('') + (mode === 'allowlist-legacy'
    ? '<p class="note">This policy uses the older address-based allowlist. It filters '
      + 'ADDRESSES, which go stale when a CDN rotates and can be reached with a '
      + 'different SNI. Pick Allowlist above to switch to name matching.</p>' : '');

  const s4 = document.getElementById('s4');
  const names = listed === 'block' ? (s.block||[]) : (s.allow||[]);
  s4.style.display = (mode === 'airgap') ? 'none' : 'block';
  document.getElementById('s4title').textContent = listed === 'block'
    ? 'Sites to block' : 'Sites students may reach';
  document.getElementById('s4hint').textContent = listed === 'block'
    ? 'One name per line. Subdomains are included. Everything not listed here works.'
    : 'One name per line. Subdomains are included. Everything not listed here is refused instantly. Paste a whole URL if it is easier \u2014 it is reduced to the hostname.';
  const ta = document.getElementById('listbox');
  // The newline below is written as a DOUBLED backslash on purpose. This block
  // is an ordinary Python string, so a single backslash escape is consumed at
  // import time and arrives here as a real line break inside a JavaScript
  // string literal -- a syntax error that takes the whole panel down, leaving
  // every dynamic section blank with one message in the console.
  if (!editing[listed]) ta.value = names.join('\\n') + (names.length ? '\\n' : '');
  ta.dataset.which = listed;

  const s5 = document.getElementById('s5');
  s5.className = 'step ' + (live ? 'done' : (configured && pf.ready ? 'now' : ''));
  const rb = document.getElementById('runbadge');
  rb.className = 'badge ' + (live ? 'up' : 'downb');
  rb.textContent = live ? 'exam network is up' : 'stopped';
  document.getElementById('startbtn').disabled = busy || live || !configured || !pf.ready;
  document.getElementById('stopbtn').disabled  = busy || !(s.ap_running || s.portal_running);
  document.getElementById('detect').disabled   = busy || live;
  document.getElementById('rotate').disabled   = busy || live;
  document.getElementById('recheck').disabled  = busy;
  document.getElementById('savelist').disabled = busy;
  document.getElementById('s5links').style.display = live ? 'flex' : 'none';
  document.getElementById('console').href = 'http://127.0.0.1:' + s.console_port + '/';

  statusbar(s);
  document.getElementById('refusals').innerHTML = refusals(s);

  const out = document.getElementById('out');
  if (s.last && s.last.action){
    out.style.display = 'block';
    out.className = 'out' + (s.last.ok === false ? ' bad' : '');
    out.textContent = s.last.output || '';
  } else { out.style.display = 'none'; }
}

async function refresh(){
  try{
    const r = await fetch('/api/state', {cache:'no-store'});
    render(await r.json());
  }catch(e){ /* the next tick will try again */ }
}

async function act(action, extra, note){
  if (busy) return;
  busy = true;
  const w = document.getElementById('working');
  w.classList.add('on');
  w.textContent = note || 'Working\u2026';
  try{
    await fetch('/api/action', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify(Object.assign({action}, extra||{}))});
  }catch(e){ /* the refresh below shows the real state */ }
  busy = false;
  w.classList.remove('on');
  editing = {allow:false, block:false};
  await refresh();
}

document.getElementById('detect').onclick   = () => act('autoconfigure', null,
  'Detecting adapters and assigning bands\u2026');
document.getElementById('rotate').onclick   = () => act('rotate_passphrase', null,
  'Generating a new password\u2026');
document.getElementById('startbtn').onclick = () => act('start_exam', null,
  'Starting the radios, DHCP, DNS, firewall, proxy and portal\u2026');
document.getElementById('stopbtn').onclick  = () => act('stop_exam', null,
  'Stopping the exam and restoring this host\u2026');
document.getElementById('recheck').onclick  = () => refresh();
document.getElementById('savelist').onclick = () => {
  const ta = document.getElementById('listbox');
  act('set_list', {which: ta.dataset.which, text: ta.value},
      'Saving the list and reloading the proxy\u2026');
};
document.getElementById('listbox').oninput = (e) => { editing[e.target.dataset.which] = true; };
document.getElementById('modes').onclick = (e) => {
  const b = e.target.closest('[data-mode]');
  if (b) act('set_mode', {mode: b.dataset.mode}, 'Switching mode\u2026');
};
document.getElementById('refusals').onclick = (e) => {
  const b = e.target.closest('[data-allow]');
  if (b) act('allow_name', {host: b.dataset.allow},
             'Adding ' + b.dataset.allow + ' and reloading the proxy\u2026');
};

refresh();
setInterval(() => { if (!busy) refresh(); }, 5000);
"""


def operator_page() -> str:
    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Themis — set up the exam</title>
<style>{CSS}{OPERATOR_CSS}</style>
</head><body><div class="wrap">

<h1>Set up the exam</h1>
<p class="sub">Nothing to type, and nothing here looks at a student's machine.</p>

<div class="statusbar" id="statusbar"></div>

<div class="step" id="s1">
  <h3><span class="num">1</span> This computer
    <button class="btn2" id="recheck" style="margin-left:auto">Re-check</button>
  </h3>
  <p class="h">Whether this host can run an exam at all.</p>
  <div id="s1body"></div>
</div>

<div class="step" id="s2">
  <h3><span class="num">2</span> The Wi-Fi</h3>
  <p class="h">Detect finds every adapter, checks which bands it may legally
    beacon on, and assigns one to 2.4 GHz and one to 5 GHz under a single network name.</p>
  <div class="row">
    <button id="detect" class="ghost">Detect adapters</button>
    <button id="rotate" class="ghost">New password</button>
  </div>
  <div id="s2body"></div>
</div>

<div class="step" id="s3">
  <h3><span class="num">3</span> What students may reach</h3>
  <p class="h">Three different guarantees, not three settings of one.</p>
  <div class="modes" id="modes"></div>
</div>

<div class="step" id="s4">
  <h3><span class="num">4</span> <span id="s4title">The list</span></h3>
  <p class="h" id="s4hint"></p>
  <textarea id="listbox" spellcheck="false"></textarea>
  <div class="row">
    <button id="savelist" class="ghost">Save the list</button>
  </div>
  <p class="note">Saving reloads the proxy in place. Nobody is disconnected, so a
    missing site can be added during an exam.</p>
</div>

<div class="step" id="s5">
  <h3><span class="num">5</span> Run it <span class="badge downb" id="runbadge">stopped</span></h3>
  <p class="h">Starts the radios, DHCP, DNS, the firewall, the proxy and the sign-in page together.</p>
  <div class="row">
    <button id="startbtn" class="big">Start the exam</button>
    <button id="stopbtn" class="big danger">Stop the exam</button>
  </div>
  <div class="row" id="s5links" style="display:none">
    <a class="btn2" id="console" href="#" target="_blank">Open the proctor console</a>
  </div>
  <div class="working" id="working"></div>
</div>

<div class="step">
  <h3>Refused so far</h3>
  <p class="h">What students' devices actually asked for and did not get. A site
    the exam genuinely needs shows up here the first time someone hits it, which
    is how the list gets built from real traffic instead of guesswork.</p>
  <div id="refusals"></div>
</div>

<div class="out" id="out" style="display:none"></div>

<hr class="rule">
<p class="note">Three things are not blocked by any of this and cannot be: a phone
on cellular, a local AI model on a student's own laptop, and collusion inside a
site you have allowed. Jamming the first is illegal, the second emits no packets,
and the third is carried inside a connection you deliberately permitted. Oral
spot-checks are the control that covers all three.</p>
<p class="foot">Themis · this panel is reachable only from this machine</p>

<script>{OPERATOR_JS}</script>
</div></body></html>"""
