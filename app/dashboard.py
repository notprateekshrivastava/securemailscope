"""Interactive dashboard served by the backend itself.

Why the backend serves it
-------------------------
The problem statement requires an interactive dashboard. Serving it from FastAPI
means there is no separate frontend to build, install or configure, nothing is
loaded from the internet, and the whole system works on a machine with no network
access - which matters when the captures come from an organisation such as NTRO.

The page is one HTML file with inline CSS and vanilla JavaScript. No CDN, no build
step, no npm. It calls the same public API documented in ``FRONTEND_API.md``, so a
separate React/Vue frontend can replace it later without touching the backend.

Layout
------
The page is deliberately calm: a verdict band answers "how bad is this capture?" in one
glance, and everything else lives in four tabs (Overview, Findings, Sessions, Actions) so
a 70-finding capture never becomes one long scroll. Session rows expand in place for the
full evidence, and both tables can be filtered from a single input.

Two ways to open it
-------------------
1. Live, against a running API:

       uvicorn app.main:app --port 8000
       http://localhost:8000/dashboard

2. Offline, as a single file with the stored analyses embedded (for screenshots,
   for a judge's laptop with no server running, or for the slide deck):

       python tools\\build_dashboard_snapshot.py
       reports\\dashboard_snapshot.html
"""

from __future__ import annotations

DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureMailScope - Cryptographic Security Posture Dashboard</title>
<style>
/* ---------------------------------------------------------------------------
   Design tokens. One scale for spacing, one for type, one for colour, so the
   page stays consistent as sections are added.
   --------------------------------------------------------------------------- */
:root {
  --bg: #0b1220; --bg-soft: #0e1626; --panel: #121c2d; --panel-2: #16223a;
  --line: #22304a; --line-soft: #1b2740;
  --text: #e9eef7; --muted: #94a3bb; --faint: #6b7d99;
  --accent: #4f8cff; --accent-soft: rgba(79,140,255,.14);
  --crit: #ff5c5c; --high: #ff9a4d; --med: #f5c451; --low: #46d39a; --info: #8194ad;
  --r-lg: 16px; --r-md: 12px; --r-sm: 9px;
  --sp-1: 6px; --sp-2: 10px; --sp-3: 14px; --sp-4: 20px; --sp-5: 28px;
  --shadow: 0 6px 22px rgba(3,8,18,.35);
}
* { box-sizing: border-box; }
html, body { height: 100%; }
body {
  margin: 0; background: radial-gradient(1100px 520px at 82% -12%, rgba(79,140,255,.10) 0%, rgba(79,140,255,0) 62%);
  background-color: var(--bg); color: var(--text);
  font: 14px/1.55 "Segoe UI", system-ui, -apple-system, Roboto, "Helvetica Neue", sans-serif;
  -webkit-font-smoothing: antialiased;
}
a { color: var(--accent); text-decoration: none; }
h1, h2, h3, h4 { margin: 0; font-weight: 650; letter-spacing: -.1px; }

/* ---- header -------------------------------------------------------------- */
header {
  position: sticky; top: 0; z-index: 20;
  background: rgba(11,18,32,.86); backdrop-filter: blur(10px);
  border-bottom: 1px solid var(--line-soft);
  padding: 14px 26px; display: flex; align-items: center; gap: 16px; flex-wrap: wrap;
}
.brand { display: flex; align-items: center; gap: 12px; }
.mark {
  width: 34px; height: 34px; border-radius: 10px; display: grid; place-items: center;
  background: linear-gradient(140deg, #2f6df6, #7c4dff); color: #fff; font-weight: 800; font-size: 15px;
  box-shadow: var(--shadow);
}
header h1 { font-size: 16.5px; }
header .sub { color: var(--muted); font-size: 12.5px; }
.spacer { flex: 1; }

main { padding: var(--sp-4) 26px 70px; max-width: 1560px; margin: 0 auto; }

/* ---- shell --------------------------------------------------------------- */
.cols { display: grid; grid-template-columns: 330px minmax(0, 1fr); gap: var(--sp-4); align-items: start; }
@media (max-width: 1080px) { .cols { grid-template-columns: 1fr; } }
.panel {
  background: var(--panel); border: 1px solid var(--line-soft);
  border-radius: var(--r-lg); padding: var(--sp-4);
}
.panel + .panel { margin-top: var(--sp-3); }
.panel-head { display: flex; align-items: center; gap: var(--sp-2); margin-bottom: var(--sp-3); }
.panel-head h2 { font-size: 12px; text-transform: uppercase; letter-spacing: .1em; color: var(--muted); }
.panel-head .count { color: var(--faint); font-size: 12px; }

/* ---- upload -------------------------------------------------------------- */
.drop {
  border: 1.5px dashed var(--line); border-radius: var(--r-md); padding: var(--sp-4) var(--sp-3);
  text-align: center; color: var(--muted); font-size: 12.5px; background: var(--bg-soft);
  transition: border-color .15s, background .15s, color .15s;
}
.drop.over { border-color: var(--accent); background: var(--accent-soft); color: var(--text); }
.drop strong { color: var(--text); display: block; font-size: 13px; margin-bottom: 3px; }
input[type=file] { color: var(--muted); font-size: 12px; margin-top: var(--sp-2); max-width: 100%; }
.field { margin-top: var(--sp-3); }
.field label { display: block; color: var(--faint); font-size: 11px; text-transform: uppercase;
  letter-spacing: .08em; margin-bottom: 6px; }
select, input[type=text], input[type=search] {
  width: 100%; background: var(--bg-soft); color: var(--text);
  border: 1px solid var(--line); border-radius: var(--r-sm); padding: 9px 11px; font-size: 13px;
  font-family: inherit;
}
select:focus, input:focus { outline: 2px solid var(--accent-soft); border-color: var(--accent); }
button, .btn {
  background: var(--accent); color: #fff; border: 0; border-radius: var(--r-sm);
  padding: 9px 15px; font-size: 13px; font-weight: 600; cursor: pointer; font-family: inherit;
  text-decoration: none; display: inline-flex; align-items: center; gap: 7px;
  transition: filter .15s, background .15s, border-color .15s;
}
button:hover, .btn:hover { filter: brightness(1.08); }
button.ghost, .btn.ghost { background: transparent; border: 1px solid var(--line); color: var(--text); font-weight: 500; }
button.ghost:hover, .btn.ghost:hover { border-color: var(--accent); color: #fff; }
button.primary { padding: 10px 18px; }
button:disabled { opacity: .5; cursor: default; filter: none; }
.row { display: flex; gap: var(--sp-2); align-items: center; flex-wrap: wrap; }

/* ---- analysis list ------------------------------------------------------- */
.item {
  background: var(--bg-soft); border: 1px solid var(--line-soft); border-radius: var(--r-md);
  padding: 12px 13px; cursor: pointer; margin-bottom: 8px; transition: border-color .15s, background .15s;
}
.item:hover { border-color: var(--line); background: var(--panel-2); }
.item.active { border-color: var(--accent); background: var(--panel-2); box-shadow: inset 3px 0 0 var(--accent); }
.item .name { font-weight: 600; font-size: 13px; overflow-wrap: anywhere; }
.item .meta { color: var(--muted); font-size: 11.5px; margin-top: 6px; display: flex; gap: 9px; flex-wrap: wrap; align-items: center; }

/* ---- hero / verdict ------------------------------------------------------ */
.hero {
  display: flex; gap: var(--sp-4); align-items: center; flex-wrap: wrap;
  padding: var(--sp-4); border-radius: var(--r-lg);
  background: linear-gradient(120deg, #16233c 0%, #121c2d 55%, #16233c 100%);
  border: 1px solid var(--line);
}
.hero .who { min-width: 240px; flex: 1; }
.hero h2 { font-size: 19px; word-break: break-all; }
.hero .meta { color: var(--muted); font-size: 12px; margin-top: 6px; display: flex; gap: var(--sp-3); flex-wrap: wrap; }
.hero .meta b { color: var(--text); font-weight: 600; }
.ring-wrap { display: flex; align-items: center; gap: var(--sp-3); }
.ring-wrap .ringbox { display: flex; flex-direction: column; align-items: center; gap: 4px; }
.ring { position: relative; width: 100px; height: 100px; flex: 0 0 100px; }
.ring svg { transform: rotate(-90deg); }
.ring .ring-value { position: absolute; inset: 0; display: grid; place-items: center; }
.ring .ring-value b { font-size: 23px; line-height: 1; }
.ring-cap { font-size: 9.5px; color: var(--faint); text-transform: uppercase; letter-spacing: .08em; }
.verdict { display: flex; flex-direction: column; gap: 7px; }
.verdict .label { font-size: 11px; text-transform: uppercase; letter-spacing: .09em; color: var(--faint); }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(126px, 1fr)); gap: var(--sp-2); }
.tile { background: var(--bg-soft); border: 1px solid var(--line-soft); border-radius: var(--r-md); padding: 12px 13px; }
.tile .k { color: var(--faint); font-size: 10.5px; text-transform: uppercase; letter-spacing: .09em; }
.tile .v { font-size: 21px; font-weight: 700; margin-top: 5px; }
.tile .h { color: var(--muted); font-size: 11.5px; }

/* ---- pills / chips ------------------------------------------------------- */
.pill {
  display: inline-block; padding: 3px 10px; border-radius: 999px;
  font-size: 11px; font-weight: 700; letter-spacing: .04em; white-space: nowrap;
}
.p-CRITICAL { background: rgba(255,92,92,.16); color: var(--crit); }
.p-HIGH { background: rgba(255,154,77,.16); color: var(--high); }
.p-MEDIUM { background: rgba(245,196,81,.16); color: var(--med); }
.p-LOW { background: rgba(70,211,154,.16); color: var(--low); }
.p-INFO, .p-UNKNOWN { background: rgba(129,148,173,.2); color: var(--info); }

/* ---- tabs ---------------------------------------------------------------- */
.tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--line-soft); margin: var(--sp-4) 0 var(--sp-3); flex-wrap: wrap; }
.tab {
  background: none; color: var(--muted); border: 0; border-bottom: 2px solid transparent;
  padding: 10px 14px; font-size: 13px; font-weight: 600; cursor: pointer; border-radius: 0;
}
.tab:hover { color: var(--text); filter: none; }
.tab.active { color: #fff; border-bottom-color: var(--accent); }
.tab .badge {
  background: var(--panel-2); border: 1px solid var(--line); border-radius: 999px;
  padding: 1px 7px; font-size: 11px; color: var(--muted); margin-left: 6px;
}

/* ---- tables -------------------------------------------------------------- */
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th {
  color: var(--faint); font-size: 10.5px; text-transform: uppercase; letter-spacing: .09em;
  font-weight: 650; text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--line);
  position: sticky; top: 62px; background: var(--panel);
}
td { padding: 10px; border-bottom: 1px solid var(--line-soft); vertical-align: middle; }
tbody tr:nth-child(even) td { background: rgba(255,255,255,.012); }
tr.session { cursor: pointer; }
tr.session:hover td { background: var(--panel-2); }
tr.detail > td { background: var(--bg-soft); padding: 0; border-bottom: 2px solid var(--line); }
.mono { font-family: ui-monospace, Consolas, "SF Mono", monospace; font-size: 12px; }
.nowrap { white-space: nowrap; }
.dim { color: var(--muted); font-size: 11.5px; }
.right { text-align: right; }

/* ---- detail expansion ---------------------------------------------------- */
.detailbox { padding: var(--sp-4); display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: var(--sp-4); }
.detailbox h4 { font-size: 11px; text-transform: uppercase; letter-spacing: .09em; color: var(--muted); margin-bottom: 9px; }
.kv { display: grid; grid-template-columns: auto 1fr; gap: 4px 14px; font-size: 12.5px; }
.kv .k { color: var(--faint); }
.kv .v { word-break: break-word; }

/* ---- findings ------------------------------------------------------------ */
.finding {
  border-left: 3px solid var(--info); background: var(--bg-soft);
  border-radius: 0 var(--r-md) var(--r-md) 0; padding: 12px 14px; margin-bottom: 9px;
}
.finding.sev-CRITICAL { border-left-color: var(--crit); }
.finding.sev-HIGH { border-left-color: var(--high); }
.finding.sev-MEDIUM { border-left-color: var(--med); }
.finding.sev-LOW { border-left-color: var(--low); }
.finding .ftitle { font-weight: 600; display: flex; align-items: center; gap: 9px; flex-wrap: wrap; }
.finding .fdesc { color: var(--muted); font-size: 12.5px; margin-top: 5px; }
.finding .frec { font-size: 12.5px; margin-top: 7px; }
.finding .frec strong { color: var(--low); }
.finding .ev { font-family: ui-monospace, Consolas, monospace; font-size: 11.5px; color: var(--muted); margin-top: 5px; }

/* ---- severity chart ------------------------------------------------------ */
.sev { display: grid; grid-template-columns: 96px 1fr 34px; gap: 9px; align-items: center; margin-bottom: 7px; }
.sev .name { font-size: 11.5px; font-weight: 650; display: flex; align-items: center; gap: 7px; }
.sev .dot { width: 8px; height: 8px; border-radius: 50%; }
.sev .track { height: 9px; border-radius: 999px; background: #1b2740; overflow: hidden; }
.sev .track i { display: block; height: 100%; border-radius: 999px; }
.sev .n { text-align: right; font-size: 12px; color: var(--muted); font-variant-numeric: tabular-nums; }
.sev-note { color: var(--faint); font-size: 11.5px; margin: 3px 0 11px 105px; }

/* ---- banners ------------------------------------------------------------- */
.banner { border-radius: var(--r-md); padding: 12px 15px; margin-bottom: var(--sp-3); font-size: 13px; }
.banner.warn { background: rgba(245,196,81,.1); border: 1px solid rgba(245,196,81,.32); }
.banner.err { background: rgba(255,92,92,.1); border: 1px solid rgba(255,92,92,.32); }
.banner.ok { background: rgba(70,211,154,.09); border: 1px solid rgba(70,211,154,.28); }
.banner b { font-weight: 650; }
.banner.unclassified { background: var(--bg-soft); border: 1px solid var(--line); border-left: 4px solid var(--med); }

/* ---- misc ---------------------------------------------------------------- */
.empty { color: var(--muted); padding: 22px 6px; text-align: center; font-size: 13px; }
.note { color: var(--faint); font-size: 11.5px; line-height: 1.6; }
code { background: #0a1120; border: 1px solid var(--line-soft); padding: 2px 6px; border-radius: 6px; font-size: 12px; }
ol.actions { list-style: none; margin: 0; padding: 0; counter-reset: a; }
ol.actions li { display: flex; gap: 12px; padding: 11px 0; border-bottom: 1px solid var(--line-soft); font-size: 13px; }
ol.actions li:last-child { border-bottom: 0; }
ol.actions .num {
  flex: 0 0 24px; width: 24px; height: 24px; border-radius: 50%; background: var(--accent-soft);
  color: var(--accent); font-weight: 700; font-size: 12px; display: grid; place-items: center;
}
.foot { color: var(--faint); font-size: 12px; margin-top: var(--sp-5); line-height: 1.75; max-width: 900px; }
.hint { color: var(--faint); font-size: 11.5px; margin-top: 6px; }
.skeleton { background: linear-gradient(90deg, #16223a 25%, #1b2740 37%, #16223a 63%); background-size: 400% 100%;
  animation: sk 1.4s ease infinite; border-radius: 8px; }
@keyframes sk { 0% { background-position: 100% 50%; } 100% { background-position: 0 50%; } }
</style>
</head>
<body>
<header>
  <div class="brand">
    <div class="mark">SM</div>
    <div>
      <h1>SecureMailScope</h1>
      <div class="sub">Cryptographic security posture of SMTP, IMAP and POP3 traffic</div>
    </div>
  </div>
  <div class="spacer"></div>
  <div class="row">
    <span id="health" class="pill p-UNKNOWN">checking API...</span>
    <button class="ghost" id="refresh">Refresh</button>
    <a class="btn ghost" href="/docs" target="_blank" rel="noopener">API docs</a>
  </div>
</header>

<main>
  <div id="banners"></div>

  <div class="cols">
    <div>
      <section class="panel">
        <div class="panel-head"><h2>Upload a capture</h2></div>
        <div class="drop" id="drop">
          <strong>Drop a .pcap / .pcapng here</strong>
          or choose a file - up to a few hundred MB per capture
          <div><input type="file" id="file" accept=".pcap,.pcapng,.cap,.gz,.json"></div>
        </div>
        <div class="field">
          <label for="src">Provenance of this capture</label>
          <select id="src">
            <option value="user">user - ordinary user upload</option>
            <option value="ntro">ntro - supplied by the organisation</option>
            <option value="team">team - our own test captures</option>
          </select>
          <div class="hint">Recorded with the analysis, so every result carries where it came from.</div>
        </div>
        <div class="row" style="margin-top:var(--sp-3)">
          <button class="primary" id="go" disabled>Analyse capture</button>
          <span id="upstatus" class="dim"></span>
        </div>
      </section>

      <section class="panel">
        <div class="panel-head"><h2>Analyses</h2><div class="spacer"></div><span class="count" id="listcount"></span></div>
        <div id="list"><div class="empty">Loading&hellip;</div></div>
      </section>
    </div>

    <div id="detail">
      <div class="panel"><div class="empty">
        Select an analysis on the left, or upload a capture to begin.
      </div></div>
    </div>
  </div>

  <div class="foot">
    <b>What this page does and does not claim.</b>
    It reads passive capture evidence only, never decrypts or displays email content, and reports
    missing evidence as UNKNOWN rather than as a weakness. Values labelled <i>negotiated</i> come from
    the server's own handshake; values the client merely offered are labelled as offers. A passive
    capture cannot prove a man-in-the-middle or downgrade attack - the findings describe the
    configuration that was observed. The ML column is a triage hint trained on this project's own
    rule labels and never replaces a finding.
  </div>
</main>

<script>
(function () {
  "use strict";

  // A snapshot build embeds the stored analyses so the same page works with no
  // server running. Everything else is a normal fetch against the public API.
  var SNAP = window.__SECUREMAILSCOPE_SNAPSHOT__ || null;

  var state = { list: [], current: null, health: null, tab: "overview", filter: "" };

  var SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  var SEV_COLOR = { CRITICAL: "#ff5c5c", HIGH: "#ff9a4d", MEDIUM: "#f5c451", LOW: "#46d39a", INFO: "#8194ad" };
  var SEV_MEANING = {
    CRITICAL: "Credentials or content were exposed - act now",
    HIGH: "A serious weakness to fix before it is relied on again",
    MEDIUM: "A weak configuration to schedule a fix for",
    LOW: "Minor or hygiene item",
    INFO: "Context, or evidence that was not visible"
  };
  // The rule class is the evidence. The ML class is a triage hint. A session where they
  // disagree is shown as a disagreement rather than quietly picking one.
  function mlCell(policy, ml) {
    var same = String(policy || "").toUpperCase() === String(ml || "").toUpperCase();
    return '<span class="pill ' + cls(ml) + '">' + esc(ml) + '</span>' +
      (same ? "" : ' <span class="dim" title="The rule finding disagrees with the triage hint">&#9888;</span>');
  }

  function esc(value) {
    if (value === null || value === undefined) return "";
    return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function cls(risk) { return "p-" + String(risk || "UNKNOWN").toUpperCase(); }
  function sev(risk) { return "sev-" + String(risk || "INFO").toUpperCase(); }
  function num(value) { return (value === null || value === undefined || value === "") ? "-" : value; }
  function pct(value) { return Math.max(0, Math.min(100, Number(value) || 0)); }
  function get(path) {
    return fetch(path).then(function (r) {
      if (!r.ok) throw new Error(path + " -> HTTP " + r.status);
      return r.json();
    });
  }
  function setHealth(text, klass) {
    var el = document.getElementById("health");
    el.textContent = text;
    el.className = "pill " + (klass || "p-UNKNOWN");
  }
  function banners(html) { document.getElementById("banners").innerHTML = html || ""; }

  // ---- header / banners ---------------------------------------------------- //
  function loadHealth() {
    if (SNAP) { state.health = SNAP.health || null; renderHealth(); return Promise.resolve(); }
    return get("/api/v1/health").then(function (h) {
      state.health = h; renderHealth();
    }).catch(function (err) {
      setHealth("API unreachable", "p-CRITICAL");
      banners('<div class="banner err"><b>The API is not answering.</b> Start it with ' +
        '<code>.\\scripts\\restart_and_test.ps1 -SkipTests</code>, then press Refresh. ' +
        'Details: ' + esc(err.message) + '</div>');
    });
  }

  function renderHealth() {
    var h = state.health;
    if (!h) return;
    setHealth("API " + (h.status || "unknown"), "p-LOW");
    var notes = [];
    notes.push(h.tshark_available
      ? '<div class="banner ok">TShark is available, so captures can be parsed.</div>'
      : '<div class="banner err"><b>TShark is not available</b>, so no capture can be parsed. ' +
        'Install Wireshark, or set <code>SECUREMAILSCOPE_TSHARK_PATH</code>.</div>');
    var mlBad = ["not_loaded", "load_failed", "stale", ""];
    if (h.ml_model_status && mlBad.indexOf(h.ml_model_status) !== -1) {
      notes.push('<div class="banner warn"><b>ML model not in use</b> (status: ' +
        esc(h.ml_model_status) + '). ' + esc(h.ml_model_note || "") +
        ' Train it with <code>python -m ml.train</code>. Rule-based classification is applied meanwhile.</div>');
    }
    if (SNAP) {
      notes.unshift('<div class="banner warn">Offline snapshot: shows the analyses stored when the ' +
        'file was generated. Uploads are disabled. Run the API and open <code>/dashboard</code> for the live view.</div>');
      document.getElementById("go").disabled = true;
    }
    banners(notes.join(""));
  }

  // ---- analyses list ------------------------------------------------------- //
  function loadList() {
    if (SNAP) { state.list = SNAP.analyses || []; renderList(); return Promise.resolve(); }
    // summary_only keeps the list small: the full record is fetched per capture when a row
    // is opened, so a list of large captures no longer downloads every session.
    return get("/api/v1/analyses?summary_only=true").then(function (items) {
      state.list = items || []; renderList();
    }).catch(function () { /* the health banner already explains it */ });
  }

  function statusPill(a) {
    var s = a.summary || {};
    var unclassified = (a.unclassified_streams || []).length;
    // Three separate states, because they mean three different things. A capture with no
    // mail session must never be dressed up as a green low-risk result.
    if (unclassified) {
      return '<span class="pill p-UNKNOWN">UNCLASSIFIED</span>' +
        '<span>' + num(unclassified) + ' encrypted stream(s)</span>' +
        '<span>protocol not provable</span>';
    }
    if (!(s.total_sessions > 0)) {
      return '<span class="pill p-UNKNOWN">NO MAIL SESSIONS</span>' +
        '<span>nothing to score</span>' +
        '<span>' + num(s.total_findings) + ' finding(s)</span>';
    }
    return '<span class="pill ' + cls(s.overall_risk_class) + '">' + esc(s.overall_risk_class) + '</span>' +
      '<span>posture ' + num(s.overall_posture_score) + '/100</span>' +
      '<span>' + num(s.total_sessions) + ' session(s)</span>' +
      '<span>' + num(s.total_findings) + ' finding(s)</span>';
  }

  function renderList() {
    var box = document.getElementById("list");
    document.getElementById("listcount").textContent = state.list.length ? state.list.length + " stored" : "";
    if (!state.list.length) {
      box.innerHTML = '<div class="empty">No analyses stored yet.<br>Upload a capture above to begin.</div>';
      return;
    }
    box.innerHTML = state.list.map(function (a) {
      var active = state.current && state.current.analysis_id === a.analysis_id;
      return '<div class="item' + (active ? " active" : "") + '" data-id="' + esc(a.analysis_id) + '">' +
        '<div class="name">' + esc(a.source_filename) + '</div>' +
        '<div class="meta">' + statusPill(a) + '</div>' +
        '<div class="meta"><span>' + esc(a.uploaded_by) + '</span><span>v' + esc(a.analyzer_version || "-") + '</span></div>' +
        '</div>';
    }).join("");
    Array.prototype.forEach.call(box.querySelectorAll(".item"), function (node) {
      node.addEventListener("click", function () { select(node.getAttribute("data-id")); });
    });
  }

  function select(id) {
    if (SNAP) {
      state.current = (SNAP.analyses || []).filter(function (a) { return a.analysis_id === id; })[0] || null;
      state.tab = "overview"; state.filter = "";
      renderList(); renderDetail();
      return;
    }
    get("/api/v1/analyses/" + encodeURIComponent(id)).then(function (full) {
      state.current = full; state.tab = "overview"; state.filter = "";
      renderList(); renderDetail();
    });
  }

  // ---- small renderers ----------------------------------------------------- //
  function ring(score, riskClass, hasSessions) {
    var size = 100, stroke = 9, r = (size - stroke) / 2, c = 2 * Math.PI * r;
    var value = hasSessions ? pct(score) : 0;
    var colour = hasSessions ? (SEV_COLOR[String(riskClass || "").toUpperCase()] || "#4f8cff") : "#38506f";
    return '<div class="ringbox"><div class="ring"><svg width="' + size + '" height="' + size + '">' +
      '<circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" fill="none" stroke="#1b2740" stroke-width="' + stroke + '"/>' +
      '<circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" fill="none" stroke="' + colour +
        '" stroke-width="' + stroke + '" stroke-linecap="round" stroke-dasharray="' + c +
        '" stroke-dashoffset="' + (c - c * value / 100).toFixed(1) + '"/>' +
      '</svg><div class="ring-value"><b>' + (hasSessions ? num(score) : "n/a") + '</b></div></div>' +
      '<div class="ring-cap">' + (hasSessions ? "posture /100" : "not scored") + '</div></div>';
  }

  function tiles(items) {
    return '<div class="tiles">' + items.map(function (t) {
      return '<div class="tile"><div class="k">' + esc(t.k) + '</div>' +
        '<div class="v">' + t.v + '</div><div class="h">' + esc(t.h || "") + '</div></div>';
    }).join("") + '</div>';
  }

  function severityChart(counts) {
    var counts_ = counts || {};
    var total = SEV_ORDER.reduce(function (sum, key) { return sum + (counts_[key] || 0); }, 0);
    var worst = Math.max.apply(null, SEV_ORDER.map(function (k) { return counts_[k] || 0; }).concat([1]));
    if (!total) {
      return '<div class="empty">No findings were raised for this capture.</div>';
    }
    return SEV_ORDER.map(function (key) {
      var value = counts_[key] || 0;
      return '<div class="sev"><div class="name"><span class="dot" style="background:' + SEV_COLOR[key] +
        '"></span>' + key + '</div>' +
        '<div class="track"><i style="width:' + Math.round(value / worst * 100) + '%;background:' + SEV_COLOR[key] + '"></i></div>' +
        '<div class="n">' + value + '</div></div>' +
        '<div class="sev-note">' + SEV_MEANING[key] + '</div>';
    }).join("") + '<div class="sev-note">' + total + ' finding(s) in total, highest severity first in the list below.</div>';
  }

  // Shown instead of nothing when a capture produced no session but did contain encrypted
  // streams. Implicit TLS on a port TShark does not recognise hides every protocol word, so
  // the protocol inside cannot be proven - and saying so is the honest answer.
  function unclassifiedBanner(a) {
    var streams = a.unclassified_streams || [];
    if (!streams.length) return "";
    var rows = streams.slice(0, 12).map(function (st) {
      return '<div class="kv"><span class="k mono">' + esc(st.stream_id) + '</span><span>' +
        'port ' + num(st.server_port) + ' &middot; ' + esc(st.tls_version || "TLS version UNKNOWN") +
        ' (from ' + esc(st.tls_version_source || "UNKNOWN") + ')' +
        (st.server_name ? ' &middot; client asked for ' + esc(st.server_name) : '') +
        ' &middot; ' + (st.certificate_visible ? 'certificate visible' : 'certificate NOT observable') +
        '</span></div>';
    }).join("");
    return '<div class="banner unclassified"><b>UNCLASSIFIED - encrypted traffic found, protocol not provable</b>' +
      '<div class="dim" style="margin:6px 0 10px">' +
        esc(a.unclassified_note || "Encrypted streams were seen in this capture but no SMTP, IMAP or POP3 session could be identified.") +
      '</div>' + rows +
      '<div class="note" style="margin-top:10px">Implicit TLS sends a ClientHello before any mail command, so there is no ' +
      'protocol vocabulary in the capture to read. A port number alone is a convention, not evidence, so the protocol is ' +
      'left UNKNOWN rather than guessed. Ask the submitter for the server configuration, or for a capture that includes ' +
      'the client connection setup.</div></div>';
  }

  // The provenance of a value only matters when there is a value. Printing
  // "UNKNOWN / UNKNOWN" under every unobserved session is noise, not evidence.
  function subline(value, source) {
    if (!value || !source) return "";
    var v = String(value).toUpperCase(), src = String(source).toUpperCase();
    return (v === src) ? "" : '<div class="dim">' + esc(source) + '</div>';
  }

  function sessionRow(s) {
    var t = s.tls || {}, st = s.starttls || {}, ml = s.ml || {};
    var upgrade = st.upgrade_successful ? "upgraded" : (st.rejected ? "rejected" : (t.detected ? "-" : "cleartext"));
    var upgradeClass = st.upgrade_successful ? "p-LOW" : (st.rejected ? "p-HIGH" : (t.detected ? "p-INFO" : "p-MEDIUM"));
    return '<tr class="session" data-sid="' + esc(s.session_id) + '">' +
      '<td class="nowrap"><code>' + esc(s.session_id).slice(0, 14) + '</code></td>' +
      '<td><b>' + esc(s.protocol) + '</b> <span class="dim">:' + num(s.server_port) + '</span>' +
        '<div class="dim">' + esc(s.server_ip || "-") + ' &larr; ' + esc(s.client_ip || "-") + '</div></td>' +
      '<td class="nowrap">' + esc(t.tls_version || "UNKNOWN") + subline(t.tls_version, t.version_source) + '</td>' +
      '<td class="mono" style="max-width:270px;word-break:break-word">' + esc(t.cipher_suite || "UNKNOWN") +
        subline(t.cipher_suite, t.cipher_source) + '</td>' +
      '<td><span class="pill ' + upgradeClass + '">' + upgrade + '</span></td>' +
      '<td><span class="pill ' + cls(s.policy_risk_class) + '">' + esc(s.policy_risk_class) + '</span></td>' +
      '<td>' + mlCell(s.policy_risk_class, ml.risk_class) + '</td>' +
      '<td class="right mono">' + num(s.policy_risk_score) + '</td>' +
      '</tr>';
  }

  function detailRow(s) {
    var t = s.tls || {}, c = s.certificate || {}, st = s.starttls || {}, ml = s.ml || {};
    var certHtml = c.present
      ? '<div class="kv">' +
          '<span class="k">Subject</span><span>' + esc(c.common_name || c.subject || "-") + '</span>' +
          '<span class="k">Issuer</span><span>' + esc(c.issuer || "-") + '</span>' +
          '<span class="k">SAN</span><span>' + esc((c.subject_alternative_names || []).join(", ") || "-") + '</span>' +
          '<span class="k">Valid until</span><span>' + esc(c.valid_until || "-") +
            (c.expired ? ' <span class="pill p-CRITICAL">expired</span>'
              : (c.days_remaining !== null && c.days_remaining !== undefined ? ' (' + c.days_remaining + ' days left)' : '')) + '</span>' +
          '<span class="k">Hostname match</span><span>' + esc(c.hostname_match) + '</span>' +
          '<span class="k">Self signed</span><span>' + esc(c.self_signed) + '</span>' +
          '<span class="k">Key</span><span>' + esc(c.public_key_algorithm || "-") + ' ' + num(c.public_key_bits) +
            (c.public_key_bits ? ' bits' : '') + '</span>' +
          '<span class="k">Signature</span><span>' + esc(c.signature_algorithm || "-") + '</span>' +
          '<span class="k">Chain</span><span>' + esc(c.chain_status) + ' (length ' + num(c.chain_length) + ')</span>' +
        '</div>'
      : '<div class="note">No certificate was visible in this capture. TLS 1.3 encrypts the certificate, and an ' +
        'incomplete capture may cut it off. This is reported as unknown evidence, not as a weakness.</div>';

    var tlsHtml = '<div class="kv">' +
        '<span class="k">Version</span><span>' + esc(t.tls_version || "UNKNOWN") + ' (' + esc(t.version_source || "-") + ')</span>' +
        '<span class="k">Offered</span><span>' + esc((t.offered_versions || []).join(", ") || "-") + '</span>' +
        '<span class="k">Cipher</span><span class="mono">' + esc(t.cipher_suite || "UNKNOWN") + '</span>' +
        '<span class="k">Key exchange</span><span>' + esc(t.key_exchange || "-") + '</span>' +
        '<span class="k">Forward secrecy</span><span>' + esc(t.forward_secrecy) + '</span>' +
        '<span class="k">SNI</span><span>' + esc(t.sni || "-") + '</span>' +
        '<span class="k">Group</span><span>' + esc(t.named_group || "-") + '</span>' +
        '<span class="k">Alerts</span><span>' + (t.alert_seen ? "yes" : "no") + ', failures ' + num(t.handshake_failures) + '</span>' +
        '<span class="k">Handshake</span><span>' + num(t.handshake_duration_ms) + ' ms &middot; ' + esc(t.handshake_status || "UNKNOWN") + '</span>' +
      '</div>';

    var upgradeHtml = '<div class="kv">' +
        '<span class="k">Advertised</span><span>' + esc(st.advertised) + '</span>' +
        '<span class="k">Command seen</span><span>' + esc(st.command_seen) + '</span>' +
        '<span class="k">Accepted</span><span>' + esc(st.accepted) + '</span>' +
        '<span class="k">Rejected</span><span>' + esc(st.rejected) + '</span>' +
        '<span class="k">Upgraded</span><span>' + esc(st.upgrade_successful) + '</span>' +
        '<span class="k">Plaintext auth</span><span>' + esc(st.plaintext_authentication_seen) + '</span>' +
        '<span class="k">Implicit TLS</span><span>' + esc(st.implicit_tls) + '</span>' +
      '</div>';

    var mlHtml = '<div class="kv">' +
        '<span class="k">Class</span><span>' + mlCell(s.policy_risk_class, ml.risk_class) + '</span>' +
        '<span class="k">Confidence</span><span>' + (ml.confidence === null || ml.confidence === undefined ? "-" : (ml.confidence * 100).toFixed(1) + "%") + '</span>' +
        '<span class="k">Anomaly score</span><span>' + (ml.anomaly_score === null || ml.anomaly_score === undefined ? "-" : Number(ml.anomaly_score).toFixed(3)) + '</span>' +
        '<span class="k">Anomalous</span><span>' + esc(ml.anomalous) + '</span>' +
        '<span class="k">Model</span><span>' + esc(ml.model_version) + '</span>' +
      '</div>' +
      ((ml.explanation || []).length ? '<div class="note" style="margin-top:7px">Why: ' +
        esc(ml.explanation.join("; ")) + '</div>' : "");

    var findings = s.findings || [];
    var findingsHtml = findings.length ? findings.map(function (item) {
      return '<div class="finding ' + sev(item.severity) + '">' +
        '<div class="ftitle"><span class="pill ' + cls(item.severity) + '">' + esc(item.severity) + '</span>' +
          esc(item.title) + ' <span class="dim mono">' + esc(item.code) + '</span></div>' +
        '<div class="fdesc">' + esc(item.description) + '</div>' +
        ((item.evidence || []).length ? '<div class="ev">' + esc(item.evidence.join(" | ")) + '</div>' : "") +
        '<div class="frec"><strong>Fix:</strong> ' + esc(item.recommendation) + '</div>' +
        '</div>';
    }).join("") : '<div class="note">No findings for this session.</div>';

    return '<tr class="detail"><td colspan="8"><div class="detailbox">' +
      '<div><h4>TLS evidence</h4>' + tlsHtml + '</div>' +
      '<div><h4>Certificate</h4>' + certHtml + '</div>' +
      '<div><h4>STARTTLS / STLS</h4>' + upgradeHtml + '<h4 style="margin-top:16px">Classification</h4>' + mlHtml + '</div>' +
      '<div style="grid-column:1/-1"><h4>Findings for this session</h4>' + findingsHtml + '</div>' +
      '</div></td></tr>';
  }

  function facts(result) {
    var s = result.summary || {};
    var protocols = Object.keys(s.protocols || {}).map(function (k) { return k + " x" + s.protocols[k]; }).join(", ");
    var versions = Object.keys(s.tls_versions || {}).map(function (k) { return k + " x" + s.tls_versions[k]; }).join(", ");
    var ciphers = Object.keys(s.ciphers || {}).map(function (k) { return k + " x" + s.ciphers[k]; }).join(", ");
    return '<div class="kv">' +
      '<span class="k">Protocols</span><span>' + esc(protocols || "-") + '</span>' +
      '<span class="k">TLS versions</span><span>' + esc(versions || "none observed") + '</span>' +
      '<span class="k">Cipher suites</span><span class="mono">' + esc(ciphers || "none observed") + '</span>' +
      '<span class="k">Capture size</span><span>' + num(result.source_size_bytes) + ' bytes</span>' +
      '<span class="k">SHA-256</span><span class="mono">' + esc(String(result.source_sha256 || "").slice(0, 24)) + '&hellip;</span>' +
      '</div>';
  }

  // ---- detail -------------------------------------------------------------- //
  function renderDetail() {
    var box = document.getElementById("detail");
    var a = state.current;
    if (!a) {
      box.innerHTML = '<div class="panel"><div class="empty">Select an analysis on the left, ' +
        'or upload a capture to begin.</div></div>';
      return;
    }
    var s = a.summary || {};
    var hasSessions = (s.total_sessions || 0) > 0;
    var counts = s.findings_by_severity || {};
    var findings = a.findings || [];
    var sessions = a.sessions || [];
    var recs = a.recommendations || [];
    var base = a.analysis_id;

    var downloads = SNAP
      ? '<span class="dim">Report files were exported next to the HTML report by <code>export_reports.ps1</code>.</span>'
      : '<div class="row">' +
          '<a class="btn ghost" href="/api/v1/analyses/' + esc(base) + '/reports/json">JSON</a>' +
          '<a class="btn ghost" href="/api/v1/analyses/' + esc(base) + '/reports/html" target="_blank" rel="noopener">HTML</a>' +
          '<a class="btn ghost" href="/api/v1/analyses/' + esc(base) + '/reports/pdf">PDF</a>' +
        '</div>';

    // A 3,000-session capture produced a 13 MB response and a 3,000-row table, which the
    // browser renders slowly enough to look broken. Show the worst sessions first and say
    // plainly how many are not listed; the JSON and HTML reports hold every session.
    var SESSION_ROW_LIMIT = 200;
    var ordered = sessions.slice().sort(function (x, y) {
      return (y.policy_risk_score || 0) - (x.policy_risk_score || 0);
    });
    var visible = ordered.slice(0, SESSION_ROW_LIMIT);
    var overflowNote = (ordered.length > visible.length)
      ? '<div class="note" style="padding:10px 2px 0">Showing the ' + num(visible.length) +
        ' highest-risk of ' + num(ordered.length) + ' sessions. Every session is in the JSON and HTML ' +
        'reports, and the batch path writes one row per session.</div>'
      : '';
    var detailRows = {};
    visible.forEach(function (item) { detailRows[item.session_id] = detailRow(item); });

    // -- hero ---------------------------------------------------------------- //
    var heroTiles = tiles([
      { k: "Sessions", v: num(s.total_sessions), h: num(s.tls_sessions) + " TLS, " + num(s.plaintext_sessions) + " cleartext" },
      { k: "Upgrades", v: num(s.successful_upgrades), h: "of " + num(s.starttls_sessions) + " requested" },
      { k: "Findings", v: num(s.total_findings), h: num(counts.CRITICAL || 0) + " critical" },
      { k: "Anomalies", v: num(s.anomalous_sessions), h: "ML anomaly indicators" },
      { k: "Evidence", v: num(s.evidence_completeness), h: "1.0 = everything visible" }
    ]);

    var hero = '<section class="hero">' +
      '<div class="who"><h2>' + esc(a.source_filename) + '</h2>' +
        '<div class="meta">' +
          '<span>Uploaded by <b>' + esc(a.uploaded_by) + '</b></span>' +
          '<span>' + esc(a.created_at) + '</span>' +
          '<span>analyzer <b>v' + esc(a.analyzer_version || "-") + '</b></span>' +
          '<span class="mono">' + esc(String(a.source_sha256 || "").slice(0, 12)) + '&hellip;</span>' +
        '</div>' + downloads + '</div>' +
      '<div class="ring-wrap">' + ring(s.overall_posture_score, s.overall_risk_class, hasSessions) +
        '<div class="verdict">' +
          '<div class="label">Worst session</div>' +
          (hasSessions
            ? '<div><span class="pill ' + cls(s.overall_risk_class) + '">' + esc(s.overall_risk_class) +
              '</span></div><div class="dim">risk score ' + num(s.overall_risk_score) + '/100</div>'
            : '<div><span class="pill p-UNKNOWN">NONE ASSESSED</span></div>' +
              '<div class="dim">' +
                ((a.unclassified_streams || []).length ? 'encrypted traffic, protocol not proven'
                                                       : 'no mail session to score') + '</div>') +
        '</div></div>' +
      '</section>';

    // -- tabs ---------------------------------------------------------------- //
    function tabButton(name, label, count) {
      return '<button class="tab' + (state.tab === name ? " active" : "") + '" data-tab="' + name + '">' +
        label + (count === undefined ? "" : '<span class="badge">' + count + '</span>') + '</button>';
    }
    var tabs = '<div class="tabs">' +
      tabButton("overview", "Overview") +
      tabButton("findings", "Findings", findings.length) +
      tabButton("sessions", "Sessions", sessions.length) +
      tabButton("actions", "Actions", recs.length) +
      '</div>';

    // -- panels -------------------------------------------------------------- //
    var overview = '<div class="cols" style="grid-template-columns:repeat(auto-fit,minmax(320px,1fr))">' +
        '<section class="panel"><div class="panel-head"><h2>Finding severity</h2></div>' +
          severityChart(counts) + '</section>' +
        '<section class="panel"><div class="panel-head"><h2>Capture facts</h2></div>' + facts(a) +
          '<div class="note" style="margin-top:12px">The ML column is a triage hint trained on this ' +
          'project\'s own rule labels. Where it disagrees with a rule class it is marked with a warning ' +
          'sign, and the finding stays the evidence.</div></section>' +
      '</div>' + heroTilesBlock(heroTiles);

    function heroTilesBlock(html) {
      return '<section class="panel" style="margin-top:14px"><div class="panel-head"><h2>At a glance</h2></div>' + html + '</section>';
    }

    var filterBox = '<input type="search" id="filter" placeholder="Filter findings and sessions (protocol, cipher, finding, session id)..." value="' + esc(state.filter) + '">';
    function matches(text) {
      if (!state.filter) return true;
      return String(text || "").toLowerCase().indexOf(state.filter.toLowerCase()) !== -1;
    }

    var filteredFindings = findings.filter(function (item) {
      return matches([item.code, item.title, item.description, item.session_id, item.severity,
        (item.evidence || []).join(" "), item.recommendation].join(" "));
    });
    var findingsPanel = '<section class="panel">' +
      '<div class="panel-head"><h2>Prioritised findings</h2><div class="spacer"></div>' +
      '<span class="count">' + filteredFindings.length + ' of ' + findings.length + '</span></div>' +
      '<div style="margin-bottom:12px">' + filterBox + '</div>' +
      (findings.length ? (filteredFindings.length ? filteredFindings.map(function (item) {
        return '<div class="finding ' + sev(item.severity) + '">' +
          '<div class="ftitle"><span class="pill ' + cls(item.severity) + '">' + esc(item.severity) + '</span>' +
            esc(item.title) + ' <span class="dim mono">' + esc(item.code) + '</span>' +
            ' <span class="dim">impact ' + num(item.score_impact) + '</span></div>' +
          '<div class="fdesc">' + esc(item.description) + '</div>' +
          '<div class="dim mono" style="margin-top:5px">session ' + esc(item.session_id || "-") + '</div>' +
          ((item.evidence || []).length ? '<div class="ev">' + esc(item.evidence.join(" | ")) + '</div>' : "") +
          '<div class="frec"><strong>Fix:</strong> ' + esc(item.recommendation) + '</div>' +
          '</div>';
      }).join("") : '<div class="empty">No finding matches the filter.</div>')
        : '<div class="empty">No findings were raised for this capture.</div>') +
      '</section>';

    var filteredSessions = visible.filter(function (item) {
      var t = item.tls || {};
      return matches([item.session_id, item.protocol, item.server_port, t.tls_version, t.cipher_suite,
        item.policy_risk_class, (item.ml || {}).risk_class].join(" "));
    });
    var sessionsRowHtml = filteredSessions.map(sessionRow).join("");
    var sessionsPanel = '<section class="panel">' +
      '<div class="panel-head"><h2>Sessions</h2><div class="spacer"></div>' +
      '<span class="count">' + (sessions.length ? "click a row for the full evidence" : "") + '</span></div>' +
      (sessions.length
        ? '<div style="margin-bottom:12px">' + filterBox + '</div>' +
          '<table><thead><tr><th>Session</th><th>Server &larr; client</th><th>TLS version</th><th>Cipher suite</th>' +
          '<th>Upgrade</th><th>Rules</th><th>ML</th><th class="right">Score</th></tr></thead><tbody>' +
          sessionsRowHtml + '</tbody></table>' + overflowNote +
          (filteredSessions.length ? "" : '<div class="empty">No session matches the filter.</div>')
        : '<div class="empty">No email sessions were found in this capture.' +
          ((a.unclassified_streams || []).length
            ? ' Encrypted traffic was seen, but it could not be attributed to a mail protocol.'
            : ' The analyzer only reads SMTP, IMAP and POP3 traffic.') + '</div>') +
      '</section>';

    var actionsPanel = '<section class="panel">' +
      '<div class="panel-head"><h2>Recommended actions</h2></div>' +
      (recs.length
        ? '<ol class="actions">' + recs.map(function (r) {
            return '<li><span class="num">' + (recs.indexOf(r) + 1) + '</span><span>' + esc(r) + '</span></li>';
          }).join("") + '</ol>'
        : '<div class="empty">No remediation items: no weaknesses were found in this capture.</div>') +
      '</section>';

    var body = state.tab === "findings" ? findingsPanel
      : state.tab === "sessions" ? sessionsPanel
      : state.tab === "actions" ? actionsPanel
      : overview;

    box.innerHTML = hero + unclassifiedBanner(a) + tabs +
      (state.tab === "overview" ? body : body);

    // -- wiring -------------------------------------------------------------- //
    Array.prototype.forEach.call(box.querySelectorAll(".tab"), function (node) {
      node.addEventListener("click", function () {
        state.tab = node.getAttribute("data-tab");
        renderDetail();
      });
    });
    var input = document.getElementById("filter");
    if (input) {
      input.addEventListener("input", function () {
        state.filter = input.value;
        var caret = input.selectionStart;
        renderDetail();
        var again = document.getElementById("filter");
        if (again) { again.focus(); try { again.setSelectionRange(caret, caret); } catch (e) {} }
      });
    }
    Array.prototype.forEach.call(box.querySelectorAll("tr.session"), function (row) {
      row.addEventListener("click", function () {
        var id = row.getAttribute("data-sid");
        var next = row.nextElementSibling;
        if (next && next.classList.contains("detail")) { next.remove(); return; }
        var holder = document.createElement("tbody");
        holder.innerHTML = detailRows[id] || "";
        if (holder.firstChild) row.parentNode.insertBefore(holder.firstChild, row.nextSibling);
      });
    });
  }

  // ---- upload --------------------------------------------------------------- //
  function upload() {
    var input = document.getElementById("file");
    if (!input.files.length) return;
    var file = input.files[0];
    var form = new FormData();
    form.append("file", file, file.name);
    form.append("uploaded_by", document.getElementById("src").value);
    document.getElementById("go").disabled = true;
    document.getElementById("upstatus").textContent = "analysing " + file.name + "...";
    fetch("/api/v1/analyses/upload", { method: "POST", body: form })
      .then(function (r) { return r.json().then(function (body) { return { ok: r.ok, body: body }; }); })
      .then(function (out) {
        document.getElementById("go").disabled = false;
        if (!out.ok) {
          document.getElementById("upstatus").textContent = "failed: " +
            (out.body && out.body.detail ? out.body.detail : "unknown error");
          return;
        }
        document.getElementById("upstatus").textContent = "done: " +
          out.body.summary.total_sessions + " session(s), posture " +
          out.body.summary.overall_posture_score + "/100";
        document.getElementById("file").value = "";
        loadList().then(function () { select(out.body.analysis_id); });
      })
      .catch(function (err) {
        document.getElementById("go").disabled = false;
        document.getElementById("upstatus").textContent = "failed: " + err.message;
      });
  }

  function wire() {
    var input = document.getElementById("file");
    input.addEventListener("change", function () {
      document.getElementById("go").disabled = !input.files.length;
      if (input.files.length) {
        document.getElementById("upstatus").textContent = "ready: " + input.files[0].name;
      }
    });
    document.getElementById("go").addEventListener("click", upload);
    document.getElementById("refresh").addEventListener("click", function () {
      loadHealth();
      loadList();
      if (state.current) select(state.current.analysis_id);
    });
    var drop = document.getElementById("drop");
    ["dragenter", "dragover"].forEach(function (name) {
      drop.addEventListener(name, function (e) { e.preventDefault(); drop.classList.add("over"); });
    });
    ["dragleave", "drop"].forEach(function (name) {
      drop.addEventListener(name, function (e) { e.preventDefault(); drop.classList.remove("over"); });
    });
    drop.addEventListener("drop", function (e) {
      if (e.dataTransfer && e.dataTransfer.files.length) {
        input.files = e.dataTransfer.files;
        document.getElementById("go").disabled = false;
        document.getElementById("upstatus").textContent = "ready: " + e.dataTransfer.files[0].name;
      }
    });
  }

  wire();
  loadHealth().then(loadList);
})();
</script>
</body>
</html>
"""


def render_dashboard() -> str:
    """Return the dashboard page. Kept as a function so tests can call it."""
    return DASHBOARD_HTML
