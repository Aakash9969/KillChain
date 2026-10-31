/* KillChain SPA — hash-routed, zero-dependency. */
"use strict";

/* ---------------- api ---------------- */
async function api(path, opts) {
  const r = await fetch("/api" + path, opts && {
    method: opts.method || "GET",
    headers: opts.body ? { "Content-Type": "application/json" } : undefined,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || r.statusText || "Request failed");
  return data;
}

/* ---------------- helpers ---------------- */
const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
function h(html) { const t = document.createElement("template"); t.innerHTML = html.trim(); return t.content.firstChild; }
const _A = String.fromCharCode(38); // ampersand (avoids entity mangling)
function esc(s) {
  return String(s == null ? "" : s)
    .replace(new RegExp(_A, "g"), _A + "amp;")
    .replace(/</g, _A + "lt;")
    .replace(/>/g, _A + "gt;")
    .replace(/"/g, _A + "quot;")
    .replace(/'/g, _A + '#39;');
}
function fmtTime(ts) { if (!ts) return "—"; return new Date(ts * 1000).toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }); }
function fmtBytes(n) { if (!n) return "0 B"; const u = ["B", "KB", "MB", "GB"]; let i = 0; while (n >= 1024 && i < 3) { n /= 1024; i++; } return n.toFixed(i ? 1 : 0) + " " + u[i]; }
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
function chip(sev) { return `<span class="chip ${esc(sev)}">${esc(sev)}</span>`; }
function toast(msg, isErr) {
  const t = h(`<div class="toast ${isErr ? "err" : ""}">${esc(msg)}</div>`);
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 4200);
}

/* ---------------- app shell ---------------- */
const NAV = [
  ["overview", "Overview", '<path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z" fill="none" stroke="currentColor" stroke-width="1.7"/>'],
  ["logs", "Log Explorer", '<path d="M4 6h16M4 12h16M4 18h10" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>'],
  ["investigations", "Investigations", '<path d="M10.5 3a7.5 7.5 0 1 0 4.7 13.4l5 5 1.4-1.4-5-5A7.5 7.5 0 0 0 10.5 3z" fill="none" stroke="currentColor" stroke-width="1.7"/>'],
  ["graph", "Attack Graph", '<circle cx="5" cy="19" r="2.4"/><circle cx="19" cy="5" r="2.4"/><circle cx="19" cy="19" r="2.4"/><circle cx="8" cy="8" r="2.4"/><path d="M7 17l9-10M10 9l7 8M7.5 17.5l9 0" fill="none" stroke="currentColor" stroke-width="1.5"/>'],
  ["entities", "Entity Explorer", '<circle cx="12" cy="8" r="3.4"/><path d="M5 20a7 7 0 0 1 14 0" fill="none" stroke="currentColor" stroke-width="1.7"/>'],
  ["reports", "Reports", '<path d="M6 2h9l5 5v15H6z" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="M14 2v6h6M9 13h8M9 17h8" fill="none" stroke="currentColor" stroke-width="1.5"/>'],
];

function buildShell() {
  $("#sidebar").innerHTML = `
    <div class="logo">
      <div class="mark">
        <svg viewBox="0 0 24 24" fill="none" stroke="#38e1ff" stroke-width="2">
          <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z"/>
          <path d="M8 12l2.5 2.5L16 9" stroke-width="2"/>
        </svg>
      </div>
      <div>
        <div class="word">KILL<span>CHAIN</span></div>
        <div class="sub">ATTACK RECONSTRUCTION</div>
      </div>
    </div>
    <nav>${NAV.map(([id, label, icon]) => `
      <div class="nav-item" data-nav="${id}" onclick="location.hash='#/${id}'">
        <svg viewBox="0 0 24 24">${icon}</svg><span>${label}</span>
        <span class="badge" data-badge="${id}" style="display:none"></span>
      </div>`).join("")}
    </nav>
    <div class="foot">
      <div class="pill" id="ai-pill"><span class="dot"></span><span>AI: checking…</span></div>
      <div style="margin-top:8px">KillChain v1.0 — Checkpoint 1</div>
    </div>`;
  $("#topbar").innerHTML = `
    <div class="crumb" id="crumb"></div>
    <div class="spacer"></div>
    <span class="badge-demo" id="demo-badge" style="display:none">SYNTHETIC DEMONSTRATION DATA</span>
    <span class="pill" id="events-pill"><span class="dot ok"></span><span class="mono" id="events-count">0 events</span></span>`;
}

async function refreshBadges() {
  try {
    const st = await api("/stats");
    const inc = st.totals.incidents;
    const badge = $('[data-badge="investigations"]');
    if (inc) { badge.style.display = ""; badge.textContent = inc; }
    $("#events-count").textContent = st.totals.events.toLocaleString() + " events";
    $("#demo-badge").style.display = st.totals.events > 0 && st.is_demo_data ? "" : "none";
    const p = $("#ai-pill");
    if (st.ai.available) { p.className = "pill ok"; p.innerHTML = `<span class="dot"></span><span>AI: ${esc(st.ai.model)}</span>`; }
    else { p.className = "pill warn"; p.innerHTML = `<span class="dot"></span><span>AI: not configured</span>`; }
    window.__stats = st;
  } catch (e) { /* server offline */ }
}

/* ---------------- evidence modal ---------------- */
async function showEvidence(eventId) {
  let e;
  try { e = await api(`/events/${eventId}`); } catch (err) { return toast(err.message, true); }
  const det = Object.entries(e.details || {}).map(([k, v]) =>
    `<div class="k">${esc(k)}</div><div class="v">${esc(typeof v === "object" ? JSON.stringify(v) : v)}</div>`).join("");
  const m = h(`<div class="modal-back"><div class="modal">
    <div class="m-h"><h3>Evidence — Event E#${e.id}</h3>
      <span class="right" style="margin-left:auto;display:flex;gap:8px;align-items:center">${chip(e.severity)}
      <button class="ghost" onclick="this.closest('.modal-back').remove()">Close</button></span></div>
    <div class="m-b">
      <div class="dim small" style="margin-bottom:10px">
        Source: <b class="mono">${esc(e.source ? e.source.name : e.source_id)}</b>
        (${esc(e.source ? e.source.origin : "?")}) · line <b class="mono">#${e.line_no}</b>
      </div>
      <div class="raw-box">${esc(e.raw)}</div>
      <div class="kv">
        <div class="k">timestamp</div><div class="v">${esc(e.ts_text || fmtTime(e.ts))}</div>
        <div class="k">event_type</div><div class="v">${esc(e.event_type)}</div>
        <div class="k">outcome</div><div class="v">${esc(e.outcome)}</div>
        <div class="k">user</div><div class="v">${esc(e.username || "—")}</div>
        <div class="k">src_ip</div><div class="v">${esc(e.src_ip || "—")}</div>
        <div class="k">dst_ip</div><div class="v">${esc(e.dst_ip || "—")}</div>
        <div class="k">host</div><div class="v">${esc(e.host || "—")}</div>
        <div class="k">process</div><div class="v">${esc(e.process || "—")}</div>
        <div class="k">message</div><div class="v">${esc(e.message || "—")}</div>
        ${det ? `<div class="k">parsed details</div><div class="v"></div>${det}` : ""}
      </div>
    </div></div></div>`);
  m.addEventListener("click", (ev) => { if (ev.target === m) m.remove(); });
  document.body.appendChild(m);
}
window.showEvidence = showEvidence;

/* ================= OVERVIEW ================= */
async function viewOverview(root) {
  const st = window.__stats || await api("/stats");
  const t = st.totals;
  const empty = t.events === 0;
  root.innerHTML = `
    <div class="grid cols-4">
      <div class="stat c-cyan"><div class="glow"></div><div class="k">Total Events Analyzed</div><div class="v">${t.events.toLocaleString()}</div><div class="s">across ${t.sources} ingested source(s)</div></div>
      <div class="stat c-amber"><div class="glow"></div><div class="k">Suspicious Events</div><div class="v">${t.suspicious_events.toLocaleString()}</div><div class="s">backing ${t.detections} detection(s)</div></div>
      <div class="stat c-red"><div class="glow"></div><div class="k">Incidents</div><div class="v">${t.incidents}</div><div class="s">correlated attack reconstructions</div></div>
      <div class="stat c-green"><div class="glow"></div><div class="k">Critical / High Findings</div><div class="v">${t.critical_high_findings}</div><div class="s">detections at or above high severity</div></div>
    </div>
    ${empty ? emptyState() : overviewData(st)}`;
  if (empty) {
    $("#btn-demo", root).onclick = loadDemoDataset;
    $("#btn-edrgen", root).onclick = generateEdrTelemetry;
  }
}

function emptyState() {
  return `<div class="panel"><div class="panel-b"><div class="empty">
    <div class="big">🛰️</div>
    <h2>No data ingested yet</h2>
    <p>Load the built-in synthetic demonstration dataset (a realistic multi-stage attack:
    brute force → compromise → lateral movement → privilege escalation → exfiltration),
    generate EDR telemetry in the hackathon ECS format, or import your own log files.</p>
    <div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap">
      <button class="primary" id="btn-demo">Load demonstration dataset</button>
      <button id="btn-edrgen">Generate EDR telemetry (ECS)</button>
      <button class="ghost" onclick="location.hash='#/logs'">Import log files →</button>
    </div>
    <p class="faint small" style="margin-top:14px">All demonstration data is generated locally and clearly labelled as synthetic.</p>
  </div></div></div>`;
}

function overviewData(st) {
  const sevDist = ["critical", "high", "medium", "low", "info"]
    .map(s => [s, st.severity_distribution[s] || 0]);
  const maxSev = Math.max(1, ...sevDist.map(x => x[1]));
  const colors = { critical: "#ff4d6a", high: "#ff9f43", medium: "#ffd166", low: "#4dd4ac", info: "#6b7f9e" };
  return `
  <div class="grid cols-2" style="margin-top:18px">
    <div class="panel"><div class="panel-h"><div class="bar"></div><h3>Threat severity distribution</h3></div>
      <div class="panel-b">${sevDist.map(([s, n]) => `
        <div class="sevbar"><div class="lbl">${s}</div>
        <div class="track"><div class="fill" style="width:${(n / maxSev * 100).toFixed(1)}%;background:${colors[s]};box-shadow:0 0 8px ${colors[s]}66"></div></div>
        <div class="n">${n.toLocaleString()}</div></div>`).join("")}
      <div class="faint small" style="margin-top:10px">Distribution of intrinsic severity across all ${st.totals.events.toLocaleString()} parsed events.</div>
      </div>
    </div>
    <div class="panel"><div class="panel-h"><div class="bar"></div><h3>Recent investigations</h3>
      <div class="right"><button class="ghost" onclick="location.hash='#/investigations'">View all →</button></div></div>
      <div class="panel-b">${st.recent_incidents.length ? st.recent_incidents.map(incCard).join("")
      : '<div class="faint">No incidents yet — run the analysis after ingesting logs.</div>'}</div>
    </div>
  </div>
  <div class="grid cols-2">
    <div class="panel"><div class="panel-h"><div class="bar"></div><h3>Latest detections</h3>
      <div class="right"><button class="ghost" onclick="location.hash='#/logs'">Log explorer →</button></div></div>
      <div class="panel-b">${st.recent_detections.length ? st.recent_detections.map(d => `
        <div class="det-card"><div class="top">${chip(d.severity)}<span class="title">${esc(d.title)}</span>
          <span class="chip info" style="text-transform:none">${esc(d.rule_id)}</span></div>
        <div class="exp">${esc(d.explanation)}</div>
        <div class="row"><span class="faint">MITRE:</span>${(d.mitre || []).map(t => `<span class="evid-chip">${esc(t)}</span>`).join("")}
          <span class="faint" style="margin-left:8px">Kill Chain:</span> <span class="mono dim">${esc(d.killchain_stage)}</span>
          <span class="faint" style="margin-left:8px">Evidence:</span>${(d.event_ids || []).slice(0, 4).map(id => `<span class="evid-chip" onclick="showEvidence(${id})">E#${id}</span>`).join("")}</div>
        </div>`).join("") : '<div class="faint">No detections yet.</div>'}</div>
    </div>
    <div class="panel"><div class="panel-h"><div class="bar"></div><h3>Event processing activity</h3></div>
      <div class="panel-b">
        ${st.sources.map(s => `
          <div class="ingest-row"><span class="pill ok" style="min-width:52px;justify-content:center"><span class="dot"></span>${esc(s.origin)}</span>
          <span class="nm">${esc(s.name)}</span>
          <span class="dim mono" style="margin-left:auto">${s.parsed_events.toLocaleString()} events · ${s.parse_errors} parse errors · ${fmtBytes(s.byte_size)}</span></div>`).join("")}
        <div class="faint small" style="margin-top:12px">Last analysis: ${st.last_analysis ? `#${st.last_analysis.id} — ${st.last_analysis.events_analyzed.toLocaleString()} events → ${st.last_analysis.detections} detections → ${st.last_analysis.incidents} incidents` : "not run yet"}</div>
        ${st.last_analysis ? `<button class="primary" style="margin-top:10px" onclick="rerunAnalysis()">Re-run analysis</button>` : ""}
      </div>
    </div>
  </div>`;
}

async function rerunAnalysis() {
  toast("Running analysis…");
  const r = await api("/analysis/run", { method: "POST" });
  toast(`Analysis complete: ${r.detections} detections, ${r.incidents} incidents`);
  await refreshBadges(); route();
}

/* ================= INGEST (shared actions) ================= */
async function loadDemoDataset() {
  toast("Generating + ingesting synthetic demonstration logs…");
  try {
    const r = await api("/ingest/demo", { method: "POST" });
    await pollJobs(Object.values(r.jobs));
    toast("Demo dataset ingested. Running analysis…");
    const an = await api("/analysis/run", { method: "POST" });
    toast(`Analysis complete: ${an.detections} detections, ${an.incidents} incidents`);
    await refreshBadges(); route();
  } catch (e) { toast(e.message, true); }
}

async function generateEdrTelemetry() {
  try {
    const r = await api("/ingest/edr-gen?count=900&alert_ratio=0.08", { method: "POST" });
    await pollJobs([r.job_id]);
    toast("ECS telemetry ingested. Running analysis…");
    const an = await api("/analysis/run", { method: "POST" });
    toast(`Analysis complete: ${an.detections} detections, ${an.incidents} incidents`);
    await refreshBadges(); route();
  } catch (e) { toast(e.message, true); }
}

function pollJobs(jobIds) {
  return new Promise((resolve) => {
    const ids = new Set(jobIds);
    const iv = setInterval(async () => {
      let alldone = true;
      for (const id of ids) {
        try {
          const j = await api(`/ingest/status/${id}`);
          if (j.status === "running") alldone = false;
        } catch (e) { /* keep waiting */ }
      }
      if (alldone) { clearInterval(iv); resolve(); }
    }, 400);
  });
}

/* ================= LOG EXPLORER ================= */
async function viewLogs(root) {
  root.innerHTML = `
    <div class="panel"><div class="panel-h"><div class="bar"></div><h3>Log ingestion</h3>
      <div class="right"><span class="faint small">streaming · disk-backed · raw evidence preserved</span></div></div>
      <div class="panel-b">
        <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
          <button class="primary" id="btn-demo">Load demonstration dataset</button>
          <button id="btn-edrgen">Generate EDR telemetry (ECS)</button>
          <label class="ghost" style="display:inline-flex;align-items:center;gap:8px;border:1px solid var(--border-hi);border-radius:8px;padding:7px 12px;cursor:pointer">
            <input type="file" id="file-in" style="display:none">
            📂 Import log file…
          </label>
          <select id="fmt-in"><option value="auto">auto-detect format</option><option value="syslog">syslog</option><option value="jsonl">JSON / ECS JSONL</option></select>
          <span class="faint small" id="ingest-note"></span>
        </div>
        <div id="jobs" style="margin-top:14px"></div>
      </div>
    </div>
    <div class="panel"><div class="panel-h"><div class="bar"></div><h3>Ingested sources</h3></div>
      <div class="panel-b" id="sources" style="padding-top:8px"></div></div>
    <div class="panel"><div class="panel-h"><div class="bar"></div><h3>Event stream</h3>
      <div class="right" style="gap:8px">
        <input id="ev-q" placeholder="search user / host / ip / raw…" style="width:230px">
        <select id="ev-sev"><option value="">all severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select>
        <select id="ev-type"><option value="">all types</option><option>auth_failure</option><option>auth_success</option><option>process</option><option>network</option><option>privilege</option><option>file</option><option>other</option></select>
      </div></div>
      <div class="panel-b" id="events" style="padding-top:8px;max-height:640px;overflow:auto"></div>
      <div class="panel-b" style="border-top:1px solid var(--border);display:flex;align-items:center;gap:12px">
        <button class="ghost" id="ev-prev">← Prev</button><span class="faint mono small" id="ev-page"></span><button class="ghost" id="ev-next">Next →</button>
        <span class="faint small" id="ev-total" style="margin-left:auto"></span>
      </div>
    </div>`;
  let offset = 0; const limit = 100;

  async function loadJobs() {
    const st = await api("/stats");
    $("#jobs", root).innerHTML = st.ingest_jobs.slice(0, 6).map(j => `
      <div class="ingest-row">
        <span class="pill ${j.status === "running" ? "warn" : "ok"}"><span class="dot ${j.status === "running" ? "blink" : ""}"></span>${j.status}</span>
        <span class="nm">${esc(j.filename)}</span>
        <div class="progress"><div class="pf" style="width:${j.status === "done" ? 100 : Math.min(90, (j.parsed_events % 900) / 9)}%"></div></div>
        <span class="mono dim">${j.parsed_events.toLocaleString()} parsed · ${j.parse_errors} errors</span>
      </div>`).join("") || '<div class="faint small">No ingestion jobs yet.</div>';
  }
  async function loadSources() {
    const ss = await api("/sources");
    $("#sources", root).innerHTML = ss.length ? `<table class="tbl"><tr><th>Source</th><th>Origin</th><th>Format</th><th>Lines</th><th>Events</th><th>Parse errors</th><th>Size</th><th>Imported</th></tr>
      ${ss.map(s => `<tr><td class="mono">${esc(s.name)}</td><td>${esc(s.origin)}</td><td class="mono">${esc(s.kind)}</td>
      <td class="mono">${(s.total_lines || 0).toLocaleString()}</td><td class="mono">${(s.parsed_events || 0).toLocaleString()}</td>
      <td class="mono">${s.parse_errors}</td><td class="mono">${fmtBytes(s.byte_size)}</td><td class="mono dim">${fmtTime(s.uploaded_at)}</td></tr>`).join("")}</table>`
      : '<div class="faint small">No sources ingested yet.</div>';
  }
  async function loadEvents() {
    const q = $("#ev-q", root).value.trim(), sev = $("#ev-sev", root).value, ty = $("#ev-type", root).value;
    const params = new URLSearchParams({ limit, offset });
    if (q) params.set("q", q); if (sev) params.set("severity", sev); if (ty) params.set("event_type", ty);
    const r = await api("/events?" + params);
    $("#events", root).innerHTML = `<table class="tbl"><tr><th>Time</th><th>Sev</th><th>Type</th><th>User</th><th>Host</th><th>Src IP</th><th>Dst IP</th><th>Process</th><th>Message</th><th>Ev</th></tr>
      ${r.events.map(e => `<tr class="rowbtn" onclick="showEvidence(${e.id})">
        <td class="mono dim">${fmtTime(e.ts)}</td><td>${chip(e.severity)}</td><td class="mono">${esc(e.event_type)}</td>
        <td class="mono">${esc(e.username || "—")}</td><td class="mono">${esc(e.host || "—")}</td>
        <td class="mono">${esc(e.src_ip || "—")}</td><td class="mono">${esc(e.dst_ip || "—")}</td>
        <td class="mono">${esc(e.process || "—")}</td>
        <td class="dim" style="max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(e.message || "")}</td>
        <td class="mono faint">E#${e.id}</td></tr>`).join("")}</table>`;
    $("#ev-page", root).textContent = `${offset + 1}–${offset + r.events.length}`;
    $("#ev-total", root).textContent = `${r.total.toLocaleString()} matching events`;
    $("#ev-prev", root).disabled = offset === 0;
    $("#ev-next", root).disabled = offset + limit >= r.total;
  }
  $("#btn-demo", root).onclick = loadDemoDataset;
  $("#btn-edrgen", root).onclick = generateEdrTelemetry;
  $("#file-in", root).onchange = async (ev) => {
    const f = ev.target.files[0]; if (!f) return;
    const fd = new FormData(); fd.append("file", f);
    toast(`Uploading ${f.name}…`);
    const r = await fetch("/api/ingest/upload?fmt=" + $("#fmt-in", root).value, { method: "POST", body: fd });
    const j = await r.json();
    if (!r.ok) return toast(j.detail || "Upload failed", true);
    await pollJobs([j.job_id]);
    toast(`Ingested ${f.name}. Click "Run analysis" on the Overview page or re-run analysis.`);
    await refreshBadges(); loadSources(); loadJobs(); route();
  };
  ["ev-q", "ev-sev", "ev-type"].forEach(id => { $("#" + id, root).onchange = () => { offset = 0; loadEvents(); }; });
  $("#ev-q", root).oninput = debounce(() => { offset = 0; loadEvents(); }, 350);
  $("#ev-prev", root).onclick = () => { offset = Math.max(0, offset - limit); loadEvents(); };
  $("#ev-next", root).onclick = () => { offset += limit; loadEvents(); };
  await Promise.all([loadJobs(), loadSources(), loadEvents()]);
}
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }

/* ================= INVESTIGATIONS ================= */
function incCard(i) {
  return `<div class="inc-card" onclick="location.hash='#/investigation/${i.id}'">
    ${riskMini(i.risk_score, i.severity)}
    <div style="flex:1;min-width:0">
      <div class="ref">${esc(i.ref)} · risk ${i.risk_score}/100</div>
      <div class="nm">${esc(i.name)}</div>
      <div class="ents">${chip(i.severity)}
        ${(i.entities.users || []).slice(0, 3).map(u => `<span class="ent-tag">👤 ${esc(u)}</span>`).join("")}
        ${(i.entities.hosts || []).slice(0, 3).map(u => `<span class="ent-tag">🖥 ${esc(u)}</span>`).join("")}
        ${(i.entities.ips || []).filter(ip => ip).slice(0, 3).map(u => `<span class="ent-tag">🌐 ${esc(u)}</span>`).join("")}
      </div>
      <div class="faint small" style="margin-top:6px">${fmtTime(i.first_ts)} → ${fmtTime(i.last_ts)}${i.is_demo ? ' · <span style="color:#c4b5fd">synthetic demo data</span>' : ""}</div>
    </div>
  </div>`;
}
function riskMini(score, sev) {
  const color = { critical: "#ff4d6a", high: "#ff9f43", medium: "#ffd166", low: "#4dd4ac" }[sev] || "#6b7f9e";
  const c = 2 * Math.PI * 22;
  return `<div class="risk-mini"><svg width="52" height="52" viewBox="0 0 52 52">
    <circle cx="26" cy="26" r="22" fill="none" stroke="#1c2b45" stroke-width="5"/>
    <circle cx="26" cy="26" r="22" fill="none" stroke="${color}" stroke-width="5" stroke-linecap="round"
      stroke-dasharray="${(score / 100 * c).toFixed(1)} ${c.toFixed(1)}" transform="rotate(-90 26 26)"
      style="filter:drop-shadow(0 0 4px ${color}88)"/></svg>
    <div class="n" style="color:${color}">${score}</div></div>`;
}

async function viewInvestigations(root) {
  const r = await api("/incidents");
  if (!r.incidents.length) {
    root.innerHTML = `<div class="panel"><div class="panel-b"><div class="empty">
      <div class="big">🔎</div><h2>No investigations yet</h2>
      <p>Ingest logs and run the analysis to reconstruct attack incidents.</p>
      <button class="primary" id="btn-demo">Load demonstration dataset</button></div></div></div>`;
    $("#btn-demo", root).onclick = loadDemoDataset;
    return;
  }
  root.innerHTML = `
    <div class="panel" style="margin-bottom:18px"><div class="panel-b" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
      <span class="dim small">${r.incidents.length} reconstructed incident(s) from analysis #${r.analysis_id}.</span>
      <button class="ghost" style="margin-left:auto" onclick="rerunAnalysis()">Re-run analysis</button>
    </div></div>
    ${r.incidents.map(incCard).join('<div style="height:12px"></div>')}`;
}

/* ================= INVESTIGATION DETAIL (centerpiece) ================= */
async function viewInvestigation(root, id) {
  root.innerHTML = '<div class="loading">Reconstructing attack path…</div>';
  let D;
  try { D = await api(`/incidents/${id}`); } catch (e) { root.innerHTML = `<div class="empty">Incident not found.</div>`; return; }
  const inc = D.incident, dets = D.detections;
  const techniques = {};
  dets.forEach(d => (d.mitre || []).forEach(t => {
    (techniques[t] = techniques[t] || { id: t, rules: new Set(), evs: new Set() });
    techniques[t].rules.add(d.title);
    d.event_ids.forEach(e => techniques[t].evs.add(e));
  }));
  const stages = ["Reconnaissance", "Weaponization", "Delivery", "Exploitation", "Installation", "Command and Control", "Actions on Objectives"];
  const hitStages = new Set(dets.map(d => d.killchain_stage));

  root.innerHTML = `
    <div class="panel"><div class="panel-b" style="display:flex;gap:22px;align-items:center;flex-wrap:wrap">
      ${riskRing(inc.risk_score, inc.severity)}
      <div style="flex:1;min-width:300px">
        <div class="mono" style="color:var(--accent);font-size:12px">${esc(inc.ref)} · INCIDENT RECONSTRUCTION${inc.is_demo ? ' · <span style="color:#c4b5fd">SYNTHETIC DEMO DATA</span>' : ""}</div>
        <h2 style="margin:4px 0 8px;font-size:19px">${esc(inc.name)}</h2>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:10px">
          ${chip(inc.severity)}<span class="pill"><span class="dot ok"></span>${esc(inc.status)}</span>
          <span class="mono dim small">${fmtTime(inc.first_ts)} → ${fmtTime(inc.last_ts)}</span>
          <span class="faint small">${inc.event_ids.length} events · ${dets.length} detections · ${Object.keys(techniques).length} MITRE techniques</span>
        </div>
        <div class="dim" style="font-size:13px;max-width:860px">${esc(inc.summary)}</div>
      </div>
      <div style="display:flex;flex-direction:column;gap:8px">
        <button class="primary" id="btn-report">📄 Generate incident report</button>
        <button class="ghost" onclick="location.hash='#/graph'">Open in Attack Graph</button>
      </div>
    </div></div>

    <div class="panel"><div class="panel-h"><div class="bar"></div><h3>Cyber Kill Chain progression</h3>
      <div class="right"><span class="faint small">detections mapped to stages</span></div></div>
      <div class="panel-b"><div class="kc-strip">
        ${stages.map((s, i) => `<div class="kc-node ${hitStages.has(s) ? "hit" : ""}"><span class="idx">0${i + 1}</span>${s}</div>`).join('<div class="faint">→</div>')}
      </div></div></div>

    <div class="panel"><div class="panel-h"><div class="bar"></div><h3>Interactive attack graph</h3>
      <div class="right"><span class="faint small">drag nodes · scroll to zoom · click to inspect · dashed = inferred</span></div></div>
      <div class="panel-b">
        <div id="graph-wrap">
          <div class="graph-tools">
            <button id="g-fit">Fit</button>
            <button id="g-relayout">Re-layout</button>
            <button id="g-toggle-inf" title="Show/hide inferred edges">Hide inferred</button>
          </div>
          <div class="graph-legend">
            <div class="li"><span class="sw" style="border-color:#ff4d6a"></span> attacker infrastructure</div>
            <div class="li"><span class="sw" style="border-color:#34d399"></span> user account node</div>
            <div class="li"><span class="sw" style="border-color:#7dd3fc"></span> host node</div>
            <div class="li"><span class="sw"></span> observed relationship (evidence)</div>
            <div class="li"><span class="sw dash"></span> inferred relationship (hypothesis)</div>
          </div>
          <div class="graph-inspector" id="g-inspector"></div>
        </div>
      </div></div>

    <div class="grid cols-2">
      <div class="panel"><div class="panel-h"><div class="bar"></div><h3>Attack timeline</h3>
        <div class="right"><span class="faint small">click any event for raw evidence</span></div></div>
        <div class="panel-b" style="max-height:560px;overflow:auto"><div class="timeline">
          ${D.events.map(e => {
            const detsE = dets.filter(d => d.event_ids.includes(e.id));
            const sev = detsE.length ? detsE.map(d => d.severity).sort((a, b) => SEV_ORDER[a] - SEV_ORDER[b])[0] : e.severity;
            return `<div class="tl-item sev-${sev}"><div class="tl-card" onclick="showEvidence(${e.id})">
              <div class="t">${fmtTime(e.ts)} <span class="faint">E#${e.id}</span></div>
              <div class="desc">${esc(e.message || e.event_type)}</div>
              <div class="meta">
                <span>👤 <b>${esc(e.username || "—")}</b></span><span>🖥 <b>${esc(e.host || "—")}</b></span>
                <span>🌐 <b>${esc(e.src_ip || "—")}${e.dst_ip ? " → " + esc(e.dst_ip) : ""}</b></span>
                <span>⚙ <b>${esc(e.process || "—")}</b></span>
                ${detsE.length ? `<span>🎯 MITRE <b>${[...new Set(detsE.flatMap(d => d.mitre))].join(", ") || "—"}</b></span>` : ""}
                ${chip(sev)}
              </div></div></div>`;
          }).join("")}
        </div></div></div>

      <div>
        <div class="panel"><div class="panel-h"><div class="bar"></div><h3>MITRE ATT&CK techniques</h3></div>
          <div class="panel-b" style="max-height:280px;overflow:auto">
          ${Object.values(techniques).sort((a, b) => a.id.localeCompare(b.id)).map(t => `
            <div class="mitre-card"><span class="id">${esc(t.id)}</span>
              <div class="nm">${esc(window.__TECHNIQUES__ && window.__TECHNIQUES__[t.id] || techniqueName(t.id))}</div>
              <div class="ev">${[...t.evs].slice(0, 6).map(id => `<span class="evid-chip" onclick="showEvidence(${id})">E#${id}</span>`).join("")}
              <span class="faint small" style="align-self:center">confidence: high (rule-derived)</span></div>
            </div>`).join("") || '<div class="faint">No techniques.</div>'}
          </div></div>
        <div class="panel"><div class="panel-h"><div class="bar"></div><h3>Detections</h3></div>
          <div class="panel-b" style="max-height:300px;overflow:auto">
          ${dets.map(d => `<div class="det-card"><div class="top">${chip(d.severity)}<span class="title">${esc(d.title)}</span>
            <span class="chip info" style="text-transform:none">${esc(d.rule_id)}</span></div>
            <div class="exp">${esc(d.explanation)}</div>
            <div class="row"><span class="faint">Kill Chain:</span> <span class="mono dim">${esc(d.killchain_stage)}</span>
            <span class="faint" style="margin-left:6px">Evidence:</span>${d.event_ids.slice(0, 5).map(eid => `<span class="evid-chip" onclick="showEvidence(${eid})">E#${eid}</span>`).join("")}</div></div>`).join("")}
          </div></div>
        ${inc.hypotheses && inc.hypotheses.length ? `
        <div class="panel"><div class="panel-h"><div class="bar"></div><h3>Hypotheses (inferred)</h3></div>
          <div class="panel-b">${inc.hypotheses.map(hy => `<div class="hypo"><span class="tag">⚠ ${esc(hy.label)}</span><br>${esc(hy.text)}</div>`).join("")}</div></div>` : ""}
      </div>
    </div>

    <div class="panel"><div class="panel-h"><div class="bar"></div><h3>AI investigation assistant</h3>
      <div class="right"><span class="pill" id="ai-pill2"><span class="dot"></span>checking…</span></div></div>
      <div class="panel-b" style="padding:0">
        <div class="ai-panel">
          <div class="ai-msgs" id="ai-msgs"><div class="ai-msg bot">Ask about <b>${esc(inc.ref)}</b>. The assistant answers strictly from this incident's backend evidence (${inc.event_ids.length} events, ${dets.length} detections) — it cannot invent evidence. ${window.__AI__ ? "GLM provider is connected." : "No AI provider configured: set GLM_API_KEY to enable."}</div></div>
          <div class="ai-presets">
            ${["What happened?", "Where did the attack begin?", "How did it progress?", "What MITRE techniques were observed?", "What evidence supports the findings?", "What should I investigate next?"]
              .map(q => `<button data-q="${esc(q)}">${esc(q)}</button>`).join("")}
          </div>
          <div class="ai-input"><input id="ai-q" placeholder="Ask the investigator… (Enter to send)">
          <button class="primary" id="ai-send">Ask</button></div>
        </div>
      </div></div>`;

  // ---- graph wiring ----
  const wrap = $("#graph-wrap", root);
  const graph = new KillGraph(wrap, {
    onSelectNode(n, edges) {
      const insp = $("#g-inspector", root);
      if (!n) { insp.classList.remove("open"); return; }
      insp.innerHTML = `<b style="color:${n.color}">${esc(n.label)}</b>
        <div class="faint small mono">${esc(n.kind)} · ${esc(n.ident)}${n.role === "attacker_infra" ? " · ATTACKER INFRA" : ""}</div>
        ${n.command ? `<div class="small" style="margin-top:6px">cmd: <span class="mono">${esc(n.command)}</span></div>` : ""}
        <div class="small" style="margin-top:8px"><b>${edges.length}</b> relationship(s):</div>
        ${edges.map(e => `<div class="small" style="margin:5px 0;padding-left:8px;border-left:2px solid ${e.observed ? "var(--border-hi)" : "#7c5cff"}">
          ${e.observed ? "" : '<span class="mono" style="color:#c4b5fd">INFERRED </span>'}
          <span class="dim">${esc(e.label)}</span><br>
          <span class="faint mono">${esc(e.source)} → ${esc(e.target)}</span>
          ${e.event_ids.length ? `<br>${e.event_ids.slice(0, 4).map(eid => `<span class="evid-chip" onclick="showEvidence(${eid})">E#${eid}</span>`).join("")}` : ""}
        </div>`).join("")}`;
      insp.classList.add("open");
    },
    onSelectEdge(e) {
      const insp = $("#g-inspector", root);
      insp.innerHTML = `<b>${esc(e.label)}</b>
        <div class="faint small mono">${esc(e.source)} → ${esc(e.target)}</div>
        <div class="small" style="margin:6px 0">${e.observed ? "Observed in evidence." : '<span style="color:#c4b5fd">INFERRED hypothesis — not directly observed.</span>'}</div>
        ${e.event_ids.map(eid => `<span class="evid-chip" onclick="showEvidence(${eid})">E#${eid}</span>`).join(" ")}`;
      insp.classList.add("open");
    },
    onEmpty() { wrap.innerHTML = '<div class="empty">No graph data.</div>'; },
  });
  graph.setData(D.graph);
  $("#g-fit", root).onclick = () => graph.fit();
  $("#g-relayout", root).onclick = () => graph.setData(D.graph);
  let showInf = true;
  $("#g-toggle-inf", root).onclick = (ev) => {
    showInf = !showInf;
    ev.target.textContent = showInf ? "Hide inferred" : "Show inferred";
    graph.edges.forEach(e => { if (!e.observed && e.el) e.el.style.display = showInf ? "" : "none"; });
  };

  // ---- report ----
  $("#btn-report", root).onclick = () => { location.hash = `#/report/${inc.id}`; };

  // ---- AI ----
  const st = await api("/ai/status");
  window.__AI__ = st.available;
  const pill2 = $("#ai-pill2", root);
  pill2.className = "pill " + (st.available ? "ok" : "warn");
  pill2.innerHTML = st.available ? `<span class="dot"></span>${esc(st.model)}` : `<span class="dot"></span>not configured`;
  const msgs = $("#ai-msgs", root);
  async function ask(q) {
    if (!q.trim()) return;
    msgs.appendChild(h(`<div class="ai-msg user">${esc(q)}</div>`));
    const thinking = h(`<div class="ai-msg bot">Analyzing incident evidence…</div>`);
    msgs.appendChild(thinking); msgs.scrollTop = msgs.scrollHeight;
    try {
      const r = await api(`/incidents/${inc.id}/ai`, { method: "POST", body: { question: q } });
      thinking.remove();
      msgs.appendChild(h(`<div class="ai-msg bot">${mdLite(r.answer)}</div>`));
    } catch (e) {
      thinking.remove();
      msgs.appendChild(h(`<div class="ai-msg bot err">⚠ ${esc(e.message)}</div>`));
    }
    msgs.scrollTop = msgs.scrollHeight;
  }
  $("#ai-send", root).onclick = () => { const i = $("#ai-q", root); ask(i.value); i.value = ""; };
  $("#ai-q", root).onkeydown = (ev) => { if (ev.key === "Enter") { ask(ev.target.value); ev.target.value = ""; } };
  $$(".ai-presets button", root).forEach(b => b.onclick = () => ask(b.dataset.q));
}

function riskRing(score, sev) {
  const color = { critical: "#ff4d6a", high: "#ff9f43", medium: "#ffd166", low: "#4dd4ac" }[sev] || "#6b7f9e";
  const c = 2 * Math.PI * 46;
  return `<div class="risk-ring"><svg width="108" height="108" viewBox="0 0 108 108">
    <circle cx="54" cy="54" r="46" fill="none" stroke="#1c2b45" stroke-width="8"/>
    <circle cx="54" cy="54" r="46" fill="none" stroke="${color}" stroke-width="8" stroke-linecap="round"
      stroke-dasharray="${(score / 100 * c).toFixed(1)} ${c.toFixed(1)}" transform="rotate(-90 54 54)"
      style="filter:drop-shadow(0 0 6px ${color}aa)"/></svg>
    <div class="num" style="color:${color}">${score}<small>RISK / 100</small></div></div>`;
}
function mdLite(text) {
  return esc(text)
    .replace(/^### (.*)$/gm, '<span class="md-h">$1</span>')
    .replace(/^## (.*)$/gm, '<span class="md-h">$1</span>')
    .replace(/^# (.*)$/gm, '<span class="md-h">$1</span>')
    .replace(/\*\*(.+?)\*\*/g, "<b>$1</b>")
    .replace(/\[E#(\d+)\]/g, '<span class="evid-chip" onclick="showEvidence($1)">E#$1</span>');
}
const TECH_NAMES = {
  "T1110": "Brute Force", "T1110.001": "Brute Force: Password Guessing", "T1078": "Valid Accounts",
  "T1078.001": "Valid Accounts: Default Accounts", "T1078.003": "Valid Accounts: Local Accounts",
  "T1033": "System Owner/User Discovery", "T1016": "System Network Configuration Discovery",
  "T1087": "Account Discovery", "T1057": "Process Discovery", "T1049": "System Network Connections Discovery",
  "T1046": "Network Service Discovery", "T1003": "OS Credential Dumping",
  "T1003.008": "/etc/passwd and /etc/shadow", "T1021": "Remote Services", "T1021.004": "Remote Services: SSH",
  "T1059.001": "PowerShell", "T1548": "Abuse Elevation Control Mechanism",
  "T1548.003": "Sudo and Sudo Caching", "T1005": "Data from Local System",
  "T1041": "Exfiltration Over C2 Channel", "T1567": "Exfiltration Over Web Service",
  "T1071.001": "Web Protocols", "T1547.001": "Registry Run Keys / Startup Folder",
  "T1486": "Data Encrypted for Impact",
};
function techniqueName(id) { return TECH_NAMES[id] || "MITRE ATT&CK technique"; }

/* ================= ATTACK GRAPH PAGE ================= */
async function viewGraph(root) {
  const r = await api("/incidents");
  if (!r.incidents.length) {
    root.innerHTML = `<div class="panel"><div class="panel-b"><div class="empty"><div class="big">🕸️</div>
      <h2>No incidents to graph</h2><p>Run an analysis first.</p>
      <button class="primary" onclick="loadDemoDataset()">Load demonstration dataset</button></div></div></div>`;
    return;
  }
  root.innerHTML = `
    <div class="panel"><div class="panel-b" style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
      <span class="dim small">Incident:</span>
      <select id="sel-incident" style="min-width:340px">
        ${r.incidents.map(i => `<option value="${i.id}">${esc(i.ref)} — ${esc(i.name)} (risk ${i.risk_score})</option>`).join("")}
      </select>
      <span class="faint small">solid = observed · dashed purple = inferred</span>
    </div></div>
    <div class="panel"><div class="panel-b">
      <div id="graph-wrap" style="height:640px">
        <div class="graph-tools"><button id="g-fit">Fit</button><button id="g-relayout">Re-layout</button></div>
        <div class="graph-legend">
          <div class="li"><span class="sw" style="border-color:#ff4d6a"></span> attacker infrastructure</div>
          <div class="li"><span class="sw" style="border-color:#34d399"></span> user account</div>
          <div class="li"><span class="sw" style="border-color:#7dd3fc"></span> host</div>
          <div class="li"><span class="sw" style="border-color:#c4b5fd"></span> process</div>
          <div class="li"><span class="sw dash"></span> inferred relationship</div>
        </div>
        <div class="graph-inspector" id="g-inspector"></div>
      </div>
    </div></div>`;
  const graph = new KillGraph($("#graph-wrap", root), {
    onSelectNode(n, edges) {
      const insp = $("#g-inspector", root);
      if (!n) { insp.classList.remove("open"); return; }
      insp.innerHTML = `<b style="color:${n.color}">${esc(n.label)}</b>
        <div class="faint small mono">${esc(n.kind)} · ${esc(n.ident)}</div>
        <div class="small" style="margin-top:8px"><b>${edges.length}</b> relationship(s)</div>
        ${edges.map(e => `<div class="small dim" style="margin:4px 0">${e.observed ? "" : '<span class="mono" style="color:#c4b5fd">INFERRED </span>'}${esc(e.label)}</div>`).join("")}`;
      insp.classList.add("open");
    },
  });
  async function load(id) {
    const D = await api(`/incidents/${id}`);
    graph.setData(D.graph);
    $("#crumb").innerHTML = `Attack Graph / <b>${esc(D.incident.ref)}</b>`;
  }
  $("#sel-incident", root).onchange = (e) => load(e.target.value);
  $("#g-fit", root).onclick = () => graph.fit();
  $("#g-relayout", root).onclick = () => load($("#sel-incident", root).value);
  await load(r.incidents[0].id);
}

/* ================= ENTITY EXPLORER ================= */
async function viewEntities(root) {
  root.innerHTML = `
    <div class="panel"><div class="panel-b" style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
      <input id="ent-q" placeholder="Filter entities…" style="width:260px">
      <select id="ent-kind"><option value="">all kinds</option><option value="user">users</option><option value="host">hosts</option><option value="ip">ip addresses</option></select>
      <span class="faint small">click an entity to see its events and incident membership</span>
    </div></div>
    <div class="panel"><div class="panel-b" id="ent-list" style="padding-top:8px"></div></div>
    <div id="ent-detail"></div>`;
  let all = [];
  async function load() {
    all = await api("/entities");
    render();
  }
  function render() {
    const q = $("#ent-q", root).value.toLowerCase(), kind = $("#ent-kind", root).value;
    const rows = all.filter(e => (!kind || e.kind === kind) && (!q || e.ident.toLowerCase().includes(q)));
    $("#ent-list", root).innerHTML = `<table class="tbl"><tr><th>Kind</th><th>Identifier</th><th>Events</th><th>Last seen</th><th></th></tr>
      ${rows.slice(0, 300).map(e => `<tr class="rowbtn" onclick="location.hash='#/entity/${e.kind}/${encodeURIComponent(e.ident)}'">
        <td class="mono dim">${e.kind}${e.external ? ' <span style="color:var(--critical)">EXTERNAL</span>' : ""}</td>
        <td class="mono">${esc(e.ident)}</td><td class="mono">${e.event_count.toLocaleString()}</td>
        <td class="mono dim">${fmtTime(e.last_seen)}</td>
        <td class="mono faint">inspect →</td></tr>`).join("")}</table>
      ${rows.length > 300 ? `<div class="faint small" style="padding:8px">Showing 300 of ${rows.length}</div>` : ""}`;
  }
  $("#ent-q", root).oninput = debounce(render, 200);
  $("#ent-kind", root).onchange = render;
  await load();
}

async function viewEntity(root, kind, ident) {
  root.innerHTML = '<div class="loading">Loading entity…</div>';
  const e = await api(`/entities/${kind}/${encodeURIComponent(ident)}`);
  root.innerHTML = `
    <div class="panel"><div class="panel-b" style="display:flex;gap:14px;align-items:center;flex-wrap:wrap">
      <button class="ghost" onclick="location.hash='#/entities'">← Entity explorer</button>
      <h2 class="mono" style="margin:0;font-size:17px">${esc(e.ident)}</h2>
      <span class="chip ${e.external ? "critical" : "info"}">${e.kind}${e.external ? " · external" : ""}</span>
      <span class="faint small">${e.events.length} events · ${e.incidents.length} incident(s)</span>
    </div></div>
    ${e.incidents.length ? `<div class="panel"><div class="panel-h"><div class="bar"></div><h3>Member of incidents</h3></div>
      <div class="panel-b">${e.incidents.map(incCard).join('<div style="height:10px"></div>')}</div></div>` : ""}
    <div class="panel"><div class="panel-h"><div class="bar"></div><h3>Activity</h3></div>
      <div class="panel-b" style="max-height:600px;overflow:auto"><div class="timeline">
        ${e.events.map(ev => `<div class="tl-item sev-${ev.severity}"><div class="tl-card" onclick="showEvidence(${ev.id})">
          <div class="t">${fmtTime(ev.ts)} <span class="faint">E#${ev.id}</span> ${chip(ev.severity)}</div>
          <div class="desc">${esc(ev.message || ev.event_type)}</div>
          <div class="meta"><span>🖥 <b>${esc(ev.host || "—")}</b></span><span>🌐 <b>${esc(ev.src_ip || "—")}</b></span><span>👤 <b>${esc(ev.username || "—")}</b></span></div>
        </div></div>`).join("")}
      </div></div></div>`;
}

/* ================= REPORTS ================= */
async function viewReports(root, initialId) {
  const r = await api("/incidents");
  if (!r.incidents.length) {
    root.innerHTML = `<div class="panel"><div class="panel-b"><div class="empty"><div class="big">📄</div>
      <h2>No reports yet</h2><p>Reconstruct an incident, then generate its report.</p>
      <button class="primary" onclick="loadDemoDataset()">Load demonstration dataset</button></div></div></div>`;
    return;
  }
  root.innerHTML = `
    <div class="panel"><div class="panel-b" style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
      <span class="dim small">Incident:</span>
      <select id="sel-report" style="min-width:340px">
        ${r.incidents.map(i => `<option value="${i.id}" ${String(i.id) === String(initialId) ? "selected" : ""}>${esc(i.ref)} — ${esc(i.name)}</option>`).join("")}
      </select>
      <button class="primary" id="btn-dl">⬇ Download Markdown</button>
      <button class="ghost" id="btn-print">🖨 Print / PDF</button>
    </div></div>
    <div class="panel report" id="report-body"><div class="panel-b"><div class="loading">Select an incident…</div></div></div>`;
  let lastMd = "";
  async function load(id) {
    const rep = await api(`/incidents/${id}/report`);
    lastMd = rep.markdown;
    $("#report-body", root).innerHTML = `<div class="panel-b">${mdToHtml(rep.markdown)}</div>`;
    $("#crumb").innerHTML = `Reports / <b>${esc(rep.incident_ref)}</b>`;
  }
  $("#sel-report", root).onchange = (e) => load(e.target.value);
  $("#btn-dl", root).onclick = () => {
    const blob = new Blob([lastMd], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `killchain-report-${$("#sel-report", root).selectedOptions[0].text.split(" — ")[0]}.md`;
    a.click();
  };
  $("#btn-print", root).onclick = () => window.print();
  await load(r.incidents[0].id);
}

/* minimal markdown renderer for reports */
function mdToHtml(md) {
  const inline = (s) => esc(s)
    .replace(/\*\*(.+?)\*\*/g, "<b>$1</b>")
    .replace(/`([^`]+)`/g, "<code>$1</code>");
  const lines = md.split("\n");
  let html = "", i = 0;
  while (i < lines.length) {
    const ln = lines[i];
    if (ln.startsWith("|") && i + 1 < lines.length && /^[\s|:-]+$/.test(lines[i + 1])) {
      const head = ln.split("|").slice(1, -1);
      html += "<table><thead><tr>" + head.map(c => `<th>${inline(c.trim())}</th>`).join("") + "</tr></thead><tbody>";
      i += 2;
      while (i < lines.length && lines[i].startsWith("|")) {
        html += "<tr>" + lines[i].split("|").slice(1, -1).map(c => `<td>${inline(c.trim())}</td>`).join("") + "</tr>";
        i++;
      }
      html += "</tbody></table>";
      continue;
    }
    if (ln.startsWith("# ")) html += `<h1>${inline(ln.slice(2))}</h1>`;
    else if (ln.startsWith("## ")) html += `<h2>${inline(ln.slice(3))}</h2>`;
    else if (ln.startsWith("> ")) html += `<blockquote>${inline(ln.slice(2))}</blockquote>`;
    else if (/^\d+\. /.test(ln)) html += `<div style="margin:4px 0 4px 16px">${inline(ln)}</div>`;
    else if (/^\s+- (.*)$/.test(ln)) {
      const indent = ln.match(/^\s+/)[0].length;
      html += `<div style="margin:2px 0 2px ${16 + indent * 6}px;color:${indent >= 2 ? "var(--dim)" : "inherit"}">– ${inline(ln.match(/^\s+- (.*)$/)[1])}</div>`;
    }
    else if (ln.startsWith("- ")) html += `<div style="margin:4px 0 4px 16px">• ${inline(ln.slice(2))}</div>`;
    else if (ln.trim() !== "") html += `<div>${inline(ln)}</div>`;
    i++;
  }
  return html;
}

/* ================= ROUTER ================= */
const CRUMBS = {
  overview: "Overview", logs: "Log Explorer", investigations: "Attack Investigations",
  graph: "Attack Graph", entities: "Entity Explorer", reports: "Reports",
};
async function route() {
  const hash = location.hash.replace(/^#\/?/, "") || "overview";
  const [view, ...rest] = hash.split("/");
  const root = $("#content");
  $$(".nav-item").forEach(n => n.classList.toggle("active", n.dataset.nav === view));
  $("#crumb").innerHTML = CRUMBS[view] ? `<b>${CRUMBS[view]}</b>` : hash;
  try {
    if (view === "overview") await viewOverview(root);
    else if (view === "logs") await viewLogs(root);
    else if (view === "investigations") await viewInvestigations(root);
    else if (view === "investigation") await viewInvestigation(root, rest[0]);
    else if (view === "graph") await viewGraph(root);
    else if (view === "entities") await viewEntities(root);
    else if (view === "entity") await viewEntity(root, rest[0], decodeURIComponent(rest.slice(1).join("/")));
    else if (view === "reports") await viewReports(root, rest[0]);
    else if (view === "report") await viewReports(root, rest[0]);
    else root.innerHTML = `<div class="empty"><h2>Not found</h2></div>`;
  } catch (e) {
    root.innerHTML = `<div class="panel"><div class="panel-b"><div class="empty">
      <h2>Something went wrong</h2><p class="mono">${esc(e.message)}</p>
      <p class="faint small">Is the backend running on :8000?</p></div></div></div>`;
  }
}
window.addEventListener("hashchange", route);
window.loadDemoDataset = loadDemoDataset;
window.rerunAnalysis = rerunAnalysis;
window.addEventListener("load", async () => {
  buildShell();
  await refreshBadges();
  await route();
  setInterval(refreshBadges, 15000);
});
