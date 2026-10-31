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
  <div class="panel" style="margin-top:18px"><div class="panel-h"><div class="bar"></div><h3>How these numbers relate</h3></div>
    <div class="panel-b counts-note">
      <div class="cn"><b>${st.totals.events.toLocaleString()} raw events</b><br><span class="dim">every parsed log record, benign or not</span></div>
      <div class="cn"><b>${st.totals.suspicious_events.toLocaleString()} suspicious events</b><br><span class="dim">events cited as evidence by at least one detection</span></div>
      <div class="cn"><b>${st.totals.detections} detections</b><br><span class="dim">rule matches — several detections can share events</span></div>
      <div class="cn"><b>${st.totals.incidents} incidents</b><br><span class="dim">correlated groups of detections forming one attack story</span></div>
    </div></div>
  <div class="grid cols-2">
    <div class="panel"><div class="panel-h"><div class="bar"></div><h3>Threat severity distribution</h3><div class="right"><span class="faint small">intrinsic severity of raw events</span></div></div>
      <div class="panel-b">${sevDist.map(([s, n]) => `
        <div class="sevbar"><div class="lbl">${s}</div>
        <div class="track"><div class="fill" style="width:${(n / maxSev * 100).toFixed(1)}%;background:${colors[s]};box-shadow:0 0 8px ${colors[s]}66"></div></div>
        <div class="n">${n.toLocaleString()}</div></div>`).join("")}
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
      <div class="panel-b" style="max-height:420px;overflow:auto">${st.recent_detections.length ? st.recent_detections.map(d => `
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
          <div class="ingest-row"><span class="pill ok" style="min-width:60px;justify-content:center"><span class="dot"></span>${esc(s.origin)}</span>
          <span class="nm">${esc(s.name)}</span>
          <span class="dim mono" style="margin-left:auto">${s.parsed_events.toLocaleString()} events · ${s.parse_errors} parse errors · ${fmtBytes(s.byte_size)}</span></div>`).join("")}
        <div class="faint small" style="margin-top:12px">Last analysis: ${st.last_analysis ? `#${st.last_analysis.id} — ${st.last_analysis.events_analyzed.toLocaleString()} events → ${st.last_analysis.detections} detections → ${st.last_analysis.incidents} incidents${st.last_analysis.note ? ` (${esc(st.last_analysis.note)})` : ""}` : "not run yet"}</div>
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
      <div class="right"><span class="faint small">streaming · disk-backed · raw evidence preserved · resumable</span></div></div>
      <div class="panel-b">
        <div class="grid cols-2">
          <div>
            <div class="small dim" style="margin-bottom:8px"><b style="color:var(--accent)">A · Generate sample data</b> — synthetic, clearly labelled</div>
            <div style="display:flex;gap:10px;flex-wrap:wrap">
              <button class="primary" id="btn-demo">Load demonstration dataset</button>
              <button id="btn-edrgen">Generate EDR telemetry (ECS)</button>
            </div>
            <div class="small dim" style="margin:16px 0 8px"><b style="color:var(--accent)">B · Upload log files</b> — processed through the same pipeline</div>
            <div class="dropzone" id="dropzone">
              <input type="file" id="file-in" multiple style="display:none" accept=".log,.jsonl,.json,.ndjson,.txt,.out">
              <div style="font-size:20px;margin-bottom:6px">📂</div>
              <div><b>Drop log files here</b> or click to select (multiple files supported)</div>
              <div class="faint small" style="margin-top:4px">syslog · JSON / ECS JSONL · FortiGate key=value — auto-detected</div>
            </div>
            <div id="upload-list"></div>
          </div>
          <div>
            <div class="small dim" style="margin-bottom:8px"><b style="color:var(--accent)">C · Ingest a local folder</b> — for very large datasets (GB-scale), streaming & resumable</div>
            <div style="display:flex;gap:8px">
              <input id="folder-path" placeholder="Absolute path, e.g. D:\\SecurityLogs or the project folder" style="flex:1">
              <button id="btn-scan">Scan</button>
            </div>
            <div id="folder-result" style="margin-top:10px"></div>
            <div class="faint small" style="margin-top:8px">Filesystem access is restricted to permitted directories
            (project folder + <span class="mono">data/</span> by default; add more via <span class="mono">KILLCHAIN_ALLOWED_DIRS</span>).
            Ingestion checkpoints per file and can resume after interruption.</div>
            <div id="folder-jobs"></div>
          </div>
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
  const pollHandles = new Set();
  const pollTick = async () => {
    if (!pollHandles.size) return;
    await loadJobs();
    for (const id of [...pollHandles]) {
      try {
        const j = await api(`/ingest/status/${id}`);
        if (j.status !== "running") pollHandles.delete(id);
      } catch (e) { pollHandles.delete(id); }
    }
    if (pollHandles.size) setTimeout(pollTick, 700);
  };
  const track = (jobIds) => { jobIds.forEach(id => pollHandles.add(id)); pollTick(); };

  async function loadJobs() {
    const st = await api("/stats");
    const jobs = st.ingest_jobs.slice(0, 8);
    $("#jobs", root).innerHTML = jobs.length ? jobs.map(j => {
      const pct = j.total_bytes ? Math.min(100, (j.bytes_done || 0) / j.total_bytes * 100)
        : (j.status === "done" ? 100 : Math.min(90, (j.parsed_events % 900) / 9));
      return `<div class="ingest-row" style="flex-wrap:wrap">
        <span class="pill ${j.status === "running" ? "warn" : j.status === "done" ? "ok" : ""}" style="min-width:86px;justify-content:center">
          <span class="dot ${j.status === "running" ? "blink" : ""}"></span>${j.status}</span>
        <span class="nm" style="max-width:330px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(j.filename)}</span>
        <div class="progress"><div class="pf" style="width:${pct.toFixed(1)}%"></div></div>
        <span class="mono dim small">${(j.parsed_events || 0).toLocaleString()} events · ${(j.parse_errors || 0).toLocaleString()} errors
        ${j.total_bytes ? `· ${((j.bytes_done || 0) / 1e9).toFixed(2)}/${(j.total_bytes / 1e9).toFixed(2)} GB` : ""}
        ${j.speed_eps ? `· ${Math.round(j.speed_eps).toLocaleString()} ev/s` : ""}
        ${j.eta_seconds && j.status === "running" ? `· ETA ${Math.ceil(j.eta_seconds / 60)} min` : ""}</span>
        ${j.status === "interrupted" && j.resumable ? `<button class="ghost" style="padding:3px 10px;font-size:11px" data-resume="${j.id}">▶ Resume</button>` : ""}
      </div>
      ${j.files ? `<div class="job-files">${j.files.slice(0, 12).map(fl => `
        <div class="jf"><span class="pill ${fl.status === "done" ? "ok" : fl.status === "running" ? "warn" : ""}" style="min-width:70px;justify-content:center;font-size:10px"><span class="dot"></span>${fl.status}</span>
        <span class="mono">${esc(fl.name)}</span>
        <span class="faint">${(fl.byte_size / 1e9).toFixed(2)} GB</span>
        <span class="mono dim">${(fl.parsed_events || 0).toLocaleString()} ev · ${(fl.parse_errors || 0).toLocaleString()} err</span>
        ${fl.error_text ? `<span class="small" style="color:var(--high)">${esc(fl.error_text)}</span>` : ""}</div>`).join("")}</div>` : ""}`;
    }).join("") : '<div class="faint small">No ingestion jobs yet.</div>';
    $$("button[data-resume]", root).forEach(b => b.onclick = async () => {
      try {
        await api("/ingest/folder/resume", { method: "POST", body: { job_id: b.dataset.resume } });
        toast("Resuming ingestion from checkpoint…");
        track([b.dataset.resume]);
      } catch (e) { toast(e.message, true); }
    });
  }
  async function loadSources() {
    const ss = await api("/sources");
    $("#sources", root).innerHTML = ss.length ? `<table class="tbl"><tr><th>Source</th><th>Origin</th><th>Format</th><th>Lines</th><th>Events</th><th>Parse errors</th><th>Size</th><th>Imported</th></tr>
      ${ss.map(s => `<tr><td class="mono">${esc(s.name)}</td><td>${originChip(s.origin)}</td><td class="mono">${esc(s.kind)}</td>
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

  // ---- multi-file upload + drag & drop ----
  const dz = $("#dropzone", root), fi = $("#file-in", root);
  const picked = [];
  function renderPicked() {
    $("#upload-list", root).innerHTML = picked.length
      ? picked.map((p, i) => `<span class="file-chip">${esc(p.name)} <span class="faint">${fmtBytes(p.size)}</span><span class="x" data-i="${i}">✕</span></span>`).join("") +
        `<div style="margin-top:8px"><button class="primary" id="btn-upload">Upload & ingest ${picked.length} file(s)</button></div>`
      : "";
    $$("#upload-list .x", root).forEach(x => x.onclick = () => { picked.splice(Number(x.dataset.i), 1); renderPicked(); });
    const b = $("#btn-upload", root);
    if (b) b.onclick = async () => {
      const fd = new FormData();
      picked.forEach(p => fd.append("files", p));
      toast(`Uploading ${picked.length} file(s)…`);
      const r = await fetch("/api/ingest/upload", { method: "POST", body: fd });
      const j = await r.json();
      if (!r.ok) return toast(j.detail || "Upload failed", true);
      picked.length = 0; renderPicked();
      toast(`${j.jobs.length} file(s) ingested. Re-run analysis to include them.`);
      track(j.jobs.map(x => x.job_id));
      await refreshBadges(); loadSources(); loadJobs();
    };
  }
  dz.onclick = () => fi.click();
  fi.onchange = () => { [...fi.files].forEach(f => picked.push(f)); fi.value = ""; renderPicked(); };
  ["dragover", "dragenter"].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add("over"); }));
  ["dragleave", "drop"].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove("over"); }));
  dz.addEventListener("drop", e => { [...e.dataTransfer.files].forEach(f => picked.push(f)); renderPicked(); });

  // ---- local folder ingestion ----
  $("#btn-scan", root).onclick = async () => {
    const p = $("#folder-path", root).value.trim();
    if (!p) return toast("Enter an absolute folder path", true);
    $("#folder-result", root).innerHTML = '<div class="loading">Scanning…</div>';
    try {
      const scan = await api("/ingest/folder/scan", { method: "POST", body: { path: p } });
      if (!scan.ok) { $("#folder-result", root).innerHTML = `<div class="hypo"><span class="tag" style="color:var(--critical)">SCAN FAILED</span><br>${esc(scan.error)}</div>`; return; }
      const sel = new Set(scan.files.map(f => f.path));
      $("#folder-result", root).innerHTML = `
        <div class="small dim">${scan.files.length} supported file(s), ${(scan.total_bytes / 1e9).toFixed(2)} GB total.</div>
        <div style="max-height:240px;overflow:auto;margin-top:6px">
        <table class="tbl"><tr><th></th><th>File</th><th>Size</th><th>Format</th></tr>
        ${scan.files.slice(0, 60).map(f => `<tr><td><input type="checkbox" class="fsel" value="${esc(f.path)}" checked></td>
          <td class="mono small">${esc(f.name)}</td><td class="mono">${f.size > 1e9 ? (f.size / 1e9).toFixed(2) + " GB" : fmtBytes(f.size)}</td>
          <td class="mono dim">${esc(f.format)}</td></tr>`).join("")}</table></div>
        <button class="primary" id="btn-folder-ingest" style="margin-top:8px">Ingest selected files</button>`;
      $$(".fsel", root).forEach(c => c.onchange = () => {
        if (c.checked) sel.add(c.value); else sel.delete(c.value);
      });
      $("#btn-folder-ingest", root).onclick = async () => {
        if (!sel.size) return toast("Select at least one file", true);
        toast(`Starting folder ingestion of ${sel.size} file(s)…`);
        const r = await api("/ingest/folder/start", { method: "POST", body: { path: scan.directory, files: [...sel] } });
        track([r.job_id]);
        toast("Folder job started — progress appears below. You can leave the page; it keeps running.");
      };
    } catch (e) {
      $("#folder-result", root).innerHTML = `<div class="hypo"><span class="tag" style="color:var(--critical)">ERROR</span><br>${esc(e.message)}</div>`;
    }
  };

  ["ev-q", "ev-sev", "ev-type"].forEach(id => { $("#" + id, root).onchange = () => { offset = 0; loadEvents(); }; });
  $("#ev-q", root).oninput = debounce(() => { offset = 0; loadEvents(); }, 350);
  $("#ev-prev", root).onclick = () => { offset = Math.max(0, offset - limit); loadEvents(); };
  $("#ev-next", root).onclick = () => { offset += limit; loadEvents(); };
  await Promise.all([loadJobs(), loadSources(), loadEvents()]);
}
function originChip(origin) {
  const map = { demo: ["synthetic · demo", "rgba(124,92,255,.5)"], edr_gen: ["synthetic · ECS", "rgba(124,92,255,.5)"], upload: ["uploaded", "rgba(56,225,255,.5)"], folder: ["local folder", "rgba(52,211,153,.5)"] };
  const [label, color] = map[origin] || [origin, "var(--border-hi)"];
  return `<span class="ent-tag" style="border-color:${color}">${esc(label)}</span>`;
}

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
  const inc = D.incident, dets = D.detections, sb = D.storyboard, la = D.lookahead;
  const techniques = {};
  dets.forEach(d => (d.mitre || []).forEach(t => {
    (techniques[t] = techniques[t] || { id: t, rules: new Set(), evs: new Set() });
    techniques[t].rules.add(d.title);
    d.event_ids.forEach(e => techniques[t].evs.add(e));
  }));

  root.innerHTML = `
    <div class="panel"><div class="panel-b" style="display:flex;gap:22px;align-items:center;flex-wrap:wrap">
      ${riskRing(inc.risk_score, inc.severity)}
      <div style="flex:1;min-width:300px">
        <div class="mono" style="color:var(--accent);font-size:12px">${esc(inc.ref)} · ATTACK STORYBOARD${inc.is_demo ? ' · <span style="color:#c4b5fd">SYNTHETIC DEMO DATA</span>' : ""}</div>
        <h2 style="margin:4px 0 8px;font-size:19px">${esc(inc.name)}</h2>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:10px">
          ${chip(inc.severity)}<span class="pill"><span class="dot ok"></span>${esc(inc.status)}</span>
          <span class="mono dim small">${fmtTime(inc.first_ts)} → ${fmtTime(inc.last_ts)}</span>
          <span class="faint small">${inc.event_ids.length} evidence events · ${dets.length} detections · ${Object.keys(techniques).length} MITRE techniques</span>
        </div>
        <div class="dim" style="font-size:13px;max-width:900px">${esc(inc.summary)}</div>
      </div>
      <div style="display:flex;flex-direction:column;gap:8px">
        <button class="primary" id="btn-report">📄 Generate incident report</button>
        <button class="ghost" onclick="location.hash='#/graph'">Open in Attack Graph</button>
      </div>
    </div></div>

    <div class="panel"><div class="panel-h"><div class="bar"></div><h3>Attack storyboard</h3>
      <div class="right"><span class="faint small">chronological · click a step to highlight it in the graph below</span></div></div>
      <div class="panel-b" id="storyboard" style="padding-top:10px"></div></div>

    <div class="panel"><div class="panel-h"><div class="bar"></div><h3>Attack graph</h3>
      <div class="right" style="gap:8px">
        <button class="ghost" id="g-layout-tl" style="font-size:11px">Timeline layout</button>
        <button class="ghost" id="g-layout-force" style="font-size:11px">Force layout</button>
        <button class="ghost" id="g-toggle-inf" style="font-size:11px" title="Show/hide inferred edges">Hide inferred</button>
      </div></div>
      <div class="panel-b">
        <div id="graph-wrap" style="height:560px">
          <div class="graph-legend">
            <div class="li"><span class="sw" style="border-color:#ff4d6a"></span> attacker infrastructure</div>
            <div class="li"><span class="sw" style="border-color:#34d399"></span> user account</div>
            <div class="li"><span class="sw" style="border-color:#7dd3fc"></span> host</div>
            <div class="li"><span class="sw"></span> observed relationship (evidence)</div>
            <div class="li"><span class="sw dash"></span> inferred relationship (hypothesis)</div>
          </div>
          <div class="graph-inspector" id="g-inspector"></div>
        </div>
      </div></div>

    <div class="grid cols-2">
      <div class="panel"><div class="panel-h"><div class="bar"></div><h3>Potential next targets</h3>
        <div class="right"><span class="faint small">look-ahead · INFERRED, not confirmed</span></div></div>
        <div class="panel-b" id="lookahead"></div></div>
      <div class="panel"><div class="panel-h"><div class="bar"></div><h3>Hypotheses & uncertainty</h3></div>
        <div class="panel-b" id="hyp-panel">
        ${inc.hypotheses && inc.hypotheses.length ? inc.hypotheses.map(hy => `<div class="hypo"><span class="tag">⚠ ${esc(hy.label)}</span><br>${esc(hy.text)}</div>`).join("") : '<div class="faint small">No additional hypotheses beyond the confirmed findings.</div>'}
        ${(la.missing_information || []).map(m => `<div class="hypo" style="border-color:var(--border-hi)"><span class="tag" style="color:var(--dim)">MISSING INFORMATION</span><br><span class="dim">${esc(m)}</span></div>`).join("")}
        </div></div>
    </div>

    <div class="grid cols-2">
      <div class="panel"><div class="panel-h"><div class="bar"></div><h3>MITRE ATT&CK techniques</h3></div>
        <div class="panel-b" style="max-height:320px;overflow:auto">
        ${Object.values(techniques).sort((a, b) => a.id.localeCompare(b.id)).map(t => `
          <div class="mitre-card"><span class="id">${esc(t.id)}</span>
            <div class="nm">${esc(techniqueName(t.id))}</div>
            <div class="ev">${[...t.evs].slice(0, 6).map(id => `<span class="evid-chip" onclick="showEvidence(${id})">E#${id}</span>`).join("")}
            <span class="faint small" style="align-self:center">evidence-backed mapping</span></div>
          </div>`).join("") || '<div class="faint">No techniques.</div>'}
        </div></div>
      <div class="panel"><div class="panel-h"><div class="bar"></div><h3>Detections</h3></div>
        <div class="panel-b" style="max-height:320px;overflow:auto">
        ${dets.map(d => `<div class="det-card"><div class="top">${chip(d.severity)}<span class="title">${esc(d.title)}</span>
          <span class="chip info" style="text-transform:none">${esc(d.rule_id)}</span>
          ${d.aggregate ? `<span class="pill" style="font-size:10px">aggregate · ${(d.total_events || 0).toLocaleString()} events</span>` : ""}</div>
          <div class="exp">${esc(d.explanation)}</div>
          <div class="row"><span class="faint">Kill Chain:</span> <span class="mono dim">${esc(d.killchain_stage)}</span>
          <span class="faint" style="margin-left:6px">Evidence:</span>${d.event_ids.slice(0, 5).map(eid => `<span class="evid-chip" onclick="showEvidence(${eid})">E#${eid}</span>`).join("")}
          ${d.event_ids.length > 5 ? `<span class="faint small">+${d.event_ids.length - 5} more</span>` : ""}</div></div>`).join("")}
        </div></div>
    </div>

    <div class="panel"><div class="panel-h"><div class="bar"></div><h3>Full event timeline</h3>
      <div class="right"><span class="faint small">click any event for raw evidence</span></div></div>
      <div class="panel-b" style="max-height:480px;overflow:auto"><div class="timeline" id="full-timeline">
        ${D.events.map(e => {
          const detsE = dets.filter(d => d.event_ids.includes(e.id));
          const sev = detsE.length ? detsE.map(d => d.severity).sort((a, b) => SEV_ORDER[a] - SEV_ORDER[b])[0] : e.severity;
          return `<div class="tl-item sev-${sev}" data-ev="${e.id}"><div class="tl-card" onclick="showEvidence(${e.id})">
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

    <div class="panel"><div class="panel-h"><div class="bar"></div><h3>AI investigation assistant</h3>
      <div class="right"><span class="pill" id="ai-pill2"><span class="dot"></span>checking…</span></div></div>
      <div class="panel-b" style="padding:0">
        <div class="ai-panel">
          <div class="ai-msgs" id="ai-msgs"><div class="ai-msg bot">Ask about <b>${esc(inc.ref)}</b>. The assistant answers strictly from this incident's backend evidence (${inc.event_ids.length} events, ${dets.length} detections) — it cannot invent evidence. ${window.__AI__ ? "GLM provider is connected." : "No AI provider configured: set GLM_API_KEY to enable."}</div></div>
          <div class="ai-presets">
            ${["What happened?", "Where did the attack begin?", "How did it progress?", "What MITRE techniques were observed?", "What could the attacker do next?", "What evidence supports the findings?", "What should I investigate next?"]
              .map(q => `<button data-q="${esc(q)}">${esc(q)}</button>`).join("")}
          </div>
          <div class="ai-input"><input id="ai-q" placeholder="Ask the investigator… (Enter to send)">
          <button class="primary" id="ai-send">Ask</button></div>
        </div>
      </div></div>`;

  renderStoryboard(root, D);
  renderLookahead(root, la);

  // ---- graph ----
  const wrap = $("#graph-wrap", root);
  const graph = new KillGraph(wrap, {
    onSelectNode(n, edges) {
      const insp = $("#g-inspector", root);
      if (!n) { insp.classList.remove("open"); graph.clearHighlight(); clearStoryboardActive(root); return; }
      const evIds = graph.eventsForNode(n.id);
      graph.highlightByEvents(evIds, true);
      highlightStoryboardEvents(root, evIds.slice(0, 400));
      insp.innerHTML = `<b style="color:${n.color}">${esc(n.label)}</b>
        <div class="faint small mono">${esc(n.kind)} · ${esc(n.ident)}${n.role === "attacker_infra" ? " · ATTACKER INFRA" : ""}</div>
        ${n.command ? `<div class="small" style="margin-top:6px">cmd: <span class="mono">${esc(n.command)}</span></div>` : ""}
        <div class="small" style="margin-top:8px"><b>${edges.length}</b> relationship(s) · <b>${evIds.length}</b> linked evidence event(s)</div>
        ${edges.map(e => `<div class="small" style="margin:5px 0;padding-left:8px;border-left:2px solid ${e.observed ? "var(--border-hi)" : "#7c5cff"}">
          ${e.observed ? "" : '<span class="mono" style="color:#c4b5fd">INFERRED </span>'}
          <span class="dim">${esc(e.label)}</span>
          ${e.event_ids.length ? `<br>${e.event_ids.slice(0, 4).map(eid => `<span class="evid-chip" onclick="showEvidence(${eid})">E#${eid}</span>`).join("")}` : ""}
        </div>`).join("")}
        <div class="small faint" style="margin-top:8px">Related storyboard steps are highlighted above.</div>`;
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
  window.__graphRef = graph;
  graph.setData(D.graph);
  $("#g-layout-tl", root).onclick = () => graph.applyLayout("timeline");
  $("#g-layout-force", root).onclick = () => graph.applyLayout("force");
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

/* ---- storyboard rendering + graph sync ---- */
function renderStoryboard(root, D) {
  const sb = D.storyboard;
  const host = $("#storyboard", root);
  if (!sb.phases.length) {
    host.innerHTML = '<div class="faint">No phased activity could be reconstructed for this incident.</div>';
    return;
  }
  host.innerHTML = `
    <div class="sb-rail">
    ${sb.phases.map((ph, pi) => `
      <div class="sb-phase" data-phase="${pi}">
        <div class="sb-phase-head">
          <div class="sb-phase-num">${String(pi + 1).padStart(2, "0")}</div>
          <div style="flex:1;min-width:0">
            <div class="sb-phase-title">${esc(ph.stage)}
              ${ph.detected ? '<span class="chip high" style="font-size:9.5px">detected</span>' : '<span class="chip info" style="font-size:9.5px">supporting activity</span>'}
            </div>
            <div class="faint small">${esc(ph.description)}</div>
          </div>
          <div class="mono faint small" style="text-align:right">${fmtTime(ph.first_ts)}<br>→ ${fmtTime(ph.last_ts)} · ${ph.item_count} event(s)</div>
        </div>
        <div class="sb-items">
          ${ph.items.slice(0, 120).map((it, ii) => `
            <div class="sb-item sev-${it.severity}" data-events="${(it.event_ids || []).join(",")}" data-idx="${pi}-${ii}">
              <div class="sb-t mono">${fmtTime(it.ts)}</div>
              <div class="sb-body">
                <div class="sb-action">${esc(it.action)}</div>
                <div class="sb-meta">
                  ${it.user ? `<span>👤 ${esc(it.user)}</span>` : ""}
                  ${it.host ? `<span>🖥 ${esc(it.host)}</span>` : ""}
                  ${it.src_ip ? `<span>🌐 ${esc(it.src_ip)}${it.dst_ip ? " → " + esc(it.dst_ip) : ""}</span>` : ""}
                  ${it.process ? `<span>⚙ ${esc(it.process)}</span>` : ""}
                  ${(it.mitre || []).length ? `<span class="mono" style="color:var(--accent)">🎯 ${it.mitre.join(", ")}</span>` : ""}
                  ${it.detection ? `<span class="mono dim">rule: ${esc(it.detection.rule_id)}</span>` : ""}
                  ${chip(it.severity)}
                  ${(it.event_ids || []).slice(0, 3).map(eid => `<span class="evid-chip" onclick="event.stopPropagation();showEvidence(${eid})">E#${eid}</span>`).join("")}
                  ${(it.event_ids || []).length > 3 ? `<span class="faint small">+${it.event_ids.length - 3}</span>` : ""}
                  ${it.confidence ? `<span class="faint small">confidence: ${esc(it.confidence)}</span>` : ""}
                </div>
              </div>
            </div>`).join("")}
          ${ph.items.length > 120 ? `<div class="faint small" style="padding:6px 12px">… ${ph.items.length - 120} more events in this phase — see the full timeline below.</div>` : ""}
        </div>
      </div>`).join('<div class="sb-arrow">↓</div>')}
    </div>
    ${sb.unsupported_stages && sb.unsupported_stages.length ? `
      <div class="hypo" style="margin-top:14px"><span class="tag" style="color:var(--dim)">NOT OBSERVED IN EVIDENCE</span><br>
      <span class="dim">${esc(sb.unsupported_note)}</span></div>` : ""}`;
  $$(".sb-item", host).forEach(el => {
    el.onclick = () => {
      const evIds = el.dataset.events ? el.dataset.events.split(",").map(Number).filter(x => x) : [];
      clearStoryboardActive(root);
      el.classList.add("active");
      const g = window.__graphRef;
      if (g) g.highlightByEvents(evIds);
      const insp = $("#g-inspector", root);
      if (insp) {
        const phaseEl = el.closest(".sb-phase");
        const ph = D.storyboard.phases[Number(phaseEl ? phaseEl.dataset.phase : 0)];
        const ii = Number(el.dataset.idx.split("-")[1]);
        const item = ph && ph.items[ii];
        insp.innerHTML = item ? `<b>Storyboard step — ${esc(item.stage)}</b>
          <div class="small" style="margin:6px 0">${esc(item.action)}</div>
          <div class="small dim mono">${fmtTime(item.ts)}${item.confidence ? " · confidence " + esc(item.confidence) : ""}</div>
          <div style="margin-top:6px">${evIds.map(eid => `<span class="evid-chip" onclick="showEvidence(${eid})">E#${eid}</span>`).join(" ")}</div>
          ${evIds.length === 0 ? '<div class="faint small">(aggregate row — open the Log Explorer for the full evidence)</div>' : ""}` : "";
        insp.classList.add("open");
      }
    };
  });
}
function clearStoryboardActive(root) {
  $$(".sb-item.active", root).forEach(el => el.classList.remove("active"));
  $$(".sb-item.hl", root).forEach(el => el.classList.remove("hl"));
}
function highlightStoryboardEvents(root, eventIds) {
  const set = new Set(eventIds);
  let first = null;
  $$(".sb-item", root).forEach(el => {
    const evs = (el.dataset.events || "").split(",").filter(Boolean);
    const hit = evs.some(x => set.has(Number(x)));
    el.classList.toggle("hl", hit);
    if (hit && !first) first = el;
  });
  if (first) first.scrollIntoView({ block: "nearest", behavior: "smooth" });
}

/* ---- look-ahead panel ---- */
function renderLookahead(root, la) {
  const host = $("#lookahead", root);
  if (!la) { host.innerHTML = '<div class="faint">Look-ahead unavailable.</div>'; return; }
  const confColor = { high: "var(--critical)", medium: "var(--high)", low: "var(--dim)" };
  host.innerHTML = la.targets.length ? `
    ${la.targets.map(t => `
      <div class="hypo" style="display:block">
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <b style="color:#c4b5fd">${esc(t.target.label)}</b>
          <span class="mono small" style="color:${confColor[t.confidence] || "var(--dim)"}">${esc(t.confidence)} confidence</span>
          <span class="chip info" style="font-size:9.5px">INFERRED</span>
        </div>
        <div class="small dim" style="margin:6px 0">${esc(t.why)}</div>
        <div class="row small">
          <span class="faint">Enabler:</span> <span class="dim">${esc(t.enabler)}</span>
        </div>
        <div style="margin-top:6px">${t.evidence_event_ids.slice(0, 5).map(eid => `<span class="evid-chip" onclick="showEvidence(${eid})">E#${eid}</span>`).join("")}
        ${t.evidence_event_ids.length > 5 ? `<span class="faint small">+${t.evidence_event_ids.length - 5}</span>` : ""}</div>
        <div class="faint small" style="margin-top:5px">${esc(t.relevance)}</div>
      </div>`).join("")}
    <div class="faint small" style="margin-top:8px">⚠ ${esc(la.disclaimer)}</div>
  ` : '<div class="faint small">No potential next targets are supported by the evidence in this incident.</div>';
}

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
      <span style="flex:1"></span>
      <button class="ghost" id="g-layout-tl">Timeline layout</button>
      <button class="ghost" id="g-layout-force">Force layout</button>
    </div></div>
    <div class="panel"><div class="panel-b">
      <div id="graph-wrap" style="height:640px">
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
  $("#g-layout-tl", root).onclick = () => graph.applyLayout("timeline");
  $("#g-layout-force", root).onclick = () => graph.applyLayout("force");
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
      <p class="faint small">Is the KillChain backend running? Start it with: <span class="mono">.venv\Scripts\python -m uvicorn backend.app.main:app --port 8765</span></p></div></div></div>`;
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
