# KillChain — Cybersecurity Attack Reconstruction Platform

KillChain ingests raw security logs (EDR telemetry, firewall exports, syslog), detects
suspicious behavior with **deterministic, explainable rules**, correlates scattered events
into **reconstructed attack incidents**, and presents each investigation as an
**Attack Storyboard** — a chronological, evidence-backed narrative synchronized with an
interactive attack graph — plus MITRE ATT&CK mapping, look-ahead analysis of potential
next targets, and exportable incident reports.

> ⚠️ Demo datasets shipped with the project are **SYNTHETIC DEMONSTRATION DATA**
> generated locally. Findings derived from them are labelled as such in the UI and in
> reports and are never presented as a real intrusion. Datasets you ingest yourself
> (uploads / local folders) are treated as real data and are *not* labelled as demo.

---

## Quick start

```powershell
# from the project root (Windows, Python 3.11+)
python -m venv .venv
.venv\Scripts\pip install fastapi "uvicorn[standard]" python-multipart httpx
.venv\Scripts\python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8765
```

Then open **http://127.0.0.1:8765** (or run `start.bat`).

> Port 8765 is used because 8000 is commonly occupied by other local tools. KillChain
> serves its own frontend, so any port works.

## Demo workflow

1. **Overview** → *Load demonstration dataset* — generates + streams three synthetic log
   files and runs the analysis. Or *Generate EDR telemetry (ECS)* using the
   hackathon-provided `edr_log_generator.py`.
2. **Log Explorer** → view the event stream, search/filter, click any event for its raw
   evidence; import your own files (multi-file drag & drop) or ingest a local folder.
3. **Investigations** → open the reconstructed incident. The **Attack Storyboard** tells
   the story chronologically in Kill-Chain phases; click any step to highlight it in the
   graph and vice versa.
4. Inspect **Potential next targets** (look-ahead), **MITRE ATT&CK** mappings,
   **detections** with explanations and evidence IDs, **hypotheses**, and the AI
   assistant (optional).
5. **Reports** → full incident report (Markdown download / print).

## Supported log formats

| Format | Files | Notes |
|---|---|---|
| FortiGate key=value | `.log` | traffic, DNS, webfilter, IPS, virus, admin/VPN logins (the large `firex-*.log` datasets) |
| syslog (OpenSSH/sshd/sudo/openvpn) | `.log`, `.txt` | line-based |
| JSON / ECS JSONL | `.jsonl`, `.json`, `.ndjson` | flat JSON and ECS (hackathon EDR generator) |

Format is auto-detected per file (peek at first line) and per line; malformed lines are
counted as parse errors and never stop ingestion. **Binary/corrupted regions are skipped
automatically** (the parser re-syncs on the next valid record) and reported per file.

## Large datasets (tested at multi-GB scale)

- **Local-folder ingestion**: enter an absolute directory path in the Log Explorer, scan,
  select files (name/size/format shown), and ingest. Files are read **streaming in 4 MB
  chunks** with 1000-event batches — memory stays flat regardless of file size.
- **Resumable**: every file has a byte-offset checkpoint committed at line boundaries.
  If the process dies, the job is marked `interrupted` on next start and can be resumed
  from the checkpoint (no duplicate events). Compressed formats are not supported.
- **Progress** comes from the backend: bytes processed/total, records, parsed, errors,
  events/s, ETA, per-file status.
- **Analysis at scale**: datasets above `KILLCHAIN_FULL_SCAN_LIMIT` (default 200,000
  events) are analyzed with **SQL-first aggregations** (GROUP BY/HAVING over indexed
  columns, including a partial covering index for network events) that materialize only
  bounded evidence samples. Memory stays O(detections), not O(events).

**Actually tested (this machine):** 6.54 GB FortiGate file (`firex-10G.log`, 4.9 GB of
real logs + binary padding tail), 9,125,385 events ingested in ~26 min (~5,900 ev/s,
zero parse errors on the real portion), analysis in streaming mode with **peak RSS
< 0.1 GB** (51 MB observed during ingestion, 63 MB during analysis). The 30 GB target
is architecturally supported by the same streaming path but has **not** been tested at
full 30 GB scale on this machine.

## The Attack Storyboard

The storyboard groups an incident's evidence into Kill-Chain phases (only phases with
evidence appear; unsupported stages are explicitly listed as gaps). Each step shows
time, action narrative, source/target entities, user, host, IPs, process, MITRE
techniques, detection, severity, confidence, and clickable evidence IDs. The storyboard
and the attack graph are synchronized both ways (storyboard step → graph highlight;
graph node → related storyboard steps).

## Look-ahead (potential next targets)

Deterministic analysis of what the attacker could reach next, strictly from observed
evidence: probed-but-not-accessed hosts, accounts valid on other systems, reachable
services. Every target is labelled **INFERRED**, cites evidence, and states why it is
relevant. Missing information (privileges, topology) is stated explicitly. Potential
targets are never presented as confirmed compromises. AI is never involved in this
analysis.

## AI assistant (optional, evidence-bound)

```
GLM_API_KEY     API key (enables the assistant)
GLM_BASE_URL    OpenAI-compatible base URL (default https://api.z.ai/api/paas/v4)
GLM_MODEL       model name (default glm-4.6)
```

The backend assembles the incident's real detections/storyboard/timeline/look-ahead as
context; the system prompt forbids inventing evidence and requires event-ID citations.
Without a key everything else works and the assistant shows a clear unavailable state.

## Configuration & security

- `KILLCHAIN_DATA_DIR` — data directory (default `./data`).
- `KILLCHAIN_ALLOWED_DIRS` — semicolon-separated roots for local-folder ingestion
  (default: project folder + `data/`). Paths outside are rejected (validated server-side;
  no browser filesystem pretense, no traversal).
- `KILLCHAIN_FULL_SCAN_LIMIT` — event count above which analysis switches to the
  SQL-first streaming path.
- Server binds to localhost by default. Original log files are never modified; log
  contents are treated as untrusted data (parsed, never executed). Uploaded filenames
  are sanitized. Raw evidence is preserved for every ingested event.

## Detection rules (deterministic, evidence-citing)

| Rule | Behavior | MITRE | Kill Chain |
|---|---|---|---|
| BRUTE_FORCE_AUTH | repeated failed logins (pair burst / per (user,ip)) | T1110.001 | Delivery |
| AUTH_SPRAYING | one source failing against many accounts | T1110.003 | Delivery |
| AUTH_TARGETED_BRUTE | one account attacked from many sources | T1110.001 | Delivery |
| SUCCESS_AFTER_FAILURES | success after failure burst (same account+source) | T1078 | Exploitation |
| SUSPICIOUS_AUTH_ODD_HOUR | night login from first-seen external source | T1078.001 | Exploitation |
| SUSPICIOUS_PROCESS_EXEC | discovery/credential tooling in EDR telemetry | T1033/T1087/... | Installation |
| LATERAL_MOVEMENT | internal pivoting, only with suspicious context | T1021.004 | Installation |
| NETWORK_PROBE_INTERNAL | internal reachability scans | T1046 | Reconnaissance |
| PORT_SCAN | cross-boundary port scanning (distinct ports per target) | T1046 | Reconnaissance |
| PRIVILEGE_ESCALATION_ATTEMPT | failed sudo/elevation (attempt ≠ success) | T1548.003 | Installation |
| EXFIL_EXTERNAL | staged upload to external infra (observed transfer) | T1041 | Actions on Objectives |
| DATA_TRANSFER_CANDIDATE | large outbound transfer (candidate, unconfirmed) | T1041 | Actions on Objectives |
| WEB_THREAT_BLOCKED | web/AV blocks — attempts observed, not infections | T1189/T1203 | Delivery |
| IPS_ALERTS | IDS/IPS drops — attempts observed, not compromises | T1203 | Delivery |
| EDR_TAGGED_ALERT | surfaces pre-tagged EDR alerts (ECS threat fields) | from log | from tactic |

Blocked/failed activity is always described as an attempt; successful authentication
alone does not assert compromise beyond the account.

## Tests

```powershell
.venv\Scripts\pip install pytest psutil
.venv\Scripts\python -m pytest tests\ -q          # 14 tests: parsers (incl. FortiGate),
                                                  # detectors, correlation, storyboard,
                                                  # look-ahead, resume, streaming equivalence
.venv\Scripts\python scripts\smoke_test.py        # headless pipeline test (demo data)
.venv\Scripts\python scripts\test_workflow.py     # real-HTTP workflow test (server on 8765)
.venv\Scripts\python scripts\bench_firex.py firex-10G   # large-file ingestion benchmark
.venv\Scripts\python scripts\run_analysis_bench.py      # streaming-analysis benchmark
```

## Architecture

```
backend/app
  config.py            settings & thresholds (env-driven; no secrets)
  db.py                SQLite (WAL) + migrations + incremental severity counters
  ingest/parsers.py    syslog + JSON/JSONL + ECS + FortiGate parsers
  ingest/pipeline.py   streaming ingestion (single/multi upload), job registry
  ingest/folder.py     resumable local-folder ingestion (byte-offset checkpoints)
  ingest/demo.py       deterministic synthetic multi-stage attack dataset
  analysis/detectors.py    in-memory rules (small/medium datasets)
  analysis/fw_detectors.py SQL-first rules (millions of events, bounded evidence)
  analysis/correlate.py    conservative entity linking -> incidents
  analysis/storyboard.py   phase-grouped chronological narrative
  analysis/lookahead.py    potential next targets (INFERRED, evidence-cited)
  analysis/graph.py        attack graph (observed vs inferred edges)
  analysis/mitre.py        ATT&CK catalog + Kill Chain stages
  analysis/engine.py       pipeline orchestration (full / streaming modes)
  reports.py           incident report (structured + markdown)
  ai/assistant.py      optional GLM provider integration
  api/routes.py        REST API
frontend/              dark SOC SPA: Overview, Log Explorer, Investigation
                       (Storyboard + synchronized graph + look-ahead), Attack Graph,
                       Entity Explorer, Reports; custom force/timeline graph layouts
data/                  killchain.db (SQLite), uploads/, demo/, edr_gen/ (gitignored)
```

## Known limitations

- 30-50 GB ingest/analyze is architecturally supported (streaming + SQL-first analysis)
  but the largest size actually tested on this machine is the 6.54 GB file above.
- FortiGate sources dedupe by first occurrence of each key per line (standard for these
  logs); exotic multi-value keys would need format-specific handling when the
  organizers' real dataset arrives.
- Single-process ingestion (one file at a time, sequential per job).
- The AI assistant requires a GLM API key; without it the button shows a clear
  unavailable state and everything else functions.
