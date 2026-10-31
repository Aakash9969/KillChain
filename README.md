# KillChain — Cybersecurity Attack Reconstruction Platform

KillChain ingests raw security logs, detects suspicious behavior with **deterministic,
explainable rules**, correlates scattered events into **reconstructed attack incidents**,
maps them to **MITRE ATT&CK** and the **Cyber Kill Chain**, and renders everything as an
interactive attack graph, timeline, AI-assisted investigation and exportable report.

> ⚠️ All demonstration datasets shipped with the project are **SYNTHETIC DEMONSTRATION
> DATA** generated locally. Findings produced from them are labelled as such in the UI
> and in reports, and never claimed to come from a real intrusion.

---

## Quick start

```powershell
# from the project root (Windows, Python 3.11+)
python -m venv .venv
.venv\Scripts\pip install fastapi "uvicorn[standard]" python-multipart httpx
.venv\Scripts\python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Then open **http://127.0.0.1:8000** (or `start.bat`).

### Demo workflow (Checkpoint 1)

1. Open the dashboard (Overview).
2. Click **Load demonstration dataset** — generates + streams three synthetic log files
   (`auth_gateway.log`, `edr_endpoints.jsonl`, `db_server.log`) and runs the analysis.
   - Alternatively: **Generate EDR telemetry (ECS)** runs the hackathon-provided
     `edr_log_generator.py` and ingests 900 ECS-format events.
   - Or import your own log file in the **Log Explorer** (syslog / JSON / ECS JSONL,
     auto-detected, streaming ingestion with live progress).
3. View detections in Overview / Log Explorer; click any event for its raw evidence.
4. Open **Investigations** → the reconstructed incident (risk score, kill-chain strip).
5. Explore the **interactive attack graph** (drag, zoom, click nodes/edges; dashed =
   inferred, solid = observed evidence).
6. Follow the chronological **timeline**, inspect **MITRE ATT&CK** mappings and open the
   evidence behind every detection.
7. Ask the **AI investigator** (see below) or open **Reports** for the full incident
   report (download as Markdown, print to PDF).

## AI Investigation Assistant (optional)

The assistant uses the GLM provider through environment variables only — nothing is
hardcoded, and **everything else works without it**:

```
GLM_API_KEY    your API key
GLM_BASE_URL   OpenAI-compatible base URL (default: https://api.z.ai/api/paas/v4)
GLM_MODEL      model name (default: glm-4.6)
```

The assistant is strictly evidence-bound: the backend feeds it the incident's real
detections/timeline/edges, and the system prompt forbids inventing evidence; answers
cite event ids (clickable).

## Architecture

```
backend/app
  config.py            settings & thresholds (no secrets)
  db.py                SQLite (WAL) disk-backed store, raw evidence preserved
  ingest/parsers.py    syslog + JSON/JSONL + ECS parsers (auto-detect)
  ingest/pipeline.py   streaming ingestion (batched, never loads whole files), job progress
  ingest/demo.py       deterministic synthetic multi-stage attack dataset
  analysis/detectors.py  8 deterministic detection rules with explanations & evidence
  analysis/correlate.py  conservative entity linking (union-find, time windows) -> incidents
  analysis/mitre.py    ATT&CK catalog + Kill Chain stages
  analysis/graph.py    attack graph builder (observed vs inferred edges)
  analysis/engine.py   pipeline orchestration
  reports.py           incident report (structured + markdown), confirmed vs hypotheses
  ai/assistant.py      optional GLM provider integration
  api/routes.py        REST API
frontend/              zero-dependency dark SOC SPA (custom force-directed graph)
scripts/               smoke tests (headless + HTTP workflow)
```

### Detection rules (all deterministic, each cites its evidence)

| Rule | Behavior | MITRE | Kill Chain |
|---|---|---|---|
| BRUTE_FORCE_AUTH | repeated failed logins per account+source | T1110(.001) | Delivery |
| SUCCESS_AFTER_FAILURES | success after failure burst | T1078 | Exploitation |
| SUSPICIOUS_AUTH_ODD_HOUR | night login from first-seen source | T1078.001 | Exploitation |
| SUSPICIOUS_PROCESS_EXEC | discovery/credential tooling in EDR telemetry | T1033/T1087/T1003/... | Installation |
| LATERAL_MOVEMENT | internal pivoting, only with suspicious context | T1021.004 | Installation |
| NETWORK_PROBE_INTERNAL | internal reachability scans | T1046 | Reconnaissance |
| PRIVILEGE_ESCALATION_ATTEMPT | failed sudo elevation | T1548.003 | Installation |
| EXFIL_EXTERNAL | staged upload to external infra | T1041 | Actions on Objectives |
| EDR_TAGGED_ALERT | surfaces pre-tagged EDR alerts (ECS threat fields) | from log | from tactic |

Correlation links events **only** through strong identity relationships (same
account+source IP, same account on same host, observed host-to-host authentication
bridges) within bounded time windows — it never merges unrelated suspicious activity.
Hypotheses (possible next targets, credential reuse) are always explicitly labelled
**INFERRED**.

## Tests

```powershell
.venv\Scripts\python scripts\smoke_test.py     # headless pipeline test
.venv\Scripts\python scripts\test_ecs.py      # hackathon ECS generator end-to-end
# with the server running:
.venv\Scripts\python scripts\test_workflow.py # real-HTTP workflow test
```

## Notes

- Storage: `data/killchain.db` (SQLite, WAL) — delete for a fresh start or use
  `POST /api/admin/reset`.
- Ingestion streams files line-by-line in batches; raw log lines are always preserved
  and viewable as evidence.
- No secrets are stored in the repository; the AI key is read from the environment.
