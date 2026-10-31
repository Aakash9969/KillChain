"""AI Investigation Assistant (optional GLM provider).

The AI is strictly evidence-bound: the backend assembles the incident's real
data (detections, timeline, entities, graph edges) and the model must only
reason over it. Without a configured provider the rest of KillChain works and
the assistant endpoint returns a clear 503.
"""
from __future__ import annotations

import httpx
from fastapi import HTTPException

from .. import config, db
from ..analysis import engine
from ..analysis.graph import build_graph

SYSTEM_PROMPT = """You are KillChain's AI investigation assistant for security analysts.

STRICT GROUNDING RULES:
- You may ONLY use the incident data provided in the user message (detections, events, entities, edges).
- NEVER invent events, IP addresses, accounts, hosts, timestamps or relationships that are not in the data.
- When referencing a finding, cite the supporting event ids in brackets, e.g. [E#123].
- Distinguish observed evidence from hypotheses (edges/labels marked INFERRED are hypotheses).
- If asked about something the evidence does not cover, say explicitly that the evidence does not cover it.
- Be concise, structured and professional. Use short markdown sections when helpful."""


def ai_status() -> dict:
    return {
        "available": config.ai_available(),
        "model": config.GLM_MODEL if config.ai_available() else None,
        "provider": "glm" if config.ai_available() else None,
    }


def _incident_context(conn, incident_id: int) -> dict:
    inc = engine.get_incident(conn, incident_id)
    if not inc:
        raise HTTPException(404, "Incident not found")
    events = engine.get_incident_events(conn, inc["event_ids"])
    dets = engine.get_incident_detections(conn, inc["detection_ids"])
    graph = build_graph(inc, events, dets)

    timeline = [{
        "id": e["id"],
        "time": e.get("ts_text") or e.get("ts"),
        "type": e["event_type"],
        "user": e.get("username"),
        "host": e.get("host"),
        "src_ip": e.get("src_ip"),
        "dst_ip": e.get("dst_ip"),
        "outcome": e.get("outcome"),
        "summary": (e.get("message") or "")[:220],
    } for e in events]

    detections_view = [{
        "rule_id": d["rule_id"], "title": d["title"], "severity": d["severity"],
        "confidence": d["confidence"], "killchain_stage": d["killchain_stage"],
        "mitre": d["mitre"], "explanation": d["explanation"],
        "event_ids": d["event_ids"],
    } for d in dets]

    return {
        "incident": {
            "ref": inc["ref"], "name": inc["name"], "summary": inc["summary"],
            "risk_score": inc["risk_score"], "severity": inc["severity"],
            "entities": inc["entities"], "entry_point": inc["entry_point"],
            "progressions": inc["progressions"], "hypotheses": inc["hypotheses"],
            "first_seen": inc["first_ts"], "last_seen": inc["last_ts"],
        },
        "detections": detections_view,
        "timeline": timeline,
        "graph_edges": [{"source": e["source"], "target": e["target"], "kind": e["kind"],
                         "observed": e["observed"]} for e in graph["edges"]],
    }


PRESET_QUESTIONS = [
    "What happened in this incident?",
    "Where did the attack begin and how did it progress?",
    "Which machines and accounts were involved?",
    "What MITRE ATT&CK techniques were observed and what is the evidence?",
    "What should I investigate next?",
]


async def ask(incident_id: int, question: str) -> dict:
    if not config.ai_available():
        raise HTTPException(
            503,
            "AI provider is not configured. Set the GLM_API_KEY environment variable to enable "
            "the AI investigator. All other KillChain features work without it.")

    conn = db.get_db()
    context = _incident_context(conn, incident_id)
    user_msg = (
        f"INCIDENT DATA (authoritative - do not add anything beyond this):\n"
        f"{db.jdump(context)}\n\nANALYST QUESTION: {question}")

    try:
        async with httpx.AsyncClient(timeout=90) as client:
            resp = await client.post(
                f"{config.GLM_BASE_URL}/chat/completions",
                headers={"Authorization": f"Bearer {config.GLM_API_KEY}"},
                json={
                    "model": config.GLM_MODEL,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_msg},
                    ],
                    "temperature": 0.2,
                    "max_tokens": 1500,
                })
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(502, f"GLM provider error {exc.response.status_code}: "
                                 f"{exc.response.text[:300]}")
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"Could not reach the GLM provider: {exc}")

    try:
        answer = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise HTTPException(502, "Unexpected response shape from GLM provider.")
    return {"answer": answer, "model": config.GLM_MODEL,
            "grounded_on": {"incident_ref": context["incident"]["ref"],
                            "events": len(context["timeline"]),
                            "detections": len(context["detections"])}}
