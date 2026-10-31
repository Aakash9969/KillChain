"""Incident report generation (structured + markdown)."""
from __future__ import annotations

from . import db
from .analysis import engine, mitre
from .analysis import detectors as det_mod


def build_report(conn, incident_id: int) -> dict:
    inc = engine.get_incident(conn, incident_id)
    if not inc:
        return None
    events = engine.get_incident_events(conn, inc["event_ids"])
    dets = engine.get_incident_detections(conn, inc["detection_ids"])

    techniques = []
    seen = set()
    for d in dets:
        for tid in d["mitre"]:
            if tid not in seen:
                seen.add(tid)
                info = mitre.ATTACK_TECHNIQUES.get(tid, {})
                techniques.append({
                    "id": tid, "name": info.get("name", "Unknown"),
                    "tactic": info.get("tactic", ""),
                    "from_rules": [x["title"] for x in dets if tid in x["mitre"]],
                    "evidence_event_ids": sorted({e for x in dets if tid in x["mitre"]
                                                  for e in x["event_ids"]}),
                })

    timeline = []
    for e in events:
        dets_e = [d for d in dets if e["id"] in d["event_ids"]]
        timeline.append({
            "time": det_mod.fmt_time(e.get("ts")),
            "description": e.get("message") or e["event_type"],
            "user": e.get("username"), "host": e.get("host"),
            "src_ip": e.get("src_ip"), "dst_ip": e.get("dst_ip"),
            "mitre": sorted({t for d in dets_e for t in d["mitre"]}),
            "severity": max((d["severity"] for d in dets_e),
                            key=lambda s: det_mod.SEV_RANK.get(s, 0), default="info"),
            "evidence_ref": f"E#{e['id']} ({e.get('ts_text') or 'ts'}, source line "
                            f"{e.get('line_no')} of source #{e.get('source_id')})",
            "event_id": e["id"],
        })

    confirmed = [{"title": d["title"], "rule_id": d["rule_id"], "severity": d["severity"],
                  "explanation": d["explanation"], "confidence": d["confidence"],
                  "evidence_event_ids": d["event_ids"]} for d in dets]
    hypotheses = inc.get("hypotheses") or []

    next_steps = _next_steps(dets, inc)
    risk = {
        "score": inc["risk_score"], "severity": inc["severity"],
        "rationale": (f"Risk score {inc['risk_score']}/100 derived from "
                      f"{len(dets)} detection(s) (severity mix: "
                      f"{', '.join(sorted({d['severity'] for d in dets}))}), "
                      f"{len(seen)} MITRE techniques, external infrastructure involvement and "
                      f"multi-host spread across {len(set(e.get('host') for e in events if e.get('host')))} host(s)."),
    }

    report = {
        "incident_ref": inc["ref"], "name": inc["name"], "generated_from": "KillChain analysis engine",
        "is_synthetic_demo": bool(inc.get("is_demo")),
        "executive_summary": _exec_summary(inc, dets, events),
        "entry_point": inc.get("entry_point"),
        "progression": inc.get("progressions") or [],
        "affected_entities": inc.get("entities") or {},
        "mitre_mapping": techniques,
        "timeline": timeline,
        "confirmed_findings": confirmed,
        "hypotheses": hypotheses,
        "risk": risk,
        "recommended_next_steps": next_steps,
    }
    report["markdown"] = to_markdown(report, timeline, techniques, confirmed, hypotheses)
    return report


def _exec_summary(inc, dets, events) -> str:
    entry = inc.get("entry_point")
    hosts = inc.get("entities", {}).get("hosts", [])
    users = inc.get("entities", {}).get("users", [])
    crit = sum(1 for d in dets if d["severity"] == "critical")
    s = (f"Incident {inc['ref']} correlates {len(events)} security events into a reconstructed "
         f"attack path. The analysis engine raised {len(dets)} detection(s)"
         f"{f', including {crit} critical' if crit else ''}, spanning "
         f"{', '.join(hosts[:3]) or 'multiple hosts'} and account(s) {', '.join(users[:3]) or 'multiple'}. ")
    if entry:
        s += (f"The reconstructed entry point is external IP {entry['attacker_ip']} targeting "
              f"account '{entry['account']}' on {entry['target_host']}, first observed "
              f"{det_mod.fmt_time(entry['first_seen_ts'])}. ")
    s += ("The attack progressed through the Cyber Kill Chain stages listed below. All findings "
          "in the Confirmed Findings section are backed by preserved raw log evidence; "
          "hypotheses are clearly separated.")
    return s


def _next_steps(dets, inc) -> list[str]:
    steps = []
    rules = {d["rule_id"] for d in dets}
    if "BRUTE_FORCE_AUTH" in rules or "SUCCESS_AFTER_FAILURES" in rules:
        steps.append("Disable / rotate the credentials of the compromised account(s) and review "
                     "all authentication activity from the attacker IP across the whole estate.")
        steps.append("Block the attacker IP at the perimeter and check perimeter logs for other "
                     "sources from the same ASN during the attack window.")
    if "SUSPICIOUS_PROCESS_EXEC" in rules:
        steps.append("Isolate the affected hosts and collect full EDR process trees; look for "
                     "persistence mechanisms created in the same time window.")
    if "LATERAL_MOVEMENT" in rules:
        steps.append("Audit authentication logs on all systems reachable from the compromised "
                     "hosts for the same account usage during and after the incident window.")
    if "PRIVILEGE_ESCALATION_ATTEMPT" in rules:
        steps.append("Review sudoers / local admin group membership for the involved accounts "
                     "and confirm whether any elevation eventually succeeded.")
    if "EXFIL_EXTERNAL" in rules or any("T1005" in d["mitre"] for d in dets):
        steps.append("Determine what data was collected/uploaded (file names, sizes, contents) "
                     "and engage data owners on notification obligations.")
    steps.append("Hunt across historical logs for earlier activity by the same accounts and IPs.")
    return steps


def to_markdown(r, timeline, techniques, confirmed, hypotheses) -> str:
    L = []
    L.append(f"# KillChain Incident Report - {r['incident_ref']}")
    L.append("")
    if r["is_synthetic_demo"]:
        L.append("> **NOTE: This report is based on SYNTHETIC DEMONSTRATION DATA generated "
                 "for the KillChain demo. It does not reflect a real intrusion.**")
        L.append("")
    L.append(f"**Incident:** {r['name']}  ")
    L.append(f"**Risk score:** {r['risk']['score']}/100 ({r['risk']['severity']})  ")
    L.append(f"**Risk rationale:** {r['risk']['rationale']}")
    L.append("")
    L.append("## 1. Executive summary")
    L.append(r["executive_summary"])
    L.append("")
    L.append("## 2. Attack entry point")
    ep = r["entry_point"]
    if ep:
        L.append(f"- First externally-sourced authentication activity: **{ep['description']}**")
        L.append(f"- First seen: {det_mod.fmt_time(ep['first_seen_ts'])} (event E#{ep['first_seen_event_id']})")
    else:
        L.append("- No externally-sourced entry point present in the analyzed evidence.")
    L.append("")
    L.append("## 3. Attack progression (Cyber Kill Chain)")
    for st in r["progression"]:
        L.append(f"- **{st['stage']}** - {st['description']}")
        for d in st["detections"]:
            L.append(f"  - {d['title']} ({d['severity']})")
    L.append("")
    L.append("## 4. Affected entities")
    for k, v in r["affected_entities"].items():
        if v:
            L.append(f"- **{k}:** {', '.join(map(str, v))}")
    L.append("")
    L.append("## 5. MITRE ATT&CK mapping")
    L.append("| Technique | Name | Tactic | Triggered by | Evidence |")
    L.append("|---|---|---|---|---|")
    for t in techniques:
        L.append(f"| {t['id']} | {t['name']} | {t['tactic']} | "
                 f"{'; '.join(sorted(set(t['from_rules'])))} | "
                 f"E#{', E#'.join(map(str, t['evidence_event_ids'][:8]))} |")
    L.append("")
    L.append("## 6. Timeline")
    L.append("| Time | Description | User | Host | Source IP | MITRE | Severity | Evidence |")
    L.append("|---|---|---|---|---|---|---|---|")
    for t in timeline:
        desc = (t["description"] or "").replace("|", "/")[:90]
        L.append(f"| {t['time']} | {desc} | {t['user'] or '-'} | {t['host'] or '-'} | "
                 f"{t['src_ip'] or '-'} | {', '.join(t['mitre']) or '-'} | {t['severity']} | "
                 f"E#{t['event_id']} |")
    L.append("")
    L.append("## 7. Confirmed findings (observed evidence)")
    for i, c in enumerate(confirmed, 1):
        L.append(f"{i}. **{c['title']}** ({c['severity']}, confidence: {c['confidence']})")
        L.append(f"   - {c['explanation']}")
        L.append(f"   - Evidence events: E#{', E#'.join(map(str, c['evidence_event_ids'][:12]))}")
    L.append("")
    L.append("## 8. Hypotheses (INFERRED - not directly observed)")
    if hypotheses:
        for h in hypotheses:
            L.append(f"- **{h['label']}:** {h['text']}")
    else:
        L.append("- No hypotheses beyond confirmed findings.")
    L.append("")
    L.append("## 9. Recommended investigation steps")
    for i, s in enumerate(r["recommended_next_steps"], 1):
        L.append(f"{i}. {s}")
    L.append("")
    return "\n".join(L)
