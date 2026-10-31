"""Attack Storyboard: turns an incident's evidence into a chronological,
phase-grouped narrative. Every item cites its events; only stages supported
by evidence appear, and unsupported stages are explicitly listed as gaps.

The storyboard is deterministic: same incident data -> same story.
"""
from __future__ import annotations

from . import detectors as det_mod
from . import mitre

# Kill Chain stages in canonical order (only these can ever appear)
STAGES = [s for s, _ in mitre.KILL_CHAIN_STAGES]
STAGE_DESC = dict(mitre.KILL_CHAIN_STAGES)

# maximum age of an un-flagged event to be attached to a neighbouring phase
_SUPPORT_GAP_SECONDS = 30 * 60


def _fmt_ip(ip):
    return ip or "unknown IP"


def _describe(e: dict, det: dict | None) -> tuple[str, dict, dict]:
    """Return (action sentence, source entity, target entity) for an event."""
    user = e.get("username") or "unknown account"
    host = e.get("host") or "unknown host"
    src, dst = e.get("src_ip"), e.get("dst_ip")
    d = e.get("details") or {}
    etype, outcome = e["event_type"], e.get("outcome")

    def ent_user(u):
        return {"kind": "user", "id": f"user:{u}", "label": u}
    def ent_host(h):
        return {"kind": "host", "id": f"host:{h}", "label": h}
    def ent_ip(ip, external=None):
        ext = det_mod.is_external(ip) if external is None else external
        return {"kind": "ip", "id": f"ip:{ip}", "label": ip, "external": ext}

    src_ent = ent_ip(src) if src and det_mod.is_external(src) else (
        ent_host(host) if host else ent_ip(src) if src else {"kind": "unknown", "id": "?", "label": "?"})
    tgt_ent = ent_host(host) if host else (ent_ip(dst) if dst else {"kind": "unknown", "id": "?", "label": "?"})

    if etype == "auth_failure":
        action = (f"'{user}' failed authentication against {host}"
                  f"{' (admin interface)' if (d.get('action') or e.get('action')) == 'admin_login' else ''}"
                  f" from {_fmt_ip(src)}.")
        src_ent = ent_ip(src) if src else src_ent
        tgt_ent = ent_host(host)
    elif etype == "auth_success":
        action = (f"'{user}' successfully authenticated to {host} from {_fmt_ip(src)}")
        action += " - account treated as compromised by the correlation engine." if det else "."
        src_ent = ent_ip(src) if src else src_ent
        tgt_ent = ent_host(host)
    elif etype == "privilege":
        if outcome == "failure":
            action = (f"'{user}' FAILED a privilege-escalation attempt via sudo on {host} "
                      f"(target: {(d.get('target_user') or 'root')}). Attempt observed; "
                      f"elevation did not succeed.")
        else:
            action = f"'{user}' ran a privileged command on {host}: {(d.get('command') or 'sudo')}."
        src_ent, tgt_ent = ent_user(user), ent_host(host)
    elif etype == "process":
        cmd = d.get("command") or e.get("message") or ""
        action = f"'{user}' executed '{e.get('process')}' on {host}"
        action += f" (command: {cmd[:120]})" if cmd and cmd != e.get("process") else "."
        action += " Discovery/credential tooling observed." if det else "."
        src_ent, tgt_ent = ent_user(user), ent_host(host)
    elif etype == "network":
        if e.get("action") == "network_probe" or d.get("action") == "network_probe":
            action = (f"Reachability probe from {host or src} to {dst} port {d.get('dst_port') or '?'} "
                      f"({outcome}) - scanning for the next reachable system.")
        elif d.get("action") == "webfilter" or e.get("action") == "webfilter":
            action = (f"Firewall {outcome} a web request from {src} to {dst} "
                      f"({d.get('category') or 'flagged category'}). Block observed in evidence.")
        elif d.get("action") == "ips" or e.get("action") == "ips":
            action = (f"IDS/IPS {outcome} traffic {src} -> {dst}:{d.get('dst_port') or '?'} - "
                      f"intrusion-prevention signature matched.")
        elif d.get("action") == "virus" or e.get("action") == "virus":
            action = f"Malware {outcome} in traffic {src} -> {dst} by the security gateway."
        elif d.get("action") == "dns" or e.get("action") == "dns":
            action = f"DNS query from {src} for '{d.get('dns_query') or '?'}' ({dst})."
        else:
            svc = d.get("service") or ""
            action = (f"Connection {src} -> {dst}"
                      f"{':' + str(d.get('dst_port')) if d.get('dst_port') else ''}"
                      f"{f' ({svc})' if svc else ''} - {outcome}.")
        src_ent = ent_ip(src) if src else ent_host(host)
        tgt_ent = ent_ip(dst) if dst else {"kind": "unknown", "id": "?", "label": "?"}
    else:
        action = e.get("message") or etype
    return action, src_ent, tgt_ent


def _phase_for_event(e: dict, det_by_event: dict[int, list[dict]]) -> str | None:
    """Map an event to a Kill Chain stage via its detections."""
    dets = det_by_event.get(e["id"])
    if dets:
        best = max(dets, key=lambda d: det_mod.SEV_RANK.get(d["severity"], 0))
        return best.get("killchain_stage")
    return None


def build_storyboard(inc: dict, events: list[dict], detections: list[dict]) -> dict:
    events = sorted([e for e in events if e.get("ts") is not None],
                    key=lambda e: (e["ts"], e["id"]))
    det_by_event: dict[int, list[dict]] = {}
    for d in detections:
        for eid in d["event_ids"]:
            det_by_event.setdefault(eid, []).append(d)

    phases: dict[str, dict] = {}
    unattached: list[dict] = []
    for e in events:
        stage = _phase_for_event(e, det_by_event)
        dets = det_by_event.get(e["id"]) or []
        det = max(dets, key=lambda d: det_mod.SEV_RANK.get(d["severity"], 0)) if dets else None
        if stage is None:
            unattached.append(e)
            continue
        action, src_ent, tgt_ent = _describe(e, det)
        item = {
            "ts": e["ts"], "event_ids": [e["id"]],
            "action": action, "source": src_ent, "target": tgt_ent,
            "user": e.get("username"), "host": e.get("host"),
            "src_ip": e.get("src_ip"), "dst_ip": e.get("dst_ip"),
            "process": e.get("process"),
            "mitre": sorted({t for d in dets for t in d.get("mitre", [])}),
            "stage": stage,
            "severity": det["severity"] if det else e.get("severity", "info"),
            "detection": {"rule_id": det["rule_id"], "title": det["title"]} if det else None,
            "confidence": det["confidence"] if det else None,
            "observed": True,
        }
        phases.setdefault(stage, {"items": [], "detected": False})
        phases[stage]["items"].append(item)
        if det:
            phases[stage]["detected"] = True

    # attach un-flagged events to the temporally nearest phase (supporting context)
    anchored = [p for p in phases.values()]
    for e in unattached:
        best_stage, best_gap = None, None
        for stage, ph in phases.items():
            for it in ph["items"]:
                gap = abs(it["ts"] - e["ts"])
                if gap <= _SUPPORT_GAP_SECONDS and (best_gap is None or gap < best_gap):
                    best_stage, best_gap = stage, gap
        if best_stage is None:
            continue
        action, src_ent, tgt_ent = _describe(e, None)
        phases[best_stage]["items"].append({
            "ts": e["ts"], "event_ids": [e["id"]],
            "action": action + " (supporting activity - not flagged as suspicious)",
            "source": src_ent, "target": tgt_ent,
            "user": e.get("username"), "host": e.get("host"),
            "src_ip": e.get("src_ip"), "dst_ip": e.get("dst_ip"),
            "process": e.get("process"), "mitre": [], "stage": best_stage,
            "severity": e.get("severity", "info"), "detection": None,
            "confidence": None, "observed": True,
        })

    out_phases = []
    for stage in STAGES:
        if stage not in phases:
            continue
        ph = phases[stage]
        items = sorted(ph["items"], key=lambda i: (i["ts"], i["event_ids"]))
        # cap enormous phases (firewall datasets can produce 100k failed logins)
        if len(items) > 400:
            head = items[:120]
            tail = items[-40:]
            dropped = len(items) - len(head) - len(tail)
            items = head + [{
                "ts": (head[-1]["ts"] + tail[0]["ts"]) / 2,
                "event_ids": [],
                "action": f"... {dropped:,} further events of the same behavior in this phase "
                          f"(aggregate view - full evidence remains queryable in the Log Explorer).",
                "source": {"kind": "info", "id": "agg", "label": "aggregate"},
                "target": {"kind": "info", "id": "agg", "label": "aggregate"},
                "user": None, "host": None, "src_ip": None, "dst_ip": None,
                "process": None, "mitre": [], "stage": stage, "severity": "info",
                "detection": None, "confidence": None, "observed": True,
                "aggregate": True,
            }] + tail
        out_phases.append({
            "stage": stage,
            "title": stage,
            "description": STAGE_DESC.get(stage, ""),
            "detected": ph["detected"],
            "first_ts": items[0]["ts"],
            "last_ts": items[-1]["ts"],
            "item_count": len(ph["items"]),
            "items": items,
        })

    unsupported = [s for s in STAGES if s not in phases]
    return {
        "phases": out_phases,
        "unsupported_stages": unsupported,
        "unsupported_note": ("These Cyber Kill Chain stages have no supporting events in this "
                             "incident's evidence and are therefore not shown as story steps: "
                             + ", ".join(unsupported)) if unsupported else "",
        "event_count": len(events),
        "flagged_event_count": len(det_by_event),
        "story_generated_by": "deterministic storyboard builder",
    }
