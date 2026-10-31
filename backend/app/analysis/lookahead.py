"""Look-ahead analysis: what could the attacker potentially reach next?

STRICT correctness rules:
- Only relationships supported by observed events are considered.
- Every target is labelled INFERRED (a potential next step, never a compromise).
- When the logs lack privilege/topology information, that limitation is stated.
- The analysis is deterministic and explainable; AI never generates these.
"""
from __future__ import annotations

from collections import defaultdict

from . import detectors as det_mod
from .correlate import build_ip_host_map

PROBE_PORTS_FOR_MEDIUM = 3      # distinct ports probed -> medium confidence
SCAN_PORTS_FOR_HIGH = 10        # distinct ports probed -> high confidence


def _ent_host(ident, label=None):
    return {"kind": "host", "id": f"host:{ident}", "label": label or ident}


def _ent_ip(ident):
    return {"kind": "ip", "id": f"ip:{ident}", "label": ident,
            "external": det_mod.is_external(ident)}


def build_lookahead(events: list[dict], detections: list[dict]) -> dict:
    ip_host = build_ip_host_map(events)
    det_by_event: dict[int, list[dict]] = {}
    for d in detections:
        for eid in d["event_ids"]:
            det_by_event.setdefault(eid, []).append(d)

    # ---- observed state -------------------------------------------------
    probed: dict[tuple, dict] = {}          # (src_host, dst_key) -> probe info
    accessed_hosts: set[str] = set()        # hosts with successful authentication
    accessed_pairs: set[tuple] = set()      # (user, host) successful pairs
    auth_by_user: dict[str, set] = defaultdict(set)   # user -> hosts observed (success)
    compromised_accounts: set[str] = set()  # accounts flagged by detections
    remote_services: dict[tuple, dict] = {}  # (src_host, dst_key, port) -> conn info
    compromised_hosts: set[str] = set()     # hosts flagged by detections

    for d in detections:
        ents = d.get("entities") or {}
        compromised_accounts.update(ents.get("users") or [])
        for h in ents.get("hosts") or []:
            compromised_hosts.add(h)

    for e in events:
        host, user = e.get("host"), e.get("username")
        d = e.get("details") or {}
        if e["event_type"] == "auth_success" and host:
            accessed_hosts.add(host)
            if user:
                accessed_pairs.add((user, host))
                auth_by_user[user].add(host)
        if e["event_type"] == "network" and e.get("dst_ip"):
            dst_key = ip_host.get(e["dst_ip"], e["dst_ip"])
            src_host = e.get("host") or ip_host.get(e.get("src_ip"))
            if d.get("action") == "network_probe":
                pr = probed.setdefault((src_host, dst_key), {
                    "src_host": src_host, "dst_key": dst_key, "dst_ip": e["dst_ip"],
                    "ports": set(), "event_ids": [], "fail": 0, "ok": 0})
                pr["ports"].add(d.get("dst_port") or e.get("dst_port"))
                pr["event_ids"].append(e["id"])
                pr["fail" if e.get("outcome") == "failure" else "ok"] += 1
            elif e.get("outcome") == "success" and not det_by_event.get(e["id"]):
                # successful connection WITHOUT a subsequent observed auth => reachable service
                key = (src_host, dst_key, d.get("dst_port"))
                remote_services.setdefault(key, {
                    "src_host": src_host, "dst_key": dst_key, "port": d.get("dst_port"),
                    "service": d.get("service"), "event_ids": [e["id"]]})

    targets = []

    # ---- Signal 1: probed but never accessed ----------------------------
    for (src_host, dst_key), pr in probed.items():
        accessed = dst_key in accessed_hosts or pr["dst_ip"] in accessed_hosts
        if accessed:
            continue  # the incident already covers this host
        nports = len({p for p in pr["ports"] if p})
        conf = "high" if nports >= SCAN_PORTS_FOR_HIGH else (
            "medium" if nports >= PROBE_PORTS_FOR_MEDIUM else "low")
        is_ip = dst_key.replace(".", "").isdigit()
        target_ent = _ent_ip(pr["dst_ip"]) if is_ip else _ent_host(dst_key)
        targets.append({
            "target": target_ent,
            "label": "Potential next target (INFERRED)",
            "why": (f"{pr['src_host'] or pr['dst_ip'] and 'an attacker-controlled host'} probed "
                    f"{dst_key} on {nports} port(s) "
                    f"({', '.join(str(p) for p in sorted(pr['ports'], key=str)[:8])}"
                    f"{', ...' if nports > 8 else ''}); "
                    f"{'most probes were refused' if pr['fail'] >= pr['ok'] else 'at least one probe succeeded'}"
                    f". No successful authentication to this host appears in the evidence."),
            "enabler": f"network reachability observed from {src_host or 'compromised host'}",
            "evidence_event_ids": sorted(pr["event_ids"])[:40],
            "confidence": conf,
            "observed": False,
            "inference": True,
            "relevance": ("Probing of internal systems is standard attacker behavior to locate "
                          "the next pivot; treat as reconnaissance toward this host."),
        })

    # ---- Signal 2: accounts observed valid on other hosts ----------------
    for user in compromised_accounts:
        for host in auth_by_user.get(user, set()):
            if host in compromised_hosts:
                continue
            evs = [e["id"] for e in events if e.get("username") == user
                   and e.get("host") == host and e["event_type"] == "auth_success"]
            if not evs:
                continue
            targets.append({
                "target": _ent_host(host),
                "label": "Credential reuse risk (INFERRED)",
                "why": (f"Account '{user}' - flagged in this incident - has also authenticated "
                        f"successfully to {host} elsewhere in the analyzed data. If the attacker "
                        f"obtains these credentials, this host is reachable with them."),
                "enabler": f"observed valid account '{user}' on {host}",
                "evidence_event_ids": sorted(evs)[:40],
                "confidence": "medium",
                "observed": False,
                "inference": True,
                "relevance": ("Valid-account reuse is the most common lateral movement path; "
                              "verify where this account exists and rotate it."),
            })

    # ---- Signal 3: reachable services without observed follow-on auth ----
    for (src_host, dst_key, port), svc in remote_services.items():
        if dst_key in accessed_hosts:
            continue
        is_ip = dst_key.replace(".", "").isdigit()
        targets.append({
            "target": _ent_ip(dst_key) if is_ip else _ent_host(dst_key),
            "label": "Reachable service (INFERRED)",
            "why": (f"A successful connection from {src_host or 'a compromised host'} to "
                    f"{dst_key} port {port} was observed"
                    f"{' (service: ' + str(svc['service']) + ')' if svc.get('service') else ''}, "
                    f"but no authentication to that host follows in the evidence. The service "
                    f"was reachable - compromise is NOT established."),
            "enabler": f"network path to {dst_key}:{port}",
            "evidence_event_ids": svc["event_ids"][:20],
            "confidence": "low",
            "observed": False,
            "inference": True,
            "relevance": "Reachable remote services are candidate pivot points if credentials are obtained.",
        })

    # de-duplicate by target id keeping highest confidence
    rank = {"high": 3, "medium": 2, "low": 1}
    best: dict[str, dict] = {}
    for t in targets:
        cur = best.get(t["target"]["id"])
        if cur is None or rank[t["confidence"]] > rank[cur["confidence"]]:
            best[t["target"]["id"]] = t
    targets = sorted(best.values(),
                     key=lambda t: -rank[t["confidence"]])

    missing = [
        "Account privilege / group-membership information is not present in the analyzed "
        "logs, so administrative rights on other systems cannot be confirmed or denied.",
        "Network topology (which hosts can reach which) is inferred only from observed "
        "connections and probes in these logs.",
        "If additional sources (CMDB, firewall policy, identity data) become available, "
        "attach them to sharpen this analysis.",
    ]
    return {
        "targets": targets,
        "missing_information": missing,
        "generated_by": "deterministic look-ahead analyzer (no AI involvement)",
        "disclaimer": ("Potential next targets are hypotheses derived from observed evidence. "
                       "None of them is a confirmed compromise."),
    }
