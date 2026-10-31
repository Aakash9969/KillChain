"""Attack graph construction for an incident.

Nodes: attacker/external IPs, user accounts, hosts, suspicious processes.
Edges carry `observed: true|false` - inferred edges are always explicitly
labelled and are only produced from real observed signals (e.g. a host that
was probed but never successfully accessed).
"""
from __future__ import annotations

from collections import defaultdict

from . import detectors as det_mod
from . import mitre
from .correlate import build_ip_host_map


def _node(kind: str, ident: str, label: str | None = None, **extra) -> dict:
    return {"id": f"{kind}:{ident}", "kind": kind, "ident": ident,
            "label": label or ident, **extra}


def build_graph(inc: dict, events: list[dict], detections: list[dict]) -> dict:
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    edge_seen: set[tuple] = set()

    def add_node(n: dict) -> dict:
        if n["id"] not in nodes:
            nodes[n["id"]] = n
        return nodes[n["id"]]

    def add_edge(src: str, dst: str, kind: str, label: str, observed: bool,
                 event_ids: list[int], **extra) -> None:
        key = (src, dst, kind)
        if key in edge_seen:
            for e in edges:
                if (e["source"], e["target"], e["kind"]) == key:
                    e["event_ids"] = sorted(set(e["event_ids"]) | set(event_ids))
                    return
            return
        edge_seen.add(key)
        edges.append({"source": src, "target": dst, "kind": kind, "label": label,
                      "observed": observed, "event_ids": event_ids, **extra})

    det_by_event: dict[int, list[dict]] = defaultdict(list)
    for d in detections:
        for eid in d["event_ids"]:
            det_by_event[eid].append(d)

    def det_of(e: dict) -> list[dict]:
        return det_by_event.get(e["id"], [])

    users_hosts: dict[str, set] = defaultdict(set)
    ip_host = build_ip_host_map(events)

    for e in events:
        user, src, dst, host = e.get("username"), e.get("src_ip"), e.get("dst_ip"), e.get("host")
        etype, outcome = e["event_type"], e.get("outcome")
        dets = det_of(e)
        mitre_ids = sorted({t for d in dets for t in d["mitre"]})

        if user and host and etype in ("auth_success", "auth_failure", "privilege"):
            users_hosts[user].add(host)

        if etype in ("auth_failure", "auth_success") and src:
            ext = det_mod.is_external(src)
            if ext:
                srcn = add_node(_node("ip", src, kind_extra="external"))
                srcn["role"] = "attacker_infra"
            elif src in ip_host:
                srcn = add_node(_node("host", ip_host[src]))
            else:
                srcn = add_node(_node("ip", src, kind_extra="internal"))
            un = add_node(_node("user", user))
            hn = add_node(_node("host", host))
            if etype == "auth_failure":
                add_edge(srcn["id"], un["id"], "failed_auth", "failed logins", True, [e["id"]],
                         severity="high")
                add_edge(un["id"], hn["id"], "targeted", "targeted account", True, [e["id"]])
            else:
                add_edge(srcn["id"], un["id"], "authenticated", "authenticated as", True, [e["id"]],
                         severity="critical")
                add_edge(un["id"], hn["id"], "logged_in_to", "logged in to", True, [e["id"]],
                         severity="critical", mitre=mitre_ids)

        if etype == "privilege" and host and user:
            hn = add_node(_node("host", host))
            un = add_node(_node("user", user))
            add_edge(un["id"], hn["id"], "privilege_attempt", "privilege escalation attempt",
                     True, [e["id"]], severity="high", mitre=mitre_ids)

        if etype == "process" and any(d["rule_id"] == "SUSPICIOUS_PROCESS_EXEC" for d in dets):
            hn = add_node(_node("host", host))
            proc = e.get("process") or "process"
            pn = add_node(_node("process", f"{host}:{proc}", proc,
                                command=(e.get("details") or {}).get("command")))
            un = add_node(_node("user", user)) if user else None
            if un:
                add_edge(un["id"], pn["id"], "executed", "executed", True, [e["id"]],
                         mitre=mitre_ids)
            add_edge(pn["id"], hn["id"], "ran_on", "ran on", True, [e["id"]], severity="high")

        if etype == "network" and src and dst:
            d = e.get("details") or {}
            dst_port = d.get("dst_port") or d.get("port")
            src_host = e.get("host") or ip_host.get(src)
            dst_host = ip_host.get(dst)
            shn = add_node(_node("host", src_host)) if src_host else \
                add_node(_node("ip", src, kind_extra="internal"))
            dhn = add_node(_node("host", dst_host, f"{dst_host} ({dst})")) if dst_host else \
                add_node(_node("ip", dst, kind_extra="internal"))
            if d.get("action") == "network_probe":
                add_edge(shn["id"], dhn["id"], "probed", f"port probes ({dst_port})", True,
                         [e["id"]], severity="medium", mitre=mitre_ids)
            else:
                add_edge(shn["id"], dhn["id"], "remote_connection",
                         f"{d.get('action') or 'remote connection'}" + (f":{dst_port}" if dst_port else ""),
                         True, [e["id"]], severity="high", mitre=mitre_ids)

        if etype in ("process", "network") \
                and any(d["rule_id"] == "EXFIL_EXTERNAL" for d in dets):
            ext_ip = e.get("dst_ip")
            if ext_ip:
                ipn = add_node(_node("ip", ext_ip, kind_extra="external"))
                ipn["role"] = "attacker_infra"
                hn = add_node(_node("host", e.get("host")))
                add_edge(hn["id"], ipn["id"], "exfiltrated_to", "uploaded data to", True,
                         [e["id"]], severity="critical", mitre=["T1041"])

    # ---- Inferred edges (explicitly labelled) --------------------------------
    probed: dict[tuple, list[dict]] = defaultdict(list)
    accessed: set[str] = set()
    for e in events:
        d = e.get("details") or {}
        if e["event_type"] == "network" and d.get("action") == "network_probe" and e.get("dst_ip"):
            probed[(e.get("host"), e["dst_ip"])].append(e)
        if e["event_type"] == "auth_success" and e.get("host"):
            accessed.add(e["host"])
    for (src_host, dst_ip), evs in probed.items():
        dst_host = ip_host.get(dst_ip)
        target_id = f"host:{dst_host}" if dst_host else f"ip:{dst_ip}"
        if not (dst_host in accessed or dst_ip in accessed):
            if dst_host:
                add_node(_node("host", dst_host, f"{dst_host} ({dst_ip})"))
            else:
                add_node(_node("ip", dst_ip, kind_extra="internal"))
            add_edge(f"host:{src_host}", target_id, "potential_next_target",
                     "potential next target (INFERRED)", False, [e["id"] for e in evs],
                     inference=True)

    # users seen on several hosts -> credential reuse (inferred, only between
    # hosts where the SAME account was observed)
    for user, hosts in users_hosts.items():
        if len(hosts) > 1:
            hs = sorted(hosts)
            for a, b in zip(hs, hs[1:]):
                add_edge(f"host:{a}", f"host:{b}", "credential_reuse",
                         f"possible credential reuse of {user} (INFERRED)", False, [],
                         inference=True)

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "kill_chain": [{"stage": s, "description": d} for s, d in mitre.KILL_CHAIN_STAGES],
    }
