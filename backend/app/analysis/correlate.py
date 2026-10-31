"""Event correlation: link related events via shared evidence and group
them into incidents using union-find with bounded time windows.

Linking is deliberately conservative - events are connected only when they
share a strong identity relationship (same account + source IP, same account
on the same host, or an observed host-to-host authentication bridge). We do
NOT connect events merely because they are suspicious at the same time.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from .. import config, db
from . import detectors as det_mod


class UnionFind:
    def __init__(self, n: int) -> None:
        self.p = list(range(n))

    def find(self, x: int) -> int:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)


def build_ip_host_map(events: list[dict]) -> dict[str, str]:
    """Map internal IPs to the hosts that own them.

    Only reliable sources are used:
      * network (EDR) events: the logging host is the SOURCE of the connection,
        so its local src_ip belongs to that host;
      * auth pairing: an 'Accepted password' on host X from internal IP P within
        3 minutes of a network connection from P to internal IP D means D
        belongs to X (the target of the carried connection).
    """
    ip_host: dict[str, str] = {}
    for e in events:
        if e["event_type"] == "network" and e.get("host") and e.get("src_ip") \
                and not det_mod.is_external(e["src_ip"]):
            ip_host.setdefault(e["src_ip"], e["host"])
    auths = [e for e in events if e["event_type"] == "auth_success" and e.get("host")
             and e.get("src_ip") and not det_mod.is_external(e["src_ip"])]
    nets = [e for e in events if e["event_type"] == "network" and e.get("src_ip")
            and e.get("dst_ip") and not det_mod.is_external(e["dst_ip"])]
    for a in auths:
        for n in nets:
            if n["src_ip"] == a["src_ip"] and a.get("ts") and n.get("ts") \
                    and 0 <= (a["ts"] - n["ts"]) <= 180:
                ip_host.setdefault(n["dst_ip"], a["host"])
    return ip_host


def _link_key_pairs(events: list[dict]) -> list[set[str]]:
    """Compute conservative linkage keys for each event."""
    keys: list[set[str]] = [set() for _ in events]
    ip_host = build_ip_host_map(events)

    for i, e in enumerate(events):
        user, src, dst, host = e.get("username"), e.get("src_ip"), e.get("dst_ip"), e.get("host")
        if user and src:
            keys[i].add(f"auth|{user}|{src}")
        if user and host:
            keys[i].add(f"hostuser|{user}|{host}")
        # bridge: an auth arriving at host H from internal IP P links to activity
        # of the same account on the host that owns P (observed lateral movement)
        if user and host and src and not det_mod.is_external(src):
            owner = ip_host.get(src)
            if owner and owner != host:
                keys[i].add(f"lateral|{user}|{owner}")
        if user and dst and not det_mod.is_external(dst):
            owner = ip_host.get(dst)
            if owner and owner != host:
                keys[i].add(f"hostuser|{user}|{owner}")
    return keys


def correlate(events: list[dict]) -> list[list[dict]]:
    """Return groups of related events (potential incidents)."""
    if not events:
        return []
    events = sorted(events, key=lambda e: (e.get("ts") or 0, e["id"]))
    idx_of = {e["id"]: i for i, e in enumerate(events)}
    keys = _link_key_pairs(events)
    uf = UnionFind(len(events))
    max_gap = config.CORRELATION_LINK_WINDOW_HOURS * 3600

    by_key: dict[str, list[int]] = defaultdict(list)
    for i, ks in enumerate(keys):
        for k in ks:
            by_key[k].append(i)
    for group in by_key.values():
        group.sort(key=lambda i: (events[i].get("ts") or 0, events[i]["id"]))
        for a, b in zip(group, group[1:]):
            ta, tb = events[a].get("ts"), events[b].get("ts")
            if ta is not None and tb is not None and (tb - ta) <= max_gap:
                uf.union(a, b)

    components: dict[int, list[int]] = defaultdict(list)
    for i in range(len(events)):
        components[uf.find(i)].append(i)

    groups = []
    for comp in components.values():
        comp.sort(key=lambda i: (events[i].get("ts") or 0, events[i]["id"]))
        span = (events[comp[-1]].get("ts") or 0) - (events[comp[0]].get("ts") or 0)
        # keep a component as an incident if it spans meaningful activity
        if len(comp) >= 2 or span >= 60:
            groups.append([events[i] for i in comp])
    return groups


def _risk_score(detections: list[dict], events: list[dict]) -> int:
    pts = 0.0
    for d in detections:
        pts += {"critical": 32, "high": 18, "medium": 8, "low": 3, "info": 1}.get(d["severity"], 2)
    techniques = set()
    for d in detections:
        techniques.update(d["mitre"])
    pts += min(len(techniques), 10) * 2
    if any(det_mod.is_external(e.get("src_ip")) for e in events):
        pts += 8
    hosts = {e.get("host") for e in events if e.get("host")}
    if len(hosts) > 1:
        pts += (len(hosts) - 1) * 5
    return max(1, min(100, round(pts)))


def _find_entry_point(events: list[dict]) -> dict | None:
    """Earliest externally-sourced authentication activity in the incident."""
    for e in events:  # events are time-sorted
        if e.get("event_type") in ("auth_failure", "auth_success") \
                and det_mod.is_external(e.get("src_ip")):
            return {
                "attacker_ip": e["src_ip"], "target_host": e.get("host"),
                "account": e.get("username"), "first_seen_ts": e.get("ts"),
                "first_seen_event_id": e["id"],
                "description": f"First externally-sourced authentication activity against "
                               f"{e.get('host')} for account '{e.get('username')}' from {e['src_ip']}.",
            }
    return None


def _hypotheses(events: list[dict], detections: list[dict]) -> list[dict]:
    """Explicitly-labelled inferences - never presented as observed facts."""
    hyps = []
    probed: dict[tuple, list[dict]] = defaultdict(list)
    accessed: set[tuple] = set()
    for e in events:
        d = e.get("details") or {}
        if e["event_type"] == "network" and d.get("action") == "network_probe":
            probed[(e.get("host"), e.get("dst_ip"))].append(e)
        if e["event_type"] == "auth_success" and e.get("host") and e.get("username"):
            accessed.add((e["username"], e["host"]))
    for (src_host, dst_ip), evs in probed.items():
        dst_host = evs[-1].get("details", {}).get("dst_host") or dst_ip
        if not any(a[1] in (dst_host, dst_ip) for a in accessed):
            hyps.append({
                "label": "Potential next target (INFERRED)",
                "text": f"{src_host} probed {dst_ip} on multiple ports but no successful "
                        f"authentication to it is present in the analyzed data. The attacker "
                        f"may attempt lateral movement to {dst_ip} next - verify whether the "
                        f"compromised credentials are valid there.",
                "supporting_event_ids": [e["id"] for e in evs],
            })
    users_multi_host: dict[str, set] = defaultdict(set)
    for e in events:
        if e["event_type"] == "auth_success" and e.get("username") and e.get("host"):
            users_multi_host[e["username"]].add(e["host"])
    for user, hosts in users_multi_host.items():
        if len(hosts) > 1:
            hyps.append({
                "label": "Credential reuse (INFERRED)",
                "text": f"Account '{user}' was used successfully on {', '.join(sorted(hosts))}. "
                        f"Credentials of this account may be reused on other systems that trust "
                        f"it - enumerate systems where the account exists.",
                "supporting_event_ids": [e["id"] for e in events
                                         if e.get("username") == user and e["event_type"] == "auth_success"],
            })
    return hyps


def build_incidents(events: list[dict], detections: list[dict], analysis_id: int,
                    is_demo: bool) -> list[dict]:
    """Group correlated events into incidents enriched with detections."""
    det_by_event: dict[int, list[dict]] = defaultdict(list)
    for d in detections:
        for eid in d["event_ids"]:
            det_by_event[eid].append(d)

    incidents = []
    groups = correlate(events)
    seq = 0
    for group in groups:
        group_dets: dict[tuple, dict] = {}
        for e in group:
            for d in det_by_event.get(e["id"], []):
                group_dets[id(d)] = d
        dets = list(group_dets.values())
        if not dets:
            continue  # only correlated activity backed by detections becomes an incident
        seq += 1
        tss = [e.get("ts") for e in group if e.get("ts") is not None]
        risk = _risk_score(dets, group)
        sev = max((d["severity"] for d in dets), key=lambda s: det_mod.SEV_RANK.get(s, 0))
        top_rules = sorted({d["rule_id"] for d in dets})
        entry = _find_entry_point(group)
        hosts = sorted({e.get("host") for e in group if e.get("host")})
        users = sorted({e.get("username") for e in group if e.get("username")})
        ips = sorted({ip for e in group for ip in (e.get("src_ip"), e.get("dst_ip")) if ip})
        name = f"{', '.join(hosts[:2]) or 'Unknown hosts'} - {dets[0]['title'].lower()}"
        incidents.append({
            "analysis_id": analysis_id,
            "ref": f"INC-2026-{seq:04d}",
            "name": name,
            "summary": _summary(group, dets, entry, hosts, users, ips),
            "risk_score": risk,
            "severity": sev,
            "first_ts": min(tss) if tss else None,
            "last_ts": max(tss) if tss else None,
            "event_ids": [e["id"] for e in group],
            "detection_ids": [d["rule_id"] + ":" + str(d["event_ids"][0]) for d in dets],
            "_detections": dets,
            "entities": {"users": users, "hosts": hosts, "ips": ips,
                         "processes": sorted({e.get("process") for e in group
                                              if e.get("process") and e["event_type"] == "process"})},
            "entry_point": entry,
            "hypotheses": _hypotheses(group, dets),
            "is_demo": is_demo,
        })
    incidents.sort(key=lambda i: -i["risk_score"])
    return incidents


def _summary(group: list[dict], dets: list[dict], entry, hosts, users, ips) -> str:
    host_list = ", ".join(hosts[:3]) or "unknown hosts"
    user_list = ", ".join(users[:3]) or "unknown accounts"
    rule_names = ", ".join(sorted({d["title"] for d in dets})[:4])
    s = (f"Correlated incident spanning {len(group)} events on {host_list} involving account(s) "
         f"{user_list}. Detected behavior: {rule_names}.")
    if entry:
        s += (f" Reconstructed entry point: authentication activity against {entry['target_host']} "
              f"from external IP {entry['attacker_ip']} beginning "
              f"{det_mod.fmt_time(entry['first_seen_ts'])}.")
    ext = sorted({ip for ip in ips if det_mod.is_external(ip)})
    if ext:
        s += f" External infrastructure involved: {', '.join(ext[:3])}."
    return s
