"""MITRE ATT&CK technique metadata + Cyber Kill Chain stage definitions.

Technique names/tactics are a small static catalog covering the techniques our
deterministic rules emit. Kill Chain stages are deliberately kept separate from
ATT&CK tactics/techniques.
"""
from __future__ import annotations

ATTACK_TECHNIQUES: dict[str, dict] = {
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1110.001": {"name": "Brute Force: Password Guessing", "tactic": "Credential Access"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access"},
    "T1078.001": {"name": "Valid Accounts: Default Accounts", "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access"},
    "T1078.003": {"name": "Valid Accounts: Local Accounts", "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access"},
    "T1033": {"name": "System Owner/User Discovery", "tactic": "Discovery"},
    "T1016": {"name": "System Network Configuration Discovery", "tactic": "Discovery"},
    "T1087": {"name": "Account Discovery", "tactic": "Discovery"},
    "T1057": {"name": "Process Discovery", "tactic": "Discovery"},
    "T1049": {"name": "System Network Connections Discovery", "tactic": "Discovery"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1003.008": {"name": "OS Credential Dumping: /etc/passwd and /etc/shadow", "tactic": "Credential Access"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1021.004": {"name": "Remote Services: SSH", "tactic": "Lateral Movement"},
    "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell", "tactic": "Execution"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation, Defense Evasion"},
    "T1548.003": {"name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "tactic": "Privilege Escalation, Defense Evasion"},
    "T1005": {"name": "Data from Local System", "tactic": "Collection"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
}

KILL_CHAIN_STAGES = [
    ("Reconnaissance", "Selecting targets and probing for reachable services / accounts."),
    ("Weaponization", "Preparing the tooling and credentials to be used (rarely visible in logs)."),
    ("Delivery", "The intrusion attempt reaches the target (e.g. credential attacks arriving)."),
    ("Exploitation", "The attacker gains an initial foothold (e.g. valid-account login succeeds)."),
    ("Installation", "Post-access activity on the compromised host: discovery tooling, privilege escalation, lateral movement."),
    ("Command and Control", "Channels back to attacker infrastructure."),
    ("Actions on Objectives", "The final goal: data collection, staging and exfiltration."),
]

STAGE_ORDER = {name: i for i, (name, _) in enumerate(KILL_CHAIN_STAGES)}


def enrich_techniques(ids: list[str]) -> list[dict]:
    out = []
    for tid in ids:
        info = ATTACK_TECHNIQUES.get(tid, {})
        out.append({
            "id": tid,
            "name": info.get("name", "Unknown technique"),
            "tactic": info.get("tactic", "Unknown tactic"),
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
        })
    return out
