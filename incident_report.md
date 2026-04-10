# Incident Report — Brute Force Attack Detection

**Date:** 2026-04-10
**Analyst:** Aurelio Avila
**Severity:** High
**Status:** Resolved

---

## Summary
Multiple failed authentication attempts were detected against the
administrator account on DESKTOP-001. SPL analysis confirmed a
brute force attack originating from IP 192.168.1.105, with 5
failed logons in 4 seconds followed by a successful login.

---

## Timeline

| Time (UTC) | Event |
|---|---|
| 08:15:23 | First failed logon attempt — administrator from 192.168.1.105 |
| 08:15:27 | Fifth failed logon attempt — pattern confirmed |
| 08:15:28 | Successful logon — administrator from 192.168.1.105 |
| 08:17:10 | Privilege escalation — SeDebugPrivilege assigned |
| 08:18:45 | cmd.exe spawned by administrator |
| 08:19:02 | net.exe executed — possible lateral movement |

---

## Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Source IP | 192.168.1.105 |
| Target Account | administrator |
| Workstation | DESKTOP-001 |
| Failed Attempts | 5 in 4 seconds |
| EventCodes | 4625, 4624, 4672, 4688 |

---

## Analysis
The attacker performed a brute force attack against the local
administrator account. After 5 failed attempts, authentication
succeeded. The attacker then escalated privileges and spawned
cmd.exe followed by net.exe — consistent with post-exploitation
reconnaissance or lateral movement attempts.

---

## Actions Taken
1. Brute force pattern identified via SPL query in Splunk
2. Successful logon after failed attempts confirmed compromise
3. Privilege escalation and suspicious process execution documented
4. Incident escalated for endpoint isolation

---

## Recommendations
1. Block IP 192.168.1.105 at firewall level immediately
2. Disable the administrator account or enforce MFA
3. Investigate net.exe execution for lateral movement
4. Review all systems accessed from 192.168.1.105
5. Implement account lockout policy after 3 failed attempts

---

## Verdict
**BRUTE FORCE ATTACK CONFIRMED — Escalate immediately**