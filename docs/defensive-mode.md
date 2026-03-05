# Defensive Mode

KaliMentor supports three defensive challenge types for blue team work:

| Type | Use Case |
|------|----------|
| `defend` | Incident investigation — analyse logs, trace attacker activity, produce timeline |
| `harden` | Configuration audit — check against CIS Benchmarks, produce remediation plan |
| `hunt` | Threat hunting — proactively search logs/artifacts for IOCs |

---

## Quick Start

```bash
# Investigate an incident on a remote host
kalimentor start -c defend -t 192.168.1.10 --llm anthropic

# Audit a server's configuration
kalimentor start -c harden -t 192.168.1.10 --llm anthropic

# Hunt through a PCAP file
kalimentor start -c hunt --file /path/to/capture.pcap --llm anthropic

# Analyse local log files
kalimentor start -c defend --file /var/log/auth.log --llm anthropic
```

---

## Defend Mode

The agent acts as a blue team analyst. It will:

1. Enumerate logs and identify relevant artifacts
2. Extract IOCs (IPs, domains, hashes, usernames)
3. Trace attacker activity chronologically
4. Map findings to MITRE ATT&CK techniques
5. Produce a remediation plan

**Tools used:** `analyze_logs`, `bash`, `read_file`, `grep_tool`, `detect_persistence`, `map_to_attack`, `record_finding`

**Example session:**

```
> Investigate suspicious SSH activity on this server

KaliMentor: I'll start by examining the authentication logs...

[bash] tail -n 5000 /var/log/auth.log
[analyze_logs] /var/log/auth.log (type: auth)

Found: 847 failed SSH attempts from 45.33.32.156 between 02:14 and 02:47 UTC
Found: Successful login as 'backup' at 02:51 UTC (unusual account)
Found: sudo session opened for 'backup' at 02:52 UTC

Mapping to ATT&CK: T1110.001 (Brute Force: Password Guessing), T1078 (Valid Accounts)

Recommend: Block 45.33.32.156, audit 'backup' account, review sudo rules
```

---

## Harden Mode

The agent acts as a security auditor. It will:

1. Audit SSH config, sudoers, firewall rules, and file permissions
2. Check against CIS Benchmark controls
3. Identify misconfigurations with severity ratings
4. Produce a prioritised remediation roadmap

**Tools used:** `check_config`, `bash`, `read_file`, `record_finding`

**Example output:**

```
Finding: SSH PermitRootLogin is enabled
Severity: HIGH
CIS Control: 5.2.10
Recommendation: Set PermitRootLogin no in /etc/ssh/sshd_config

Finding: sudoers contains NOPASSWD for user 'deploy'
Severity: MEDIUM
CIS Control: 5.3.4
Recommendation: Remove NOPASSWD or restrict to specific commands
```

---

## Hunt Mode

The agent acts as a threat hunter. It will:

1. Proactively search for indicators of compromise
2. Look for anomalous patterns (unusual processes, network connections, file changes)
3. Correlate findings across data sources
4. Produce a hunt report with confidence levels

**Tools used:** `analyze_logs`, `analyze_pcap`, `bash`, `grep_tool`, `detect_persistence`, `generate_yara_rule`, `generate_sigma_rule`

**Supplying artifacts:**

```bash
# Analyse a PCAP for C2 traffic
kalimentor start -c hunt --file capture.pcap --llm anthropic

# Analyse memory dump
kalimentor start -c hunt --file memory.raw --llm anthropic

# Multiple files (pass directory)
kalimentor start -c hunt --file /evidence/ --llm anthropic
```

---

## Detection Rule Generation

During any defensive session, ask the agent to generate detection rules:

```
> Generate a Sigma rule for this brute force pattern
> Create a YARA rule to detect this malware
> Write a Suricata rule for this C2 traffic
```

**Sigma rule example output:**

```yaml
title: SSH Brute Force Attack
status: experimental
logsource:
  product: linux
  service: auth
detection:
  selection:
    sshd_keyword: 'Failed password'
  timeframe: 5m
  condition: selection | count() > 10
falsepositives:
  - Legitimate failed logins from developers
level: medium
tags:
  - attack.credential_access
  - attack.t1110.001
```

---

## MITRE ATT&CK Mapping

The agent automatically maps findings to ATT&CK during defensive sessions. Use `map_to_attack` explicitly:

```
> Map "attacker used cron job to maintain persistence" to ATT&CK
```

Output:
```
Technique: T1053.003 — Scheduled Task/Job: Cron
Tactic: Persistence (TA0003)
Detection: Monitor cron file modifications, unusual cron job additions
```

---

## Exporting Reports

```bash
# Inside session
/export /tmp/incident-report.md

# Or via CLI
kalimentor export <session-id> -o report.md
```

Reports include: executive summary, timeline, IOCs, ATT&CK techniques, findings table, remediation steps.
