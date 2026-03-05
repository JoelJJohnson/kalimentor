# KaliMentor Tools Reference

All tools are registered in the `ToolRegistry` and exposed to the LLM via JSON Schema. The LLM calls tools by name; the registry dispatches to the handler, applies the risk gate, and returns the result.

List available tools in any session with `/tools`.

---

## bash

**Risk:** Dynamic (SAFE / CONFIRM / DANGEROUS based on command content)

Run a shell command in a persistent session. The working directory persists across calls (cd commands carry over).

```json
{
  "command": "nmap -sV 10.10.10.1",
  "timeout": 120
}
```

**Risk classification** (command text is scanned):

| Pattern | Risk |
|---------|------|
| `cat`, `ls`, `grep`, `find`, `nmap` (no aggressive flags), `curl` (GET), `whoami` | SAFE |
| `gobuster`, `ffuf`, `nikto`, `sqlmap`, `hydra`, `wget`, `nmap -sS / -A / -p-`, file write (`>`) | CONFIRM |
| `msfconsole`, `msfvenom`, `exploit`, `payload`, `nc -e`, `bash -i`, `/dev/tcp` | DANGEROUS |

Output is truncated to 30,000 chars; a `[truncated N chars]` note is added if exceeded.

---

## read_file

**Risk:** SAFE

Read a file's contents, optionally restricted to a line range.

```json
{
  "path": "/etc/passwd",
  "line_range": "1-50"
}
```

---

## write_file

**Risk:** CONFIRM

Write or overwrite a file.

```json
{
  "path": "/tmp/exploit.py",
  "content": "#!/usr/bin/env python3\n..."
}
```

---

## list_directory

**Risk:** SAFE

List files and directories up to 2 levels deep.

```json
{
  "path": "/var/www/html"
}
```

---

## search_files

**Risk:** SAFE

Find files by glob pattern or regex.

```json
{
  "pattern": "*.conf",
  "path": "/etc",
  "regex": false
}
```

---

## grep_tool

**Risk:** SAFE

Search file contents (like ripgrep).

```json
{
  "pattern": "password",
  "path": "/var/www",
  "include": "*.php"
}
```

---

## search_cve

**Risk:** SAFE

Query searchsploit and NVD for CVEs affecting a service/version. Returns CVE ID, description, CVSS score, and exploit availability.

```json
{
  "service": "vsftpd",
  "version": "2.3.4"
}
```

---

## search_exploit

**Risk:** SAFE

Run `searchsploit` and return structured results.

```json
{
  "query": "apache 2.4.49"
}
```

---

## query_gtfobins

**Risk:** SAFE

Look up a binary on GTFOBins for privilege escalation vectors.

```json
{
  "binary": "python3"
}
```

---

## parse_nmap_xml

**Risk:** SAFE

Parse nmap XML output into structured host/port/service data.

```json
{
  "filepath": "/tmp/scan.xml"
}
```

---

## check_tool_installed

**Risk:** SAFE

Check if a tool exists in PATH.

```json
{
  "tool_name": "gobuster"
}
```

---

## install_tool

**Risk:** CONFIRM

Install a tool via apt or git clone + build.

```json
{
  "tool_name_or_repo_url": "gobuster"
}
```

---

## update_plan

**Risk:** SAFE

Update the session TODO list. The plan is injected as a reminder after every tool result to keep the LLM on track.

```json
{
  "tasks": [
    {"id": "1", "task": "Run nmap scan", "status": "done", "phase": "recon", "priority": "high"},
    {"id": "2", "task": "Enumerate HTTP on port 80", "status": "in_progress", "phase": "recon", "priority": "high"},
    {"id": "3", "task": "Check for SQLi on login form", "status": "pending", "phase": "exploit", "priority": "medium"}
  ]
}
```

Status values: `pending`, `in_progress`, `done`, `skipped`, `failed`.

---

## read_memory

**Risk:** SAFE

Read the current KALIMENTOR.md session memory file.

```json
{}
```

---

## write_memory

**Risk:** SAFE

Write or append to KALIMENTOR.md. The LLM calls this after significant discoveries.

```json
{
  "content": "## Credentials\n- admin:password123 (HTTP Basic on /admin)\n"
}
```

---

## record_finding

**Risk:** SAFE

Record a structured finding to the session findings table.

```json
{
  "category": "credentials",
  "key": "SSH key",
  "value": "Found RSA private key at /home/user/.ssh/id_rsa",
  "source": "read_file",
  "severity": "critical"
}
```

---

## list_findings

**Risk:** SAFE

Return all recorded findings for the session.

```json
{}
```

---

## analyze_logs

**Risk:** SAFE

Parse log files (auth.log, syslog, Apache/Nginx access logs, Windows Event Logs). Extracts failed logins, suspicious IPs, unusual commands, privilege escalation attempts.

```json
{
  "log_path": "/var/log/auth.log",
  "log_type": "auth"
}
```

---

## check_config

**Risk:** SAFE

Audit a configuration file against CIS benchmarks. Returns finding, severity, recommendation, and CIS control ID.

```json
{
  "config_type": "ssh",
  "path": "/etc/ssh/sshd_config"
}
```

Supported config types: `ssh`, `sudoers`, `firewall`, `passwd`.

---

## detect_persistence

**Risk:** SAFE

Check common persistence mechanisms (cron, systemd, at, .bashrc, SUID changes; registry Run keys, scheduled tasks, WMI for Windows).

```json
{
  "target_type": "linux"
}
```

---

## generate_sigma_rule

**Risk:** SAFE

Generate a Sigma detection rule YAML from a described behaviour.

```json
{
  "description": "PowerShell downloading from the internet",
  "log_source": "windows_powershell",
  "detection_logic": "EventID 4104 and ScriptBlockText contains 'DownloadString'"
}
```

---

## generate_yara_rule

**Risk:** SAFE

Generate a YARA rule from described indicators.

```json
{
  "description": "Mimikatz strings",
  "strings": ["sekurlsa", "lsadump", "mimikatz"],
  "condition": "any of them"
}
```

---

## map_to_attack

**Risk:** SAFE

Map an observed technique to a MITRE ATT&CK ID, tactic, and procedure.

```json
{
  "technique_description": "Attacker used scheduled tasks for persistence"
}
```

---

## analyze_pcap

**Risk:** SAFE

Run tshark with a display filter and parse results for C2 beacons, DNS tunneling, or exfiltration patterns.

```json
{
  "pcap_path": "/tmp/capture.pcap",
  "filter": "dns"
}
```

---

## spawn_agent

**Risk:** SAFE

Spawn a scoped sub-agent to handle a focused subtask. The sub-agent runs its own tool-use loop with a restricted tool set and returns a text report.

```json
{
  "task": "Enumerate all open ports and services on 10.10.10.1",
  "agent_type": "recon",
  "tools_allowed": ["bash", "read_file", "grep_tool"]
}
```

Agent types: `recon`, `research`, `defender`.
