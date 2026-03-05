"""Defensive security tools for KaliMentor's blue-team / incident-response mode.

All tools are read-only or generative (no system modification).
They are registered at SAFE risk level — they never touch the host offensively.

Tools:
  analyze_logs      — Parse auth.log, syslog, web access logs, Windows Event Logs.
  check_config      — Audit SSH, sudoers, firewall rules, passwd/shadow against CIS.
  detect_persistence — Enumerate common persistence mechanisms (cron, systemd, registry…).
  generate_sigma_rule — Produce a Sigma YAML detection rule.
  generate_yara_rule  — Produce a YARA rule from described indicators.
  map_to_attack       — Map a described technique to MITRE ATT&CK ID and tactic.
  analyze_pcap        — Run tshark with a filter and parse results.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
from pathlib import Path
from typing import Any

from .registry import ToolRegistry, ToolRiskLevel


# ─────────────────────────────────────────────────────────────────────────────
#  MITRE ATT&CK keyword map  (offline subset — most common techniques)
# ─────────────────────────────────────────────────────────────────────────────

_ATTACK_MAP: list[dict[str, str]] = [
    {"id": "T1059", "tactic": "Execution", "name": "Command and Scripting Interpreter",
     "keywords": "bash powershell cmd script shell interpreter execute command"},
    {"id": "T1059.001", "tactic": "Execution", "name": "PowerShell",
     "keywords": "powershell ps1 invoke-expression iex encoded command"},
    {"id": "T1078", "tactic": "Persistence / Defence Evasion", "name": "Valid Accounts",
     "keywords": "valid account credential stolen legitimate login"},
    {"id": "T1053", "tactic": "Persistence", "name": "Scheduled Task / Job",
     "keywords": "cron crontab scheduled task at job systemd timer"},
    {"id": "T1053.003", "tactic": "Persistence", "name": "Cron",
     "keywords": "cron crontab /etc/cron"},
    {"id": "T1053.005", "tactic": "Persistence", "name": "Scheduled Task",
     "keywords": "schtasks scheduled task taskschd windows task"},
    {"id": "T1136", "tactic": "Persistence", "name": "Create Account",
     "keywords": "useradd adduser new account created user passwd shadow"},
    {"id": "T1543", "tactic": "Persistence", "name": "Create or Modify System Process",
     "keywords": "systemd service daemon init.d upstart launchd"},
    {"id": "T1543.003", "tactic": "Persistence", "name": "Windows Service",
     "keywords": "service sc.exe registry services run key"},
    {"id": "T1547.001", "tactic": "Persistence", "name": "Registry Run Keys / Startup Folder",
     "keywords": "run key registry startup hkcu hklm currentversion"},
    {"id": "T1098", "tactic": "Persistence", "name": "Account Manipulation",
     "keywords": "ssh authorized_keys sudoers passwd shadow account modification"},
    {"id": "T1548.003", "tactic": "Privilege Escalation", "name": "Sudo and Sudo Caching",
     "keywords": "sudo sudoers nopasswd privilege escalation"},
    {"id": "T1548.001", "tactic": "Privilege Escalation", "name": "Setuid and Setgid",
     "keywords": "suid sgid setuid setgid chmod 4755 find suid"},
    {"id": "T1055", "tactic": "Defence Evasion / Privilege Escalation",
     "name": "Process Injection",
     "keywords": "process injection ptrace ld_preload inject shellcode"},
    {"id": "T1110", "tactic": "Credential Access", "name": "Brute Force",
     "keywords": "brute force hydra medusa crackmapexec failed login attempts"},
    {"id": "T1003", "tactic": "Credential Access", "name": "OS Credential Dumping",
     "keywords": "credential dump lsass mimikatz hash ntds sam secrets hashdump"},
    {"id": "T1021", "tactic": "Lateral Movement", "name": "Remote Services",
     "keywords": "ssh rdp smb winrm psexec remote service lateral movement"},
    {"id": "T1021.004", "tactic": "Lateral Movement", "name": "SSH",
     "keywords": "ssh scp sftp authorized_keys remote login"},
    {"id": "T1046", "tactic": "Discovery", "name": "Network Service Scanning",
     "keywords": "nmap scan port service discovery network scan"},
    {"id": "T1057", "tactic": "Discovery", "name": "Process Discovery",
     "keywords": "ps aux process list tasklist discovery enumeration"},
    {"id": "T1083", "tactic": "Discovery", "name": "File and Directory Discovery",
     "keywords": "ls find dir file directory discovery enumeration"},
    {"id": "T1082", "tactic": "Discovery", "name": "System Information Discovery",
     "keywords": "uname hostname whoami id systeminfo lscpu osinfo"},
    {"id": "T1071", "tactic": "Command and Control", "name": "Application Layer Protocol",
     "keywords": "c2 beacon http https dns command control callback"},
    {"id": "T1071.004", "tactic": "Command and Control", "name": "DNS",
     "keywords": "dns tunneling dnscat iodine txt record exfiltration"},
    {"id": "T1048", "tactic": "Exfiltration", "name": "Exfiltration Over Alternative Protocol",
     "keywords": "exfiltration ftp dns icmp upload data transfer out"},
    {"id": "T1070", "tactic": "Defence Evasion", "name": "Indicator Removal",
     "keywords": "log deletion clear history bash_history rm log truncate"},
    {"id": "T1562.001", "tactic": "Defence Evasion", "name": "Disable or Modify Tools",
     "keywords": "disable antivirus firewall iptables ufw selinux apparmor"},
]


def _match_attack(description: str) -> list[dict[str, str]]:
    """Return ATT&CK techniques whose keywords match the description (top 3)."""
    desc_lower = description.lower()
    scored: list[tuple[int, dict[str, str]]] = []
    for entry in _ATTACK_MAP:
        keywords = entry["keywords"].split()
        score = sum(1 for kw in keywords if kw in desc_lower)
        if score > 0:
            scored.append((score, entry))
    scored.sort(key=lambda x: -x[0])
    return [e for _, e in scored[:3]]


# ─────────────────────────────────────────────────────────────────────────────
#  Log parsing helpers
# ─────────────────────────────────────────────────────────────────────────────

def _parse_auth_log(text: str) -> dict[str, Any]:
    failed_logins: list[str] = []
    accepted_logins: list[str] = []
    sudo_events: list[str] = []
    suspicious: list[str] = []

    for line in text.splitlines():
        ll = line.lower()
        if "failed password" in ll or "authentication failure" in ll:
            failed_logins.append(line.strip())
        elif "accepted password" in ll or "accepted publickey" in ll:
            accepted_logins.append(line.strip())
        elif "sudo:" in ll:
            sudo_events.append(line.strip())
        if re.search(r"invalid user|did not receive identification|break-in attempt", ll):
            suspicious.append(line.strip())

    # Extract unique IPs from failed logins
    ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "\n".join(failed_logins)))
    top_ips = sorted(ips)[:20]

    return {
        "failed_logins": len(failed_logins),
        "accepted_logins": len(accepted_logins),
        "sudo_events": len(sudo_events),
        "suspicious_lines": len(suspicious),
        "top_attacker_ips": top_ips,
        "sample_failed": failed_logins[:5],
        "sample_accepted": accepted_logins[:5],
        "sample_suspicious": suspicious[:5],
        "sample_sudo": sudo_events[:5],
    }


def _parse_web_log(text: str) -> dict[str, Any]:
    errors: list[str] = []
    scanners: list[str] = []
    injections: list[str] = []
    ips: list[str] = []

    scan_patterns = re.compile(
        r"nikto|sqlmap|nmap|masscan|gobuster|dirbuster|burpsuite|"
        r"python-requests|curl/|wget/|zgrab|nuclei", re.I
    )
    injection_patterns = re.compile(
        r"union\+select|%27|%3c|<script|eval\(|base64_decode|cmd=|exec=|"
        r"\.\.\/|etc/passwd|/bin/sh", re.I
    )

    for line in text.splitlines():
        ip_match = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})", line)
        if ip_match:
            ips.append(ip_match.group(1))
        if re.search(r'" [45]\d{2} ', line):
            errors.append(line.strip())
        if scan_patterns.search(line):
            scanners.append(line.strip())
        if injection_patterns.search(line):
            injections.append(line.strip())

    from collections import Counter
    top_ips = [ip for ip, _ in Counter(ips).most_common(10)]

    return {
        "total_lines": len(text.splitlines()),
        "error_responses": len(errors),
        "scanner_signatures": len(scanners),
        "injection_attempts": len(injections),
        "top_source_ips": top_ips,
        "sample_errors": errors[:5],
        "sample_scanners": scanners[:3],
        "sample_injections": injections[:3],
    }


def _parse_syslog(text: str) -> dict[str, Any]:
    kernel_errors: list[str] = []
    service_failures: list[str] = []
    unusual: list[str] = []

    for line in text.splitlines():
        ll = line.lower()
        if "kernel:" in ll and ("error" in ll or "oops" in ll or "panic" in ll):
            kernel_errors.append(line.strip())
        if re.search(r"failed|error|cannot|denied|terminated", ll):
            service_failures.append(line.strip())
        if re.search(r"setuid|suid|capability|prctl|ptrace", ll):
            unusual.append(line.strip())

    return {
        "kernel_errors": len(kernel_errors),
        "service_failures": len(service_failures),
        "privilege_events": len(unusual),
        "sample_kernel": kernel_errors[:5],
        "sample_failures": service_failures[:5],
        "sample_privilege": unusual[:5],
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Config audit helpers
# ─────────────────────────────────────────────────────────────────────────────

_SSH_CHECKS = [
    ("PermitRootLogin", r"PermitRootLogin\s+yes", "PermitRootLogin no",
     "High", "CIS 5.2.8 — Root login should be disabled."),
    ("PasswordAuthentication", r"PasswordAuthentication\s+yes", "PasswordAuthentication no",
     "High", "CIS 5.2.11 — Password auth should be disabled; prefer keys."),
    ("PermitEmptyPasswords", r"PermitEmptyPasswords\s+yes", "PermitEmptyPasswords no",
     "Critical", "CIS 5.2.9 — Empty passwords must never be permitted."),
    ("X11Forwarding", r"X11Forwarding\s+yes", "X11Forwarding no",
     "Medium", "CIS 5.2.6 — X11 forwarding should be disabled."),
    ("MaxAuthTries", r"MaxAuthTries\s+([6-9]|\d{2,})", "MaxAuthTries 4",
     "Medium", "CIS 5.2.7 — Limit auth attempts to ≤ 4."),
]

_SUDOERS_CHECKS = [
    (r"NOPASSWD", "Medium", "NOPASSWD in sudoers allows passwordless privilege escalation."),
    (r"ALL\s*=\s*\(ALL\)\s*ALL", "High", "Unrestricted sudo — user can run any command as root."),
    (r"ALL\s*=\s*NOPASSWD:\s*ALL", "Critical", "Full passwordless root sudo — critical misconfiguration."),
]


def _audit_ssh_config(text: str) -> list[dict[str, str]]:
    findings = []
    for name, pattern, recommendation, severity, cis in _SSH_CHECKS:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append({
                "check": name,
                "severity": severity,
                "current": re.search(pattern, text, re.IGNORECASE).group(0).strip(),
                "recommendation": recommendation,
                "cis_control": cis,
            })
    return findings


def _audit_sudoers(text: str) -> list[dict[str, str]]:
    findings = []
    for pattern, severity, message in _SUDOERS_CHECKS:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            line = _line_containing(text, match.start())
            if not line.strip().startswith("#"):
                findings.append({
                    "severity": severity,
                    "line": line.strip(),
                    "issue": message,
                    "recommendation": "Restrict sudo rules to specific commands with passwords.",
                })
    return findings


def _line_containing(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    return text[start:end if end != -1 else len(text)]


# ─────────────────────────────────────────────────────────────────────────────
#  Shell execution helper
# ─────────────────────────────────────────────────────────────────────────────

async def _run(cmd: str, timeout: int = 30) -> tuple[str, str, int]:
    """Run a shell command, return (stdout, stderr, returncode)."""
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode or 0
    except asyncio.TimeoutError:
        return "", f"[Timeout after {timeout}s]", 1
    except Exception as e:
        return "", str(e), 1


# ─────────────────────────────────────────────────────────────────────────────
#  Registration
# ─────────────────────────────────────────────────────────────────────────────

def register_defense_tools(registry: ToolRegistry) -> None:
    """Register all defensive analysis tools into *registry*."""

    # ── analyze_logs ───────────────────────────────────────────────────────

    @registry.register(
        name="analyze_logs",
        description=(
            "Parse a log file to extract security-relevant events. "
            "Supports: auth (auth.log, secure), web (Apache/Nginx access logs), "
            "syslog. Returns structured findings: failed logins, attacker IPs, "
            "scanner signatures, injection attempts, privilege events."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "log_path": {
                    "type": "string",
                    "description": "Absolute path to the log file.",
                },
                "log_type": {
                    "type": "string",
                    "enum": ["auth", "web", "syslog"],
                    "description": "Log format to parse.",
                },
            },
            "required": ["log_path", "log_type"],
        },
        risk=ToolRiskLevel.SAFE,
    )
    async def analyze_logs(log_path: str, log_type: str) -> str:
        p = Path(log_path)
        if not p.exists():
            return f"[ERROR] File not found: {log_path}"
        if p.stat().st_size > 50 * 1024 * 1024:
            return f"[ERROR] File too large (>{50}MB). Use grep_tool to filter first."

        text = p.read_text(encoding="utf-8", errors="replace")

        if log_type == "auth":
            result = _parse_auth_log(text)
        elif log_type == "web":
            result = _parse_web_log(text)
        elif log_type == "syslog":
            result = _parse_syslog(text)
        else:
            return f"[ERROR] Unknown log_type: {log_type}"

        return json.dumps(result, indent=2)

    # ── check_config ───────────────────────────────────────────────────────

    @registry.register(
        name="check_config",
        description=(
            "Audit a configuration file against CIS Benchmark recommendations. "
            "config_type: ssh (sshd_config), sudoers (/etc/sudoers or /etc/sudoers.d/*). "
            "Returns: list of findings with severity, current value, recommendation, CIS control."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "config_type": {
                    "type": "string",
                    "enum": ["ssh", "sudoers"],
                    "description": "Configuration type to audit.",
                },
                "path": {
                    "type": "string",
                    "description": "Path to the config file.",
                },
            },
            "required": ["config_type", "path"],
        },
        risk=ToolRiskLevel.SAFE,
    )
    async def check_config(config_type: str, path: str) -> str:
        p = Path(path)
        if not p.exists():
            return f"[ERROR] File not found: {path}"
        text = p.read_text(encoding="utf-8", errors="replace")

        if config_type == "ssh":
            findings = _audit_ssh_config(text)
        elif config_type == "sudoers":
            findings = _audit_sudoers(text)
        else:
            return f"[ERROR] Unknown config_type: {config_type}"

        if not findings:
            return json.dumps({"status": "clean", "findings": []})
        return json.dumps({"status": "findings", "count": len(findings), "findings": findings}, indent=2)

    # ── detect_persistence ─────────────────────────────────────────────────

    @registry.register(
        name="detect_persistence",
        description=(
            "Enumerate common persistence mechanisms on the target system. "
            "target_type: linux (checks cron, systemd, .bashrc, SUID, at jobs, "
            "authorized_keys, /etc/rc.local) or windows (checks registry Run keys, "
            "scheduled tasks, startup folder, WMI subscriptions). "
            "Returns a list of findings with suspicion level."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target_type": {
                    "type": "string",
                    "enum": ["linux", "windows"],
                    "description": "Operating system type.",
                },
            },
            "required": ["target_type"],
        },
        risk=ToolRiskLevel.SAFE,
    )
    async def detect_persistence(target_type: str) -> str:
        findings: list[dict[str, str]] = []

        if target_type == "linux":
            checks = [
                ("crontab -l 2>/dev/null; cat /etc/cron* /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null",
                 "Cron jobs", "medium"),
                ("systemctl list-units --type=service --state=enabled 2>/dev/null | head -40",
                 "Enabled systemd services", "low"),
                ("find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system "
                 "-name '*.service' -newer /etc/passwd 2>/dev/null",
                 "Recently modified systemd units", "high"),
                ("cat ~/.bashrc ~/.bash_profile ~/.profile /etc/profile /etc/bash.bashrc 2>/dev/null | grep -v '^#'",
                 ".bashrc / profile modifications", "medium"),
                ("find / -perm -4000 -type f 2>/dev/null | head -30",
                 "SUID binaries", "high"),
                ("find / -perm -2000 -type f 2>/dev/null | head -20",
                 "SGID binaries", "medium"),
                ("find /home /root -name authorized_keys 2>/dev/null -exec echo {} \\; -exec cat {} \\;",
                 "SSH authorized_keys", "high"),
                ("cat /etc/rc.local 2>/dev/null",
                 "/etc/rc.local startup script", "medium"),
                ("atq 2>/dev/null",
                 "Scheduled 'at' jobs", "medium"),
            ]

        elif target_type == "windows":
            checks = [
                ('reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run 2>/dev/null',
                 "HKCU Run key", "high"),
                ('reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run 2>/dev/null',
                 "HKLM Run key", "high"),
                ('schtasks /query /fo LIST /v 2>/dev/null | head -80',
                 "Scheduled tasks", "medium"),
                ('dir "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" 2>/dev/null',
                 "User startup folder", "medium"),
                ('wmic service where "StartMode=Auto" get Name,PathName 2>/dev/null | head -30',
                 "Auto-start services", "low"),
            ]
        else:
            return f"[ERROR] Unknown target_type: {target_type}"

        for cmd, label, suspicion in checks:
            stdout, stderr, rc = await _run(cmd, timeout=15)
            output = stdout.strip()
            if output:
                findings.append({
                    "mechanism": label,
                    "suspicion_level": suspicion,
                    "output": output[:800],
                    "command": cmd,
                })

        if not findings:
            return json.dumps({"status": "no_persistence_found", "findings": []})
        return json.dumps({
            "status": "findings",
            "count": len(findings),
            "findings": findings,
        }, indent=2)

    # ── generate_sigma_rule ────────────────────────────────────────────────

    @registry.register(
        name="generate_sigma_rule",
        description=(
            "Generate a Sigma detection rule YAML from a described behaviour. "
            "Provide a natural language description, the log source category "
            "(e.g. 'process_creation', 'authentication', 'network_connection'), "
            "and key detection fields. Returns valid Sigma YAML."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "description": {
                    "type": "string",
                    "description": "Natural language description of the behaviour to detect.",
                },
                "log_source": {
                    "type": "string",
                    "description": "Sigma log source category, e.g. 'process_creation', 'authentication'.",
                },
                "detection_logic": {
                    "type": "string",
                    "description": (
                        "Key fields and values that identify the behaviour, "
                        "e.g. 'CommandLine contains \"mimikatz\" OR Image ends with \"lsass.exe\"'."
                    ),
                },
            },
            "required": ["description", "log_source", "detection_logic"],
        },
        risk=ToolRiskLevel.SAFE,
    )
    async def generate_sigma_rule(
        description: str,
        log_source: str,
        detection_logic: str,
    ) -> str:
        attack_matches = _match_attack(description)
        tags = [f"attack.{m['id'].lower().replace('.', '_')}" for m in attack_matches]
        tactics = list({m["tactic"].lower().split("/")[0].strip().replace(" ", "_")
                        for m in attack_matches})
        tags += [f"attack.{t}" for t in tactics]

        # Parse detection_logic into a simple Sigma selection block
        selection_lines = _logic_to_sigma_selection(detection_logic)
        tag_block = "\n    - ".join(tags) if tags else "attack.unknown"

        rule = f"""\
title: {description[:80]}
id: {_generate_uuid()}
status: experimental
description: {description}
references:
    - https://attack.mitre.org/techniques/{attack_matches[0]['id'].replace('.', '/')}/
author: KaliMentor (auto-generated)
date: {_today()}
tags:
    - {tag_block}
logsource:
    category: {log_source}
detection:
    selection:
{selection_lines}
    condition: selection
falsepositives:
    - Legitimate administrative activity
level: medium
"""
        return rule

    # ── generate_yara_rule ─────────────────────────────────────────────────

    @registry.register(
        name="generate_yara_rule",
        description=(
            "Generate a YARA rule from described indicators of compromise. "
            "Provide a list of strings/patterns to match and a condition expression."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "description": {
                    "type": "string",
                    "description": "What this YARA rule detects.",
                },
                "strings": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of strings, hex patterns, or regex to match.",
                },
                "condition": {
                    "type": "string",
                    "description": "YARA condition expression, e.g. 'any of them' or '2 of ($a*, $b*)'.",
                },
            },
            "required": ["description", "strings", "condition"],
        },
        risk=ToolRiskLevel.SAFE,
    )
    async def generate_yara_rule(
        description: str,
        strings: list[str],
        condition: str,
    ) -> str:
        rule_name = re.sub(r"[^a-zA-Z0-9_]", "_", description[:40]).strip("_") or "KaliMentor_Rule"
        string_defs: list[str] = []
        for i, s in enumerate(strings):
            var = f"$s{i}"
            if s.startswith("{") and s.endswith("}"):
                string_defs.append(f"        {var} = {s}")        # hex
            elif s.startswith("/") and s.endswith("/"):
                string_defs.append(f"        {var} = {s}")        # regex
            else:
                escaped = s.replace('"', '\\"')
                string_defs.append(f'        {var} = "{escaped}"')

        strings_block = "\n".join(string_defs) if string_defs else '        $placeholder = "REPLACE_ME"'

        rule = f"""\
rule {rule_name}
{{
    meta:
        description = "{description}"
        author = "KaliMentor (auto-generated)"
        date = "{_today()}"

    strings:
{strings_block}

    condition:
        {condition}
}}
"""
        return rule

    # ── map_to_attack ──────────────────────────────────────────────────────

    @registry.register(
        name="map_to_attack",
        description=(
            "Map an observed attacker technique or behaviour to MITRE ATT&CK. "
            "Returns matching technique IDs, tactics, names, and detection guidance."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "technique_description": {
                    "type": "string",
                    "description": "Description of the observed attacker behaviour or technique.",
                },
            },
            "required": ["technique_description"],
        },
        risk=ToolRiskLevel.SAFE,
    )
    async def map_to_attack(technique_description: str) -> str:
        matches = _match_attack(technique_description)
        if not matches:
            return json.dumps({
                "status": "no_match",
                "message": "No ATT&CK technique matched. Try with more specific keywords.",
            })

        results = []
        for m in matches:
            results.append({
                "technique_id": m["id"],
                "technique_name": m["name"],
                "tactic": m["tactic"],
                "url": f"https://attack.mitre.org/techniques/{m['id'].replace('.', '/')}/",
                "detection_guidance": (
                    f"Monitor for {m['name'].lower()} activity. "
                    f"Enable logging for relevant data sources. "
                    f"See https://attack.mitre.org/techniques/{m['id'].replace('.', '/')}/#detection"
                ),
            })

        return json.dumps({"matches": results}, indent=2)

    # ── analyze_pcap ───────────────────────────────────────────────────────

    @registry.register(
        name="analyze_pcap",
        description=(
            "Analyse a PCAP file using tshark. Provide a display filter "
            "(e.g. 'http', 'dns', 'tcp.flags.syn==1', 'ip.dst==10.0.0.1'). "
            "Returns parsed packet summary. Requires tshark to be installed."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "pcap_path": {
                    "type": "string",
                    "description": "Absolute path to the .pcap or .pcapng file.",
                },
                "filter": {
                    "type": "string",
                    "description": "Wireshark/tshark display filter string.",
                    "default": "",
                },
            },
            "required": ["pcap_path"],
        },
        risk=ToolRiskLevel.SAFE,
    )
    async def analyze_pcap(pcap_path: str, filter: str = "") -> str:
        if not shutil.which("tshark"):
            return "[ERROR] tshark not found. Install with: apt install tshark"

        p = Path(pcap_path)
        if not p.exists():
            return f"[ERROR] File not found: {pcap_path}"

        filter_arg = f'-Y "{filter}"' if filter else ""
        cmd = (
            f'tshark -r "{pcap_path}" {filter_arg} '
            f'-T fields -e frame.number -e frame.time_relative '
            f'-e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info '
            f'-E header=y -E separator=, 2>/dev/null | head -200'
        )
        stdout, stderr, rc = await _run(cmd, timeout=60)

        if rc != 0 and not stdout:
            return f"[ERROR] tshark failed: {stderr[:500]}"

        # Also run basic stats
        stats_cmd = f'tshark -r "{pcap_path}" -q -z io,phs 2>/dev/null | head -50'
        stats_out, _, _ = await _run(stats_cmd, timeout=30)

        return f"=== Packet Summary ===\n{stdout}\n\n=== Protocol Hierarchy ===\n{stats_out}"


# ─────────────────────────────────────────────────────────────────────────────
#  Minor utilities
# ─────────────────────────────────────────────────────────────────────────────

def _generate_uuid() -> str:
    import uuid
    return str(uuid.uuid4())


def _today() -> str:
    from datetime import date
    return date.today().isoformat()


def _logic_to_sigma_selection(logic: str) -> str:
    """Convert free-text detection logic into a basic Sigma selection block."""
    lines: list[str] = []
    # Split on ' OR ' to create separate conditions
    parts = re.split(r"\bOR\b", logic, flags=re.IGNORECASE)
    for part in parts:
        part = part.strip()
        # Extract field and value patterns like: FieldName contains "value"
        m = re.match(r"(\w+)\s+(?:contains|equals|starts with|ends with)\s+[\"']?(.+?)[\"']?$",
                     part, re.IGNORECASE)
        if m:
            field, value = m.group(1).strip(), m.group(2).strip().strip("\"'")
            lines.append(f"        {field}|contains: '{value}'")
        else:
            lines.append(f"        # {part}")
    return "\n".join(lines) if lines else "        # TODO: fill in detection fields"
