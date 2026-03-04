"""Output parser — extracts structured findings from raw tool output."""

from __future__ import annotations

import re

from .models import Finding


class OutputParser:
    """Parse tool output into structured Findings."""

    @staticmethod
    def parse_nmap(output: str, action_id: str = "") -> list[Finding]:
        findings = []
        port_re = re.compile(r"(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)", re.I)
        for m in port_re.finditer(output):
            port, proto, state, svc, ver = m.groups()
            pk = f"{port}/{proto}"
            findings.append(Finding(category="port", key=pk, value=state, source_action_id=action_id, tags=["nmap"]))
            if svc and svc != "unknown":
                findings.append(Finding(category="service", key=pk, value=f"{svc} {ver}".strip(), source_action_id=action_id, tags=["nmap"]))

        for m in re.finditer(r"OS details?:\s*(.+)", output, re.I):
            findings.append(Finding(category="os", key="os_guess", value=m.group(1).strip(), confidence=0.8, source_action_id=action_id, tags=["nmap"]))

        for m in re.finditer(r"\|_?\s*(\S+):\s*(.*)", output):
            findings.append(Finding(category="nse_script", key=m.group(1), value=m.group(2).strip(), source_action_id=action_id, tags=["nmap", "nse"]))

        return findings

    @staticmethod
    def parse_directory_scan(output: str, action_id: str = "") -> list[Finding]:
        findings = []
        for m in re.finditer(r"(/\S+)\s+\(Status:\s*(\d+)\)", output):
            findings.append(Finding(category="directory", key=m.group(1), value=f"HTTP {m.group(2)}", source_action_id=action_id, tags=["web"]))
        for m in re.finditer(r"(\S+)\s+\[Status:\s*(\d+)", output):
            findings.append(Finding(category="directory", key=f"/{m.group(1)}", value=f"HTTP {m.group(2)}", source_action_id=action_id, tags=["web"]))
        return findings

    @staticmethod
    def parse_smb(output: str, action_id: str = "") -> list[Finding]:
        findings = []
        for m in re.finditer(r"(\S+)\s+(Disk|IPC|Printer)\s+(.*)", output):
            findings.append(Finding(category="smb_share", key=m.group(1), value=f"{m.group(2)}: {m.group(3).strip()}", source_action_id=action_id, tags=["smb"]))
        for m in re.finditer(r"user:\[(\S+)\]", output):
            findings.append(Finding(category="user", key=m.group(1), value="enum", source_action_id=action_id, tags=["smb"]))
        return findings

    @staticmethod
    def parse_peas(output: str, action_id: str = "") -> list[Finding]:
        findings = []
        for m in re.finditer(r"-[rwxs-]+ \d .* (/\S+)", output):
            findings.append(Finding(category="suid", key=m.group(1), value="SUID binary", source_action_id=action_id, tags=["privesc"]))
        for m in re.finditer(r"(password|passwd|pwd|credential|secret)\s*[=:]\s*(\S+)", output, re.I):
            findings.append(Finding(category="credential", key=m.group(1), value=m.group(2), confidence=0.6, source_action_id=action_id, tags=["privesc"]))
        for m in re.finditer(r"Linux version (\S+)", output):
            findings.append(Finding(category="kernel", key="kernel_version", value=m.group(1), source_action_id=action_id, tags=["privesc"]))
        return findings

    @staticmethod
    def parse_bloodhound(output: str, action_id: str = "") -> list[Finding]:
        findings = []
        for m in re.finditer(r"Found (\d+) (users|groups|computers|domains)", output, re.I):
            findings.append(Finding(category="ad_objects", key=m.group(2), value=m.group(1), source_action_id=action_id, tags=["ad"]))
        return findings

    @staticmethod
    def parse_generic(output: str, action_id: str = "") -> list[Finding]:
        findings = []
        seen = set()
        for m in re.finditer(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", output):
            ip = m.group(1)
            if ip not in seen and not ip.startswith(("0.", "255.", "127.")):
                seen.add(ip)
                findings.append(Finding(category="ip_address", key=ip, value="discovered", confidence=0.5, source_action_id=action_id))
        for m in re.finditer(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", output):
            findings.append(Finding(category="email", key=m.group(0), value="discovered", source_action_id=action_id))
        for m in re.finditer(r"\b([a-fA-F0-9]{32})\b", output):
            findings.append(Finding(category="hash", key=m.group(1)[:16] + "...", value="MD5/NTLM", confidence=0.4, source_action_id=action_id, tags=["hash"]))
        return findings

    TOOL_PARSERS = {
        "nmap": parse_nmap.__func__,
        "gobuster": parse_directory_scan.__func__,
        "ffuf": parse_directory_scan.__func__,
        "feroxbuster": parse_directory_scan.__func__,
        "dirsearch": parse_directory_scan.__func__,
        "smbclient": parse_smb.__func__,
        "enum4linux": parse_smb.__func__,
        "enum4linux-ng": parse_smb.__func__,
        "linpeas": parse_peas.__func__,
        "winpeas": parse_peas.__func__,
        "bloodhound-python": parse_bloodhound.__func__,
    }

    @classmethod
    def parse(cls, tool_name: str, output: str, action_id: str = "") -> list[Finding]:
        findings = []
        parser = cls.TOOL_PARSERS.get(tool_name.lower())
        if parser:
            findings.extend(parser(output, action_id))
        findings.extend(cls.parse_generic(output, action_id))

        seen = set()
        unique = []
        for f in findings:
            k = (f.category, f.key)
            if k not in seen:
                seen.add(k)
                unique.append(f)
        return unique
