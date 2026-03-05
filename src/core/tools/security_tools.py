"""Security tools — CVE/exploit search, GTFOBins lookup, nmap XML parsing,
tool installation checks.

These tools expose offensive research capabilities to the LLM agent.
"""

from __future__ import annotations

import asyncio
import json
import re
import shlex
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .registry import ToolRegistry, ToolRiskLevel


def register_security_tools(registry: ToolRegistry) -> None:
    """Register all security tools into *registry*."""

    # ── search_cve ─────────────────────────────────────────────────────────

    @registry.register(
        name="search_cve",
        description=(
            "Search for CVEs affecting a service/software, optionally filtered by version. "
            "Queries local searchsploit database. Returns CVE ID, description, CVSS score, "
            "and exploit availability."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Service or software name, e.g. 'OpenSSH', 'Apache httpd'.",
                },
                "version": {
                    "type": "string",
                    "description": "Optional version string, e.g. '7.4'. Narrows results.",
                },
            },
            "required": ["service"],
        },
        risk=ToolRiskLevel.SAFE,
    )
    async def search_cve(service: str, version: str | None = None) -> str:
        query = service
        if version:
            query = f"{service} {version}"

        # Try searchsploit first (local, fast)
        searchsploit_result = await _run_searchsploit(query)

        lines = [f"CVE/Exploit search for: {query}"]
        if searchsploit_result:
            lines.append("\n--- Searchsploit results ---")
            lines.append(searchsploit_result)
        else:
            lines.append("searchsploit: not found or not installed.")

        return "\n".join(lines)

    # ── search_exploit ─────────────────────────────────────────────────────

    @registry.register(
        name="search_exploit",
        description=(
            "Search the local Exploit-DB (via searchsploit) for exploits matching a query. "
            "Returns exploit title, path, and type in structured format."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query, e.g. 'vsftpd 2.3.4' or 'Apache Struts RCE'.",
                },
            },
            "required": ["query"],
        },
        risk=ToolRiskLevel.SAFE,
    )
    async def search_exploit(query: str) -> str:
        result = await _run_searchsploit(query, json_output=True)
        if not result:
            return f"No exploits found for '{query}' (searchsploit may not be installed)."
        return result

    # ── query_gtfobins ─────────────────────────────────────────────────────

    @registry.register(
        name="query_gtfobins",
        description=(
            "Look up a binary on GTFOBins to find privilege escalation, "
            "file read/write, and shell escape vectors."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary": {
                    "type": "string",
                    "description": "Binary name, e.g. 'find', 'vim', 'python3'.",
                },
            },
            "required": ["binary"],
        },
        risk=ToolRiskLevel.SAFE,
    )
    async def query_gtfobins(binary: str) -> str:
        binary = binary.strip().lower()

        # Check local dataset first
        local_result = _check_local_gtfobins(binary)
        if local_result:
            return local_result

        # Fallback: construct the GTFOBins URL and note it for the user
        url = f"https://gtfobins.github.io/gtfobins/{binary}/"
        return (
            f"No local GTFOBins data for '{binary}'.\n"
            f"Check online: {url}\n\n"
            "Tip: Install a local copy with:\n"
            "  git clone https://github.com/GTFOBins/GTFOBins.github.io /opt/gtfobins"
        )

    # ── parse_nmap_xml ─────────────────────────────────────────────────────

    @registry.register(
        name="parse_nmap_xml",
        description=(
            "Parse an nmap XML output file into structured host/port/service data. "
            "Returns hosts with their open ports, services, and versions."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "filepath": {
                    "type": "string",
                    "description": "Path to the nmap XML file (use nmap -oX output.xml).",
                },
            },
            "required": ["filepath"],
        },
        risk=ToolRiskLevel.SAFE,
    )
    async def parse_nmap_xml(filepath: str) -> str:
        p = Path(filepath)
        if not p.exists():
            return f"[ERROR] File not found: {filepath}"
        try:
            tree = ET.parse(str(p))
            root = tree.getroot()
        except ET.ParseError as e:
            return f"[ERROR] Failed to parse XML: {e}"

        results: list[str] = []
        for host in root.findall("host"):
            # IP / hostname
            addr_el = host.find("address[@addrtype='ipv4']")
            addr = addr_el.get("addr", "unknown") if addr_el is not None else "unknown"

            hostname_el = host.find(".//hostname")
            hostname = hostname_el.get("name", "") if hostname_el is not None else ""

            status_el = host.find("status")
            state = status_el.get("state", "unknown") if status_el is not None else "unknown"

            label = f"{addr} ({hostname})" if hostname else addr
            results.append(f"\nHost: {label}  [{state}]")

            # OS detection
            osmatch = host.find(".//osmatch")
            if osmatch is not None:
                results.append(f"  OS: {osmatch.get('name')} ({osmatch.get('accuracy')}% confidence)")

            # Ports
            for port in host.findall(".//port"):
                portid = port.get("portid", "?")
                proto = port.get("protocol", "tcp")
                port_state_el = port.find("state")
                port_state = port_state_el.get("state", "?") if port_state_el is not None else "?"

                service_el = port.find("service")
                if service_el is not None:
                    svc = service_el.get("name", "")
                    product = service_el.get("product", "")
                    version = service_el.get("version", "")
                    extra = service_el.get("extrainfo", "")
                    svc_str = " ".join(filter(None, [svc, product, version, extra]))
                else:
                    svc_str = ""

                results.append(f"  {portid}/{proto}  {port_state:<10}  {svc_str}")

                # NSE scripts
                for script in port.findall("script"):
                    sid = script.get("id", "")
                    output = script.get("output", "").strip().replace("\n", " ")[:120]
                    results.append(f"    |_{sid}: {output}")

        if not results:
            return "No hosts found in nmap XML output."
        return "\n".join(results)

    # ── check_tool_installed ───────────────────────────────────────────────

    @registry.register(
        name="check_tool_installed",
        description="Check if a tool/binary exists in PATH.",
        input_schema={
            "type": "object",
            "properties": {
                "tool_name": {
                    "type": "string",
                    "description": "Tool name, e.g. 'nmap', 'gobuster', 'python3'.",
                },
            },
            "required": ["tool_name"],
        },
        risk=ToolRiskLevel.SAFE,
    )
    async def check_tool_installed(tool_name: str) -> str:
        proc = await asyncio.create_subprocess_shell(
            f"which {shlex.quote(tool_name)}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        path = stdout.decode().strip()
        if proc.returncode == 0 and path:
            return f"[FOUND] {tool_name} → {path}"
        return f"[NOT FOUND] {tool_name} is not in PATH."

    # ── install_tool ───────────────────────────────────────────────────────

    @registry.register(
        name="install_tool",
        description=(
            "Install a tool via apt-get, or clone a GitHub repository. "
            "Pass a package name (e.g. 'nmap') or a full GitHub URL."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "tool_name_or_repo_url": {
                    "type": "string",
                    "description": "Package name for apt install, or https://github.com/... URL for git clone.",
                },
            },
            "required": ["tool_name_or_repo_url"],
        },
        risk=ToolRiskLevel.CONFIRM,
    )
    async def install_tool(tool_name_or_repo_url: str) -> str:
        target = tool_name_or_repo_url.strip()
        if target.startswith("http://") or target.startswith("https://"):
            repo_name = target.rstrip("/").split("/")[-1].removesuffix(".git")
            dest = f"/opt/{repo_name}"
            cmd = f"git clone --depth 1 {shlex.quote(target)} {shlex.quote(dest)}"
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            out = stdout.decode(errors="replace")
            if proc.returncode == 0:
                return f"[OK] Cloned to {dest}\n{out}"
            return f"[ERROR] git clone failed (exit {proc.returncode}):\n{out}"
        else:
            cmd = f"apt-get install -y {shlex.quote(target)}"
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            out = stdout.decode(errors="replace")
            if proc.returncode == 0:
                return f"[OK] Installed {target}\n{out}"
            return f"[ERROR] apt-get failed (exit {proc.returncode}):\n{out}"


# ── Internal helpers ───────────────────────────────────────────────────────────

async def _run_searchsploit(query: str, json_output: bool = False) -> str:
    """Run searchsploit and return parsed output."""
    flags = "--json" if json_output else ""
    cmd = f"searchsploit {flags} {shlex.quote(query)}"
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
    except (asyncio.TimeoutError, FileNotFoundError):
        return ""

    raw = stdout.decode(errors="replace")
    if not raw.strip():
        return ""

    if json_output:
        try:
            data = json.loads(raw)
            exploits = data.get("RESULTS_EXPLOIT", [])
            if not exploits:
                return f"No exploits found for '{query}'."
            lines = [f"{'Title':<60}  {'Path':<40}  Type"]
            lines.append("-" * 110)
            for ex in exploits[:30]:
                title = ex.get("Title", "")[:58]
                path = ex.get("Path", "")[:38]
                etype = ex.get("Type", "")
                lines.append(f"{title:<60}  {path:<40}  {etype}")
            if len(exploits) > 30:
                lines.append(f"... and {len(exploits) - 30} more results.")
            return "\n".join(lines)
        except (json.JSONDecodeError, KeyError):
            return raw[:3000]

    return raw[:3000]


def _check_local_gtfobins(binary: str) -> str:
    """Check known local GTFOBins dataset paths."""
    candidate_dirs = [
        Path("/opt/gtfobins/GTFOBins.github.io/_gtfobins"),
        Path("/opt/GTFOBins.github.io/_gtfobins"),
        Path("/usr/share/gtfobins/_gtfobins"),
    ]
    for d in candidate_dirs:
        yml = d / f"{binary}.md"
        if yml.exists():
            try:
                content = yml.read_text(encoding="utf-8", errors="replace")
                # Strip front-matter and return the markdown body
                parts = content.split("---", 2)
                body = parts[2].strip() if len(parts) >= 3 else content
                return f"GTFOBins — {binary}\n\n{body[:3000]}"
            except Exception:
                pass
    return ""
