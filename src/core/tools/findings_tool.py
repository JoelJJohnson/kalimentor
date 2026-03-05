"""Findings tool — structured discovery tracking for the agentic loop.

The LLM calls ``record_finding`` to log significant discoveries (open ports,
credentials, vulnerabilities, misconfigurations, etc.) in a structured format.

Findings are stored in the session's FindingsStore and displayed via the
/findings slash command as a Rich Table.

Finding schema
--------------
category   : str  — e.g. "port", "credential", "vulnerability", "config", "flag"
key        : str  — short label, e.g. "SSH on 22", "admin:admin", "CVE-2024-1234"
value      : str  — detail or evidence
source     : str  — which tool produced it, e.g. "nmap", "nikto", "manual"
severity   : str  — info | low | medium | high | critical  (optional, default info)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .registry import ToolRegistry, ToolRiskLevel


@dataclass
class Finding:
    category: str
    key: str
    value: str
    source: str
    severity: str = "info"


class FindingsStore:
    """In-memory findings list for the current session."""

    def __init__(self) -> None:
        self._findings: list[Finding] = []

    def add(self, finding: Finding) -> None:
        self._findings.append(finding)

    def all(self) -> list[Finding]:
        return list(self._findings)

    def as_table(self) -> "RichTable":
        """Return findings as a Rich Table for display."""
        from rich.table import Table as RichTable

        tbl = RichTable(title="Findings", show_lines=True, expand=False)
        tbl.add_column("Category", style="cyan", width=14)
        tbl.add_column("Severity", width=10)
        tbl.add_column("Key", style="bold", max_width=30)
        tbl.add_column("Value", max_width=50)
        tbl.add_column("Source", style="dim", max_width=16)

        _sev_color = {
            "critical": "bold red",
            "high":     "red",
            "medium":   "yellow",
            "low":      "blue",
            "info":     "dim",
        }

        if not self._findings:
            tbl.add_row("—", "", "", "[dim]No findings yet[/dim]", "")
            return tbl

        # Sort by severity weight descending
        _weight = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        for f in sorted(self._findings, key=lambda x: _weight.get(x.severity, 0), reverse=True):
            sev = f.severity.lower()
            color = _sev_color.get(sev, "white")
            tbl.add_row(
                f.category,
                f"[{color}]{sev}[/{color}]",
                f.key,
                f.value[:48],
                f.source[:14],
            )
        return tbl

    def summary(self) -> str:
        """One-line summary: 'N findings (H high, M medium, …)'"""
        if not self._findings:
            return "0 findings"
        counts: dict[str, int] = {}
        for f in self._findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        order = ["critical", "high", "medium", "low", "info"]
        parts = [f"{counts[s]} {s}" for s in order if s in counts]
        return f"{len(self._findings)} findings ({', '.join(parts)})"

    def to_markdown(self) -> str:
        """Markdown table for /export reports."""
        if not self._findings:
            return "_No findings recorded._"
        lines = [
            "| Category | Severity | Key | Value | Source |",
            "|----------|----------|-----|-------|--------|",
        ]
        for f in self._findings:
            lines.append(
                f"| {f.category} | {f.severity} | {f.key} | {f.value[:60]} | {f.source} |"
            )
        return "\n".join(lines)


# Module-level singleton — replaced per session by the agent
_store = FindingsStore()


def get_findings_store() -> FindingsStore:
    return _store


def set_findings_store(store: FindingsStore) -> None:
    global _store
    _store = store


def register_findings_tool(registry: ToolRegistry) -> None:
    """Register the ``record_finding`` tool into *registry*."""

    @registry.register(
        name="record_finding",
        description=(
            "Record a significant discovery (open port, credential, vulnerability, "
            "misconfiguration, flag, etc.) in structured form for tracking and reporting. "
            "Call this whenever you find something worth preserving."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Finding type: port | service | credential | vulnerability | config | flag | other",
                },
                "key": {
                    "type": "string",
                    "description": "Short label, e.g. 'SSH on 22', 'admin:admin', 'CVE-2024-1234'",
                },
                "value": {
                    "type": "string",
                    "description": "Detail or evidence supporting this finding.",
                },
                "source": {
                    "type": "string",
                    "description": "Tool or method that produced this finding, e.g. 'nmap', 'nikto', 'manual'",
                },
                "severity": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                    "description": "Severity level (default: info).",
                },
            },
            "required": ["category", "key", "value", "source"],
        },
        risk=ToolRiskLevel.SAFE,
    )
    async def record_finding(
        category: str,
        key: str,
        value: str,
        source: str,
        severity: str = "info",
    ) -> str:
        store = get_findings_store()
        f = Finding(
            category=category,
            key=key,
            value=value,
            source=source,
            severity=severity.lower(),
        )
        store.add(f)
        return f"Finding recorded: [{severity.upper()}] {category} — {key}"
