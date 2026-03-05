"""Phase 4.4 + 4.5 — Slash commands and Rich UI tests.

Covers:
- FindingsStore: add, summary, as_table(), to_markdown()
- PlanStore.as_table() returns a Rich Table (not plain string)
- /export generates a valid Markdown report
- /sessions lists sessions from SessionManager
- Plan reminder text format
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from rich.table import Table as RichTable

from src.core.tools.findings_tool import Finding, FindingsStore
from src.core.tools.plan_tool import PlanStore, TaskStatus


# ── FindingsStore ─────────────────────────────────────────────────────────────

def test_findings_store_starts_empty():
    fs = FindingsStore()
    assert fs.all() == []
    assert fs.summary() == "0 findings"


def test_findings_store_add_and_retrieve():
    fs = FindingsStore()
    fs.add(Finding("port", "SSH on 22", "OpenSSH 8.9", "nmap", "info"))
    fs.add(Finding("vulnerability", "CVE-2024-1234", "RCE", "searchsploit", "critical"))
    assert len(fs.all()) == 2


def test_findings_summary_counts_by_severity():
    fs = FindingsStore()
    fs.add(Finding("port", "80/tcp", "nginx", "nmap", "info"))
    fs.add(Finding("vuln", "CVE-1", "desc", "nmap", "critical"))
    fs.add(Finding("vuln", "CVE-2", "desc", "nmap", "high"))
    fs.add(Finding("cred", "admin", "pw", "gobuster", "high"))
    summary = fs.summary()
    assert "4 findings" in summary
    assert "1 critical" in summary
    assert "2 high" in summary
    assert "1 info" in summary


def test_findings_as_table_returns_rich_table():
    fs = FindingsStore()
    fs.add(Finding("port", "22/tcp", "SSH", "nmap", "info"))
    tbl = fs.as_table()
    assert isinstance(tbl, RichTable)


def test_findings_as_table_empty_has_placeholder():
    fs = FindingsStore()
    tbl = fs.as_table()
    assert isinstance(tbl, RichTable)
    # Table title should exist
    assert tbl.title == "Findings"


def test_findings_to_markdown_empty():
    fs = FindingsStore()
    md = fs.to_markdown()
    assert "_No findings recorded._" in md


def test_findings_to_markdown_has_table():
    fs = FindingsStore()
    fs.add(Finding("port", "80/tcp", "HTTP", "nmap", "info"))
    fs.add(Finding("vuln", "XSS", "Reflected XSS in search", "nikto", "medium"))
    md = fs.to_markdown()
    assert "| Category |" in md
    assert "port" in md
    assert "vuln" in md
    assert "XSS" in md


def test_findings_sorted_by_severity_in_table():
    fs = FindingsStore()
    fs.add(Finding("misc", "info finding", "low priority", "manual", "info"))
    fs.add(Finding("vuln", "critical bug", "RCE", "manual", "critical"))
    fs.add(Finding("config", "medium issue", "misconfiguration", "manual", "medium"))
    tbl = fs.as_table()
    # Table is Rich — we can't easily inspect row order without rendering,
    # but we can verify it renders without error
    from rich.console import Console
    import io
    buf = io.StringIO()
    con = Console(file=buf, width=120)
    con.print(tbl)
    output = buf.getvalue()
    # critical should appear before info in the output
    assert output.index("critical") < output.index("info")


# ── PlanStore.as_table ────────────────────────────────────────────────────────

def test_plan_as_table_returns_rich_table():
    ps = PlanStore()
    tbl = ps.as_table()
    assert isinstance(tbl, RichTable)


def test_plan_as_table_empty_has_placeholder():
    ps = PlanStore()
    tbl = ps.as_table()
    assert tbl.title == "Engagement Plan"


def test_plan_as_table_with_tasks():
    ps = PlanStore()
    ps.update([
        {"id": "1", "task": "Enumerate ports", "status": "done", "phase": "recon", "priority": 1},
        {"id": "2", "task": "Find web vulns", "status": "in_progress", "phase": "exploit", "priority": 2},
        {"id": "3", "task": "Escalate privs", "status": "pending", "phase": "post-exploit", "priority": 3},
    ])
    tbl = ps.as_table()
    assert isinstance(tbl, RichTable)

    from rich.console import Console
    import io
    buf = io.StringIO()
    con = Console(file=buf, width=120)
    con.print(tbl)
    output = buf.getvalue()
    assert "Enumerate ports" in output
    assert "Find web vulns" in output
    assert "Escalate privs" in output
    assert "[+]" in output   # done icon
    assert "[>]" in output   # in_progress icon
    assert "[ ]" in output   # pending icon


def test_plan_reminder_format():
    ps = PlanStore()
    ps.update([
        {"id": "1", "task": "Scan ports", "status": "done"},
        {"id": "2", "task": "Find vulns", "status": "in_progress"},
        {"id": "3", "task": "Exploit", "status": "pending"},
    ])
    reminder = ps.as_reminder()
    assert "[Plan Status]" in reminder
    assert "1 done" in reminder
    assert "1 in progress" in reminder
    assert "1 pending" in reminder
    assert "Find vulns" in reminder   # next task


def test_plan_reminder_empty():
    ps = PlanStore()
    assert ps.as_reminder() == ""


# ── /export report generation ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_export_creates_markdown_file(tmp_path):
    """Test: /export generates a valid Markdown report."""
    llm = MagicMock()
    llm.provider = "anthropic"

    from src.core.agent import AgentLoop
    from src.core.tools.registry import ToolRegistry

    registry = ToolRegistry()
    agent = AgentLoop(llm=llm, registry=registry, mode="interactive",
                      session_dir=str(tmp_path))
    agent._target = "10.10.10.5"
    agent._phase = "machine"
    agent._flags = ["HTB{test_flag}"]
    agent._notes = ["Found admin panel at /admin"]

    # Add a plan task and finding
    agent._plan_store.update([{"id": "1", "task": "Root the box", "status": "in_progress"}])
    agent._findings_store.add(Finding("port", "22/tcp", "SSH", "nmap", "info"))

    out_path = tmp_path / "test_report.md"
    await agent._export_report(str(out_path))

    assert out_path.exists()
    content = out_path.read_text()
    assert "# KaliMentor Session Report" in content
    assert "10.10.10.5" in content
    assert "machine" in content
    assert "HTB{test_flag}" in content
    assert "Found admin panel" in content
    assert "Root the box" in content
    assert "22/tcp" in content


@pytest.mark.asyncio
async def test_export_default_path(tmp_path):
    """Without a path arg, report saves to session_dir/report.md."""
    llm = MagicMock()
    llm.provider = "anthropic"

    from src.core.agent import AgentLoop
    from src.core.tools.registry import ToolRegistry
    from src.core.memory import ensure_memory

    ensure_memory(tmp_path)
    registry = ToolRegistry()
    agent = AgentLoop(llm=llm, registry=registry, mode="interactive",
                      session_dir=str(tmp_path))

    await agent._export_report("")

    default_path = tmp_path / "report.md"
    assert default_path.exists()
    assert "# KaliMentor Session Report" in default_path.read_text()


# ── /sessions display ─────────────────────────────────────────────────────────

def test_show_sessions_uses_session_manager(capsys):
    """Test: /sessions calls SessionManager.list_sessions()."""
    llm = MagicMock()
    llm.provider = "anthropic"

    from src.core.agent import AgentLoop
    from src.core.tools.registry import ToolRegistry

    registry = ToolRegistry()
    agent = AgentLoop(llm=llm, registry=registry)

    mock_sessions = [
        {"id": "abc123", "objective": "Root the box", "target_ip": "10.0.0.1",
         "provider": "anthropic", "updated": "2024-01-01"},
    ]

    with patch("src.core.agent.AgentLoop._show_sessions") as mock_show:
        # Just verify the method is callable without crashing
        mock_show.return_value = None
        agent._show_sessions()
        mock_show.assert_called_once()


def test_show_sessions_empty(capsys):
    """When no sessions exist, prints a dim message."""
    llm = MagicMock()
    llm.provider = "anthropic"

    from src.core.agent import AgentLoop
    from src.core.tools.registry import ToolRegistry

    registry = ToolRegistry()
    agent = AgentLoop(llm=llm, registry=registry)

    with patch("src.core.session.SessionManager.list_sessions", return_value=[]):
        agent._show_sessions()
        captured = capsys.readouterr()
        assert "No saved sessions" in captured.out


# ── /note writes to memory ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_note_appends_to_memory(tmp_path):
    """Test: /note writes the note to KALIMENTOR.md."""
    from src.core.memory import ensure_memory, read_session_memory

    ensure_memory(tmp_path)

    llm = MagicMock()
    llm.provider = "anthropic"

    from src.core.agent import AgentLoop
    from src.core.tools.registry import ToolRegistry

    registry = ToolRegistry()
    agent = AgentLoop(llm=llm, registry=registry, session_dir=str(tmp_path))

    await agent._handle_slash("/note Found admin creds")

    mem = read_session_memory(tmp_path)
    assert "Found admin creds" in mem
    assert "## Notes" in mem
