"""Unit tests for individual tools.

Tests run without a real LLM, network, or Kali tools installed.
All filesystem operations use temp directories.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ─────────────────────────────────────────────────────────────────────────────
#  Tool Registry
# ─────────────────────────────────────────────────────────────────────────────

class TestToolRegistry:

    def setup_method(self):
        from src.core.tools.registry import ToolRegistry, ToolRiskLevel
        self.ToolRiskLevel = ToolRiskLevel
        self.registry = ToolRegistry()

    def _reg(self, name: str, risk):
        async def handler(x: str = "") -> str:
            return f"ok:{x}"
        self.registry.register(
            name=name,
            description=f"test {name}",
            input_schema={"type": "object", "properties": {"x": {"type": "string"}}, "required": []},
            risk=risk,
        )(handler)

    def test_register_and_get(self):
        self._reg("alpha", self.ToolRiskLevel.SAFE)
        tool = self.registry.get("alpha")
        assert tool is not None
        assert tool.name == "alpha"

    def test_get_unknown_returns_none(self):
        assert self.registry.get("nonexistent") is None

    def test_list_tools(self):
        self._reg("a", self.ToolRiskLevel.SAFE)
        self._reg("b", self.ToolRiskLevel.CONFIRM)
        names = [t.name for t in self.registry.list_tools()]
        assert "a" in names
        assert "b" in names

    def test_schema_anthropic(self):
        self._reg("read_file", self.ToolRiskLevel.SAFE)
        schemas = self.registry.get_schemas("anthropic")
        assert any(s["name"] == "read_file" for s in schemas)

    def test_schema_openai(self):
        self._reg("bash", self.ToolRiskLevel.CONFIRM)
        schemas = self.registry.get_schemas("openai")
        assert all(s["type"] == "function" for s in schemas)

    def test_schema_gemini(self):
        self._reg("grep_tool", self.ToolRiskLevel.SAFE)
        schemas = self.registry.get_schemas("gemini")
        assert any(s["name"] == "grep_tool" for s in schemas)

    def test_risk_safe_no_confirmation(self):
        self._reg("cat", self.ToolRiskLevel.SAFE)
        assert not self.registry.needs_confirmation("cat", {})

    def test_risk_confirm_needs_confirmation(self):
        self._reg("gobuster", self.ToolRiskLevel.CONFIRM)
        assert self.registry.needs_confirmation("gobuster", {})

    def test_risk_dangerous_needs_confirmation(self):
        self._reg("exploit", self.ToolRiskLevel.DANGEROUS)
        assert self.registry.needs_confirmation("exploit", {})

    def test_bash_dangerous_command_escalates(self):
        self._reg("bash", self.ToolRiskLevel.SAFE)
        assert self.registry.needs_confirmation("bash", {"command": "msfconsole -q"})

    def test_bash_confirm_command_escalates(self):
        self._reg("bash", self.ToolRiskLevel.SAFE)
        assert self.registry.needs_confirmation("bash", {"command": "gobuster dir -u http://target"})

    def test_bash_safe_command_no_confirmation(self):
        self._reg("bash", self.ToolRiskLevel.SAFE)
        assert not self.registry.needs_confirmation("bash", {"command": "cat /etc/hostname"})

    def test_unknown_tool_always_confirms(self):
        assert self.registry.needs_confirmation("unknown_tool", {})

    @pytest.mark.asyncio
    async def test_execute_runs_handler(self):
        self._reg("echo", self.ToolRiskLevel.SAFE)
        result = await self.registry.execute("echo", {"x": "hello"})
        assert result == "ok:hello"

    @pytest.mark.asyncio
    async def test_execute_unknown_raises(self):
        with pytest.raises(KeyError):
            await self.registry.execute("no_such_tool", {})


# ─────────────────────────────────────────────────────────────────────────────
#  File Tools
# ─────────────────────────────────────────────────────────────────────────────

class TestFileTools:

    def setup_method(self):
        from src.core.tools.registry import ToolRegistry
        from src.core.tools.file_tools import register_file_tools
        self.registry = ToolRegistry()
        register_file_tools(self.registry)
        self.tmp = tempfile.mkdtemp()

    @pytest.mark.asyncio
    async def test_write_and_read_file(self):
        path = str(Path(self.tmp) / "test.txt")
        await self.registry.execute("write_file", {"path": path, "content": "hello world"})
        result = await self.registry.execute("read_file", {"path": path})
        assert "hello world" in result

    @pytest.mark.asyncio
    async def test_read_missing_file(self):
        result = await self.registry.execute("read_file", {"path": "/nonexistent/path.txt"})
        assert "error" in result.lower() or "not found" in result.lower() or "no such" in result.lower()

    @pytest.mark.asyncio
    async def test_list_directory(self):
        Path(self.tmp, "a.txt").write_text("a")
        Path(self.tmp, "b.txt").write_text("b")
        result = await self.registry.execute("list_directory", {"path": self.tmp})
        assert "a.txt" in result
        assert "b.txt" in result

    @pytest.mark.asyncio
    async def test_grep_tool_finds_match(self):
        p = Path(self.tmp) / "sample.py"
        p.write_text("def main():\n    password = 'secret'\n    return password\n")
        result = await self.registry.execute("grep_tool", {"pattern": "password", "path": self.tmp})
        assert "password" in result

    @pytest.mark.asyncio
    async def test_search_files_glob(self):
        Path(self.tmp, "exploit.py").write_text("# exploit")
        Path(self.tmp, "notes.txt").write_text("notes")
        result = await self.registry.execute("search_files", {"pattern": "*.py", "path": self.tmp})
        assert "exploit.py" in result

    @pytest.mark.asyncio
    async def test_read_file_line_range(self):
        p = Path(self.tmp) / "lines.txt"
        p.write_text("\n".join(f"content_line_{i}" for i in range(1, 21)))
        result = await self.registry.execute("read_file", {"path": str(p), "line_range": "5-7"})
        assert "content_line_5" in result
        assert "content_line_7" in result
        # Line 1 should not appear (outside range)
        assert "content_line_1 " not in result and result.count("content_line_1") <= 1  # only in line 15 etc


# ─────────────────────────────────────────────────────────────────────────────
#  Plan Tool
# ─────────────────────────────────────────────────────────────────────────────

class TestPlanTool:

    def setup_method(self):
        from src.core.tools.registry import ToolRegistry
        from src.core.tools.plan_tool import register_plan_tool, set_plan_store, PlanStore
        self.registry = ToolRegistry()
        register_plan_tool(self.registry)
        set_plan_store(PlanStore())

    @pytest.mark.asyncio
    async def test_update_and_retrieve_plan(self):
        # priority is an int (1=highest)
        tasks = [
            {"id": "1", "task": "Nmap scan", "status": "done", "phase": "recon", "priority": 1},
            {"id": "2", "task": "Gobuster enum", "status": "pending", "phase": "recon", "priority": 2},
        ]
        result = await self.registry.execute("update_plan", {"tasks": tasks})
        assert "Nmap" in result or "plan" in result.lower() or "Gobuster" in result

    @pytest.mark.asyncio
    async def test_plan_status_counts(self):
        from src.core.tools.plan_tool import get_plan_store
        tasks = [
            {"id": "1", "task": "A", "status": "done", "phase": "recon", "priority": 1},
            {"id": "2", "task": "B", "status": "in_progress", "phase": "recon", "priority": 1},
            {"id": "3", "task": "C", "status": "pending", "phase": "exploit", "priority": 2},
        ]
        await self.registry.execute("update_plan", {"tasks": tasks})
        store = get_plan_store()
        all_tasks = list(store._tasks.values())
        statuses = [t.status.value for t in all_tasks]
        assert statuses.count("done") == 1
        assert statuses.count("in_progress") == 1
        assert statuses.count("pending") == 1


# ─────────────────────────────────────────────────────────────────────────────
#  Memory Tool
# ─────────────────────────────────────────────────────────────────────────────

class TestMemoryTool:

    def setup_method(self):
        from src.core.tools.registry import ToolRegistry
        from src.core.tools.memory_tool import register_memory_tools
        self.tmp = tempfile.mkdtemp()
        self.registry = ToolRegistry()
        register_memory_tools(self.registry, session_dir=self.tmp)

    @pytest.mark.asyncio
    async def test_write_and_read_memory(self):
        content = "## Credentials\n- admin:password123\n"
        await self.registry.execute("write_memory", {"content": content})
        result = await self.registry.execute("read_memory", {})
        assert "admin:password123" in result

    @pytest.mark.asyncio
    async def test_read_memory_empty_session(self):
        result = await self.registry.execute("read_memory", {})
        # Should return template or empty string, not crash
        assert isinstance(result, str)


# ─────────────────────────────────────────────────────────────────────────────
#  Findings Tool
# ─────────────────────────────────────────────────────────────────────────────

class TestFindingsTool:

    def setup_method(self):
        from src.core.tools.registry import ToolRegistry
        from src.core.tools.findings_tool import register_findings_tool, set_findings_store, FindingsStore
        self.registry = ToolRegistry()
        register_findings_tool(self.registry)
        set_findings_store(FindingsStore())

    @pytest.mark.asyncio
    async def test_record_finding_returns_confirmation(self):
        result = await self.registry.execute("record_finding", {
            "category": "credentials",
            "key": "SSH key",
            "value": "Found RSA key at /home/user/.ssh/id_rsa",
            "source": "read_file",
            "severity": "critical",
        })
        # Should return some confirmation string
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_multiple_findings_stored(self):
        from src.core.tools.findings_tool import get_findings_store
        for i in range(3):
            await self.registry.execute("record_finding", {
                "category": "ports",
                "key": f"port_{i}",
                "value": f"Open port {i}",
                "source": "bash",
                "severity": "info",
            })
        store = get_findings_store()
        assert len(store.all()) == 3
