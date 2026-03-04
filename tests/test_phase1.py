"""Phase 1 test suite — verifies the tool_use agentic loop architecture.

Covers:
  1.1  Tool Registry
  1.2  Core Tools (bash, file, security, plan, memory)
  1.3  LLM backends — response parsing (mocked HTTP)
  1.4  Agent loop — mode gates, system prompt, message history
  1.5  System prompts
  1.6  CLI wiring (import + argument parsing)

Tests run without a real LLM, network, or Kali tools installed.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ─────────────────────────────────────────────────────────────────────────────
#  1.1 — Tool Registry
# ─────────────────────────────────────────────────────────────────────────────

class TestToolRegistry:

    def setup_method(self):
        from src.core.tools.registry import ToolRegistry, ToolRiskLevel
        self.ToolRiskLevel = ToolRiskLevel
        self.registry = ToolRegistry()

    def _register_dummy(self, name: str, risk):
        async def handler(x: str = "default") -> str:
            return f"result:{x}"
        self.registry.register(
            name=name,
            description=f"Dummy {name}",
            input_schema={"type": "object", "properties": {"x": {"type": "string"}}, "required": []},
            risk=risk,
        )(handler)

    def test_register_and_retrieve(self):
        self._register_dummy("mytool", self.ToolRiskLevel.SAFE)
        tool = self.registry.get("mytool")
        assert tool is not None
        assert tool.name == "mytool"

    def test_list_tools(self):
        self._register_dummy("a", self.ToolRiskLevel.SAFE)
        self._register_dummy("b", self.ToolRiskLevel.CONFIRM)
        names = [t.name for t in self.registry.list_tools()]
        assert "a" in names and "b" in names

    def test_get_schemas_anthropic(self):
        self._register_dummy("bash", self.ToolRiskLevel.SAFE)
        schemas = self.registry.get_schemas("anthropic")
        assert schemas[0]["name"] == "bash"
        assert "input_schema" in schemas[0]

    def test_get_schemas_openai(self):
        self._register_dummy("bash", self.ToolRiskLevel.SAFE)
        schemas = self.registry.get_schemas("openai")
        assert schemas[0]["type"] == "function"
        assert "function" in schemas[0]

    def test_get_schemas_gemini(self):
        self._register_dummy("bash", self.ToolRiskLevel.SAFE)
        schemas = self.registry.get_schemas("gemini")
        assert "parameters" in schemas[0]

    def test_risk_check_safe(self):
        self._register_dummy("ls_tool", self.ToolRiskLevel.SAFE)
        assert not self.registry.risk_check("ls_tool", {})

    def test_risk_check_confirm(self):
        self._register_dummy("nikto", self.ToolRiskLevel.CONFIRM)
        assert self.registry.risk_check("nikto", {})

    def test_risk_check_dangerous(self):
        self._register_dummy("exploit", self.ToolRiskLevel.DANGEROUS)
        assert self.registry.risk_check("exploit", {})

    def test_risk_check_unknown_tool(self):
        assert self.registry.risk_check("nonexistent", {})

    def test_bash_dynamic_risk_escalation_dangerous(self):
        # Register bash as SAFE; dangerous command should escalate
        self._register_dummy("bash", self.ToolRiskLevel.SAFE)
        # Rename to bash so the pattern matching fires
        self.registry._tools["bash"] = self.registry._tools.pop(list(self.registry._tools.keys())[-1])
        from src.core.tools.registry import Tool, ToolRiskLevel
        async def dummy(command: str) -> str: return ""
        from src.core.tools.registry import ToolRiskLevel
        tool = self.registry._tools.get("bash")
        if tool:
            tool.risk_level = ToolRiskLevel.SAFE
        assert self.registry.risk_check("bash", {"command": "msfconsole"})

    def test_bash_dynamic_risk_escalation_confirm(self):
        from src.core.tools.registry import Tool, ToolRiskLevel
        async def dummy(command: str) -> str: return ""
        self.registry._tools["bash"] = Tool(
            name="bash", description="", input_schema={},
            handler=dummy, risk_level=ToolRiskLevel.SAFE,
        )
        assert self.registry.risk_check("bash", {"command": "gobuster dir -u http://10.0.0.1"})

    def test_bash_safe_command_no_confirm(self):
        from src.core.tools.registry import Tool, ToolRiskLevel
        async def dummy(command: str) -> str: return ""
        self.registry._tools["bash"] = Tool(
            name="bash", description="", input_schema={},
            handler=dummy, risk_level=ToolRiskLevel.SAFE,
        )
        assert not self.registry.risk_check("bash", {"command": "ls -la"})

    @pytest.mark.asyncio
    async def test_execute_calls_handler(self):
        results = []
        async def handler(x: str = "hi") -> str:
            results.append(x)
            return f"got:{x}"
        from src.core.tools.registry import Tool, ToolRiskLevel
        self.registry._tools["echo"] = Tool(
            name="echo", description="", input_schema={},
            handler=handler, risk_level=ToolRiskLevel.SAFE,
        )
        out = await self.registry.execute("echo", {"x": "world"})
        assert out == "got:world"
        assert results == ["world"]

    @pytest.mark.asyncio
    async def test_execute_unknown_tool_raises(self):
        with pytest.raises(KeyError):
            await self.registry.execute("ghost", {})


# ─────────────────────────────────────────────────────────────────────────────
#  1.2 — Core Tools
# ─────────────────────────────────────────────────────────────────────────────

class TestFileTools:

    def setup_method(self):
        from src.core.tools.registry import ToolRegistry
        from src.core.tools.file_tools import register_file_tools
        self.registry = ToolRegistry()
        register_file_tools(self.registry)

    @pytest.mark.asyncio
    async def test_read_file(self, tmp_path):
        f = tmp_path / "hello.txt"
        f.write_text("line1\nline2\nline3")
        result = await self.registry.execute("read_file", {"path": str(f)})
        assert "line1" in result
        assert "line2" in result

    @pytest.mark.asyncio
    async def test_read_file_line_range(self, tmp_path):
        f = tmp_path / "lines.txt"
        f.write_text("\n".join(f"L{i}" for i in range(1, 11)))
        result = await self.registry.execute("read_file", {"path": str(f), "line_range": "3-5"})
        assert "L3" in result
        assert "L5" in result
        assert "L1" not in result

    @pytest.mark.asyncio
    async def test_read_file_not_found(self):
        result = await self.registry.execute("read_file", {"path": "/nonexistent/path.txt"})
        assert "[ERROR]" in result

    @pytest.mark.asyncio
    async def test_write_file(self, tmp_path):
        f = tmp_path / "out.txt"
        result = await self.registry.execute("write_file", {"path": str(f), "content": "hello"})
        assert "[OK]" in result
        assert f.read_text() == "hello"

    @pytest.mark.asyncio
    async def test_list_directory(self, tmp_path):
        (tmp_path / "a.txt").write_text("x")
        (tmp_path / "sub").mkdir()
        result = await self.registry.execute("list_directory", {"path": str(tmp_path)})
        assert "a.txt" in result
        assert "sub" in result

    @pytest.mark.asyncio
    async def test_search_files_glob(self, tmp_path):
        (tmp_path / "foo.py").write_text("x")
        (tmp_path / "bar.txt").write_text("x")
        result = await self.registry.execute("search_files", {"pattern": "*.py", "path": str(tmp_path)})
        assert "foo.py" in result
        assert "bar.txt" not in result

    @pytest.mark.asyncio
    async def test_grep_tool(self, tmp_path):
        (tmp_path / "src.py").write_text("def hello():\n    pass\n")
        result = await self.registry.execute("grep_tool", {"pattern": "def hello", "path": str(tmp_path)})
        assert "def hello" in result


class TestPlanTool:

    def setup_method(self):
        from src.core.tools.registry import ToolRegistry
        from src.core.tools.plan_tool import register_plan_tool, PlanStore, set_plan_store
        self.registry = ToolRegistry()
        self.store = PlanStore()
        set_plan_store(self.store)
        register_plan_tool(self.registry)

    @pytest.mark.asyncio
    async def test_update_plan_creates_tasks(self):
        await self.registry.execute("update_plan", {"tasks": [
            {"id": "1", "task": "Port scan", "status": "pending", "phase": "recon", "priority": 1},
            {"id": "2", "task": "Web enum", "status": "pending", "phase": "enum", "priority": 2},
        ]})
        table = self.store.as_table()
        assert "Port scan" in table
        assert "Web enum" in table

    @pytest.mark.asyncio
    async def test_update_plan_upserts_status(self):
        await self.registry.execute("update_plan", {"tasks": [
            {"id": "1", "task": "Port scan", "status": "pending"},
        ]})
        await self.registry.execute("update_plan", {"tasks": [
            {"id": "1", "task": "Port scan", "status": "done"},
        ]})
        table = self.store.as_table()
        assert "Port scan" in table

    def test_reminder_format(self):
        self.store.update([
            {"id": "1", "task": "Recon", "status": "done", "phase": "recon", "priority": 1},
            {"id": "2", "task": "Enum", "status": "in_progress", "phase": "enum", "priority": 2},
            {"id": "3", "task": "Exploit", "status": "pending", "phase": "exploit", "priority": 3},
        ])
        reminder = self.store.as_reminder()
        assert "Plan Status" in reminder
        assert "1/3" in reminder

    def test_empty_store_gives_empty_reminder(self):
        from src.core.tools.plan_tool import PlanStore
        s = PlanStore()
        assert s.as_reminder() == ""


class TestMemoryTool:

    @pytest.mark.asyncio
    async def test_write_and_read_memory(self, tmp_path):
        from src.core.tools.registry import ToolRegistry
        from src.core.tools.memory_tool import register_memory_tools
        registry = ToolRegistry()
        register_memory_tools(registry, session_dir=str(tmp_path))

        await registry.execute("write_memory", {"content": "# KaliMentor\n\n## Creds\nadmin:admin"})
        result = await registry.execute("read_memory", {})
        assert "admin:admin" in result

    @pytest.mark.asyncio
    async def test_memory_template_created_on_first_read(self, tmp_path):
        from src.core.tools.registry import ToolRegistry
        from src.core.tools.memory_tool import register_memory_tools
        registry = ToolRegistry()
        register_memory_tools(registry, session_dir=str(tmp_path))

        result = await registry.execute("read_memory", {})
        assert "KaliMentor Session Memory" in result


class TestBashToolRegistration:

    def test_registers_bash(self, tmp_path):
        from src.core.tools.registry import ToolRegistry
        from src.core.tools.bash_tool import register_bash_tool
        registry = ToolRegistry()
        register_bash_tool(registry, working_dir=str(tmp_path))
        assert registry.get("bash") is not None

    def test_bash_risk_is_safe(self, tmp_path):
        from src.core.tools.registry import ToolRegistry, ToolRiskLevel
        from src.core.tools.bash_tool import register_bash_tool
        registry = ToolRegistry()
        register_bash_tool(registry, working_dir=str(tmp_path))
        tool = registry.get("bash")
        assert tool.risk_level == ToolRiskLevel.SAFE

    def test_bash_blocked_command(self, tmp_path):
        from src.core.tools.bash_tool import _is_blocked
        blocked, reason = _is_blocked("rm -rf /")
        assert blocked
        assert "Blocked" in reason

    def test_bash_safe_command_not_blocked(self, tmp_path):
        from src.core.tools.bash_tool import _is_blocked
        blocked, _ = _is_blocked("ls -la /tmp")
        assert not blocked

    def test_bash_output_truncation(self):
        from src.core.tools.bash_tool import _truncate
        long = "x" * 50_000
        result = _truncate(long, limit=30_000)
        assert "truncated" in result
        assert len(result) < 35_000


class TestSecurityToolsRegistration:

    def test_all_tools_registered(self):
        from src.core.tools.registry import ToolRegistry
        from src.core.tools.security_tools import register_security_tools
        registry = ToolRegistry()
        register_security_tools(registry)
        expected = {
            "search_cve", "search_exploit", "query_gtfobins",
            "parse_nmap_xml", "check_tool_installed", "install_tool",
        }
        registered = {t.name for t in registry.list_tools()}
        assert expected == registered

    @pytest.mark.asyncio
    async def test_parse_nmap_xml(self, tmp_path):
        from src.core.tools.registry import ToolRegistry
        from src.core.tools.security_tools import register_security_tools
        registry = ToolRegistry()
        register_security_tools(registry)

        xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.10.10.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.41"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.4"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        f = tmp_path / "scan.xml"
        f.write_text(xml)
        result = await registry.execute("parse_nmap_xml", {"filepath": str(f)})
        assert "10.10.10.1" in result
        assert "80/tcp" in result
        assert "Apache httpd" in result
        assert "22/tcp" in result

    @pytest.mark.asyncio
    async def test_parse_nmap_xml_missing_file(self, tmp_path):
        from src.core.tools.registry import ToolRegistry
        from src.core.tools.security_tools import register_security_tools
        registry = ToolRegistry()
        register_security_tools(registry)
        result = await registry.execute("parse_nmap_xml", {"filepath": "/tmp/ghost.xml"})
        assert "[ERROR]" in result


# ─────────────────────────────────────────────────────────────────────────────
#  1.3 — LLM Response Parsing
# ─────────────────────────────────────────────────────────────────────────────

class TestLLMResponseTypes:

    def test_toolcall_dataclass(self):
        from src.core.llm import ToolCall
        tc = ToolCall(id="abc123", name="bash", input={"command": "ls"})
        assert tc.id == "abc123"
        assert tc.name == "bash"
        assert tc.input == {"command": "ls"}

    def test_llmresponse_dataclass(self):
        from src.core.llm import LLMResponse, ToolCall
        tc = ToolCall(id="x", name="bash", input={})
        r = LLMResponse(text="hello", tool_calls=[tc], stop_reason="tool_use", raw={})
        assert r.text == "hello"
        assert len(r.tool_calls) == 1
        assert r.stop_reason == "tool_use"

    def test_parse_openai_response_text_only(self):
        from src.core.llm import _parse_openai_response
        data = {
            "choices": [{
                "message": {"role": "assistant", "content": "Hello world", "tool_calls": None},
                "finish_reason": "stop",
            }]
        }
        r = _parse_openai_response(data)
        assert r.text == "Hello world"
        assert r.tool_calls == []
        assert r.stop_reason == "end_turn"

    def test_parse_openai_response_tool_call(self):
        from src.core.llm import _parse_openai_response
        data = {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": "call_abc",
                        "function": {
                            "name": "bash",
                            "arguments": json.dumps({"command": "nmap -sV 10.0.0.1"}),
                        },
                    }],
                },
                "finish_reason": "tool_calls",
            }]
        }
        r = _parse_openai_response(data)
        assert len(r.tool_calls) == 1
        assert r.tool_calls[0].name == "bash"
        assert r.tool_calls[0].input["command"] == "nmap -sV 10.0.0.1"
        assert r.stop_reason == "tool_use"

    def test_anthropic_message_builders(self):
        from src.core.llm import (
            LLMResponse, ToolCall,
            user_message, assistant_message, tool_result_message,
        )
        um = user_message("hello")
        assert um == {"role": "user", "content": "hello"}

        tc = ToolCall(id="t1", name="bash", input={"command": "ls"})
        resp = LLMResponse(text="Running ls", tool_calls=[tc], stop_reason="tool_use", raw={})
        am = assistant_message(resp)
        assert am["role"] == "assistant"
        blocks = am["content"]
        assert any(b.get("type") == "text" for b in blocks)
        assert any(b.get("type") == "tool_use" for b in blocks)

        tr = tool_result_message([{"tool_use_id": "t1", "content": "output"}])
        assert tr["role"] == "user"
        assert tr["content"][0]["type"] == "tool_result"
        assert tr["content"][0]["tool_use_id"] == "t1"

    def test_context_window_sizes(self):
        from src.core.llm import CONTEXT_WINDOWS
        assert CONTEXT_WINDOWS["anthropic"] == 200_000
        assert CONTEXT_WINDOWS["gemini"] == 1_000_000
        assert CONTEXT_WINDOWS["deepseek"] == 128_000

    def test_ollama_tool_capability_detection(self):
        from src.core.llm import OllamaBackend
        assert OllamaBackend(model="llama3.1")._supports_tools()
        assert OllamaBackend(model="qwen2.5:14b")._supports_tools()
        assert not OllamaBackend(model="llama2")._supports_tools()
        assert not OllamaBackend(model="mistral")._supports_tools()

    def test_create_backend_factory(self):
        from src.core.llm import create_backend, OllamaBackend
        b = create_backend("ollama", model="llama3.1")
        assert isinstance(b, OllamaBackend)
        assert b.model == "llama3.1"

    def test_create_backend_unknown_raises(self):
        from src.core.llm import create_backend
        with pytest.raises(ValueError, match="Unknown provider"):
            create_backend("grok")


# ─────────────────────────────────────────────────────────────────────────────
#  1.4 — Agent Loop
# ─────────────────────────────────────────────────────────────────────────────

class TestAgentLoopModes:
    """Test mode-based risk gating without a real LLM."""

    def _make_agent(self, mode: str, tmp_path):
        from src.core.tools.registry import ToolRegistry
        from src.core.tools.plan_tool import PlanStore, set_plan_store
        from src.core.llm import OllamaBackend
        from src.core.agent import AgentLoop
        r = ToolRegistry()
        set_plan_store(PlanStore())
        llm = OllamaBackend()
        return AgentLoop(llm=llm, registry=r, system="test", mode=mode, session_dir=str(tmp_path))

    def test_interactive_safe_no_confirm(self, tmp_path):
        from src.core.tools.registry import ToolRiskLevel
        agent = self._make_agent("interactive", tmp_path)
        assert not agent._mode_requires_confirm(ToolRiskLevel.SAFE)

    def test_interactive_confirm_needs_confirm(self, tmp_path):
        from src.core.tools.registry import ToolRiskLevel
        agent = self._make_agent("interactive", tmp_path)
        assert agent._mode_requires_confirm(ToolRiskLevel.CONFIRM)

    def test_interactive_dangerous_needs_confirm(self, tmp_path):
        from src.core.tools.registry import ToolRiskLevel
        agent = self._make_agent("interactive", tmp_path)
        assert agent._mode_requires_confirm(ToolRiskLevel.DANGEROUS)

    def test_autonomous_confirm_no_confirm(self, tmp_path):
        from src.core.tools.registry import ToolRiskLevel
        agent = self._make_agent("autonomous", tmp_path)
        assert not agent._mode_requires_confirm(ToolRiskLevel.CONFIRM)

    def test_autonomous_dangerous_needs_confirm(self, tmp_path):
        from src.core.tools.registry import ToolRiskLevel
        agent = self._make_agent("autonomous", tmp_path)
        assert agent._mode_requires_confirm(ToolRiskLevel.DANGEROUS)

    def test_yolo_dangerous_no_confirm(self, tmp_path):
        from src.core.tools.registry import ToolRiskLevel
        agent = self._make_agent("yolo", tmp_path)
        assert not agent._mode_requires_confirm(ToolRiskLevel.DANGEROUS)

    def test_socratic_dangerous_needs_confirm(self, tmp_path):
        from src.core.tools.registry import ToolRiskLevel
        agent = self._make_agent("socratic", tmp_path)
        assert agent._mode_requires_confirm(ToolRiskLevel.DANGEROUS)


class TestAgentLoopSystemPrompt:

    def _make_agent(self, mode: str, tmp_path):
        from src.core.tools.registry import ToolRegistry
        from src.core.tools.plan_tool import PlanStore, set_plan_store
        from src.core.llm import OllamaBackend
        from src.core.agent import AgentLoop
        set_plan_store(PlanStore())
        return AgentLoop(
            llm=OllamaBackend(), registry=ToolRegistry(),
            system="BASE SYSTEM", mode=mode, session_dir=str(tmp_path),
        )

    def test_base_system_included(self, tmp_path):
        agent = self._make_agent("interactive", tmp_path)
        assert "BASE SYSTEM" in agent._build_system()

    def test_plan_reminder_injected(self, tmp_path):
        from src.core.tools.plan_tool import PlanStore, set_plan_store
        from src.core.tools.registry import ToolRegistry
        from src.core.llm import OllamaBackend
        from src.core.agent import AgentLoop
        # Set populated store BEFORE creating agent (don't use _make_agent which resets it)
        store = PlanStore()
        store.update([{"id": "1", "task": "Recon", "status": "in_progress", "phase": "recon", "priority": 1}])
        set_plan_store(store)
        agent = AgentLoop(
            llm=OllamaBackend(), registry=ToolRegistry(),
            system="BASE SYSTEM", mode="interactive", session_dir=str(tmp_path),
        )
        assert "Plan Status" in agent._build_system()

    def test_socratic_note_appended(self, tmp_path):
        agent = self._make_agent("socratic", tmp_path)
        assert "Socratic mode" in agent._build_system()

    def test_socratic_note_absent_in_interactive(self, tmp_path):
        agent = self._make_agent("interactive", tmp_path)
        assert "Socratic mode" not in agent._build_system()


class TestAgentLoopWithMockedLLM:
    """Test the full run() cycle with a mock LLM that returns predefined responses."""

    @pytest.mark.asyncio
    async def test_text_only_response_breaks_loop(self, tmp_path):
        """LLM returns text with no tool calls → loop exits, returns text."""
        from src.core.tools.registry import ToolRegistry
        from src.core.tools.plan_tool import PlanStore, set_plan_store
        from src.core.llm import LLMResponse
        from src.core.agent import AgentLoop

        set_plan_store(PlanStore())
        registry = ToolRegistry()

        mock_llm = AsyncMock()
        del mock_llm.stream_message
        mock_llm.provider = "anthropic"
        mock_llm.create_message = AsyncMock(return_value=LLMResponse(
            text="I found the answer.", tool_calls=[], stop_reason="end_turn", raw={},
        ))

        agent = AgentLoop(llm=mock_llm, registry=registry, system="", mode="yolo", session_dir=str(tmp_path))
        result = await agent.run("what is 2+2?")
        assert result == "I found the answer."
        assert mock_llm.create_message.call_count == 1

    @pytest.mark.asyncio
    async def test_tool_call_then_text_response(self, tmp_path):
        """LLM calls a tool, gets result, then returns text → 2 LLM calls."""
        from src.core.tools.registry import ToolRegistry, Tool, ToolRiskLevel
        from src.core.tools.plan_tool import PlanStore, set_plan_store
        from src.core.llm import LLMResponse, ToolCall
        from src.core.agent import AgentLoop

        set_plan_store(PlanStore())
        registry = ToolRegistry()

        # Register a simple tool
        async def my_tool(query: str) -> str:
            return f"result for {query}"
        registry._tools["my_tool"] = Tool(
            name="my_tool", description="test", input_schema={},
            handler=my_tool, risk_level=ToolRiskLevel.SAFE,
        )

        call_count = 0
        async def fake_create_message(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return LLMResponse(
                    text="",
                    tool_calls=[ToolCall(id="tc1", name="my_tool", input={"query": "ports"})],
                    stop_reason="tool_use",
                    raw={},
                )
            else:
                return LLMResponse(text="Done.", tool_calls=[], stop_reason="end_turn", raw={})

        mock_llm = MagicMock()
        del mock_llm.stream_message
        mock_llm.provider = "anthropic"
        mock_llm.create_message = fake_create_message

        agent = AgentLoop(llm=mock_llm, registry=registry, system="", mode="yolo", session_dir=str(tmp_path))
        result = await agent.run("scan the target")

        assert result == "Done."
        assert call_count == 2
        # Tool result should appear in message history
        roles = [m["role"] for m in agent._messages]
        assert roles.count("user") == 2   # original + tool_result
        assert roles.count("assistant") == 2

    @pytest.mark.asyncio
    async def test_user_declined_tool_returns_declined_message(self, tmp_path):
        """In interactive mode, declining a CONFIRM tool returns declined message to LLM."""
        from src.core.tools.registry import ToolRegistry, Tool, ToolRiskLevel
        from src.core.tools.plan_tool import PlanStore, set_plan_store
        from src.core.llm import LLMResponse, ToolCall
        from src.core.agent import AgentLoop

        set_plan_store(PlanStore())
        registry = ToolRegistry()

        async def risky_tool() -> str:
            return "should not run"
        registry._tools["risky"] = Tool(
            name="risky", description="risky", input_schema={},
            handler=risky_tool, risk_level=ToolRiskLevel.CONFIRM,
        )

        call_count = 0
        async def fake_create_message(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return LLMResponse(
                    text="",
                    tool_calls=[ToolCall(id="tc1", name="risky", input={})],
                    stop_reason="tool_use",
                    raw={},
                )
            return LLMResponse(text="OK, skipping.", tool_calls=[], stop_reason="end_turn", raw={})

        mock_llm = MagicMock()
        del mock_llm.stream_message
        mock_llm.provider = "anthropic"
        mock_llm.create_message = fake_create_message

        agent = AgentLoop(llm=mock_llm, registry=registry, system="", mode="interactive", session_dir=str(tmp_path))
        # Patch confirmation to always return False (user declines)
        agent._ask_confirmation = AsyncMock(return_value=False)

        result = await agent.run("do something risky")
        assert result == "OK, skipping."
        # Tool result in history should be the declined message
        tool_result_msg = agent._messages[2]  # user message with tool_result
        assert "declined" in tool_result_msg["content"][0]["content"].lower()


# ─────────────────────────────────────────────────────────────────────────────
#  1.5 — System Prompts
# ─────────────────────────────────────────────────────────────────────────────

class TestPrompts:

    def test_offensive_prompt_has_required_sections(self):
        from src.core.prompts import OFFENSIVE_SYSTEM_PROMPT
        for keyword in ["bash", "update_plan", "write_memory", "Reconnaissance", "Safety"]:
            assert keyword in OFFENSIVE_SYSTEM_PROMPT, f"Missing: {keyword}"

    def test_defender_prompt_has_required_sections(self):
        from src.core.prompts import DEFENDER_SYSTEM_PROMPT
        for keyword in ["MITRE", "Timeline", "Sigma", "bash"]:
            assert keyword in DEFENDER_SYSTEM_PROMPT, f"Missing: {keyword}"

    def test_hardener_prompt_has_required_sections(self):
        from src.core.prompts import HARDENER_SYSTEM_PROMPT
        for keyword in ["Benchmark", "SSH", "CIS", "NIST"]:
            assert keyword in HARDENER_SYSTEM_PROMPT, f"Missing: {keyword}"

    def test_hunter_prompt_has_required_sections(self):
        from src.core.prompts import HUNTER_SYSTEM_PROMPT
        for keyword in ["Hypothesis", "ATT&CK", "Beaconing"]:
            assert keyword in HUNTER_SYSTEM_PROMPT, f"Missing: {keyword}"

    def test_build_system_prompt_offensive_with_context(self):
        from src.core.prompts import build_system_prompt
        p = build_system_prompt(
            mode="offensive",
            target="10.10.10.1",
            objective="Get root",
            challenge_type="web",
        )
        assert "10.10.10.1" in p
        assert "Get root" in p
        assert "web enumeration" in p

    def test_build_system_prompt_defensive_modes(self):
        from src.core.prompts import build_system_prompt
        for mode in ("defend", "harden", "hunt"):
            p = build_system_prompt(mode=mode, target="192.168.1.1")
            assert "192.168.1.1" in p

    def test_build_subagent_prompt_recon(self):
        from src.core.prompts import build_subagent_prompt
        p = build_subagent_prompt("recon", "Scan 10.10.10.1 for open ports")
        assert "10.10.10.1" in p
        assert "read-only" in p

    def test_build_subagent_prompt_research(self):
        from src.core.prompts import build_subagent_prompt
        p = build_subagent_prompt("research", "OpenSSH 7.4 CVEs")
        assert "OpenSSH 7.4" in p

    def test_recon_agent_only_safe_tools(self):
        from src.core.prompts import RECON_AGENT_PROMPT
        # Should mention safe tools only
        assert "nmap" in RECON_AGENT_PROMPT
        # Should explicitly forbid intrusive tools
        assert "gobuster" in RECON_AGENT_PROMPT  # mentioned as NOT allowed
        assert "Do NOT run" in RECON_AGENT_PROMPT


# ─────────────────────────────────────────────────────────────────────────────
#  1.6 — CLI wiring (import + structure)
# ─────────────────────────────────────────────────────────────────────────────

class TestCLIStructure:

    def test_cli_imports(self):
        from src.cli import app
        assert app is not None

    def test_cli_has_required_commands(self):
        from src.cli import app
        # Typer infers command names from callback function names when name=None
        callback_names = {
            cmd.callback.__name__
            for cmd in app.registered_commands
            if cmd.callback
        }
        assert "start" in callback_names
        assert "resume" in callback_names
        assert "sessions" in callback_names
        assert "export" in callback_names
        assert "providers" in callback_names

    def test_build_registry_returns_all_tools(self, tmp_path):
        from src.cli import _build_registry
        registry = _build_registry(str(tmp_path), "machine")
        names = {t.name for t in registry.list_tools()}
        expected = {
            "bash", "read_file", "write_file", "list_directory",
            "search_files", "grep_tool", "search_cve", "search_exploit",
            "query_gtfobins", "parse_nmap_xml", "check_tool_installed",
            "install_tool", "update_plan", "read_memory", "write_memory",
        }
        assert expected == names

    def test_session_creation_and_load(self, tmp_path, monkeypatch):
        """SessionManager.new() creates a session that can be loaded."""
        from src.core.session import SessionManager, SESSIONS_DIR
        monkeypatch.setattr("src.core.session.SESSIONS_DIR", tmp_path)
        tmp_path.mkdir(parents=True, exist_ok=True)

        mgr = SessionManager.new(
            objective="Test",
            target_ip="10.10.10.1",
            challenge_type="machine",
            mode="interactive",
            llm_provider="ollama",
        )
        sid = mgr.state.id

        loaded = SessionManager.load(sid)
        assert loaded.state.id == sid
        assert loaded.state.objective == "Test"
        assert loaded.state.target.ip == "10.10.10.1"
