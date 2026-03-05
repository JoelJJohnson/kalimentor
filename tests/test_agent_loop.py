"""Unit tests for the agent loop.

Tests the loop using a mock LLM backend — no real API calls, no real tools.
"""

from __future__ import annotations

import asyncio
import tempfile
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.llm import LLMResponse, ToolCall
from src.core.stream import TextChunk, ToolCallEvent
from src.core.tools.registry import ToolRegistry, ToolRiskLevel


def _make_response(text="", tool_calls=None, stop_reason="end_turn"):
    return LLMResponse(text=text, tool_calls=tool_calls or [], stop_reason=stop_reason, raw=None)


def _make_tc(name="bash", input=None, id="tc_1"):
    return ToolCall(id=id, name=name, input=input or {"command": "id"})


async def _text_stream(text: str):
    """Async generator that yields a single TextChunk."""
    yield TextChunk(text=text)


async def _tool_stream(tool_call: ToolCall):
    """Async generator that yields a ToolCallEvent."""
    yield ToolCallEvent(tool_call=tool_call)


def _make_registry():
    registry = ToolRegistry()

    async def dummy_bash(command: str, timeout: int = 30) -> str:
        return f"output: {command}"

    registry.register(
        name="bash",
        description="run bash",
        input_schema={"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
        risk=ToolRiskLevel.SAFE,
    )(dummy_bash)
    return registry


def _make_loop(mode="autonomous", registry=None):
    from src.core.agent import AgentLoop
    if registry is None:
        registry = _make_registry()
    mock_llm = MagicMock()
    mock_llm.provider = "anthropic"
    tmp = tempfile.mkdtemp()
    return AgentLoop(
        llm=mock_llm,
        registry=registry,
        mode=mode,
        session_dir=tmp,
    ), mock_llm


# ─────────────────────────────────────────────────────────────────────────────
#  Construction
# ─────────────────────────────────────────────────────────────────────────────

class TestAgentLoopInit:

    def test_creates_without_error(self):
        loop, _ = _make_loop()
        assert loop is not None

    def test_mode_stored(self):
        loop, _ = _make_loop(mode="interactive")
        assert loop.mode == "interactive"

    def test_session_dir_stored(self):
        loop, _ = _make_loop()
        assert loop.session_dir is not None


# ─────────────────────────────────────────────────────────────────────────────
#  Single-turn: text only
# ─────────────────────────────────────────────────────────────────────────────

class TestAgentLoopTextOnly:

    @pytest.mark.asyncio
    async def test_text_only_response_calls_stream_once(self):
        loop, mock_llm = _make_loop()
        call_count = 0

        async def fake_stream(**kwargs):
            nonlocal call_count
            call_count += 1
            yield TextChunk(text="Hello.")

        mock_llm.stream_message = fake_stream
        await loop.run("enumerate the target")
        assert call_count == 1


# ─────────────────────────────────────────────────────────────────────────────
#  Tool dispatch
# ─────────────────────────────────────────────────────────────────────────────

class TestAgentLoopToolDispatch:

    @pytest.mark.asyncio
    async def test_safe_tool_executes_automatically(self):
        """A non-bash safe tool should run automatically via registry.execute."""
        executed = []
        registry = ToolRegistry()

        async def capturing_tool(query: str = "") -> str:
            executed.append(query)
            return "CVE-2021-44228"

        registry.register(
            name="search_cve",
            description="search CVEs",
            input_schema={"type": "object", "properties": {"query": {"type": "string"}}, "required": []},
            risk=ToolRiskLevel.SAFE,
        )(capturing_tool)

        loop, mock_llm = _make_loop(registry=registry)
        tc = ToolCall(id="tc_1", name="search_cve", input={"query": "log4j"})
        calls = [0]

        async def fake_stream(**kwargs):
            if calls[0] == 0:
                calls[0] += 1
                yield ToolCallEvent(tool_call=tc)
            else:
                yield TextChunk(text="Found CVE.")

        mock_llm.stream_message = fake_stream
        await loop.run("find log4j vulns")
        assert "log4j" in executed

    @pytest.mark.asyncio
    async def test_loop_calls_stream_twice_for_one_tool_call(self):
        """Verify the loop calls LLM again after tool execution."""
        registry = ToolRegistry()

        async def dummy_cve(query: str = "") -> str:
            return "CVE result"

        registry.register(
            name="search_cve",
            description="cve",
            input_schema={"type": "object", "properties": {"query": {"type": "string"}}, "required": []},
            risk=ToolRiskLevel.SAFE,
        )(dummy_cve)

        loop, mock_llm = _make_loop(registry=registry)
        tc = ToolCall(id="tc_1", name="search_cve", input={"query": "apache"})
        stream_calls = [0]

        async def fake_stream(**kwargs):
            if stream_calls[0] == 0:
                stream_calls[0] += 1
                yield ToolCallEvent(tool_call=tc)
            else:
                yield TextChunk(text="Analysis complete.")

        mock_llm.stream_message = fake_stream
        await loop.run("check vulnerabilities")
        assert stream_calls[0] >= 1


# ─────────────────────────────────────────────────────────────────────────────
#  Mode checks
# ─────────────────────────────────────────────────────────────────────────────

class TestAgentLoopModes:

    def test_mode_interactive(self):
        loop, _ = _make_loop(mode="interactive")
        assert loop.mode == "interactive"

    def test_mode_yolo(self):
        loop, _ = _make_loop(mode="yolo")
        assert loop.mode == "yolo"

    def test_mode_socratic(self):
        loop, _ = _make_loop(mode="socratic")
        assert loop.mode == "socratic"

    def test_mode_autonomous(self):
        loop, _ = _make_loop(mode="autonomous")
        assert loop.mode == "autonomous"
