"""Tests for LLM backend response parsing.

All tests mock the HTTP layer — no real API calls made.
Verifies that each provider correctly maps its native response format
to the unified LLMResponse(text, tool_calls, stop_reason) structure.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.llm import LLMResponse, ToolCall


def _mock_http_response(json_data: dict, status_code: int = 200):
    """Return a mock httpx Response-like object."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json.return_value = json_data
    mock_resp.raise_for_status = MagicMock()
    return mock_resp


def _async_client_ctx(mock_resp):
    """Return a context manager mock that returns mock_resp on post()."""
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_resp)
    ctx = AsyncMock()
    ctx.__aenter__ = AsyncMock(return_value=mock_client)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx


# ─────────────────────────────────────────────────────────────────────────────
#  Anthropic Backend
# ─────────────────────────────────────────────────────────────────────────────

class TestAnthropicBackend:

    def _backend(self):
        from src.core.llm import AnthropicBackend
        return AnthropicBackend(api_key="sk-test", model="claude-sonnet-4-5-20251022")

    def _anthropic_response(self, content: list, stop_reason: str = "end_turn") -> dict:
        return {
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "content": content,
            "stop_reason": stop_reason,
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }

    @pytest.mark.asyncio
    async def test_text_only_response(self):
        raw = self._anthropic_response([{"type": "text", "text": "Hello world"}])
        with patch("httpx.AsyncClient", return_value=_async_client_ctx(_mock_http_response(raw))):
            resp = await self._backend().create_message([{"role": "user", "content": "hi"}])
        assert resp.text == "Hello world"
        assert resp.tool_calls == []
        assert resp.stop_reason == "end_turn"

    @pytest.mark.asyncio
    async def test_tool_use_response(self):
        raw = self._anthropic_response(
            content=[
                {"type": "text", "text": "Running nmap..."},
                {"type": "tool_use", "id": "toolu_01", "name": "bash", "input": {"command": "nmap -sV 10.10.10.1"}},
            ],
            stop_reason="tool_use",
        )
        with patch("httpx.AsyncClient", return_value=_async_client_ctx(_mock_http_response(raw))):
            resp = await self._backend().create_message([{"role": "user", "content": "scan"}])
        assert "Running nmap" in resp.text
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].name == "bash"
        assert resp.tool_calls[0].input["command"] == "nmap -sV 10.10.10.1"
        assert resp.tool_calls[0].id == "toolu_01"
        assert resp.stop_reason == "tool_use"

    @pytest.mark.asyncio
    async def test_multiple_tool_calls(self):
        raw = self._anthropic_response(
            content=[
                {"type": "tool_use", "id": "t1", "name": "bash", "input": {"command": "id"}},
                {"type": "tool_use", "id": "t2", "name": "read_file", "input": {"path": "/etc/passwd"}},
            ],
            stop_reason="tool_use",
        )
        with patch("httpx.AsyncClient", return_value=_async_client_ctx(_mock_http_response(raw))):
            resp = await self._backend().create_message([{"role": "user", "content": "go"}])
        assert len(resp.tool_calls) == 2
        names = [tc.name for tc in resp.tool_calls]
        assert "bash" in names
        assert "read_file" in names

    @pytest.mark.asyncio
    async def test_empty_content(self):
        raw = self._anthropic_response([])
        with patch("httpx.AsyncClient", return_value=_async_client_ctx(_mock_http_response(raw))):
            resp = await self._backend().create_message([{"role": "user", "content": "hi"}])
        assert resp.text == ""
        assert resp.tool_calls == []


# ─────────────────────────────────────────────────────────────────────────────
#  OpenAI Backend
# ─────────────────────────────────────────────────────────────────────────────

class TestOpenAIBackend:

    def _backend(self):
        from src.core.llm import OpenAIBackend
        return OpenAIBackend(api_key="sk-test", model="gpt-4o")

    def _openai_response(self, content=None, tool_calls=None, finish_reason="stop") -> dict:
        message = {"role": "assistant", "content": content}
        if tool_calls:
            message["tool_calls"] = tool_calls
        return {
            "choices": [{"message": message, "finish_reason": finish_reason}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        }

    @pytest.mark.asyncio
    async def test_text_only_response(self):
        raw = self._openai_response(content="Hello from OpenAI")
        with patch("httpx.AsyncClient", return_value=_async_client_ctx(_mock_http_response(raw))):
            resp = await self._backend().create_message([{"role": "user", "content": "hi"}])
        assert resp.text == "Hello from OpenAI"
        assert resp.tool_calls == []

    @pytest.mark.asyncio
    async def test_tool_call_response(self):
        raw = self._openai_response(
            content=None,
            tool_calls=[{
                "id": "call_abc",
                "type": "function",
                "function": {"name": "bash", "arguments": json.dumps({"command": "whoami"})},
            }],
            finish_reason="tool_calls",
        )
        with patch("httpx.AsyncClient", return_value=_async_client_ctx(_mock_http_response(raw))):
            resp = await self._backend().create_message([{"role": "user", "content": "go"}])
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].name == "bash"
        assert resp.tool_calls[0].input["command"] == "whoami"
        assert resp.tool_calls[0].id == "call_abc"

    @pytest.mark.asyncio
    async def test_multiple_tool_calls(self):
        raw = self._openai_response(
            tool_calls=[
                {"id": "c1", "type": "function", "function": {"name": "bash", "arguments": '{"command":"id"}'}},
                {"id": "c2", "type": "function", "function": {"name": "read_file", "arguments": '{"path":"/etc/passwd"}'}},
            ],
            finish_reason="tool_calls",
        )
        with patch("httpx.AsyncClient", return_value=_async_client_ctx(_mock_http_response(raw))):
            resp = await self._backend().create_message([{"role": "user", "content": "go"}])
        assert len(resp.tool_calls) == 2


# ─────────────────────────────────────────────────────────────────────────────
#  DeepSeek Backend (OpenAI-compatible)
# ─────────────────────────────────────────────────────────────────────────────

class TestDeepSeekBackend:

    def _backend(self):
        from src.core.llm import DeepSeekBackend
        return DeepSeekBackend(api_key="sk-test", model="deepseek-chat")

    @pytest.mark.asyncio
    async def test_text_response(self):
        raw = {
            "choices": [{"message": {"role": "assistant", "content": "DeepSeek reply"}, "finish_reason": "stop"}],
            "usage": {},
        }
        with patch("httpx.AsyncClient", return_value=_async_client_ctx(_mock_http_response(raw))):
            resp = await self._backend().create_message([{"role": "user", "content": "hi"}])
        assert resp.text == "DeepSeek reply"
        assert resp.tool_calls == []

    @pytest.mark.asyncio
    async def test_tool_call_response(self):
        raw = {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": "ds_1",
                        "type": "function",
                        "function": {"name": "bash", "arguments": '{"command":"ls"}'},
                    }],
                },
                "finish_reason": "tool_calls",
            }],
            "usage": {},
        }
        with patch("httpx.AsyncClient", return_value=_async_client_ctx(_mock_http_response(raw))):
            resp = await self._backend().create_message([{"role": "user", "content": "go"}])
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].name == "bash"


# ─────────────────────────────────────────────────────────────────────────────
#  Gemini Backend
# ─────────────────────────────────────────────────────────────────────────────

class TestGeminiBackend:

    def _backend(self):
        from src.core.llm import GeminiBackend
        return GeminiBackend(api_key="test-key", model="gemini-2.5-flash")

    def _gemini_response(self, parts: list, finish_reason: str = "STOP") -> dict:
        return {
            "candidates": [{
                "content": {"role": "model", "parts": parts},
                "finishReason": finish_reason,
            }]
        }

    @pytest.mark.asyncio
    async def test_text_only_response(self):
        raw = self._gemini_response([{"text": "Gemini says hello"}])
        with patch("httpx.AsyncClient", return_value=_async_client_ctx(_mock_http_response(raw))):
            resp = await self._backend().create_message([{"role": "user", "content": "hi"}])
        assert resp.text == "Gemini says hello"
        assert resp.tool_calls == []

    @pytest.mark.asyncio
    async def test_function_call_response(self):
        raw = self._gemini_response(
            parts=[
                {"text": "Let me run that..."},
                {"functionCall": {"name": "bash", "args": {"command": "uname -a"}}},
            ],
        )
        with patch("httpx.AsyncClient", return_value=_async_client_ctx(_mock_http_response(raw))):
            resp = await self._backend().create_message([{"role": "user", "content": "go"}])
        assert "Let me run that" in resp.text
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].name == "bash"
        assert resp.tool_calls[0].input["command"] == "uname -a"

    @pytest.mark.asyncio
    async def test_multiple_function_calls(self):
        raw = self._gemini_response(
            parts=[
                {"functionCall": {"name": "bash", "args": {"command": "id"}}},
                {"functionCall": {"name": "read_file", "args": {"path": "/etc/hostname"}}},
            ]
        )
        with patch("httpx.AsyncClient", return_value=_async_client_ctx(_mock_http_response(raw))):
            resp = await self._backend().create_message([{"role": "user", "content": "go"}])
        assert len(resp.tool_calls) == 2


# ─────────────────────────────────────────────────────────────────────────────
#  Unified LLMResponse dataclass
# ─────────────────────────────────────────────────────────────────────────────

class TestLLMResponseDataclass:

    def test_tool_call_fields(self):
        tc = ToolCall(id="tc_1", name="bash", input={"command": "ls"})
        assert tc.id == "tc_1"
        assert tc.name == "bash"
        assert tc.input == {"command": "ls"}

    def test_llm_response_fields(self):
        tc = ToolCall(id="tc_1", name="bash", input={"command": "ls"})
        resp = LLMResponse(text="running ls", tool_calls=[tc], stop_reason="tool_use", raw={})
        assert resp.text == "running ls"
        assert len(resp.tool_calls) == 1
        assert resp.stop_reason == "tool_use"

    def test_empty_llm_response(self):
        resp = LLMResponse(text="", tool_calls=[], stop_reason="end_turn", raw=None)
        assert resp.text == ""
        assert resp.tool_calls == []
