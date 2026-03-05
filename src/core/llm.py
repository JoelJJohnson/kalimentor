"""LLM backend abstraction — Claude, Gemini, DeepSeek, OpenAI, Ollama.

Every backend implements two interfaces:
  - complete()        — legacy text completion (kept for backwards compat)
  - create_message()  — native tool_use agentic loop interface

create_message() always returns LLMResponse(text, tool_calls, stop_reason, raw).
"""

from __future__ import annotations

import json
import os
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import httpx


# ═══════════════════════════════════════════════════════════════════════════
#  UNIFIED RESPONSE TYPES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ToolCall:
    """A single tool invocation requested by the LLM."""
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class LLMResponse:
    """Unified response from any LLM backend."""
    text: str                       # Combined text blocks (may be empty if only tool calls)
    tool_calls: list[ToolCall]      # Tool invocations (empty if end_turn)
    stop_reason: str                # "end_turn" | "tool_use" | "max_tokens" | "stop"
    raw: Any = field(repr=False)    # Provider-specific raw response object


# ═══════════════════════════════════════════════════════════════════════════
#  CONTEXT WINDOW SIZES (tokens)
# ═══════════════════════════════════════════════════════════════════════════

CONTEXT_WINDOWS: dict[str, int] = {
    "anthropic": 200_000,
    "claude": 200_000,
    "gemini": 1_000_000,
    "google": 1_000_000,
    "deepseek": 128_000,
    "openai": 128_000,
    "ollama": 8_000,    # conservative default; varies by model
}


# ═══════════════════════════════════════════════════════════════════════════
#  ABSTRACT BASE
# ═══════════════════════════════════════════════════════════════════════════

class LLMBackend(ABC):
    """Abstract base for all LLM inference backends."""

    provider: str = "base"
    model: str = ""

    @abstractmethod
    async def complete(self, system: str, user: str, temperature: float = 0.3) -> str:
        """Legacy single-turn text completion."""
        ...

    @abstractmethod
    async def create_message(
        self,
        messages: list[dict[str, Any]],
        system: str = "",
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send a multi-turn conversation with optional tool definitions.

        Args:
            messages: Conversation history in the provider-native format
                      (assembled by the agent loop).
            system: System prompt string.
            tools: List of tool schemas in the provider's format.
            temperature: Sampling temperature.
            max_tokens: Max tokens to generate.

        Returns:
            LLMResponse with text, tool_calls, stop_reason, raw.
        """
        ...

    async def complete_json(self, system: str, user: str) -> dict[str, Any]:
        """Complete and parse response as JSON (legacy helper)."""
        system += "\n\nRespond ONLY with valid JSON. No markdown fences, no commentary, no preamble."
        raw = await self.complete(system, user, temperature=0.1)
        return self._parse_json(raw)

    @property
    def context_window(self) -> int:
        return CONTEXT_WINDOWS.get(self.provider, 8_000)

    @staticmethod
    def _parse_json(raw: str) -> dict[str, Any]:
        raw = raw.strip()
        if raw.startswith("```"):
            first_nl = raw.find("\n")
            raw = raw[first_nl + 1:] if first_nl != -1 else raw[3:]
        if raw.endswith("```"):
            raw = raw[:-3]
        return json.loads(raw.strip())

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} model={self.model}>"


# ═══════════════════════════════════════════════════════════════════════════
#  ANTHROPIC CLAUDE
# ═══════════════════════════════════════════════════════════════════════════

class AnthropicBackend(LLMBackend):
    """Anthropic Claude Messages API with native tool_use support."""

    provider = "anthropic"

    def __init__(self, model: str = "claude-sonnet-4-6", api_key: str | None = None):
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not self.api_key:
            raise ValueError(
                "Anthropic API key required. Set ANTHROPIC_API_KEY env var or pass --api-key"
            )

    def _headers(self) -> dict[str, str]:
        return {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

    async def complete(self, system: str, user: str, temperature: float = 0.3) -> str:
        resp = await self.create_message(
            messages=[{"role": "user", "content": user}],
            system=system,
            temperature=temperature,
        )
        return resp.text

    async def create_message(
        self,
        messages: list[dict[str, Any]],
        system: str = "",
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        body: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": messages,
            "temperature": temperature,
        }
        if system:
            body["system"] = system
        if tools:
            body["tools"] = tools

        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers=self._headers(),
                json=body,
            )
            resp.raise_for_status()
            data = resp.json()

        # Parse content blocks
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []

        for block in data.get("content", []):
            if block.get("type") == "text":
                text_parts.append(block.get("text", ""))
            elif block.get("type") == "tool_use":
                tool_calls.append(ToolCall(
                    id=block.get("id", uuid.uuid4().hex),
                    name=block.get("name", ""),
                    input=block.get("input", {}),
                ))

        stop_reason = data.get("stop_reason", "end_turn")
        return LLMResponse(
            text="\n".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=stop_reason,
            raw=data,
        )

    async def stream_message(
        self,
        messages: list[dict[str, Any]],
        system: str = "",
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ):
        """Streaming variant — yields StreamEvent objects as the response arrives.

        Yields: TextChunk | ToolCallEvent | UsageEvent
        """
        from .stream import TextChunk, ToolCallEvent, UsageEvent

        body: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": messages,
            "temperature": temperature,
            "stream": True,
        }
        if system:
            body["system"] = system
        if tools:
            body["tools"] = tools

        # Track in-progress tool_use blocks: index → {id, name, input_json}
        tool_blocks: dict[int, dict[str, Any]] = {}
        # Track which block index is currently "open" and what type it is
        block_types: dict[int, str] = {}
        # Track input tokens from message_start event
        _input_tokens: int = 0

        async with httpx.AsyncClient(timeout=120) as client:
            async with client.stream(
                "POST",
                "https://api.anthropic.com/v1/messages",
                headers=self._headers(),
                json=body,
            ) as resp:
                if resp.status_code >= 400:
                    error_body = await resp.aread()
                    raise httpx.HTTPStatusError(
                        f"Anthropic API error {resp.status_code}: {error_body.decode()}",
                        request=resp.request,
                        response=resp,
                    )
                async for line in resp.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    raw = line[6:]
                    if raw in ("", "[DONE]"):
                        continue
                    try:
                        event = json.loads(raw)
                    except json.JSONDecodeError:
                        continue

                    etype = event.get("type", "")

                    if etype == "message_start":
                        usage = event.get("message", {}).get("usage", {})
                        _input_tokens = usage.get("input_tokens", 0)

                    elif etype == "content_block_start":
                        idx = event.get("index", 0)
                        block = event.get("content_block", {})
                        btype = block.get("type", "text")
                        block_types[idx] = btype
                        if btype == "tool_use":
                            tool_blocks[idx] = {
                                "id": block.get("id", ""),
                                "name": block.get("name", ""),
                                "input_json": "",
                            }

                    elif etype == "content_block_delta":
                        idx = event.get("index", 0)
                        delta = event.get("delta", {})
                        dtype = delta.get("type", "")
                        if dtype == "text_delta":
                            yield TextChunk(text=delta.get("text", ""))
                        elif dtype == "input_json_delta":
                            if idx in tool_blocks:
                                tool_blocks[idx]["input_json"] += delta.get("partial_json", "")

                    elif etype == "content_block_stop":
                        idx = event.get("index", 0)
                        if block_types.get(idx) == "tool_use" and idx in tool_blocks:
                            tb = tool_blocks.pop(idx)
                            try:
                                input_dict = json.loads(tb["input_json"]) if tb["input_json"] else {}
                            except json.JSONDecodeError:
                                input_dict = {"_raw": tb["input_json"]}
                            yield ToolCallEvent(tool_call=ToolCall(
                                id=tb["id"] or uuid.uuid4().hex,
                                name=tb["name"],
                                input=input_dict,
                            ))

                    elif etype == "message_delta":
                        usage = event.get("usage", {})
                        output_tok = usage.get("output_tokens", 0)
                        if output_tok or _input_tokens:
                            yield UsageEvent(
                                input_tokens=_input_tokens,
                                output_tokens=output_tok,
                            )


# ═══════════════════════════════════════════════════════════════════════════
#  GOOGLE GEMINI
# ═══════════════════════════════════════════════════════════════════════════

class GeminiBackend(LLMBackend):
    """Google Gemini API with function_calling (tool_use) support."""

    provider = "gemini"

    def __init__(self, model: str = "gemini-2.5-flash", api_key: str | None = None):
        self.model = model
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        if not self.api_key:
            raise ValueError(
                "Gemini API key required. Set GEMINI_API_KEY env var or pass --api-key\n"
                "Get one at https://aistudio.google.com/apikey"
            )

    def _url(self) -> str:
        return (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )

    @staticmethod
    def _to_gemini_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Convert OpenAI-style messages to Gemini contents format."""
        contents: list[dict[str, Any]] = []
        for msg in messages:
            role = msg["role"]
            content = msg.get("content", "")

            if role == "assistant":
                gemini_role = "model"
            elif role == "tool":
                # Tool results — Gemini uses functionResponse parts
                gemini_role = "user"
                tool_result_content = msg.get("content", "")
                contents.append({
                    "role": gemini_role,
                    "parts": [{
                        "functionResponse": {
                            "name": msg.get("name", "tool"),
                            "response": {"result": tool_result_content},
                        }
                    }],
                })
                continue
            else:
                gemini_role = "user"

            # Handle content that may be a list of blocks (assistant with tool calls)
            if isinstance(content, list):
                parts: list[dict[str, Any]] = []
                for block in content:
                    if isinstance(block, dict):
                        if block.get("type") == "text":
                            parts.append({"text": block.get("text", "")})
                        elif block.get("type") == "tool_use":
                            parts.append({
                                "functionCall": {
                                    "name": block.get("name", ""),
                                    "args": block.get("input", {}),
                                }
                            })
                    else:
                        parts.append({"text": str(block)})
                contents.append({"role": gemini_role, "parts": parts})
            else:
                if content:
                    contents.append({"role": gemini_role, "parts": [{"text": str(content)}]})

        return contents

    async def complete(self, system: str, user: str, temperature: float = 0.3) -> str:
        resp = await self.create_message(
            messages=[{"role": "user", "content": user}],
            system=system,
            temperature=temperature,
        )
        return resp.text

    async def create_message(
        self,
        messages: list[dict[str, Any]],
        system: str = "",
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        body: dict[str, Any] = {
            "contents": self._to_gemini_messages(messages),
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            },
        }
        if system:
            body["system_instruction"] = {"parts": [{"text": system}]}
        if tools:
            # tools are already in Gemini schema format from registry.get_schemas("gemini")
            body["tools"] = [{"function_declarations": tools}]

        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                self._url(),
                headers={"Content-Type": "application/json"},
                json=body,
            )
            resp.raise_for_status()
            data = resp.json()

        candidate = data.get("candidates", [{}])[0]
        content = candidate.get("content", {})
        parts = content.get("parts", [])
        finish_reason = candidate.get("finishReason", "STOP")

        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []

        for part in parts:
            if "text" in part:
                text_parts.append(part["text"])
            elif "functionCall" in part:
                fc = part["functionCall"]
                tool_calls.append(ToolCall(
                    id=uuid.uuid4().hex,
                    name=fc.get("name", ""),
                    input=fc.get("args", {}),
                ))

        # Map Gemini finish reasons to our vocabulary
        stop_map = {
            "STOP": "end_turn",
            "MAX_TOKENS": "max_tokens",
            "TOOL_CODE_EXECUTION": "tool_use",
        }
        stop_reason = stop_map.get(finish_reason, "end_turn")
        if tool_calls:
            stop_reason = "tool_use"

        return LLMResponse(
            text="\n".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=stop_reason,
            raw=data,
        )

    def _stream_url(self) -> str:
        return (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:streamGenerateContent?alt=sse&key={self.api_key}"
        )

    async def stream_message(
        self,
        messages: list[dict[str, Any]],
        system: str = "",
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ):
        """Streaming variant — yields StreamEvent objects."""
        from .stream import TextChunk, ToolCallEvent, UsageEvent

        body: dict[str, Any] = {
            "contents": self._to_gemini_messages(messages),
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            },
        }
        if system:
            body["system_instruction"] = {"parts": [{"text": system}]}
        if tools:
            body["tools"] = [{"function_declarations": tools}]

        async with httpx.AsyncClient(timeout=120) as client:
            async with client.stream(
                "POST",
                self._stream_url(),
                headers={"Content-Type": "application/json"},
                json=body,
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    raw = line[6:].strip()
                    if not raw:
                        continue
                    try:
                        chunk = json.loads(raw)
                    except json.JSONDecodeError:
                        continue

                    for candidate in chunk.get("candidates", []):
                        content = candidate.get("content", {})
                        for part in content.get("parts", []):
                            if "text" in part:
                                yield TextChunk(text=part["text"])
                            elif "functionCall" in part:
                                fc = part["functionCall"]
                                yield ToolCallEvent(tool_call=ToolCall(
                                    id=uuid.uuid4().hex,
                                    name=fc.get("name", ""),
                                    input=fc.get("args", {}),
                                ))

                    # Only emit usage on final chunk (when finishReason is set)
                    usage = chunk.get("usageMetadata", {})
                    final_candidate = chunk.get("candidates", [{}])[0] if chunk.get("candidates") else {}
                    if usage and final_candidate.get("finishReason"):
                        yield UsageEvent(
                            input_tokens=usage.get("promptTokenCount", 0),
                            output_tokens=usage.get("candidatesTokenCount", 0),
                        )


# ═══════════════════════════════════════════════════════════════════════════
#  DEEPSEEK  (OpenAI-compatible format)
# ═══════════════════════════════════════════════════════════════════════════

class DeepSeekBackend(LLMBackend):
    """DeepSeek API — OpenAI-compatible with tool_use support."""

    provider = "deepseek"

    def __init__(self, model: str = "deepseek-chat", api_key: str | None = None):
        self.model = model
        self.api_key = api_key or os.environ.get("DEEPSEEK_API_KEY", "")
        if not self.api_key:
            raise ValueError(
                "DeepSeek API key required. Set DEEPSEEK_API_KEY env var or pass --api-key\n"
                "Get one at https://platform.deepseek.com/"
            )

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    async def complete(self, system: str, user: str, temperature: float = 0.3) -> str:
        resp = await self.create_message(
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            temperature=temperature,
        )
        return resp.text

    async def create_message(
        self,
        messages: list[dict[str, Any]],
        system: str = "",
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        # Prepend system message if provided and not already first
        all_messages = list(messages)
        if system and (not all_messages or all_messages[0].get("role") != "system"):
            all_messages = [{"role": "system", "content": system}] + all_messages

        body: dict[str, Any] = {
            "model": self.model,
            "messages": all_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"

        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                "https://api.deepseek.com/chat/completions",
                headers=self._headers(),
                json=body,
            )
            resp.raise_for_status()
            data = resp.json()

        return _parse_openai_response(data)

    async def stream_message(
        self,
        messages: list[dict[str, Any]],
        system: str = "",
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ):
        """Streaming variant — yields StreamEvent objects."""
        all_messages = list(messages)
        if system and (not all_messages or all_messages[0].get("role") != "system"):
            all_messages = [{"role": "system", "content": system}] + all_messages

        body: dict[str, Any] = {
            "model": self.model,
            "messages": all_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"

        async with httpx.AsyncClient(timeout=120) as client:
            async with client.stream(
                "POST",
                "https://api.deepseek.com/chat/completions",
                headers=self._headers(),
                json=body,
            ) as resp:
                resp.raise_for_status()
                async for event in _stream_openai_sse(resp.aiter_lines(), "deepseek", "chat/completions"):
                    yield event


# ═══════════════════════════════════════════════════════════════════════════
#  OPENAI  (also works with vLLM, LM Studio, etc.)
# ═══════════════════════════════════════════════════════════════════════════

class OpenAIBackend(LLMBackend):
    """OpenAI-compatible backend with tool_use support."""

    provider = "openai"

    def __init__(
        self,
        model: str = "gpt-4o",
        api_key: str | None = None,
        base_url: str = "https://api.openai.com/v1",
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    async def complete(self, system: str, user: str, temperature: float = 0.3) -> str:
        resp = await self.create_message(
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            temperature=temperature,
        )
        return resp.text

    async def create_message(
        self,
        messages: list[dict[str, Any]],
        system: str = "",
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        all_messages = list(messages)
        if system and (not all_messages or all_messages[0].get("role") != "system"):
            all_messages = [{"role": "system", "content": system}] + all_messages

        body: dict[str, Any] = {
            "model": self.model,
            "messages": all_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"

        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                headers=self._headers(),
                json=body,
            )
            resp.raise_for_status()
            data = resp.json()

        return _parse_openai_response(data)

    async def stream_message(
        self,
        messages: list[dict[str, Any]],
        system: str = "",
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ):
        """Streaming variant — yields StreamEvent objects."""
        all_messages = list(messages)
        if system and (not all_messages or all_messages[0].get("role") != "system"):
            all_messages = [{"role": "system", "content": system}] + all_messages

        body: dict[str, Any] = {
            "model": self.model,
            "messages": all_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"

        async with httpx.AsyncClient(timeout=120) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/chat/completions",
                headers=self._headers(),
                json=body,
            ) as resp:
                resp.raise_for_status()
                async for event in _stream_openai_sse(resp.aiter_lines(), self.base_url, "chat/completions"):
                    yield event


# ═══════════════════════════════════════════════════════════════════════════
#  OLLAMA  (local inference)
# ═══════════════════════════════════════════════════════════════════════════

_OLLAMA_TOOL_CAPABLE_MODELS = {
    "llama3.1", "llama3.1:8b", "llama3.1:70b", "llama3.2", "llama3.2:3b",
    "llama3.3", "mistral-nemo", "mistral-small", "qwen2.5", "qwen2.5:7b",
    "qwen2.5:14b", "qwen2.5:72b", "command-r", "command-r-plus",
    "firefunction-v2", "granite3-dense", "granite3-moe",
}


class OllamaBackend(LLMBackend):
    """Local inference via Ollama.

    Tool-capable models (llama3.1, qwen2.5, etc.) use Ollama's native tool API.
    All other models fall back to JSON-mode structured output parsing.
    """

    provider = "ollama"

    def __init__(self, model: str = "llama3.1", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url.rstrip("/")

    def _supports_tools(self) -> bool:
        base = self.model.split(":")[0].lower()
        return base in _OLLAMA_TOOL_CAPABLE_MODELS or self.model in _OLLAMA_TOOL_CAPABLE_MODELS

    async def complete(self, system: str, user: str, temperature: float = 0.3) -> str:
        resp = await self.create_message(
            messages=[{"role": "user", "content": user}],
            system=system,
            temperature=temperature,
        )
        return resp.text

    async def create_message(
        self,
        messages: list[dict[str, Any]],
        system: str = "",
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        if tools and self._supports_tools():
            return await self._create_message_with_tools(messages, system, tools, temperature, max_tokens)
        elif tools:
            return await self._create_message_json_fallback(messages, system, tools, temperature, max_tokens)
        else:
            return await self._create_message_plain(messages, system, temperature, max_tokens)

    async def _create_message_with_tools(
        self,
        messages: list[dict[str, Any]],
        system: str,
        tools: list[dict[str, Any]],
        temperature: float,
        max_tokens: int,
    ) -> LLMResponse:
        """Native Ollama tool-calling path (llama3.1, qwen2.5, etc.)"""
        all_messages = list(messages)
        if system and (not all_messages or all_messages[0].get("role") != "system"):
            all_messages = [{"role": "system", "content": system}] + all_messages

        async with httpx.AsyncClient(timeout=180) as client:
            resp = await client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": all_messages,
                    "tools": tools,
                    "stream": False,
                    "options": {"temperature": temperature, "num_predict": max_tokens},
                },
            )
            resp.raise_for_status()
            data = resp.json()

        message = data.get("message", {})
        text = message.get("content", "") or ""
        raw_tool_calls = message.get("tool_calls", [])
        done_reason = data.get("done_reason", "stop")

        tool_calls: list[ToolCall] = []
        for tc in raw_tool_calls:
            fn = tc.get("function", {})
            tool_calls.append(ToolCall(
                id=uuid.uuid4().hex,
                name=fn.get("name", ""),
                input=fn.get("arguments", {}),
            ))

        stop_reason = "tool_use" if tool_calls else ("max_tokens" if done_reason == "length" else "end_turn")
        return LLMResponse(text=text, tool_calls=tool_calls, stop_reason=stop_reason, raw=data)

    async def _create_message_json_fallback(
        self,
        messages: list[dict[str, Any]],
        system: str,
        tools: list[dict[str, Any]],
        temperature: float,
        max_tokens: int,
    ) -> LLMResponse:
        """Degraded path: prompt model to output tool calls as JSON and parse manually.

        NOTE: This path is unreliable. Use a tool-capable model for best results.
        """
        tool_descriptions = "\n".join(
            f"- {t['function']['name']}: {t['function'].get('description', '')}"
            for t in tools
            if "function" in t
        )
        fallback_system = (
            f"{system}\n\n"
            "You have access to the following tools. When you want to use a tool, "
            "respond ONLY with a JSON object in this exact format:\n"
            '{"tool": "<tool_name>", "input": {<arguments>}}\n\n'
            "If you do not need a tool, respond with plain text.\n\n"
            f"Available tools:\n{tool_descriptions}"
        )

        all_messages = list(messages)
        if not all_messages or all_messages[0].get("role") != "system":
            all_messages = [{"role": "system", "content": fallback_system}] + all_messages

        async with httpx.AsyncClient(timeout=180) as client:
            resp = await client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": all_messages,
                    "stream": False,
                    "options": {"temperature": temperature, "num_predict": max_tokens},
                },
            )
            resp.raise_for_status()
            data = resp.json()

        raw_text = data.get("message", {}).get("content", "") or ""

        # Try to parse as tool call JSON
        tool_calls: list[ToolCall] = []
        text = raw_text
        stripped = raw_text.strip()
        if stripped.startswith("{"):
            try:
                parsed = json.loads(stripped)
                if "tool" in parsed and "input" in parsed:
                    tool_calls.append(ToolCall(
                        id=uuid.uuid4().hex,
                        name=parsed["tool"],
                        input=parsed["input"],
                    ))
                    text = ""
            except json.JSONDecodeError:
                pass

        stop_reason = "tool_use" if tool_calls else "end_turn"
        return LLMResponse(text=text, tool_calls=tool_calls, stop_reason=stop_reason, raw=data)

    async def _create_message_plain(
        self,
        messages: list[dict[str, Any]],
        system: str,
        temperature: float,
        max_tokens: int,
    ) -> LLMResponse:
        all_messages = list(messages)
        if system and (not all_messages or all_messages[0].get("role") != "system"):
            all_messages = [{"role": "system", "content": system}] + all_messages

        async with httpx.AsyncClient(timeout=180) as client:
            resp = await client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": all_messages,
                    "stream": False,
                    "options": {"temperature": temperature, "num_predict": max_tokens},
                },
            )
            resp.raise_for_status()
            data = resp.json()

        text = data.get("message", {}).get("content", "") or ""
        done_reason = data.get("done_reason", "stop")
        stop_reason = "max_tokens" if done_reason == "length" else "end_turn"
        return LLMResponse(text=text, tool_calls=[], stop_reason=stop_reason, raw=data)

    async def stream_message(
        self,
        messages: list[dict[str, Any]],
        system: str = "",
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ):
        """Streaming variant — yields StreamEvent objects (no UsageEvent for Ollama)."""
        from .stream import TextChunk, ToolCallEvent

        all_messages = list(messages)
        if system and (not all_messages or all_messages[0].get("role") != "system"):
            all_messages = [{"role": "system", "content": system}] + all_messages

        body: dict[str, Any] = {
            "model": self.model,
            "messages": all_messages,
            "stream": True,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        if tools and self._supports_tools():
            body["tools"] = tools

        async with httpx.AsyncClient(timeout=180) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/api/chat",
                json=body,
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    message = chunk.get("message", {})
                    content = message.get("content", "")
                    if content:
                        yield TextChunk(text=content)

                    # Tool calls only appear in the final done=true chunk
                    if chunk.get("done"):
                        for tc in message.get("tool_calls", []):
                            fn = tc.get("function", {})
                            yield ToolCallEvent(tool_call=ToolCall(
                                id=uuid.uuid4().hex,
                                name=fn.get("name", ""),
                                input=fn.get("arguments", {}),
                            ))


# ═══════════════════════════════════════════════════════════════════════════
#  SHARED HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _parse_openai_response(data: dict[str, Any]) -> LLMResponse:
    """Parse an OpenAI-format chat completion response into LLMResponse."""
    choice = data.get("choices", [{}])[0]
    message = choice.get("message", {})
    finish_reason = choice.get("finish_reason", "stop")

    text = message.get("content", "") or ""
    raw_tool_calls = message.get("tool_calls", []) or []

    tool_calls: list[ToolCall] = []
    for tc in raw_tool_calls:
        fn = tc.get("function", {})
        raw_args = fn.get("arguments", "{}")
        try:
            args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
        except json.JSONDecodeError:
            args = {"_raw": raw_args}
        tool_calls.append(ToolCall(
            id=tc.get("id", uuid.uuid4().hex),
            name=fn.get("name", ""),
            input=args,
        ))

    stop_map = {
        "stop": "end_turn",
        "tool_calls": "tool_use",
        "length": "max_tokens",
        "function_call": "tool_use",
    }
    stop_reason = stop_map.get(finish_reason, "end_turn")
    if tool_calls:
        stop_reason = "tool_use"

    return LLMResponse(text=text, tool_calls=tool_calls, stop_reason=stop_reason, raw=data)


async def _stream_openai_sse(lines_aiter, base_url: str, endpoint: str):
    """Shared SSE streaming parser for OpenAI-compatible APIs.

    Yields: TextChunk | ToolCallEvent | UsageEvent
    """
    from .stream import TextChunk, ToolCallEvent, UsageEvent

    # tool_calls accumulator: index -> {id, name, arguments_str}
    pending_tools: dict[int, dict[str, str]] = {}

    async for line in lines_aiter:
        if not line.startswith("data: "):
            continue
        raw = line[6:].strip()
        if raw == "[DONE]" or not raw:
            continue
        try:
            chunk = json.loads(raw)
        except json.JSONDecodeError:
            continue

        choices = chunk.get("choices", [])
        if choices:
            delta = choices[0].get("delta", {})
            finish_reason = choices[0].get("finish_reason")

            # Text delta
            content = delta.get("content")
            if content:
                yield TextChunk(text=content)

            # Tool call deltas
            for tc_delta in delta.get("tool_calls", []):
                idx = tc_delta.get("index", 0)
                if idx not in pending_tools:
                    pending_tools[idx] = {"id": "", "name": "", "arguments": ""}
                if tc_delta.get("id"):
                    pending_tools[idx]["id"] = tc_delta["id"]
                fn = tc_delta.get("function", {})
                if fn.get("name"):
                    pending_tools[idx]["name"] = fn["name"]
                if fn.get("arguments"):
                    pending_tools[idx]["arguments"] += fn["arguments"]

            # Emit tool calls when done
            if finish_reason == "tool_calls":
                for tc_data in pending_tools.values():
                    try:
                        args = json.loads(tc_data["arguments"]) if tc_data["arguments"] else {}
                    except json.JSONDecodeError:
                        args = {"_raw": tc_data["arguments"]}
                    yield ToolCallEvent(tool_call=ToolCall(
                        id=tc_data["id"] or uuid.uuid4().hex,
                        name=tc_data["name"],
                        input=args,
                    ))

        # Token usage (final chunk with stream_options)
        usage = chunk.get("usage")
        if usage:
            yield UsageEvent(
                input_tokens=usage.get("prompt_tokens", 0),
                output_tokens=usage.get("completion_tokens", 0),
            )


# ═══════════════════════════════════════════════════════════════════════════
#  MESSAGE BUILDER HELPERS  (used by the agent loop)
# ═══════════════════════════════════════════════════════════════════════════

def user_message(content: str) -> dict[str, Any]:
    return {"role": "user", "content": content}


def assistant_message(response: LLMResponse) -> dict[str, Any]:
    """Build the assistant message to append to history after an LLM call.

    For Anthropic format (content blocks). The agent loop uses Anthropic format
    as the canonical history format and converts for other providers as needed.
    """
    content: list[dict[str, Any]] = []
    if response.text:
        content.append({"type": "text", "text": response.text})
    for tc in response.tool_calls:
        content.append({
            "type": "tool_use",
            "id": tc.id,
            "name": tc.name,
            "input": tc.input,
        })
    return {"role": "assistant", "content": content if content else ""}


def tool_result_message(tool_results: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the tool_result message for Anthropic history format.

    Each result dict: {"tool_use_id": str, "content": str}
    """
    return {
        "role": "user",
        "content": [
            {
                "type": "tool_result",
                "tool_use_id": r["tool_use_id"],
                "content": str(r["content"]),
            }
            for r in tool_results
        ],
    }


# ═══════════════════════════════════════════════════════════════════════════
#  FACTORY
# ═══════════════════════════════════════════════════════════════════════════

BACKEND_REGISTRY: dict[str, type[LLMBackend]] = {
    "ollama": OllamaBackend,
    "anthropic": AnthropicBackend,
    "claude": AnthropicBackend,
    "gemini": GeminiBackend,
    "google": GeminiBackend,
    "deepseek": DeepSeekBackend,
    "openai": OpenAIBackend,
}

DEFAULT_MODELS: dict[str, str] = {
    "ollama": "llama3.1",
    "anthropic": "claude-sonnet-4-6",
    "claude": "claude-sonnet-4-6",
    "gemini": "gemini-2.5-flash",
    "google": "gemini-2.5-flash",
    "deepseek": "deepseek-chat",
    "openai": "gpt-4o",
}

API_KEY_ENV_VARS: dict[str, str] = {
    "anthropic": "ANTHROPIC_API_KEY",
    "claude": "ANTHROPIC_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "google": "GEMINI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "openai": "OPENAI_API_KEY",
}


def create_backend(
    provider: str,
    model: str | None = None,
    api_key: str | None = None,
    **kwargs,
) -> LLMBackend:
    """Factory — create an LLM backend by provider name."""
    provider = provider.lower().strip()
    cls = BACKEND_REGISTRY.get(provider)
    if not cls:
        available = ", ".join(sorted(set(BACKEND_REGISTRY.keys())))
        raise ValueError(f"Unknown provider '{provider}'. Available: {available}")

    init_kwargs: dict[str, Any] = {**kwargs}
    init_kwargs["model"] = model or DEFAULT_MODELS.get(provider, "")
    if api_key:
        init_kwargs["api_key"] = api_key

    return cls(**init_kwargs)


def list_providers() -> list[dict[str, str]]:
    seen: set[str] = set()
    result = []
    for name, cls in BACKEND_REGISTRY.items():
        if name in seen or name in ("claude", "google"):
            continue
        seen.add(name)
        result.append({
            "provider": name,
            "default_model": DEFAULT_MODELS.get(name, ""),
            "env_var": API_KEY_ENV_VARS.get(name, "N/A (local)"),
            "class": cls.__name__,
            "context_window": str(CONTEXT_WINDOWS.get(name, "varies")),
        })
    return result
