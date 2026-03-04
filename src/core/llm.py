"""LLM backend abstraction — Claude, Gemini, DeepSeek, OpenAI, Ollama.

Each backend implements the same interface so the rest of the system
is completely provider-agnostic.
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from typing import Any

import httpx

# ═══════════════════════════════════════════════════════════════════════════
#  ABSTRACT BASE
# ═══════════════════════════════════════════════════════════════════════════

class LLMBackend(ABC):
    """Abstract base for all LLM inference backends."""

    provider: str = "base"
    model: str = ""

    @abstractmethod
    async def complete(self, system: str, user: str, temperature: float = 0.3) -> str:
        """Generate a text completion."""
        ...

    async def complete_json(self, system: str, user: str) -> dict[str, Any]:
        """Complete and parse response as JSON."""
        system += "\n\nRespond ONLY with valid JSON. No markdown fences, no commentary, no preamble."
        raw = await self.complete(system, user, temperature=0.1)
        return self._parse_json(raw)

    @staticmethod
    def _parse_json(raw: str) -> dict[str, Any]:
        """Strip markdown fences and parse JSON."""
        raw = raw.strip()
        if raw.startswith("```"):
            # Remove opening fence (```json or ```)
            first_newline = raw.find("\n")
            if first_newline != -1:
                raw = raw[first_newline + 1:]
            else:
                raw = raw[3:]
        if raw.endswith("```"):
            raw = raw[:-3]
        raw = raw.strip()
        return json.loads(raw)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} model={self.model}>"


# ═══════════════════════════════════════════════════════════════════════════
#  OLLAMA (Local inference)
# ═══════════════════════════════════════════════════════════════════════════

class OllamaBackend(LLMBackend):
    """Local inference via Ollama. Default: llama3.1."""

    provider = "ollama"

    def __init__(self, model: str = "llama3.1", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url

    async def complete(self, system: str, user: str, temperature: float = 0.3) -> str:
        async with httpx.AsyncClient(timeout=180) as client:
            resp = await client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "stream": False,
                    "options": {"temperature": temperature},
                },
            )
            resp.raise_for_status()
            return resp.json()["message"]["content"]


# ═══════════════════════════════════════════════════════════════════════════
#  ANTHROPIC CLAUDE
# ═══════════════════════════════════════════════════════════════════════════

class AnthropicBackend(LLMBackend):
    """Anthropic Claude API. Default: claude-sonnet-4-20250514."""

    provider = "anthropic"

    def __init__(self, model: str = "claude-sonnet-4-20250514", api_key: str | None = None):
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not self.api_key:
            raise ValueError(
                "Anthropic API key required.\n"
                "Set ANTHROPIC_API_KEY env var or pass --api-key"
            )

    async def complete(self, system: str, user: str, temperature: float = 0.3) -> str:
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self.model,
                    "max_tokens": 4096,
                    "system": system,
                    "messages": [{"role": "user", "content": user}],
                    "temperature": temperature,
                },
            )
            resp.raise_for_status()
            return resp.json()["content"][0]["text"]


# ═══════════════════════════════════════════════════════════════════════════
#  GOOGLE GEMINI
# ═══════════════════════════════════════════════════════════════════════════

class GeminiBackend(LLMBackend):
    """Google Gemini API. Default: gemini-2.5-flash."""

    provider = "gemini"

    def __init__(self, model: str = "gemini-2.5-flash", api_key: str | None = None):
        self.model = model
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        if not self.api_key:
            raise ValueError(
                "Gemini API key required.\n"
                "Set GEMINI_API_KEY env var or pass --api-key\n"
                "Get one at https://aistudio.google.com/apikey"
            )

    async def complete(self, system: str, user: str, temperature: float = 0.3) -> str:
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                url,
                headers={"Content-Type": "application/json"},
                json={
                    "system_instruction": {"parts": [{"text": system}]},
                    "contents": [
                        {"role": "user", "parts": [{"text": user}]}
                    ],
                    "generationConfig": {
                        "temperature": temperature,
                        "maxOutputTokens": 4096,
                    },
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]


# ═══════════════════════════════════════════════════════════════════════════
#  DEEPSEEK
# ═══════════════════════════════════════════════════════════════════════════

class DeepSeekBackend(LLMBackend):
    """DeepSeek API (OpenAI-compatible). Default: deepseek-chat."""

    provider = "deepseek"

    def __init__(self, model: str = "deepseek-chat", api_key: str | None = None):
        self.model = model
        self.api_key = api_key or os.environ.get("DEEPSEEK_API_KEY", "")
        if not self.api_key:
            raise ValueError(
                "DeepSeek API key required.\n"
                "Set DEEPSEEK_API_KEY env var or pass --api-key\n"
                "Get one at https://platform.deepseek.com/"
            )

    async def complete(self, system: str, user: str, temperature: float = 0.3) -> str:
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                "https://api.deepseek.com/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "temperature": temperature,
                    "max_tokens": 4096,
                },
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]


# ═══════════════════════════════════════════════════════════════════════════
#  OPENAI (also works with vLLM, LM Studio, etc.)
# ═══════════════════════════════════════════════════════════════════════════

class OpenAIBackend(LLMBackend):
    """OpenAI-compatible backend. Default: gpt-4o."""

    provider = "openai"

    def __init__(
        self,
        model: str = "gpt-4o",
        api_key: str | None = None,
        base_url: str = "https://api.openai.com/v1",
    ):
        self.model = model
        self.base_url = base_url
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")

    async def complete(self, system: str, user: str, temperature: float = 0.3) -> str:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "temperature": temperature,
                    "max_tokens": 4096,
                },
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]


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

# Default model names per provider
DEFAULT_MODELS: dict[str, str] = {
    "ollama": "llama3.1",
    "anthropic": "claude-sonnet-4-20250514",
    "claude": "claude-sonnet-4-20250514",
    "gemini": "gemini-2.5-flash",
    "google": "gemini-2.5-flash",
    "deepseek": "deepseek-chat",
    "openai": "gpt-4o",
}

# Env var names per provider
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
    """Factory function — create an LLM backend by provider name."""
    provider = provider.lower().strip()
    cls = BACKEND_REGISTRY.get(provider)
    if not cls:
        available = ", ".join(sorted(set(BACKEND_REGISTRY.keys())))
        raise ValueError(f"Unknown provider: '{provider}'. Available: {available}")

    init_kwargs = {**kwargs}
    if model:
        init_kwargs["model"] = model
    else:
        default = DEFAULT_MODELS.get(provider)
        if default:
            init_kwargs["model"] = default

    if api_key:
        init_kwargs["api_key"] = api_key

    return cls(**init_kwargs)


def list_providers() -> list[dict[str, str]]:
    """List all available providers with their default models and env vars."""
    seen = set()
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
        })
    return result
