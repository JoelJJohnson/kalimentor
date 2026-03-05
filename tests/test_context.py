"""Tests for context window management and compression logic."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.context import count_tokens, needs_compression, COMPRESSION_THRESHOLD


# ─────────────────────────────────────────────────────────────────────────────
#  Token counting
# ─────────────────────────────────────────────────────────────────────────────

class TestCountTokens:

    def _msg(self, role: str, text: str) -> dict:
        return {"role": role, "content": text}

    def test_empty_messages_returns_zero(self):
        assert count_tokens([]) == 0

    def test_single_short_message(self):
        msgs = [self._msg("user", "hello")]
        count = count_tokens(msgs)
        assert count > 0

    def test_more_text_means_more_tokens(self):
        short = [self._msg("user", "hi")]
        long = [self._msg("user", "a" * 1000)]
        assert count_tokens(long) > count_tokens(short)

    def test_multiple_messages(self):
        msgs = [
            self._msg("user", "enumerate the target"),
            self._msg("assistant", "I will run nmap first."),
            self._msg("user", "ok go ahead"),
        ]
        count = count_tokens(msgs)
        assert count > 0

    def test_provider_anthropic(self):
        msgs = [self._msg("user", "test message")]
        count = count_tokens(msgs, provider="anthropic")
        assert count > 0

    def test_provider_gemini(self):
        msgs = [self._msg("user", "test message")]
        count = count_tokens(msgs, provider="gemini")
        assert count > 0

    def test_tool_result_content_counted(self):
        """Tool result blocks (list content) should not crash the counter."""
        msgs = [
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "tc_1", "content": "nmap output here"}
                ]
            }
        ]
        count = count_tokens(msgs)
        assert count >= 0  # Should not raise


# ─────────────────────────────────────────────────────────────────────────────
#  needs_compression
# ─────────────────────────────────────────────────────────────────────────────

class TestNeedsCompression:

    def _make_big_messages(self, n: int) -> list[dict]:
        """Generate a list of messages with ~4000 tokens each."""
        text = "a" * 16000  # ~4000 tokens at 4 chars/token
        return [{"role": "user", "content": text} for _ in range(n)]

    def test_small_conversation_no_compression(self):
        msgs = [{"role": "user", "content": "hello"}]
        assert not needs_compression(msgs, provider="anthropic", context_window=200_000)

    def test_large_conversation_triggers_compression(self):
        msgs = self._make_big_messages(50)
        # Use a small window to force trigger
        assert needs_compression(msgs, provider="anthropic", context_window=1000)

    def test_threshold_respected(self):
        """Compression triggers at COMPRESSION_THRESHOLD of the window."""
        msgs = [{"role": "user", "content": "x"}]
        # Window of 1 token → even 1 token is over 92%
        assert needs_compression(msgs, provider="anthropic", context_window=1)


# ─────────────────────────────────────────────────────────────────────────────
#  compress()
# ─────────────────────────────────────────────────────────────────────────────

class TestCompress:

    @pytest.mark.asyncio
    async def test_compress_reduces_message_count(self):
        from src.core.context import compress

        # Build 20 messages
        messages = []
        for i in range(20):
            messages.append({"role": "user", "content": f"message {i}"})
            messages.append({"role": "assistant", "content": f"response {i}"})

        mock_llm = AsyncMock()
        from src.core.llm import LLMResponse
        mock_llm.create_message = AsyncMock(return_value=LLMResponse(
            text="## Target\n10.10.10.1\n## Findings\nPort 80 open\n",
            tool_calls=[],
            stop_reason="end_turn",
            raw=None,
        ))

        compressed = await compress(messages, llm=mock_llm)

        # Should have fewer messages than original (summary + recent kept)
        assert len(compressed) < len(messages)

    @pytest.mark.asyncio
    async def test_compress_keeps_recent_messages(self):
        from src.core.context import compress, KEEP_RECENT

        messages = []
        for i in range(30):
            messages.append({"role": "user", "content": f"message {i}"})
            messages.append({"role": "assistant", "content": f"response {i}"})

        mock_llm = AsyncMock()
        from src.core.llm import LLMResponse
        mock_llm.create_message = AsyncMock(return_value=LLMResponse(
            text="Summary text",
            tool_calls=[],
            stop_reason="end_turn",
            raw=None,
        ))

        compressed = await compress(messages, llm=mock_llm)

        # Recent messages should be preserved verbatim
        recent_content = [m["content"] for m in messages[-KEEP_RECENT:] if isinstance(m.get("content"), str)]
        compressed_content = [m["content"] for m in compressed if isinstance(m.get("content"), str)]
        for content in recent_content:
            assert content in compressed_content

    @pytest.mark.asyncio
    async def test_compress_short_history_unchanged(self):
        """compress() on a short history should return it unchanged."""
        from src.core.context import compress, KEEP_RECENT
        messages = [{"role": "user", "content": f"msg {i}"} for i in range(KEEP_RECENT - 1)]
        mock_llm = AsyncMock()
        compressed = await compress(messages, llm=mock_llm)
        assert len(compressed) == len(messages)
