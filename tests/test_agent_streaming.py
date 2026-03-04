# tests/test_agent_streaming.py
import asyncio, pytest
from unittest.mock import AsyncMock, MagicMock, patch
from src.core.stream import TextChunk, ToolCallEvent, UsageEvent
from src.core.llm import ToolCall, LLMResponse


async def make_stream(*events):
    for e in events:
        yield e


@pytest.mark.asyncio
async def test_agent_uses_stream_message_when_available():
    """AgentLoop uses stream_message() when the backend supports it."""
    from src.core.agent import AgentLoop
    from src.core.tools.registry import ToolRegistry

    mock_llm = MagicMock()
    mock_llm.provider = "anthropic"
    mock_llm.context_window = 200_000

    # Backend has stream_message
    mock_llm.stream_message = MagicMock(return_value=make_stream(
        TextChunk(text="Hello"),
        TextChunk(text=" world"),
        UsageEvent(input_tokens=10, output_tokens=5),
    ))

    registry = ToolRegistry()
    loop = AgentLoop(llm=mock_llm, registry=registry, system="test")

    with patch.object(loop, '_persist_message'):
        with patch('src.core.agent.needs_compression', return_value=False):
            result = await loop.run("hi")

    assert "Hello" in result
    assert " world" in result
    mock_llm.stream_message.assert_called_once()


@pytest.mark.asyncio
async def test_agent_falls_back_to_create_message_when_no_stream():
    """AgentLoop falls back to create_message when stream_message not available."""
    from src.core.agent import AgentLoop
    from src.core.tools.registry import ToolRegistry

    mock_llm = MagicMock()
    mock_llm.provider = "anthropic"
    mock_llm.context_window = 200_000
    # No stream_message — use spec to exclude it
    del mock_llm.stream_message

    mock_llm.create_message = AsyncMock(return_value=LLMResponse(
        text="Fallback response",
        tool_calls=[],
        stop_reason="end_turn",
        raw=None,
    ))

    registry = ToolRegistry()
    loop = AgentLoop(llm=mock_llm, registry=registry, system="test")

    with patch.object(loop, '_persist_message'):
        with patch('src.core.agent.needs_compression', return_value=False):
            result = await loop.run("hi")

    assert result == "Fallback response"
    mock_llm.create_message.assert_called_once()
