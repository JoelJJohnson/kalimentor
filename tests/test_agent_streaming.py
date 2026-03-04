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


@pytest.mark.asyncio
async def test_agent_streams_bash_output():
    """AgentLoop uses on_line queue for bash tool output streaming."""
    from src.core.agent import AgentLoop
    from src.core.tools.registry import ToolRegistry
    from src.core.llm import ToolCall
    from src.core.tools.bash_tool import PersistentShell

    mock_llm = MagicMock()
    mock_llm.provider = "anthropic"
    mock_llm.context_window = 200_000

    tc = ToolCall(id="1", name="bash", input={"command": "echo hello"})

    call_count = 0

    async def fake_stream(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            yield ToolCallEvent(tool_call=tc)
        else:
            yield TextChunk(text="Done")

    mock_llm.stream_message = MagicMock(side_effect=fake_stream)

    registry = ToolRegistry()

    mock_shell = AsyncMock(spec=PersistentShell)
    mock_shell.run = AsyncMock(return_value=("hello\nworld", 0))

    loop = AgentLoop(llm=mock_llm, registry=registry, system="test")
    loop._bash_shell = mock_shell  # inject mock shell

    # Register stub bash tool so registry doesn't fail on execute
    @registry.register(
        name="bash",
        description="bash",
        input_schema={
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    )
    async def bash(command: str) -> str:
        return "hello\nworld"

    with patch.object(loop, '_persist_message'):
        with patch('src.core.agent.needs_compression', return_value=False):
            result = await loop.run("run something")

    # Shell was called with an on_line queue
    assert mock_shell.run.called
    call_kwargs = mock_shell.run.call_args
    # on_line should be in kwargs or args[2]
    on_line = call_kwargs.kwargs.get("on_line") or (call_kwargs.args[2] if len(call_kwargs.args) > 2 else None)
    assert on_line is not None, "shell.run was not called with on_line queue"
