# tests/test_llm_streaming.py
import asyncio, json, pytest
from unittest.mock import AsyncMock, patch, MagicMock
from src.core.stream import TextChunk, ToolCallEvent, UsageEvent

# Helper to collect all events from an async generator
async def collect(gen):
    return [item async for item in gen]

@pytest.mark.asyncio
async def test_anthropic_stream_text_only():
    """stream_message yields TextChunk events for a pure-text response."""
    from src.core.llm import AnthropicBackend
    backend = AnthropicBackend(model="claude-3-haiku-20240307", api_key="test-key")

    sse_lines = [
        'event: message_start',
        'data: {"type":"message_start","message":{"usage":{"input_tokens":10}}}',
        '',
        'event: content_block_start',
        'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
        '',
        'event: content_block_delta',
        'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}',
        '',
        'event: content_block_delta',
        'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" world"}}',
        '',
        'event: content_block_stop',
        'data: {"type":"content_block_stop","index":0}',
        '',
        'event: message_delta',
        'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}',
        '',
        'event: message_stop',
        'data: {"type":"message_stop"}',
        '',
    ]

    async def mock_aiter_lines():
        for line in sse_lines:
            yield line

    mock_response = MagicMock()
    mock_response.aiter_lines = mock_aiter_lines
    mock_response.raise_for_status = MagicMock()

    mock_stream_cm = AsyncMock()
    mock_stream_cm.__aenter__ = AsyncMock(return_value=mock_response)
    mock_stream_cm.__aexit__ = AsyncMock(return_value=False)

    with patch('httpx.AsyncClient') as MockClient:
        mock_client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_client.stream = MagicMock(return_value=mock_stream_cm)

        events = await collect(backend.stream_message(
            messages=[{"role": "user", "content": "hi"}],
            system="",
        ))

    text_events = [e for e in events if isinstance(e, TextChunk)]
    usage_events = [e for e in events if isinstance(e, UsageEvent)]

    assert len(text_events) == 2
    assert text_events[0].text == "Hello"
    assert text_events[1].text == " world"
    assert len(usage_events) == 1
    assert usage_events[0].input_tokens == 10
    assert usage_events[0].output_tokens == 5
