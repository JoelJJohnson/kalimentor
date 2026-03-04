"""Stream event types for live LLM output display."""
from __future__ import annotations
from dataclasses import dataclass
from typing import TYPE_CHECKING, Union

if TYPE_CHECKING:
    from .llm import ToolCall


@dataclass
class TextChunk:
    """A chunk of text from the LLM as it streams."""
    text: str


@dataclass
class ToolCallEvent:
    """A complete tool call parsed from the stream."""
    tool_call: "ToolCall"


@dataclass
class UsageEvent:
    """Token usage reported at end of stream."""
    input_tokens: int
    output_tokens: int


StreamEvent = Union[TextChunk, ToolCallEvent, UsageEvent]
