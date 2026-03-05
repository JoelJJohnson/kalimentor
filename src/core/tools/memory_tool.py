"""Memory tool — read and write KALIMENTOR.md session memory.

The LLM calls these tools after significant discoveries:
  - New credentials found
  - Confirmed vulnerabilities
  - Access level changes
  - Dead ends to avoid repeating

KALIMENTOR.md is also prepended to the system prompt at every LLM call
so the agent always has its notes in context.
"""

from __future__ import annotations

from .registry import ToolRegistry, ToolRiskLevel
from ..memory import read_session_memory, write_session_memory, ensure_memory


def register_memory_tools(registry: ToolRegistry, session_dir: str) -> None:
    """Register ``read_memory`` and ``write_memory`` tools into *registry*."""

    # Ensure the file exists on startup
    ensure_memory(session_dir)

    # ── read_memory ────────────────────────────────────────────────────────

    @registry.register(
        name="read_memory",
        description=(
            "Read the current KALIMENTOR.md session memory file. "
            "Contains discovered facts, credentials, attack path, and dead ends."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "required": [],
        },
        risk=ToolRiskLevel.SAFE,
    )
    async def read_memory() -> str:
        return read_session_memory(session_dir)

    # ── write_memory ───────────────────────────────────────────────────────

    @registry.register(
        name="write_memory",
        description=(
            "Write or update the KALIMENTOR.md session memory file. "
            "Call this after significant discoveries: new creds, confirmed vulns, "
            "access level changes, or dead ends. Pass the full updated markdown content."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "Full markdown content to write to KALIMENTOR.md.",
                },
            },
            "required": ["content"],
        },
        risk=ToolRiskLevel.SAFE,
    )
    async def write_memory(content: str) -> str:
        write_session_memory(session_dir, content)
        return f"[OK] Memory updated ({len(content)} chars)."
