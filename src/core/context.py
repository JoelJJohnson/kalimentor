"""Context window management — token counting and conversation compression.

When the conversation approaches the model's context limit, compress() summarises
the oldest messages into a single summary message, preserving all discovered facts.
Key facts are also written to KALIMENTOR.md so they survive future compressions.
"""

from __future__ import annotations

import json
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .llm import LLMBackend
    from .session import SessionManager

# Fraction of context window at which compression triggers
COMPRESSION_THRESHOLD = 0.92

# How many recent messages to keep verbatim after compression
KEEP_RECENT = 10

COMPRESSION_PROMPT = """\
You are summarising a cybersecurity engagement conversation for long-term memory.

Produce a concise but COMPLETE summary. You MUST preserve:
- All discovered facts (open ports, services, OS, hostnames, software versions)
- All credentials (usernames, passwords, hashes, API keys, tokens)
- All confirmed vulnerabilities and CVEs
- Every access level change (user → root, etc.)
- What techniques were attempted and whether they succeeded or failed
- Current engagement phase and next planned steps
- Any captured flags

Format as structured Markdown under these headings:
## Target
## Findings
## Credentials
## Attack Path (what worked)
## Dead Ends (what failed)
## Current Position
## Next Steps

Be factually precise. Do NOT omit any credential, port, or access level detail.
"""


# ─────────────────────────────────────────────────────────────────────────────
#  Token counting
# ─────────────────────────────────────────────────────────────────────────────

def count_tokens(messages: list[dict[str, Any]], provider: str = "anthropic") -> int:
    """Approximate token count for a list of messages.

    Uses tiktoken for OpenAI/DeepSeek if available; falls back to the
    4-chars-per-token heuristic for all other providers.
    """
    if provider in ("openai", "deepseek"):
        try:
            import tiktoken
            enc = tiktoken.get_encoding("cl100k_base")
            total = 0
            for msg in messages:
                content = msg.get("content", "")
                if isinstance(content, str):
                    total += len(enc.encode(content))
                elif isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict):
                            total += len(enc.encode(json.dumps(block)))
            return total
        except ImportError:
            pass

    # Heuristic: 4 chars ≈ 1 token
    total_chars = 0
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str):
            total_chars += len(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    total_chars += len(json.dumps(block))
        total_chars += 4  # role overhead
    return total_chars // 4


# ─────────────────────────────────────────────────────────────────────────────
#  Compression
# ─────────────────────────────────────────────────────────────────────────────

async def compress(
    messages: list[dict[str, Any]],
    llm: "LLMBackend",
    session_manager: "SessionManager | None" = None,
) -> list[dict[str, Any]]:
    """Compress old messages into a summary, keeping KEEP_RECENT messages verbatim.

    1. Takes all messages except the last KEEP_RECENT.
    2. Asks the LLM to summarise them.
    3. Replaces them with a single summary system message.
    4. Optionally writes key facts to KALIMENTOR.md via session_manager.

    Returns the new (shorter) message list.
    """
    if len(messages) <= KEEP_RECENT:
        return messages

    to_summarise = messages[:-KEEP_RECENT]
    to_keep = messages[-KEEP_RECENT:]

    # Build a plain-text dump for the summarisation call
    history_text = _messages_to_text(to_summarise)

    from .llm import user_message
    summary_messages = [user_message(
        f"{COMPRESSION_PROMPT}\n\n---\n\nConversation to summarise:\n\n{history_text}"
    )]

    response = await llm.create_message(
        messages=summary_messages,
        system="You are a precise summarisation assistant.",
        tools=None,
    )
    summary = response.text.strip()

    # Write summary to KALIMENTOR.md so it survives future compressions
    if session_manager is not None:
        _write_compression_memory(session_manager, summary)
        session_manager.save_messages(
            [_make_summary_message(summary)] + to_keep
        )

    return [_make_summary_message(summary)] + to_keep


def needs_compression(
    messages: list[dict[str, Any]],
    provider: str,
    context_window: int | None = None,
) -> bool:
    """Return True if message history is at or beyond the compression threshold."""
    from .llm import CONTEXT_WINDOWS
    window = context_window or CONTEXT_WINDOWS.get(provider, 8_000)
    used = count_tokens(messages, provider)
    return used >= int(window * COMPRESSION_THRESHOLD)


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_summary_message(summary: str) -> dict[str, Any]:
    return {
        "role": "user",
        "content": (
            f"[Context Summary — previous conversation compressed]\n\n{summary}"
        ),
    }


def _messages_to_text(messages: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for msg in messages:
        role = msg.get("role", "unknown").upper()
        content = msg.get("content", "")
        if isinstance(content, str):
            lines.append(f"[{role}]\n{content}\n")
        elif isinstance(content, list):
            parts: list[str] = []
            for block in content:
                if not isinstance(block, dict):
                    continue
                btype = block.get("type", "")
                if btype == "text":
                    parts.append(block.get("text", ""))
                elif btype == "tool_use":
                    parts.append(
                        f"<tool_call name={block.get('name','')}>"
                        f"{json.dumps(block.get('input', {}))}</tool_call>"
                    )
                elif btype == "tool_result":
                    inner = block.get("content", "")
                    if isinstance(inner, list):
                        inner = " ".join(
                            b.get("text", "") for b in inner if isinstance(b, dict)
                        )
                    parts.append(f"<tool_result>{inner}</tool_result>")
            lines.append(f"[{role}]\n{''.join(parts)}\n")
    return "\n".join(lines)


def _write_compression_memory(
    session_manager: "SessionManager",
    summary: str,
) -> None:
    """Append or overwrite the compression summary in KALIMENTOR.md."""
    memory_path = session_manager.session_dir / "KALIMENTOR.md"
    if memory_path.exists():
        existing = memory_path.read_text(encoding="utf-8")
        # Replace the previous compression block if present
        marker = "<!-- compression-summary -->"
        if marker in existing:
            before = existing[: existing.index(marker)]
            memory_path.write_text(
                f"{before}{marker}\n{summary}\n", encoding="utf-8"
            )
        else:
            memory_path.write_text(
                existing + f"\n\n<!-- compression-summary -->\n{summary}\n",
                encoding="utf-8",
            )
    else:
        memory_path.write_text(
            f"# KaliMentor Session Memory\n\n<!-- compression-summary -->\n{summary}\n",
            encoding="utf-8",
        )
