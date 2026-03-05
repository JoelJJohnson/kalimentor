"""Session memory — KALIMENTOR.md read/write helpers.

KALIMENTOR.md is the agent's long-term memory file for a session.
It is:
  - Created from a template when a new session starts.
  - Read at the start of every user turn and prepended to the LLM context.
  - Written/appended by the agent after significant discoveries.
  - Updated during context compression to preserve key facts.

Layout: ~/.kalimentor/sessions/{id}/KALIMENTOR.md
"""

from __future__ import annotations

from pathlib import Path

MEMORY_FILENAME = "KALIMENTOR.md"

MEMORY_TEMPLATE = """\
# KaliMentor Session Memory

## Target
(to be filled by agent)

## Findings

## Credentials

## Attack Path

## Dead Ends

## Current Position
"""


# ─────────────────────────────────────────────────────────────────────────────
#  Path helpers
# ─────────────────────────────────────────────────────────────────────────────

def memory_path(session_dir: Path | str) -> Path:
    return Path(session_dir) / MEMORY_FILENAME


def ensure_memory(session_dir: Path | str) -> Path:
    """Create KALIMENTOR.md from template if it does not exist. Returns path."""
    p = memory_path(session_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        p.write_text(MEMORY_TEMPLATE, encoding="utf-8")
    return p


# ─────────────────────────────────────────────────────────────────────────────
#  Public API
# ─────────────────────────────────────────────────────────────────────────────

def read_session_memory(session_dir: Path | str) -> str:
    """Return the full contents of KALIMENTOR.md (creates it if absent)."""
    return ensure_memory(session_dir).read_text(encoding="utf-8", errors="replace")


def write_session_memory(session_dir: Path | str, content: str) -> None:
    """Overwrite KALIMENTOR.md with *content*."""
    p = ensure_memory(session_dir)
    p.write_text(content, encoding="utf-8")


def append_session_memory(
    session_dir: Path | str,
    section: str,
    content: str,
) -> None:
    """Append *content* under the given *section* heading in KALIMENTOR.md.

    If the heading already exists, content is inserted after it (before the
    next heading). If not found, a new heading + content block is appended.

    Args:
        session_dir: Path to the session directory.
        section:     Heading text, e.g. ``"Credentials"`` (without ``## ``).
        content:     Text to append under that section.
    """
    p = ensure_memory(session_dir)
    text = p.read_text(encoding="utf-8")
    heading = f"## {section}"

    if heading in text:
        # Insert after the heading line
        idx = text.index(heading) + len(heading)
        # Skip to end of that line
        nl = text.find("\n", idx)
        insert_at = nl + 1 if nl != -1 else len(text)
        new_text = text[:insert_at] + content.rstrip("\n") + "\n" + text[insert_at:]
    else:
        new_text = text.rstrip("\n") + f"\n\n{heading}\n{content.rstrip()}\n"

    p.write_text(new_text, encoding="utf-8")


def is_empty(session_dir: Path | str) -> bool:
    """Return True if KALIMENTOR.md contains only the template (no real data)."""
    text = read_session_memory(session_dir)
    # Strip the template placeholder lines and check if anything remains
    stripped = text.replace(MEMORY_TEMPLATE, "").strip()
    return not stripped
