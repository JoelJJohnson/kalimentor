"""Phase 2 test suite — context management and memory.

Covers:
  2.1  Conversation history storage (messages.jsonl, rotation, resume)
  2.2  Context compression (token counting, needs_compression, compress())
  2.3  KALIMENTOR.md management (read/write/append, template init, agent injection)
  2.4  Plan reminder format (as_reminder() exact format, per-session store)

Tests run without a real LLM or network.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_msg(role: str, text: str) -> dict[str, Any]:
    return {"role": role, "content": text}


def _mock_llm(response_text: str = "Summary of session."):
    """Return a mock LLMBackend whose create_message() returns response_text."""
    from src.core.llm import LLMResponse
    llm = AsyncMock()
    llm.provider = "anthropic"
    llm.create_message = AsyncMock(
        return_value=LLMResponse(
            text=response_text,
            tool_calls=[],
            stop_reason="end_turn",
            raw=None,
        )
    )
    return llm


# ─────────────────────────────────────────────────────────────────────────────
#  2.1 — Conversation History Storage
# ─────────────────────────────────────────────────────────────────────────────

class TestConversationHistory:

    def test_new_session_creates_directory(self, tmp_path, monkeypatch):
        monkeypatch.setattr("src.core.session.SESSIONS_DIR", tmp_path)
        from src.core.session import SessionManager
        sm = SessionManager.new(objective="test")
        assert sm.session_dir.is_dir()
        assert (sm.session_dir / "state.json").exists()

    def test_append_and_load_messages(self, tmp_path, monkeypatch):
        monkeypatch.setattr("src.core.session.SESSIONS_DIR", tmp_path)
        from src.core.session import SessionManager
        sm = SessionManager.new(objective="test")

        sm.append_message(_make_msg("user", "hello"))
        sm.append_message(_make_msg("assistant", "hi"))

        msgs = sm.load_messages()
        assert len(msgs) == 2
        assert msgs[0]["role"] == "user"
        assert msgs[1]["content"] == "hi"

    def test_load_messages_empty_when_no_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr("src.core.session.SESSIONS_DIR", tmp_path)
        from src.core.session import SessionManager
        sm = SessionManager.new(objective="test")
        assert sm.load_messages() == []

    def test_save_messages_overwrites(self, tmp_path, monkeypatch):
        monkeypatch.setattr("src.core.session.SESSIONS_DIR", tmp_path)
        from src.core.session import SessionManager
        sm = SessionManager.new(objective="test")

        sm.append_message(_make_msg("user", "old"))
        sm.save_messages([_make_msg("user", "new")])

        msgs = sm.load_messages()
        assert len(msgs) == 1
        assert msgs[0]["content"] == "new"

    def test_session_resume_restores_messages(self, tmp_path, monkeypatch):
        monkeypatch.setattr("src.core.session.SESSIONS_DIR", tmp_path)
        from src.core.session import SessionManager
        sm = SessionManager.new(objective="test")
        sid = sm.state.id

        sm.append_message(_make_msg("user", "ping"))
        sm.append_message(_make_msg("assistant", "pong"))

        sm2 = SessionManager.load(sid)
        msgs = sm2.load_messages()
        assert len(msgs) == 2
        assert msgs[1]["content"] == "pong"

    def test_messages_file_rotation(self, tmp_path, monkeypatch):
        monkeypatch.setattr("src.core.session.SESSIONS_DIR", tmp_path)
        monkeypatch.setattr("src.core.session.MAX_MESSAGES_FILE_BYTES", 10)
        from src.core.session import SessionManager
        sm = SessionManager.new(objective="test")

        # First write exceeds 10 bytes immediately
        sm.append_message(_make_msg("user", "first"))
        # Second append should rotate
        sm.append_message(_make_msg("user", "second"))

        assert (sm.session_dir / "messages.1.jsonl").exists()

    def test_list_sessions_includes_new_layout(self, tmp_path, monkeypatch):
        monkeypatch.setattr("src.core.session.SESSIONS_DIR", tmp_path)
        from src.core.session import SessionManager
        sm = SessionManager.new(objective="enum test")
        sessions = SessionManager.list_sessions()
        ids = [s["id"] for s in sessions]
        assert sm.state.id in ids

    def test_legacy_flatfile_migration(self, tmp_path, monkeypatch):
        """A legacy {id}.json file should be auto-migrated on load."""
        monkeypatch.setattr("src.core.session.SESSIONS_DIR", tmp_path)
        from src.core.session import SessionManager, SessionState
        # Write a legacy flat file
        state = SessionState(objective="legacy")
        sid = state.id
        (tmp_path / f"{sid}.json").write_text(state.model_dump_json())

        sm = SessionManager.load(sid)
        assert sm.state.objective == "legacy"
        # Legacy file removed, directory created
        assert not (tmp_path / f"{sid}.json").exists()
        assert (tmp_path / sid / "state.json").exists()


# ─────────────────────────────────────────────────────────────────────────────
#  2.2 — Context Compression
# ─────────────────────────────────────────────────────────────────────────────

class TestContextCompression:

    def test_count_tokens_heuristic(self):
        from src.core.context import count_tokens
        # 400 content chars + 4 role overhead = 404 chars → 404 // 4 = 101 tokens
        msgs = [_make_msg("user", "a" * 400)]
        assert count_tokens(msgs, "anthropic") == 101

    def test_count_tokens_list_content(self):
        from src.core.context import count_tokens
        msgs = [{"role": "assistant", "content": [{"type": "text", "text": "a" * 100}]}]
        assert count_tokens(msgs, "anthropic") > 0

    def test_needs_compression_false_small(self):
        from src.core.context import needs_compression
        msgs = [_make_msg("user", "hello")]
        assert not needs_compression(msgs, "anthropic")

    def test_needs_compression_true_over_limit(self):
        from src.core.context import needs_compression
        # ollama window = 8000 tokens, threshold 92% = 7360
        # 7500 tokens * 4 chars/token = 30000 chars
        msgs = [_make_msg("user", "x" * 30_000)]
        assert needs_compression(msgs, "ollama")

    def test_needs_compression_custom_window(self):
        from src.core.context import needs_compression
        msgs = [_make_msg("user", "x" * 4000)]  # 1000 tokens
        # window=1000, threshold=92% → 920 tokens; 1000 > 920
        assert needs_compression(msgs, "anthropic", context_window=1000)

    def test_compress_reduces_message_count(self):
        from src.core.context import compress, KEEP_RECENT
        llm = _mock_llm("## Target\n10.10.10.5\n\n## Findings\nPort 80 open")

        # 15 messages: 5 will be compressed, 10 kept
        msgs = [_make_msg("user" if i % 2 == 0 else "assistant", f"msg {i}")
                for i in range(15)]

        result = asyncio.run(compress(msgs, llm))
        assert len(result) == KEEP_RECENT + 1  # summary + kept

    def test_compress_keeps_recent_verbatim(self):
        from src.core.context import compress, KEEP_RECENT
        llm = _mock_llm("Summary text")

        msgs = [_make_msg("user" if i % 2 == 0 else "assistant", f"msg {i}")
                for i in range(15)]

        result = asyncio.run(compress(msgs, llm))
        # The last KEEP_RECENT messages should be preserved exactly
        assert result[-KEEP_RECENT:] == msgs[-KEEP_RECENT:]

    def test_compress_noop_when_few_messages(self):
        from src.core.context import compress, KEEP_RECENT
        llm = _mock_llm()
        msgs = [_make_msg("user", "hi")]
        result = asyncio.run(compress(msgs, llm))
        assert result == msgs
        llm.create_message.assert_not_called()

    def test_compress_writes_kalimentor_md(self, tmp_path, monkeypatch):
        monkeypatch.setattr("src.core.session.SESSIONS_DIR", tmp_path)
        from src.core.session import SessionManager
        from src.core.context import compress, KEEP_RECENT

        sm = SessionManager.new(objective="test")
        llm = _mock_llm("## Target\n10.10.10.5")

        msgs = [_make_msg("user" if i % 2 == 0 else "assistant", f"turn {i}")
                for i in range(15)]

        asyncio.run(compress(msgs, llm, session_manager=sm))

        mem = (sm.session_dir / "KALIMENTOR.md").read_text()
        assert "10.10.10.5" in mem

    def test_compress_updates_messages_jsonl(self, tmp_path, monkeypatch):
        monkeypatch.setattr("src.core.session.SESSIONS_DIR", tmp_path)
        from src.core.session import SessionManager
        from src.core.context import compress, KEEP_RECENT

        sm = SessionManager.new(objective="test")
        llm = _mock_llm("Summary")

        msgs = [_make_msg("user" if i % 2 == 0 else "assistant", f"turn {i}")
                for i in range(15)]

        result = asyncio.run(compress(msgs, llm, session_manager=sm))

        # messages.jsonl should reflect compressed history
        persisted = sm.load_messages()
        assert len(persisted) == len(result)


# ─────────────────────────────────────────────────────────────────────────────
#  2.3 — KALIMENTOR.md Management
# ─────────────────────────────────────────────────────────────────────────────

class TestMemoryManagement:

    def test_creates_template_on_first_read(self, tmp_path):
        from src.core.memory import read_session_memory, MEMORY_TEMPLATE
        text = read_session_memory(tmp_path)
        assert "KaliMentor Session Memory" in text
        assert (tmp_path / "KALIMENTOR.md").exists()

    def test_write_and_read_roundtrip(self, tmp_path):
        from src.core.memory import write_session_memory, read_session_memory
        write_session_memory(tmp_path, "# My Notes\n\n## Target\n10.10.10.5\n")
        assert "10.10.10.5" in read_session_memory(tmp_path)

    def test_append_under_existing_section(self, tmp_path):
        from src.core.memory import write_session_memory, append_session_memory, read_session_memory
        write_session_memory(tmp_path, "# KaliMentor Session Memory\n\n## Credentials\n\n## Dead Ends\n")
        append_session_memory(tmp_path, "Credentials", "admin:password123")
        text = read_session_memory(tmp_path)
        assert "admin:password123" in text
        # Should appear before Dead Ends
        assert text.index("admin:password123") < text.index("## Dead Ends")

    def test_append_creates_new_section(self, tmp_path):
        from src.core.memory import write_session_memory, append_session_memory, read_session_memory
        write_session_memory(tmp_path, "# KaliMentor Session Memory\n\n## Target\n10.0.0.1\n")
        append_session_memory(tmp_path, "New Section", "some content")
        text = read_session_memory(tmp_path)
        assert "## New Section" in text
        assert "some content" in text

    def test_is_empty_true_for_fresh(self, tmp_path):
        from src.core.memory import is_empty, ensure_memory
        ensure_memory(tmp_path)
        assert is_empty(tmp_path)

    def test_is_empty_false_after_write(self, tmp_path):
        from src.core.memory import is_empty, write_session_memory
        write_session_memory(tmp_path, "# KaliMentor\n\n## Target\n10.10.10.5\n")
        assert not is_empty(tmp_path)

    def test_compression_marker_idempotent(self, tmp_path):
        """Second compression should replace the old summary, not append."""
        from src.core.context import _write_compression_memory
        from src.core.session import SessionManager
        import tempfile
        from unittest.mock import MagicMock

        sm = MagicMock()
        sm.session_dir = tmp_path

        _write_compression_memory(sm, "First summary")
        _write_compression_memory(sm, "Second summary")

        text = (tmp_path / "KALIMENTOR.md").read_text()
        assert "Second summary" in text
        assert "First summary" not in text

    def test_agent_injects_memory_in_system(self, tmp_path, monkeypatch):
        """AgentLoop._build_system() should include KALIMENTOR.md contents."""
        from src.core.memory import write_session_memory
        write_session_memory(tmp_path, "# KaliMentor\n\n## Target\n192.168.1.1\n")

        from src.core.agent import AgentLoop
        from src.core.tools.registry import ToolRegistry

        agent = AgentLoop(
            llm=_mock_llm(),
            registry=ToolRegistry(),
            system="Base system prompt",
            session_dir=str(tmp_path),
        )
        system = agent._build_system()
        assert "192.168.1.1" in system

    def test_agent_skips_blank_template_injection(self, tmp_path):
        """AgentLoop should not inject the blank template into the system prompt."""
        from src.core.memory import ensure_memory
        ensure_memory(tmp_path)

        from src.core.agent import AgentLoop
        from src.core.tools.registry import ToolRegistry

        agent = AgentLoop(
            llm=_mock_llm(),
            registry=ToolRegistry(),
            system="Base system prompt",
            session_dir=str(tmp_path),
        )
        system = agent._build_system()
        assert "to be filled by agent" not in system


# ─────────────────────────────────────────────────────────────────────────────
#  2.4 — Plan Reminder Injection
# ─────────────────────────────────────────────────────────────────────────────

class TestPlanReminder:

    def test_empty_store_returns_empty_string(self):
        from src.core.tools.plan_tool import PlanStore
        assert PlanStore().as_reminder() == ""

    def test_reminder_format(self):
        from src.core.tools.plan_tool import PlanStore
        store = PlanStore()
        store.update([
            {"id": "1", "task": "Nmap scan", "status": "done", "priority": 1},
            {"id": "2", "task": "Enum HTTP", "status": "in_progress", "priority": 2},
            {"id": "3", "task": "Find exploits", "status": "pending", "priority": 3},
            {"id": "4", "task": "Try creds", "status": "pending", "priority": 4},
        ])
        r = store.as_reminder()
        assert "[Plan Status]" in r
        assert "1 done" in r
        assert "1 in progress" in r
        assert "2 pending" in r
        assert "Next: Enum HTTP" in r

    def test_failed_tasks_shown(self):
        from src.core.tools.plan_tool import PlanStore
        store = PlanStore()
        store.update([
            {"id": "1", "task": "Try exploit", "status": "failed"},
            {"id": "2", "task": "Try other", "status": "pending"},
        ])
        r = store.as_reminder()
        assert "1 failed" in r

    def test_next_task_is_in_progress_before_pending(self):
        from src.core.tools.plan_tool import PlanStore
        store = PlanStore()
        store.update([
            {"id": "1", "task": "In flight", "status": "in_progress", "priority": 2},
            {"id": "2", "task": "Queued", "status": "pending", "priority": 1},
        ])
        r = store.as_reminder()
        assert "Next: In flight" in r

    def test_each_agent_loop_has_own_plan_store(self):
        """Two AgentLoop instances must not share plan state."""
        from src.core.agent import AgentLoop
        from src.core.tools.registry import ToolRegistry

        a1 = AgentLoop(llm=_mock_llm(), registry=ToolRegistry(), system="s")
        a2 = AgentLoop(llm=_mock_llm(), registry=ToolRegistry(), system="s")

        a1._plan_store.update([{"id": "x", "task": "loop1 task", "status": "pending"}])

        assert a2._plan_store.as_reminder() == ""

    def test_plan_reminder_in_system_prompt(self, tmp_path):
        from src.core.agent import AgentLoop
        from src.core.tools.registry import ToolRegistry

        agent = AgentLoop(
            llm=_mock_llm(),
            registry=ToolRegistry(),
            system="Base",
            session_dir=str(tmp_path),
        )
        agent._plan_store.update([
            {"id": "1", "task": "Run nmap", "status": "in_progress"},
        ])
        system = agent._build_system()
        assert "[Plan Status]" in system
        assert "Run nmap" in system
