"""Phase 4.2 — Hooks system tests.

Covers:
- HookManager.load() with missing / malformed / valid YAML
- Hook.matches() regex behaviour
- HookManager.fire() dispatches to correct hooks
- Environment variable building
- on_flag / pre_tool / post_tool event routing
"""

from __future__ import annotations

import asyncio
import os
import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from src.core.hooks import Hook, HookManager, VALID_EVENTS


# ── Hook.matches ──────────────────────────────────────────────────────────────

def test_hook_matches_no_pattern():
    h = Hook(name="h", event="post_tool", run="echo hi")
    assert h.matches("anything") is True
    assert h.matches("") is True


def test_hook_matches_with_pattern():
    h = Hook(name="h", event="on_finding", run="echo hi", match=r"CVE-\d{4}-\d+")
    assert h.matches("Found CVE-2024-1234 in output") is True
    assert h.matches("no match here") is False


def test_hook_matches_case_insensitive():
    h = Hook(name="h", event="post_tool", run="echo", match="password")
    assert h.matches("PASSWORD=secret") is True
    assert h.matches("username=admin") is False


def test_hook_invalid_regex_raises():
    with pytest.raises(ValueError, match="invalid regex"):
        Hook(name="h", event="post_tool", run="echo", match="[invalid")


# ── HookManager.load ──────────────────────────────────────────────────────────

def test_load_missing_file():
    mgr = HookManager.load(Path("/nonexistent/hooks.yaml"))
    assert len(mgr) == 0


def test_load_valid_yaml(tmp_path):
    hooks_file = tmp_path / "hooks.yaml"
    hooks_file.write_text(textwrap.dedent("""\
        hooks:
          - name: test_hook
            event: post_tool
            run: echo $TOOL_NAME
          - name: flag_hook
            event: on_flag
            run: echo $FLAG_VALUE
            match: "HTB[{].*[}]"
    """))
    mgr = HookManager.load(hooks_file)
    assert len(mgr) == 2
    names = [h.name for h in mgr.list_hooks()]
    assert "test_hook" in names
    assert "flag_hook" in names


def test_load_unknown_event_skipped(tmp_path):
    hooks_file = tmp_path / "hooks.yaml"
    hooks_file.write_text(textwrap.dedent("""\
        hooks:
          - name: good
            event: pre_tool
            run: echo ok
          - name: bad
            event: nonexistent_event
            run: echo bad
    """))
    mgr = HookManager.load(hooks_file)
    assert len(mgr) == 1
    assert mgr.list_hooks()[0].name == "good"


def test_load_missing_run_skipped(tmp_path):
    hooks_file = tmp_path / "hooks.yaml"
    hooks_file.write_text(textwrap.dedent("""\
        hooks:
          - name: broken
            event: post_tool
    """))
    mgr = HookManager.load(hooks_file)
    assert len(mgr) == 0


def test_empty_factory():
    mgr = HookManager.empty()
    assert len(mgr) == 0
    assert mgr.list_hooks() == []


# ── Valid events ──────────────────────────────────────────────────────────────

def test_all_expected_events_exist():
    expected = {"pre_tool", "post_tool", "pre_session", "post_session",
                "on_finding", "on_shell", "on_flag"}
    assert expected == VALID_EVENTS


# ── HookManager.fire ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fire_dispatches_correct_event(tmp_path):
    hooks_file = tmp_path / "hooks.yaml"
    hooks_file.write_text(textwrap.dedent("""\
        hooks:
          - name: pre
            event: pre_tool
            run: echo pre
          - name: post
            event: post_tool
            run: echo post
    """))
    mgr = HookManager.load(hooks_file)

    fired: list[str] = []

    async def fake_run(hook, ctx):
        fired.append(hook.name)

    with patch.object(mgr, "_run_hook", side_effect=fake_run):
        await mgr.fire("pre_tool", {})
        assert fired == ["pre"]
        await mgr.fire("post_tool", {})
        assert fired == ["pre", "post"]
        await mgr.fire("on_flag", {})
        assert fired == ["pre", "post"]   # no on_flag hooks


@pytest.mark.asyncio
async def test_fire_respects_match_filter(tmp_path):
    hooks_file = tmp_path / "hooks.yaml"
    hooks_file.write_text(textwrap.dedent("""\
        hooks:
          - name: cve_hook
            event: on_finding
            run: echo cve
            match: "CVE-"
          - name: any_hook
            event: on_finding
            run: echo any
    """))
    mgr = HookManager.load(hooks_file)

    fired: list[str] = []

    async def fake_run(hook, ctx):
        fired.append(hook.name)

    with patch.object(mgr, "_run_hook", side_effect=fake_run):
        # Only any_hook should fire (no CVE in match_text)
        await mgr.fire("on_finding", {}, match_text="some random output")
        assert fired == ["any_hook"]

        fired.clear()
        # Both should fire when CVE is present
        await mgr.fire("on_finding", {}, match_text="Found CVE-2024-9999")
        assert set(fired) == {"cve_hook", "any_hook"}


# ── Environment variable building ────────────────────────────────────────────

def test_build_env_maps_all_keys():
    ctx = {
        "target": "10.10.10.1",
        "session_id": "sess-abc",
        "tool_name": "bash",
        "tool_input": {"command": "ls"},
        "tool_output": "file1\nfile2",
        "phase": "recon",
        "flag_value": "HTB{flag}",
    }
    env = HookManager._build_env(ctx)
    assert env["TARGET"] == "10.10.10.1"
    assert env["SESSION_ID"] == "sess-abc"
    assert env["TOOL_NAME"] == "bash"
    assert "command" in env["TOOL_INPUT"]   # JSON-encoded dict
    assert env["TOOL_OUTPUT"] == "file1\nfile2"
    assert env["PHASE"] == "recon"
    assert env["FLAG_VALUE"] == "HTB{flag}"


def test_build_env_missing_keys_default_empty():
    env = HookManager._build_env({})
    assert env["TARGET"] == ""
    assert env["FLAG_VALUE"] == ""


# ── Shell obtained detection (on_shell pattern) ───────────────────────────────

@pytest.mark.asyncio
async def test_on_shell_hook_fires_on_shell_indicators(tmp_path):
    """Simulate the agent's _fire_post_hooks on_shell check."""
    hooks_file = tmp_path / "hooks.yaml"
    hooks_file.write_text(textwrap.dedent("""\
        hooks:
          - name: shell_obtained
            event: on_shell
            run: echo SHELL
    """))
    mgr = HookManager.load(hooks_file)

    fired: list[str] = []

    async def fake_run(hook, ctx):
        fired.append(hook.name)

    shell_output = "root@victim:~# id\nuid=0(root) gid=0(root)"

    with patch.object(mgr, "_run_hook", side_effect=fake_run):
        # Simulate the on_shell check from agent._fire_post_hooks
        _SHELL_INDICATORS = ("$ ", "# ", "bash-", "sh-", "root@", "www-data@",
                              "whoami", "id=", "uid=", "/bin/bash", "PTY allocated")
        if any(ind in shell_output for ind in _SHELL_INDICATORS):
            await mgr.fire("on_shell", {}, match_text=shell_output)

    assert "shell_obtained" in fired
