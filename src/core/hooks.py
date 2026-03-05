"""Hooks system — pre/post tool and session lifecycle hooks.

Hooks are loaded from ~/.kalimentor/hooks.yaml and fired at defined event points
in the agent loop. Each hook runs a shell command with environment variables
describing the current context.

Hook points
-----------
pre_tool     Before a tool call executes.
post_tool    After a tool call completes.
pre_session  When a new agent session starts.
post_session When a session ends (/quit).
on_finding   When tool output matches a regex (e.g., CVE found, password found).
on_shell     When a shell is obtained (pattern match on bash output).
on_flag      When /flag <value> is recorded.

Hook definition schema (YAML)
------------------------------
hooks:
  - name: my_hook
    event: post_tool           # one of the hook points above
    match: "CVE-\\d{4}"        # optional regex; hook only fires if it matches
    run: "notify-send 'Hit: $TOOL_NAME'"

Environment variables available in `run`
-----------------------------------------
TARGET        Target IP / URL set at session start (empty if not set).
SESSION_ID    Session identifier string.
TOOL_NAME     Name of the tool that fired the hook (pre_tool / post_tool).
TOOL_INPUT    JSON-encoded tool input dict.
TOOL_OUTPUT   Tool result string (post_tool only).
PHASE         Current session phase label (empty if not set).
FLAG_VALUE    The flag string (/flag hooks only).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore[import]
    _YAML_OK = True
except ImportError:
    _YAML_OK = False

# ── Constants ─────────────────────────────────────────────────────────────────

HOOKS_FILE = Path.home() / ".kalimentor" / "hooks.yaml"

VALID_EVENTS = {
    "pre_tool",
    "post_tool",
    "pre_session",
    "post_session",
    "on_finding",
    "on_shell",
    "on_flag",
}


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class Hook:
    name: str
    event: str
    run: str                       # Shell command template
    match: str | None = None       # Optional regex to match against output / tool name
    _compiled: re.Pattern | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.match:
            try:
                self._compiled = re.compile(self.match, re.IGNORECASE)
            except re.error as exc:
                raise ValueError(f"Hook '{self.name}': invalid regex '{self.match}': {exc}") from exc

    def matches(self, text: str) -> bool:
        """Return True if no match pattern is set, or if the pattern matches text."""
        if self._compiled is None:
            return True
        return bool(self._compiled.search(text))


# ── Manager ───────────────────────────────────────────────────────────────────

class HookManager:
    """Loads, stores, and fires lifecycle hooks.

    Usage
    -----
    manager = HookManager.load()          # load from default path
    await manager.fire("pre_session", {}) # fire all pre_session hooks
    """

    def __init__(self, hooks: list[Hook]) -> None:
        self._hooks = hooks
        # Group by event for fast lookup
        self._by_event: dict[str, list[Hook]] = {}
        for h in hooks:
            self._by_event.setdefault(h.event, []).append(h)

    # ── Constructors ─────────────────────────────────────────────────────

    @classmethod
    def load(cls, path: Path = HOOKS_FILE) -> "HookManager":
        """Load hooks from YAML file. Returns empty manager if file is missing."""
        if not path.exists():
            return cls([])
        if not _YAML_OK:
            # pyyaml not installed — skip hooks silently
            return cls([])

        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            print(f"[hooks] Failed to parse {path}: {exc}")
            return cls([])

        hooks: list[Hook] = []
        for entry in raw.get("hooks", []):
            try:
                event = entry.get("event", "")
                if event not in VALID_EVENTS:
                    print(f"[hooks] Unknown event '{event}' in hook '{entry.get('name', '?')}' — skipped.")
                    continue
                hooks.append(
                    Hook(
                        name=entry.get("name", "unnamed"),
                        event=event,
                        run=entry["run"],
                        match=entry.get("match"),
                    )
                )
            except KeyError as exc:
                print(f"[hooks] Hook entry missing required field {exc} — skipped.")

        return cls(hooks)

    @classmethod
    def empty(cls) -> "HookManager":
        return cls([])

    # ── Firing ───────────────────────────────────────────────────────────

    async def fire(
        self,
        event: str,
        ctx: dict[str, Any],
        *,
        match_text: str = "",
    ) -> None:
        """Fire all hooks registered for *event*.

        Args:
            event:      Hook event name (e.g. "post_tool").
            ctx:        Dict of context values merged into the environment.
            match_text: Text to test against each hook's optional regex match pattern.
                        Hooks with a match pattern only fire when this text matches.
        """
        relevant = self._by_event.get(event, [])
        for hook in relevant:
            if match_text and not hook.matches(match_text):
                continue
            await self._run_hook(hook, ctx)

    async def _run_hook(self, hook: Hook, ctx: dict[str, Any]) -> None:
        """Execute a single hook's shell command in a subprocess."""
        env = {**os.environ, **self._build_env(ctx)}
        try:
            proc = await asyncio.create_subprocess_shell(
                hook.run,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode(errors="replace").strip() if stdout else ""
            if output:
                # Print hook output dimly so it doesn't clutter the agent display
                from rich.console import Console
                Console().print(f"[dim][hook:{hook.name}] {output}[/dim]")
        except asyncio.TimeoutError:
            print(f"[hook:{hook.name}] Timed out after 30 s — killed.")
        except Exception as exc:
            print(f"[hook:{hook.name}] Error: {exc}")

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _build_env(ctx: dict[str, Any]) -> dict[str, str]:
        """Convert context dict to string env vars."""
        mapping = {
            "TARGET":       "target",
            "SESSION_ID":   "session_id",
            "TOOL_NAME":    "tool_name",
            "TOOL_INPUT":   "tool_input",
            "TOOL_OUTPUT":  "tool_output",
            "PHASE":        "phase",
            "FLAG_VALUE":   "flag_value",
        }
        env: dict[str, str] = {}
        for env_key, ctx_key in mapping.items():
            val = ctx.get(ctx_key, "")
            if isinstance(val, dict):
                val = json.dumps(val)
            env[env_key] = str(val)
        return env

    # ── Introspection ────────────────────────────────────────────────────

    def __len__(self) -> int:
        return len(self._hooks)

    def list_hooks(self) -> list[Hook]:
        return list(self._hooks)

    def __repr__(self) -> str:
        return f"HookManager({len(self._hooks)} hooks)"
