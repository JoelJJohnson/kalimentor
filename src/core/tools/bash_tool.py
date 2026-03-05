"""Bash tool — persistent shell session with streaming output, risk classification,
working-directory tracking, and output truncation.

Registered as the ``bash`` tool in the ToolRegistry.
"""

from __future__ import annotations

import asyncio
import os
import shlex
from pathlib import Path
from typing import AsyncIterator

from .registry import ToolRegistry, ToolRiskLevel


# ── Constants ─────────────────────────────────────────────────────────────────

OUTPUT_TRUNCATE_CHARS = 30_000  # truncate middle if output exceeds this

BLOCKED_COMMANDS: list[str] = [
    "rm -rf /",
    "rm -rf /*",
    "mkfs",
    "dd if=/dev/zero of=/dev/",
    ":(){:|:&};:",          # fork bomb
    "shutdown",
    "reboot",
    "init 0",
    "init 6",
    "poweroff",
    "halt",
]

# Per-tool timeouts (seconds)
TOOL_TIMEOUTS: dict[str, int] = {
    "nmap": 600,
    "masscan": 300,
    "gobuster": 300,
    "ffuf": 300,
    "feroxbuster": 300,
    "nikto": 600,
    "sqlmap": 900,
    "hydra": 600,
    "wpscan": 300,
    "enum4linux": 120,
    "enum4linux-ng": 120,
    "smbclient": 60,
    "rpcclient": 60,
    "ldapsearch": 60,
    "linpeas": 300,
    "winpeas": 300,
    "bloodhound-python": 180,
    "crackmapexec": 120,
    "nxc": 120,
    "responder": 300,
    "nuclei": 600,
    "whatweb": 60,
    "wfuzz": 300,
    "hashcat": 1800,
    "john": 1800,
    "_default": 120,
}


def _get_timeout(command: str) -> int:
    first = command.strip().split()[0] if command.strip() else ""
    tool = first.split("/")[-1]
    return TOOL_TIMEOUTS.get(tool, TOOL_TIMEOUTS["_default"])


def _truncate(text: str, limit: int = OUTPUT_TRUNCATE_CHARS) -> str:
    if len(text) <= limit:
        return text
    half = limit // 2
    removed = len(text) - limit
    return text[:half] + f"\n\n[... truncated {removed} chars ...]\n\n" + text[-half:]


def _is_blocked(command: str) -> tuple[bool, str]:
    cmd_lower = command.lower().strip()
    for pattern in BLOCKED_COMMANDS:
        if pattern in cmd_lower:
            return True, f"Blocked: matches dangerous pattern '{pattern}'"
    # Block piping remote content into shell
    if "|" in command and ("bash" in command or " sh " in command):
        if "curl" in command or "wget" in command:
            return True, "Blocked: piping remote content to shell"
    return False, ""


# ── Persistent shell session ───────────────────────────────────────────────────

class PersistentShell:
    """A long-lived bash process that maintains working directory across calls.

    Uses a sentinel pattern: after each command we write a unique marker to
    stdout so we know exactly where the command's output ends.
    """

    _SENTINEL_PREFIX = "__KALIMENTOR_DONE__"

    def __init__(self, working_dir: str) -> None:
        self._working_dir = working_dir
        self._proc: asyncio.subprocess.Process | None = None
        self._lock = asyncio.Lock()

    async def _start(self) -> None:
        Path(self._working_dir).mkdir(parents=True, exist_ok=True)
        self._proc = await asyncio.create_subprocess_shell(
            "bash",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,   # merge stderr into stdout
            cwd=self._working_dir,
            env={**os.environ, "PS1": ""},      # suppress prompt noise
        )

    async def _ensure_running(self) -> None:
        if self._proc is None or self._proc.returncode is not None:
            await self._start()

    async def run(
        self,
        command: str,
        timeout: int = 120,
        on_line: "asyncio.Queue[str] | None" = None,
    ) -> tuple[str, int]:
        """Execute *command* and return (output, exit_code).

        Args:
            command: Shell command to run.
            timeout: Max seconds to wait.
            on_line: If provided, each output line is put into this queue as it
                     arrives (for streaming display).

        Returns:
            (combined_stdout_stderr, exit_code)
        """
        async with self._lock:
            await self._ensure_running()
            assert self._proc and self._proc.stdin and self._proc.stdout

            import uuid
            sentinel = f"{self._SENTINEL_PREFIX}_{uuid.uuid4().hex}"

            # Write command + exit-code capture + sentinel
            payload = (
                f"{command}\n"
                f"echo {sentinel}_$?\n"
            )
            self._proc.stdin.write(payload.encode())
            await self._proc.stdin.drain()

            lines: list[str] = []
            exit_code = 0

            async def _read() -> None:
                nonlocal exit_code
                assert self._proc and self._proc.stdout
                async for raw in self._proc.stdout:
                    line = raw.decode("utf-8", errors="replace").rstrip("\n")
                    if line.startswith(sentinel):
                        # Extract exit code from sentinel line
                        try:
                            exit_code = int(line.split("_")[-1])
                        except ValueError:
                            exit_code = 0
                        return
                    lines.append(line)
                    if on_line is not None:
                        await on_line.put(line)

            try:
                await asyncio.wait_for(_read(), timeout=timeout)
            except asyncio.TimeoutError:
                lines.append(f"\n[TIMEOUT after {timeout}s — process may still be running]")
                exit_code = -1
                # Kill and restart for next call
                try:
                    self._proc.kill()
                except Exception:
                    pass
                self._proc = None

            return "\n".join(lines), exit_code

    async def close(self) -> None:
        if self._proc and self._proc.returncode is None:
            try:
                self._proc.stdin.write(b"exit\n")  # type: ignore[union-attr]
                await self._proc.stdin.drain()     # type: ignore[union-attr]
                await asyncio.wait_for(self._proc.wait(), timeout=3)
            except Exception:
                self._proc.kill()
            self._proc = None


# ── Module-level singleton (one shell per process) ────────────────────────────

_shell: PersistentShell | None = None


def get_shell(working_dir: str = "/tmp/kalimentor") -> PersistentShell:
    global _shell
    if _shell is None:
        _shell = PersistentShell(working_dir)
    return _shell


# ── Registration helper ────────────────────────────────────────────────────────

def register_bash_tool(registry: ToolRegistry, working_dir: str = "/tmp/kalimentor") -> None:
    """Register the ``bash`` tool into *registry*."""

    shell = get_shell(working_dir)

    @registry.register(
        name="bash",
        description=(
            "Execute a shell command in a persistent bash session. "
            "Working directory persists across calls — use `cd` to navigate. "
            "stdout and stderr are merged. Output is truncated if > 30 000 chars."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The shell command to execute.",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Max seconds to wait (default: auto-detected per tool).",
                },
            },
            "required": ["command"],
        },
        risk=ToolRiskLevel.SAFE,   # risk is elevated dynamically by registry.risk_check
    )
    async def bash(command: str, timeout: int | None = None) -> str:
        # Blocked-command check
        blocked, reason = _is_blocked(command)
        if blocked:
            return f"[BLOCKED] {reason}"

        effective_timeout = timeout or _get_timeout(command)
        output, exit_code = await shell.run(command, timeout=effective_timeout)
        output = _truncate(output)

        status = f"[exit {exit_code}]" if exit_code != 0 else ""
        return f"{output}\n{status}".strip()
