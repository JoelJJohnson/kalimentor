"""Tool executor — runs shell commands with safety checks, output capture, timeout."""

from __future__ import annotations

import asyncio
import os
import shlex
import time
from dataclasses import dataclass, field
from pathlib import Path


# ── Safety Configuration ───────────────────────────────────────────────

BLOCKED_COMMANDS = frozenset({
    "rm -rf /", "mkfs", "dd if=/dev/zero", ":(){:|:&};:",
    "shutdown", "reboot", "init 0", "init 6",
})

HIGH_RISK_PATTERNS = [
    "exploit", "msfconsole", "msfvenom", "reverse_tcp", "bind_tcp",
    "shell_to_meterpreter", "hashdump", "mimikatz", "secretsdump",
]

TOOL_TIMEOUTS = {
    "nmap": 600, "masscan": 300, "gobuster": 300, "ffuf": 300,
    "feroxbuster": 300, "nikto": 600, "sqlmap": 900, "hydra": 600,
    "wpscan": 300, "enum4linux": 120, "enum4linux-ng": 120,
    "smbclient": 60, "rpcclient": 60, "ldapsearch": 60,
    "linpeas": 300, "winpeas": 300, "bloodhound-python": 180,
    "crackmapexec": 120, "nxc": 120, "responder": 300,
    "nuclei": 600, "whatweb": 60, "wfuzz": 300,
    "hashcat": 1800, "john": 1800,
    "default": 120,
}


@dataclass
class ExecutionResult:
    command: str
    stdout: str
    stderr: str
    exit_code: int
    duration_seconds: float
    timed_out: bool = False
    blocked: bool = False
    block_reason: str = ""


class ToolExecutor:
    """Executes commands with safety checks, timeouts, and output capture."""

    def __init__(self, working_dir: str | None = None):
        self.working_dir = working_dir or "/tmp/kalimentor"
        Path(self.working_dir).mkdir(parents=True, exist_ok=True)
        self.execution_log: list[ExecutionResult] = []

    def _check_safety(self, command: str) -> tuple[bool, str]:
        cmd_lower = command.lower().strip()
        for blocked in BLOCKED_COMMANDS:
            if blocked in cmd_lower:
                return False, f"Blocked: matches dangerous pattern '{blocked}'"
        if "|" in command and ("bash" in command or "sh " in command):
            if "curl" in command or "wget" in command:
                return False, "Blocked: piping remote content to shell"
        return True, ""

    def _get_timeout(self, command: str) -> int:
        first_word = command.strip().split()[0] if command.strip() else ""
        tool = first_word.split("/")[-1]
        return TOOL_TIMEOUTS.get(tool, TOOL_TIMEOUTS["default"])

    def is_high_risk(self, command: str) -> bool:
        cmd_lower = command.lower()
        return any(p in cmd_lower for p in HIGH_RISK_PATTERNS)

    async def execute(
        self,
        command: str,
        timeout_override: int | None = None,
        env: dict[str, str] | None = None,
    ) -> ExecutionResult:
        is_safe, reason = self._check_safety(command)
        if not is_safe:
            result = ExecutionResult(
                command=command, stdout="", stderr=reason,
                exit_code=-1, duration_seconds=0.0, blocked=True, block_reason=reason,
            )
            self.execution_log.append(result)
            return result

        timeout = timeout_override or self._get_timeout(command)
        merged_env = {**os.environ, **(env or {})}
        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.working_dir,
                env=merged_env,
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                timed_out = False
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                stdout_b, stderr_b = b"", f"TIMEOUT after {timeout}s".encode()
                timed_out = True

            result = ExecutionResult(
                command=command,
                stdout=stdout_b.decode("utf-8", errors="replace"),
                stderr=stderr_b.decode("utf-8", errors="replace"),
                exit_code=proc.returncode or 0,
                duration_seconds=round(time.monotonic() - start, 2),
                timed_out=timed_out,
            )
        except Exception as e:
            result = ExecutionResult(
                command=command, stdout="", stderr=f"Error: {e}",
                exit_code=-1, duration_seconds=round(time.monotonic() - start, 2),
            )

        self.execution_log.append(result)
        return result

    async def check_tool(self, tool_name: str) -> bool:
        r = await self.execute(f"which {shlex.quote(tool_name)}", timeout_override=5)
        return r.exit_code == 0

    async def install_from_github(self, repo_url: str, install_cmd: str | None = None) -> ExecutionResult:
        repo = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        dest = f"{self.working_dir}/tools/{repo}"
        r = await self.execute(f"git clone --depth 1 {shlex.quote(repo_url)} {shlex.quote(dest)}", timeout_override=120)
        if r.exit_code != 0:
            return r
        if install_cmd:
            return await self.execute(f"cd {shlex.quote(dest)} && {install_cmd}", timeout_override=300)
        return r

    async def setup_workspace(self, target: str) -> None:
        """Create standard engagement directory structure."""
        dirs = ["recon", "enum", "exploit", "loot", "privesc", "notes", "tools"]
        for d in dirs:
            Path(f"{self.working_dir}/{d}").mkdir(parents=True, exist_ok=True)
