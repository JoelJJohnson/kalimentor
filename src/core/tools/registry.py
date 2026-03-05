"""Tool registry for KaliMentor's agentic loop.

Stores tool definitions, exports JSON schemas for LLM API calls,
dispatches execution by name, and enforces risk-based confirmation gates.
"""

from __future__ import annotations

import asyncio
import functools
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Awaitable


class ToolRiskLevel(str, Enum):
    """Risk classification for tools — drives confirmation gates."""
    SAFE = "safe"           # Run automatically (cat, ls, grep, nmap, curl GET…)
    CONFIRM = "confirm"     # Pause briefly for user approval (gobuster, nikto, wget…)
    DANGEROUS = "dangerous" # Require explicit approval (msfconsole, exploits, shells…)


@dataclass
class Tool:
    """A registered tool that the LLM can invoke."""
    name: str
    description: str
    input_schema: dict[str, Any]          # JSON Schema object
    handler: Callable[..., Awaitable[Any]]
    risk_level: ToolRiskLevel = ToolRiskLevel.SAFE

    def to_anthropic_schema(self) -> dict[str, Any]:
        """Return tool definition in Anthropic Messages API format."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }

    def to_openai_schema(self) -> dict[str, Any]:
        """Return tool definition in OpenAI/DeepSeek function-calling format."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.input_schema,
            },
        }

    def to_gemini_schema(self) -> dict[str, Any]:
        """Return tool definition in Gemini function_declarations format."""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.input_schema,
        }


# Commands whose presence in a bash call elevates risk to DANGEROUS
_DANGEROUS_PATTERNS = [
    "msfconsole", "msfvenom", "meterpreter",
    "exploit", "payload", "reverse_shell", "reverse shell",
    "nc -e", "bash -i", "/dev/tcp",
    "python -c", "python3 -c",  # common shell-spawn patterns
]

# Commands whose presence elevates to CONFIRM (if not already DANGEROUS)
_CONFIRM_PATTERNS = [
    "gobuster", "ffuf", "nikto", "sqlmap", "hydra",
    "netcat", "ncat", "wget", "curl -X POST", "curl --data",
    "nmap -sS", "nmap -A", "nmap -p-",
    "write_file",   # file write operations
    ">",            # shell redirect (write)
    ">>",
    "chmod", "chown", "sudo",
]


class ToolRegistry:
    """Central registry for all KaliMentor tools.

    Usage::

        registry = ToolRegistry()

        @registry.register(name="bash", risk=ToolRiskLevel.CONFIRM)
        async def run_bash(command: str, timeout: int = 120) -> str:
            ...
    """

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    # ------------------------------------------------------------------ #
    #  Registration                                                         #
    # ------------------------------------------------------------------ #

    def register(
        self,
        name: str,
        description: str,
        input_schema: dict[str, Any],
        risk: ToolRiskLevel = ToolRiskLevel.SAFE,
    ) -> Callable:
        """Decorator that registers an async function as a tool.

        Example::

            @registry.register(
                name="bash",
                description="Run a shell command.",
                input_schema={
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                    "required": ["command"],
                },
                risk=ToolRiskLevel.CONFIRM,
            )
            async def run_bash(command: str) -> str:
                ...
        """
        def decorator(fn: Callable) -> Callable:
            tool = Tool(
                name=name,
                description=description,
                input_schema=input_schema,
                handler=fn,
                risk_level=risk,
            )
            self._tools[name] = tool
            return fn
        return decorator

    def add(self, tool: Tool) -> None:
        """Register a pre-built Tool instance directly."""
        self._tools[tool.name] = tool

    # ------------------------------------------------------------------ #
    #  Schema export                                                        #
    # ------------------------------------------------------------------ #

    def get_schemas(self, fmt: str = "anthropic") -> list[dict[str, Any]]:
        """Return all tool schemas in the requested provider format.

        Args:
            fmt: One of ``"anthropic"``, ``"openai"`` / ``"deepseek"``,
                 ``"gemini"``, or ``"ollama"`` (maps to openai).
        """
        fmt = fmt.lower()
        if fmt in ("openai", "deepseek", "ollama"):
            return [t.to_openai_schema() for t in self._tools.values()]
        if fmt == "gemini":
            return [t.to_gemini_schema() for t in self._tools.values()]
        # Default: anthropic
        return [t.to_anthropic_schema() for t in self._tools.values()]

    def list_tools(self) -> list[Tool]:
        """Return all registered Tool objects."""
        return list(self._tools.values())

    def get(self, name: str) -> Tool | None:
        """Look up a tool by name."""
        return self._tools.get(name)

    # ------------------------------------------------------------------ #
    #  Risk checking                                                        #
    # ------------------------------------------------------------------ #

    def risk_check(self, tool_name: str, tool_input: dict[str, Any]) -> bool:
        """Return True if this tool call requires user confirmation before execution.

        Logic:
        - Unknown tool → always confirm (treat as dangerous).
        - DANGEROUS risk_level → always confirm.
        - CONFIRM risk_level → always confirm.
        - ``bash`` tool → inspect command text and escalate if dangerous/confirm patterns found.
        - SAFE tools → no confirmation needed.
        """
        tool = self._tools.get(tool_name)
        if tool is None:
            return True

        if tool_name == "bash":
            command = tool_input.get("command", "")
            if self._is_dangerous_command(command):
                return True
            if self._is_confirm_command(command):
                return True

        return tool.risk_level in (ToolRiskLevel.CONFIRM, ToolRiskLevel.DANGEROUS)

    # Alias used in the agent loop
    def needs_confirmation(self, tool_name: str, tool_input: dict[str, Any]) -> bool:
        return self.risk_check(tool_name, tool_input)

    def effective_risk(self, tool_name: str, tool_input: dict[str, Any]) -> ToolRiskLevel:
        """Return the effective risk level after inspecting input."""
        tool = self._tools.get(tool_name)
        if tool is None:
            return ToolRiskLevel.DANGEROUS

        if tool_name == "bash":
            command = tool_input.get("command", "")
            if self._is_dangerous_command(command):
                return ToolRiskLevel.DANGEROUS
            if self._is_confirm_command(command):
                return ToolRiskLevel.CONFIRM

        return tool.risk_level

    # ------------------------------------------------------------------ #
    #  Dispatch                                                             #
    # ------------------------------------------------------------------ #

    async def execute(self, tool_name: str, tool_input: dict[str, Any]) -> Any:
        """Execute a registered tool by name.

        Args:
            tool_name: Registered tool name.
            tool_input: Dict of arguments matching the tool's input_schema.

        Returns:
            Whatever the tool handler returns (typically a string).

        Raises:
            KeyError: If the tool name is not registered.
            Exception: Propagates any exception from the handler.
        """
        tool = self._tools.get(tool_name)
        if tool is None:
            raise KeyError(f"Tool '{tool_name}' is not registered.")

        # Call the handler — it must be async
        result = await tool.handler(**tool_input)
        return result

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_dangerous_command(command: str) -> bool:
        cmd_lower = command.lower()
        return any(pat in cmd_lower for pat in _DANGEROUS_PATTERNS)

    @staticmethod
    def _is_confirm_command(command: str) -> bool:
        cmd_lower = command.lower()
        return any(pat in cmd_lower for pat in _CONFIRM_PATTERNS)

    def __repr__(self) -> str:
        names = list(self._tools.keys())
        return f"<ToolRegistry tools={names}>"
