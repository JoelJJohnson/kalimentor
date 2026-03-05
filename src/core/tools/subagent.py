"""Sub-agent spawning tool.

The parent agent calls ``spawn_agent`` to delegate a focused task to a
restricted sub-agent. The sub-agent runs its own tool_use loop with a
scoped tool registry and a task-specific system prompt, then returns its
final text response as the tool result.

Design principles (matching the plan spec):
- One sub-agent at a time (sequential, not parallel).
- Sub-agent has its own message history — no context pollution to parent.
- Sub-agent's tool registry is restricted to the allowed tool set for its type.
- The final text response of the sub-agent is returned to the parent as a string.
"""

from __future__ import annotations

import asyncio
from typing import Any, TYPE_CHECKING

from .registry import ToolRegistry, ToolRiskLevel

if TYPE_CHECKING:
    from ..llm import LLMBackend


# ─────────────────────────────────────────────────────────────────────────────
#  Allowed tool sets per agent type
# ─────────────────────────────────────────────────────────────────────────────

#: Tools each sub-agent type is allowed to call.
#: Keys match the names registered in the parent ToolRegistry.
AGENT_TOOL_ALLOWLISTS: dict[str, set[str]] = {
    "recon": {
        "bash",
        "read_file",
        "list_directory",
        "search_files",
        "grep_tool",
        "parse_nmap_xml",
        "check_tool_installed",
    },
    "research": {
        "bash",
        "read_file",
        "search_files",
        "grep_tool",
        "search_cve",
        "search_exploit",
        "query_gtfobins",
        "check_tool_installed",
    },
    "defender": {
        "bash",
        "read_file",
        "list_directory",
        "search_files",
        "grep_tool",
        "check_tool_installed",
        "analyze_logs",
        "check_config",
        "detect_persistence",
        "generate_sigma_rule",
        "generate_yara_rule",
        "map_to_attack",
        "analyze_pcap",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
#  Sub-agent runner
# ─────────────────────────────────────────────────────────────────────────────

async def run_subagent(
    task: str,
    agent_type: str,
    parent_registry: ToolRegistry,
    llm: "LLMBackend",
    max_iterations: int = 20,
) -> str:
    """Run a scoped sub-agent loop and return its final text response.

    Args:
        task:            The task description passed to the sub-agent.
        agent_type:      "recon" | "research" | "defender"
        parent_registry: The parent's ToolRegistry; tools are filtered by allowlist.
        llm:             The LLM backend (shared with parent — no extra cost).
        max_iterations:  Safety cap on tool-call iterations.

    Returns:
        The sub-agent's final text response as a plain string.
    """
    from ..prompts import build_subagent_prompt
    from ..llm import user_message, assistant_message, tool_result_message

    # Build restricted registry
    allowed = AGENT_TOOL_ALLOWLISTS.get(agent_type, set())
    sub_registry = _build_restricted_registry(parent_registry, allowed)

    system = build_subagent_prompt(agent_type, task)
    messages: list[dict[str, Any]] = [user_message(task)]
    tools = sub_registry.get_schemas(fmt=llm.provider)

    for _ in range(max_iterations):
        response = await llm.create_message(
            messages=messages,
            system=system,
            tools=tools,
        )

        messages.append(assistant_message(response))

        # No tool calls → sub-agent is done
        if not response.tool_calls:
            return response.text or "[Sub-agent returned no text.]"

        # Execute tool calls (all run automatically — no user confirmation in sub-agents)
        tool_results: list[dict[str, Any]] = []
        for tc in response.tool_calls:
            try:
                result = await sub_registry.execute(tc.name, tc.input)
                result_str = str(result)
            except KeyError:
                result_str = f"[ERROR] Tool '{tc.name}' not available to this sub-agent."
            except Exception as e:
                result_str = f"[ERROR] {e}"
            tool_results.append({"tool_use_id": tc.id, "content": result_str})

        messages.append(tool_result_message(tool_results))

    return "[Sub-agent reached iteration limit without producing a final response.]"


def _build_restricted_registry(
    parent: ToolRegistry,
    allowed: set[str],
) -> ToolRegistry:
    """Return a new ToolRegistry containing only tools in *allowed*."""
    sub = ToolRegistry()
    for tool in parent.list_tools():
        if tool.name in allowed:
            sub._tools[tool.name] = tool  # type: ignore[attr-defined]
    return sub


# ─────────────────────────────────────────────────────────────────────────────
#  Tool registration
# ─────────────────────────────────────────────────────────────────────────────

def register_subagent_tool(
    registry: ToolRegistry,
    llm: "LLMBackend",
) -> None:
    """Register the ``spawn_agent`` tool into *registry*.

    Args:
        registry: The parent ToolRegistry.
        llm:      The LLM backend to pass to the sub-agent.
    """

    @registry.register(
        name="spawn_agent",
        description=(
            "Spawn a focused sub-agent to handle a specific task. "
            "The sub-agent runs its own tool loop with a restricted tool set, "
            "then returns a structured summary. Use this to parallelise reasoning: "
            "delegate recon, research, or defensive analysis to a sub-agent while "
            "you focus on the main engagement.\n\n"
            "agent_type values:\n"
            "  recon    — Read-only surface mapping (nmap, curl, whois, grep).\n"
            "  research — CVE/exploit research (searchsploit, search_cve, GTFOBins).\n"
            "  defender — Log/config analysis for blue team tasks."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "task": {
                    "type": "string",
                    "description": (
                        "Clear, specific task description for the sub-agent. "
                        "Include all context it will need: target IP/URL, "
                        "service name, version, file paths, etc."
                    ),
                },
                "agent_type": {
                    "type": "string",
                    "enum": ["recon", "research", "defender"],
                    "description": "Sub-agent type — determines its tool allowlist and system prompt.",
                },
            },
            "required": ["task", "agent_type"],
        },
        risk=ToolRiskLevel.CONFIRM,
    )
    async def spawn_agent(task: str, agent_type: str) -> str:
        return await run_subagent(
            task=task,
            agent_type=agent_type,
            parent_registry=registry,
            llm=llm,
        )
