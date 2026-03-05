"""Phase 4.3 + 4.6 — MCP client and error recovery tests.

Covers:
- MCPManager config parsing (valid YAML, missing file, bad entries)
- MCPManager.register_tools() injects tools into ToolRegistry
- AgentLoop._is_context_overflow() detects provider-specific messages
- AgentLoop._validate_tool_call() catches unknown tools and missing fields
- Retry backoff constants are sane
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.mcp import MCPManager, MCPServerConfig, MCPTool, _expand_env
from src.core.agent import AgentLoop
from src.core.tools.registry import ToolRegistry, ToolRiskLevel, Tool
from src.core.llm import ToolCall


# ── _expand_env ───────────────────────────────────────────────────────────────

def test_expand_env_substitutes(monkeypatch):
    monkeypatch.setenv("MY_KEY", "secret123")
    assert _expand_env("Bearer ${MY_KEY}") == "Bearer secret123"


def test_expand_env_missing_var_empty(monkeypatch):
    monkeypatch.delenv("NONEXISTENT_VAR", raising=False)
    assert _expand_env("${NONEXISTENT_VAR}") == ""


def test_expand_env_no_vars():
    assert _expand_env("plain string") == "plain string"


# ── MCPManager.from_config ────────────────────────────────────────────────────

def test_from_config_missing_file():
    mgr = MCPManager.from_config(Path("/no/such/file.yaml"))
    assert mgr.server_count() == 0
    assert mgr._configs == []


def test_from_config_valid_stdio(tmp_path):
    cfg = tmp_path / "mcp.yaml"
    cfg.write_text(textwrap.dedent("""\
        mcp_servers:
          - name: shodan
            command: npx -y @anthropic-ai/shodan-mcp
            env:
              SHODAN_API_KEY: ${SHODAN_API_KEY}
    """))
    mgr = MCPManager.from_config(cfg)
    assert len(mgr._configs) == 1
    assert mgr._configs[0].name == "shodan"
    assert mgr._configs[0].command == "npx -y @anthropic-ai/shodan-mcp"


def test_from_config_valid_sse(tmp_path):
    cfg = tmp_path / "mcp.yaml"
    cfg.write_text(textwrap.dedent("""\
        mcp_servers:
          - name: virustotal
            url: https://mcp.virustotal.com/sse
            headers:
              x-apikey: abc123
    """))
    mgr = MCPManager.from_config(cfg)
    assert len(mgr._configs) == 1
    assert mgr._configs[0].url == "https://mcp.virustotal.com/sse"
    assert mgr._configs[0].headers == {"x-apikey": "abc123"}


def test_from_config_skips_entry_without_command_or_url(tmp_path, capsys):
    cfg = tmp_path / "mcp.yaml"
    cfg.write_text(textwrap.dedent("""\
        mcp_servers:
          - name: broken
            env:
              KEY: val
    """))
    mgr = MCPManager.from_config(cfg)
    assert len(mgr._configs) == 0
    captured = capsys.readouterr()
    assert "skipped" in captured.out


def test_from_config_mixed_valid_invalid(tmp_path):
    cfg = tmp_path / "mcp.yaml"
    cfg.write_text(textwrap.dedent("""\
        mcp_servers:
          - name: good
            command: echo hello
          - name: bad
    """))
    mgr = MCPManager.from_config(cfg)
    assert len(mgr._configs) == 1
    assert mgr._configs[0].name == "good"


def test_empty_factory():
    mgr = MCPManager.empty()
    assert mgr.server_count() == 0
    assert mgr.list_tools() == []


# ── MCPManager.register_tools ────────────────────────────────────────────────

def test_register_tools_injects_into_registry():
    mgr = MCPManager.empty()

    # Inject a fake connected server with tools
    fake_conn = MagicMock()
    fake_conn.tools = [
        MCPTool(
            name="shodan_host",
            description="Look up a host on Shodan",
            input_schema={"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]},
            server_name="shodan",
        ),
        MCPTool(
            name="shodan_search",
            description="Search Shodan",
            input_schema={"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
            server_name="shodan",
        ),
    ]
    mgr._connections = [fake_conn]

    registry = ToolRegistry()
    n = mgr.register_tools(registry)

    assert n == 2
    assert registry.get("shodan_host") is not None
    assert registry.get("shodan_search") is not None

    tool = registry.get("shodan_host")
    assert tool.risk_level == ToolRiskLevel.CONFIRM
    assert "[MCP:shodan]" in tool.description


def test_register_tools_empty_manager_returns_zero():
    mgr = MCPManager.empty()
    registry = ToolRegistry()
    assert mgr.register_tools(registry) == 0


# ── MCP tools appear in /tools listing ───────────────────────────────────────

def test_mcp_tools_visible_in_registry_list():
    """Test: MCP server tools appear in /tools listing (plan item 4.7)."""
    mgr = MCPManager.empty()
    fake_conn = MagicMock()
    fake_conn.tools = [
        MCPTool("vt_scan", "Scan with VirusTotal", {"type": "object", "properties": {}}, "virustotal")
    ]
    mgr._connections = [fake_conn]

    registry = ToolRegistry()
    mgr.register_tools(registry)

    names = [t.name for t in registry.list_tools()]
    assert "vt_scan" in names


# ── AgentLoop._is_context_overflow ───────────────────────────────────────────

@pytest.mark.parametrize("message,expected", [
    ("context_length_exceeded", True),
    ("context window exceeded", True),
    ("maximum context length", True),
    ("too many tokens in your request", True),
    ("prompt is too long", True),
    ("input is too long for this model", True),
    ("exceeds the model's maximum context", True),
    ("request too large", True),
    ("please reduce the length of the messages", True),
    ("invalid api key", False),
    ("network timeout", False),
    ("rate limit exceeded", False),
    ("", False),
])
def test_is_context_overflow(message, expected):
    assert AgentLoop._is_context_overflow(Exception(message)) == expected


# ── AgentLoop._validate_tool_call ────────────────────────────────────────────

def _make_registry_with_bash() -> ToolRegistry:
    registry = ToolRegistry()

    async def bash_handler(command: str, timeout: int = 120) -> str:
        return "output"

    registry.add(Tool(
        name="bash",
        description="Run a shell command",
        input_schema={
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["command"],
        },
        handler=bash_handler,
        risk_level=ToolRiskLevel.CONFIRM,
    ))
    return registry


def _make_agent(registry: ToolRegistry) -> AgentLoop:
    """Build a minimal AgentLoop with a mock LLM."""
    llm = MagicMock()
    llm.provider = "anthropic"
    return AgentLoop(llm=llm, registry=registry, mode="interactive")


def test_validate_tool_call_unknown_tool():
    registry = _make_registry_with_bash()
    agent = _make_agent(registry)
    tc = ToolCall(id="1", name="nonexistent_tool", input={})
    error = agent._validate_tool_call(tc)
    assert error is not None
    assert "Unknown tool" in error
    assert "nonexistent_tool" in error


def test_validate_tool_call_missing_required_field():
    registry = _make_registry_with_bash()
    agent = _make_agent(registry)
    # bash requires "command" field
    tc = ToolCall(id="1", name="bash", input={"timeout": 30})
    error = agent._validate_tool_call(tc)
    assert error is not None
    assert "command" in error
    assert "required" in error.lower()


def test_validate_tool_call_valid():
    registry = _make_registry_with_bash()
    agent = _make_agent(registry)
    tc = ToolCall(id="1", name="bash", input={"command": "ls"})
    assert agent._validate_tool_call(tc) is None


def test_validate_tool_call_optional_fields_ok():
    registry = _make_registry_with_bash()
    agent = _make_agent(registry)
    # timeout is optional
    tc = ToolCall(id="1", name="bash", input={"command": "ls", "timeout": 60})
    assert agent._validate_tool_call(tc) is None


# ── Retry backoff constants ───────────────────────────────────────────────────

def test_retry_constants_are_sane():
    assert AgentLoop._MAX_RETRIES == 3
    assert AgentLoop._BACKOFF_BASE == 1.0
    # Verify backoff sequence: 1s, 2s, 4s
    backoffs = [AgentLoop._BACKOFF_BASE * (2 ** i) for i in range(AgentLoop._MAX_RETRIES - 1)]
    assert backoffs == [1.0, 2.0]


def test_retryable_errors_include_network_errors():
    errors = AgentLoop._RETRYABLE_ERRORS
    assert ConnectionError in errors
    assert TimeoutError in errors
    assert OSError in errors
