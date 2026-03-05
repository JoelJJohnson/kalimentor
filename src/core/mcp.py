"""MCP (Model Context Protocol) client for KaliMentor.

Connects to MCP servers via **stdio** (subprocess) or **SSE** (HTTP) transports,
discovers their tools, and registers them into the ToolRegistry so the LLM sees
MCP tools identically to native tools.

Protocol
--------
MCP uses JSON-RPC 2.0 over:
  - stdio  : subprocess stdin/stdout, one JSON object per line
  - SSE    : HTTP endpoint streaming Server-Sent Events

Handshake sequence
------------------
1. Client → ``initialize`` (protocolVersion, capabilities, clientInfo)
2. Server → ``InitializeResult`` (serverInfo, capabilities)
3. Client → ``notifications/initialized`` (no reply needed)
4. Client → ``tools/list``   → list of tool schemas
5. Client → ``tools/call``   → tool result

Config format (``~/.kalimentor/mcp.yaml``)
------------------------------------------
::

    mcp_servers:
      - name: shodan
        command: npx -y @anthropic-ai/shodan-mcp
        env:
          SHODAN_API_KEY: ${SHODAN_API_KEY}
      - name: virustotal
        url: https://mcp.virustotal.com/sse
        headers:
          Authorization: Bearer ${VT_API_KEY}

Usage
-----
::

    manager = await MCPManager.from_config()
    await manager.connect_all()
    manager.register_tools(registry)        # inject into ToolRegistry
    # … run agent …
    await manager.shutdown()
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml as _yaml  # type: ignore[import]
    _YAML_OK = True
except ImportError:
    _YAML_OK = False

MCP_CONFIG_FILE = Path.home() / ".kalimentor" / "mcp.yaml"
_MCP_PROTOCOL_VERSION = "2024-11-05"


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class MCPServerConfig:
    name: str
    command: str | None = None          # stdio transport: shell command
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None              # SSE transport: HTTP URL
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class MCPTool:
    name: str
    description: str
    input_schema: dict[str, Any]
    server_name: str                    # which MCP server owns this tool


# ── JSON-RPC helpers ──────────────────────────────────────────────────────────

def _rpc_request(id_: int | str, method: str, params: dict | None = None) -> bytes:
    msg = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        msg["params"] = params
    return (json.dumps(msg) + "\n").encode()


def _rpc_notification(method: str, params: dict | None = None) -> bytes:
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    return (json.dumps(msg) + "\n").encode()


def _expand_env(s: str) -> str:
    """Expand ${VAR} patterns in a string using the current environment."""
    return re.sub(
        r"\$\{([^}]+)\}",
        lambda m: os.environ.get(m.group(1), ""),
        s,
    )


# ── Stdio transport ───────────────────────────────────────────────────────────

class StdioMCPConnection:
    """Manages a persistent subprocess MCP server connection over stdio."""

    def __init__(self, config: MCPServerConfig) -> None:
        self._cfg = config
        self._proc: asyncio.subprocess.Process | None = None
        self._id = 0
        self.tools: list[MCPTool] = []

    async def connect(self) -> None:
        """Spawn the subprocess and complete the MCP handshake."""
        env = {**os.environ}
        for k, v in self._cfg.env.items():
            env[k] = _expand_env(v)

        cmd = self._cfg.command or ""
        if self._cfg.args:
            cmd = cmd + " " + " ".join(self._cfg.args)

        self._proc = await asyncio.create_subprocess_shell(
            cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=env,
        )

        # 1. initialize
        await self._send(_rpc_request(
            self._next_id(),
            "initialize",
            {
                "protocolVersion": _MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "kalimentor", "version": "1.0"},
            },
        ))
        await self._read_response()   # consume InitializeResult

        # 2. notifications/initialized
        await self._send(_rpc_notification("notifications/initialized"))

        # 3. tools/list
        req_id = self._next_id()
        await self._send(_rpc_request(req_id, "tools/list"))
        result = await self._read_response()
        self._parse_tools(result)

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        """Call a tool on the MCP server and return its text result."""
        req_id = self._next_id()
        await self._send(_rpc_request(
            req_id,
            "tools/call",
            {"name": name, "arguments": arguments},
        ))
        result = await self._read_response()
        return self._extract_content(result)

    async def shutdown(self) -> None:
        if self._proc and self._proc.returncode is None:
            try:
                self._proc.terminate()
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except Exception:
                pass

    # ── Internal ─────────────────────────────────────────────────────────

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    async def _send(self, data: bytes) -> None:
        assert self._proc and self._proc.stdin
        self._proc.stdin.write(data)
        await self._proc.stdin.drain()

    async def _read_response(self, timeout: float = 30.0) -> dict[str, Any]:
        assert self._proc and self._proc.stdout
        try:
            line = await asyncio.wait_for(
                self._proc.stdout.readline(), timeout=timeout
            )
        except asyncio.TimeoutError:
            return {}
        if not line:
            return {}
        try:
            obj = json.loads(line.decode(errors="replace"))
            return obj.get("result", obj)
        except json.JSONDecodeError:
            return {}

    def _parse_tools(self, result: dict[str, Any]) -> None:
        for t in result.get("tools", []):
            self.tools.append(MCPTool(
                name=t.get("name", "unknown"),
                description=t.get("description", ""),
                input_schema=t.get("inputSchema", {"type": "object", "properties": {}}),
                server_name=self._cfg.name,
            ))

    @staticmethod
    def _extract_content(result: dict[str, Any]) -> str:
        """Pull text from a tools/call result."""
        content = result.get("content", [])
        if isinstance(content, list):
            parts = []
            for block in content:
                if isinstance(block, dict):
                    text = block.get("text") or block.get("data") or ""
                    parts.append(str(text))
            return "\n".join(parts) if parts else str(result)
        return str(content or result)


# ── SSE transport ─────────────────────────────────────────────────────────────

class SSEMCPConnection:
    """MCP connection over HTTP/SSE (basic implementation)."""

    def __init__(self, config: MCPServerConfig) -> None:
        self._cfg = config
        self._base_url = (config.url or "").rstrip("/")
        self._headers = {k: _expand_env(v) for k, v in config.headers.items()}
        self._headers.setdefault("Content-Type", "application/json")
        self._session_url: str | None = None
        self.tools: list[MCPTool] = []

    async def connect(self) -> None:
        """Connect to the SSE MCP server and discover tools."""
        try:
            import aiohttp  # type: ignore[import]
        except ImportError:
            raise RuntimeError(
                "aiohttp is required for SSE MCP servers. "
                "Install with: pip install aiohttp"
            )

        async with aiohttp.ClientSession(headers=self._headers) as session:
            # POST to initialize
            payload = {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": _MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "kalimentor", "version": "1.0"},
                },
            }
            async with session.post(
                f"{self._base_url}/messages", json=payload, timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                await resp.json()  # consume initialize result

            # POST tools/list
            tl_payload = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
            async with session.post(
                f"{self._base_url}/messages", json=tl_payload, timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                data = await resp.json()
                result = data.get("result", data)
                self._parse_tools(result)

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        try:
            import aiohttp  # type: ignore[import]
        except ImportError:
            return "[ERROR] aiohttp not installed — cannot call SSE MCP tool."

        payload = {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
        async with aiohttp.ClientSession(headers=self._headers) as session:
            async with session.post(
                f"{self._base_url}/messages", json=payload, timeout=aiohttp.ClientTimeout(total=60)
            ) as resp:
                data = await resp.json()
                result = data.get("result", data)
                return StdioMCPConnection._extract_content(result)

    async def shutdown(self) -> None:
        pass  # No persistent connection to close

    def _parse_tools(self, result: dict[str, Any]) -> None:
        for t in result.get("tools", []):
            self.tools.append(MCPTool(
                name=t.get("name", "unknown"),
                description=t.get("description", ""),
                input_schema=t.get("inputSchema", {"type": "object", "properties": {}}),
                server_name=self._cfg.name,
            ))


# ── Manager ───────────────────────────────────────────────────────────────────

class MCPManager:
    """Manages multiple MCP server connections.

    Usage::

        manager = MCPManager.from_config()
        await manager.connect_all()
        manager.register_tools(registry)
        # … agent runs …
        await manager.shutdown()
    """

    def __init__(self, configs: list[MCPServerConfig]) -> None:
        self._configs = configs
        self._connections: list[StdioMCPConnection | SSEMCPConnection] = []

    # ── Constructors ─────────────────────────────────────────────────────

    @classmethod
    def from_config(cls, path: Path = MCP_CONFIG_FILE) -> "MCPManager":
        """Load server configs from YAML. Returns empty manager if file is missing."""
        if not path.exists():
            return cls([])
        if not _YAML_OK:
            print("[mcp] pyyaml not installed — MCP servers disabled.")
            return cls([])
        try:
            raw = _yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            print(f"[mcp] Failed to parse {path}: {exc}")
            return cls([])

        configs: list[MCPServerConfig] = []
        for entry in raw.get("mcp_servers", []):
            cfg = MCPServerConfig(
                name=entry.get("name", "unknown"),
                command=entry.get("command"),
                args=entry.get("args", []),
                env={k: str(v) for k, v in entry.get("env", {}).items()},
                url=entry.get("url"),
                headers={k: str(v) for k, v in entry.get("headers", {}).items()},
            )
            if not cfg.command and not cfg.url:
                print(f"[mcp] Server '{cfg.name}' has neither 'command' nor 'url' — skipped.")
                continue
            configs.append(cfg)

        return cls(configs)

    @classmethod
    def empty(cls) -> "MCPManager":
        return cls([])

    # ── Lifecycle ────────────────────────────────────────────────────────

    async def connect_all(self) -> None:
        """Connect to all configured MCP servers concurrently."""
        if not self._configs:
            return

        async def _connect_one(cfg: MCPServerConfig) -> StdioMCPConnection | SSEMCPConnection | None:
            conn: StdioMCPConnection | SSEMCPConnection
            if cfg.url:
                conn = SSEMCPConnection(cfg)
            else:
                conn = StdioMCPConnection(cfg)
            try:
                await asyncio.wait_for(conn.connect(), timeout=30)
                return conn
            except asyncio.TimeoutError:
                print(f"[mcp] Server '{cfg.name}' timed out during connect — skipped.")
                return None
            except Exception as exc:
                print(f"[mcp] Server '{cfg.name}' failed to connect: {exc} — skipped.")
                return None

        results = await asyncio.gather(*[_connect_one(c) for c in self._configs])
        self._connections = [r for r in results if r is not None]

    async def shutdown(self) -> None:
        """Terminate all server connections."""
        await asyncio.gather(*[c.shutdown() for c in self._connections], return_exceptions=True)

    # ── Tool registration ────────────────────────────────────────────────

    def register_tools(self, registry: Any) -> int:
        """Inject all discovered MCP tools into a ToolRegistry.

        Returns the number of tools registered.
        """
        from .tools.registry import Tool, ToolRiskLevel

        count = 0
        for conn in self._connections:
            for mcp_tool in conn.tools:
                # Capture in closure to avoid late-binding issue
                _conn = conn
                _tool_name = mcp_tool.name

                async def _handler(_c=_conn, _n=_tool_name, **kwargs: Any) -> str:
                    return await _c.call_tool(_n, kwargs)

                # MCP tools default to CONFIRM — we don't know their risk level
                tool = Tool(
                    name=mcp_tool.name,
                    description=f"[MCP:{mcp_tool.server_name}] {mcp_tool.description}",
                    input_schema=mcp_tool.input_schema,
                    handler=_handler,
                    risk_level=ToolRiskLevel.CONFIRM,
                )
                registry.add(tool)
                count += 1

        return count

    # ── Introspection ────────────────────────────────────────────────────

    def list_tools(self) -> list[MCPTool]:
        tools = []
        for conn in self._connections:
            tools.extend(conn.tools)
        return tools

    def server_count(self) -> int:
        return len(self._connections)

    def __repr__(self) -> str:
        return f"MCPManager({len(self._connections)} servers, {len(self.list_tools())} tools)"
