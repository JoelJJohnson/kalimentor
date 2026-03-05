# MCP Server Integration

KaliMentor supports the Model Context Protocol (MCP) — external tool servers that extend the agent's capabilities. MCP tools appear identically to native tools; the LLM cannot tell the difference.

---

## Configuration

Create `~/.kalimentor/mcp.yaml` (or copy from `config/mcp.example.yaml`):

```yaml
mcp_servers:
  - name: shodan
    command: npx -y @anthropic-ai/shodan-mcp
    env:
      SHODAN_API_KEY: "${SHODAN_API_KEY}"

  - name: virustotal
    command: npx -y @virustotal/mcp-server
    env:
      VT_API_KEY: "${VT_API_KEY}"

  - name: nuclei
    command: python -m nuclei_mcp
    args: ["--templates", "/usr/share/nuclei-templates"]
```

Start a session with MCP enabled:

```bash
kalimentor start -t 10.10.10.1 --llm anthropic --mcp
```

---

## Connection Methods

### stdio (default)

The MCP server is launched as a subprocess. KaliMentor communicates via stdin/stdout.

```yaml
mcp_servers:
  - name: my_server
    command: python /path/to/server.py
    args: ["--port", "8080"]
    env:
      MY_VAR: "value"
```

### SSE (HTTP server)

Connect to a running MCP server via HTTP/SSE:

```yaml
mcp_servers:
  - name: remote_server
    url: https://mcp.example.com/sse
    headers:
      Authorization: "Bearer ${MY_TOKEN}"
```

---

## Useful MCP Servers for Security

| Server | Purpose | Install |
|--------|---------|---------|
| Shodan | Internet-wide host intelligence | `npx -y @anthropic-ai/shodan-mcp` |
| VirusTotal | File/URL/IP reputation | `npx -y @virustotal/mcp-server` |
| MITRE ATT&CK | Technique lookup | Community server |
| BurpSuite | Web proxy control | Burp MCP extension |

---

## Listing MCP Tools

After starting a session with `--mcp`, use `/tools` to see all registered tools including those from MCP servers. MCP tool names are prefixed with the server name: `shodan__host_info`, `virustotal__scan_url`, etc.

---

## Writing a Custom MCP Server

An MCP server is any process that speaks the MCP protocol over stdio. Minimal example in Python:

```python
from mcp.server import Server
from mcp.server.stdio import stdio_server

server = Server("my-tools")

@server.list_tools()
async def list_tools():
    return [{"name": "my_tool", "description": "...", "inputSchema": {...}}]

@server.call_tool()
async def call_tool(name, arguments):
    if name == "my_tool":
        return [{"type": "text", "text": "result"}]

async def main():
    async with stdio_server() as streams:
        await server.run(*streams)

import asyncio
asyncio.run(main())
```

Register it in `mcp.yaml`:

```yaml
mcp_servers:
  - name: my_server
    command: python /path/to/my_server.py
```
