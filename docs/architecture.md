# KaliMentor Architecture

## Overview

KaliMentor is built around a single-threaded **tool-use agentic loop** modelled after Claude Code's architecture. The core idea: the LLM is the decision-maker; tools are the only interface to the world.

```
User input
    │
    ▼
AgentLoop.run(user_input)
    │
    ├─► compress_if_needed(messages)       ← context management
    │
    ├─► inject plan reminder               ← keep LLM on track
    │
    ├─► llm.create_message(                ← provider-agnostic call
    │       system=system_prompt,
    │       messages=messages,
    │       tools=registry.get_schemas(),
    │   )
    │
    ├─► if response.tool_calls:
    │       for tc in tool_calls:
    │           risk_check(tc)             ← confirmation gate
    │           result = registry.execute(tc.name, tc.input)
    │       messages.append(tool_results)
    │       → loop back to LLM
    │
    └─► else:
            display(response.text)         ← done, wait for user
            save_conversation_history()
```

---

## Key Components

### AgentLoop (`src/core/agent.py`)

The main loop. Runs entirely sequentially — no concurrency, no parallel tool calls. Handles:

- Message history management
- Tool call dispatching with risk gating
- Slash command parsing
- Context compression trigger
- Plan reminder injection after every tool result

### LLM Backends (`src/core/llm.py`)

Each provider returns the same `LLMResponse` dataclass:

```python
@dataclass
class ToolCall:
    id: str
    name: str
    input: dict

@dataclass
class LLMResponse:
    text: str                  # combined text content
    tool_calls: list[ToolCall] # tool invocations requested
    stop_reason: str           # "end_turn", "tool_use", "max_tokens"
    raw: Any                   # provider-specific raw response
```

Provider mapping:

| Provider | Format | Tool call field |
|----------|--------|-----------------|
| Anthropic | `content` blocks | `type: "tool_use"` blocks |
| Gemini | `candidates[].content.parts` | `function_call` parts |
| OpenAI / DeepSeek | `choices[0].message` | `tool_calls` array |
| Ollama | OpenAI-compatible (if model supports it) | `tool_calls` array |

### Tool Registry (`src/core/tools/registry.py`)

Central store for all tools. Each tool has:

- `name`: identifier used in API calls
- `description`: shown to the LLM
- `input_schema`: JSON Schema for the tool's arguments
- `handler`: async callable
- `risk_level`: `safe` / `confirm` / `dangerous`

The registry exports schemas in each provider's format and enforces risk-based confirmation gates before execution.

### Tool Set

| Module | Tools |
|--------|-------|
| `bash_tool.py` | `bash` — persistent shell with risk classification |
| `file_tools.py` | `read_file`, `write_file`, `list_directory`, `search_files`, `grep_tool` |
| `security_tools.py` | `search_cve`, `search_exploit`, `query_gtfobins`, `parse_nmap_xml`, `check_tool_installed`, `install_tool` |
| `plan_tool.py` | `update_plan` — TODO list management |
| `memory_tool.py` | `read_memory`, `write_memory` — KALIMENTOR.md access |
| `defense.py` | `analyze_logs`, `check_config`, `detect_persistence`, `generate_sigma_rule`, `generate_yara_rule`, `map_to_attack`, `analyze_pcap` |
| `findings_tool.py` | `record_finding`, `list_findings` |
| `subagent.py` | `spawn_agent` — scoped sub-agent spawning |

### Context Management (`src/core/context.py`)

When the conversation approaches the model's context window limit (checked at ~92%), the compressor:

1. Takes all messages except the last 10
2. Asks the LLM to summarise: facts, credentials, confirmed vulns, current access level, what worked, what didn't
3. Replaces old messages with a single summary message
4. Writes key facts to KALIMENTOR.md for persistence across compression events

Context window limits:

| Provider | Limit |
|----------|-------|
| Claude (Anthropic) | 200,000 tokens |
| Gemini | 1,000,000 tokens |
| DeepSeek | 128,000 tokens |
| GPT-4o | 128,000 tokens |
| Ollama | varies by model |

### Session Memory (`src/core/memory.py`)

Each session has a `KALIMENTOR.md` file in `~/.kalimentor/sessions/<id>/`. The LLM writes to it via `write_memory` after significant discoveries (credentials found, vulnerabilities confirmed, access level changes). At the start of every user turn, the file is read and prepended to context — so facts survive context compression and session resume.

### Session Storage (`src/core/session.py`)

Conversation history is stored as `messages.jsonl` (one JSON object per line) in `~/.kalimentor/sessions/<id>/`. Each entry includes role, content (including tool_use and tool_result blocks), and timestamp. Sessions are listed and resumed via the CLI.

---

## Interaction Modes

| Mode | Confirmation behaviour |
|------|----------------------|
| `interactive` | CONFIRM and DANGEROUS tools pause for user approval |
| `autonomous` | Only DANGEROUS tools require approval |
| `socratic` | System prompt instructs LLM to explain but not call tools |
| `yolo` | No confirmations — use for CTF speedruns only |

---

## Sub-Agents

The `spawn_agent` tool lets the main agent delegate focused tasks. A sub-agent is a separate `AgentLoop` call with:

- Its own restricted tool registry (e.g., recon agents get read-only tools)
- A scoped system prompt (e.g., "reconnaissance only")
- Its own isolated message history
- The task string as the initial user message

The sub-agent's final text response is returned to the parent as the tool result. Only one sub-agent runs at a time.

Available sub-agent types:

| Type | Tools | Purpose |
|------|-------|---------|
| `recon` | bash (safe), read_file, search_files, grep_tool | Surface mapping, enumeration |
| `research` | bash (safe), read_file, search_cve, search_exploit | CVE research, technique lookup |
| `defender` | bash (safe), read_file, analyze_logs, check_config | Defensive analysis |

---

## Risk System

Every tool call passes through a risk gate before execution:

```
bash "cat /etc/passwd"     → SAFE      → runs automatically
bash "gobuster dir ..."    → CONFIRM   → pauses for approval (in interactive/autonomous)
bash "msfconsole ..."      → DANGEROUS → always requires approval
write_file(...)            → CONFIRM   → pauses for approval
spawn_agent(...)           → SAFE      → runs automatically (sub-agent has its own gates)
```

The `bash` tool's risk level is determined dynamically by scanning the command text against known dangerous/confirm patterns, regardless of the tool's base risk level.

---

## Hooks (`src/core/hooks.py`)

Hooks fire shell commands in response to agent events. Configured in `~/.kalimentor/hooks.yaml`. Hook points: `pre_tool`, `post_tool`, `pre_session`, `post_session`, `on_finding`, `on_shell`, `on_flag`.

See [docs/hooks.md](hooks.md) for full documentation.

---

## MCP Servers (`src/core/mcp.py`)

External MCP (Model Context Protocol) servers can extend the tool set. KaliMentor connects via stdio or SSE, auto-discovers tools, and registers them in the tool registry. The LLM sees MCP tools identically to native tools.

See [docs/mcp.md](mcp.md) for setup.
