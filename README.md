# ⚡ KaliMentor — Agentic Cybersecurity Learning Framework

A terminal-based, LLM-augmented tool for Kali Linux that **plans, executes, observes, and teaches** offensive security through an agentic loop.

**Supported AI:** Ollama (local) · Claude · Gemini · DeepSeek · OpenAI

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                   KaliMentor CLI                      │
│                                                       │
│  ┌────────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │  Session   │  │ Planner  │  │  Research Mode   │  │
│  │  Manager   │  │  (LLM)   │  │  (standalone)    │  │
│  └─────┬──────┘  └────┬─────┘  └────────┬─────────┘  │
│        │              │                 │             │
│  ┌─────▼──────────────▼─────────────────▼──────────┐  │
│  │              Agentic Loop Engine                 │  │
│  │   user → LLM (tools) → tool calls → results →   │  │
│  │        → LLM → … → text reply                   │  │
│  └──────────────────┬───────────────────────────────┘  │
│                     │                                  │
│  ┌──────────────────▼───────────────────────────────┐  │
│  │  Tool Registry (bash · memory · findings · plan) │  │
│  └──────────────────┬───────────────────────────────┘  │
│                     │                                  │
│  ┌──────────────────▼───────────────────────────────┐  │
│  │  Textual TUI  │  Session State  │  Audit Log     │  │
│  └──────────────────────────────────────────────────┘  │
│                                                        │
│  AI: Ollama │ Claude │ Gemini │ DeepSeek │ OpenAI      │
└────────────────────────────────────────────────────────┘
```

---

## Step-by-Step Installation

### Prerequisites

- Kali Linux (2023.x+ recommended) or any Linux with pentest tools
- Python 3.10+
- git

### Step 1 — Clone

```bash
git clone https://github.com/JoelJJohnson/kalimentor.git
cd kalimentor
```

### Step 2 — Run Setup Script

```bash
chmod +x setup.sh
./setup.sh
```

Creates a virtualenv, installs all dependencies, copies config, and checks your Kali tools.

### Step 3 — Activate Environment

```bash
source .venv/bin/activate
```

### Step 4 — Add Your API Key

```bash
nano .env
```

Only one provider is needed. Ollama requires no key.

### Step 5 — Verify

```bash
kalimentor --help
kalimentor providers
```

### Manual Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[all]"
mkdir -p ~/.kalimentor/sessions
cp config/default.yaml ~/.kalimentor/config.yaml
cp .env.example .env
```

---

## AI Provider Setup

### Ollama (Free · Local · No Key)

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.1
kalimentor start -t 10.10.10.1 --llm ollama
```

### Anthropic Claude

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
kalimentor start -t 10.10.10.1 --llm anthropic
kalimentor start -t 10.10.10.1 --llm claude --model claude-sonnet-4-6
```

### Google Gemini

```bash
export GEMINI_API_KEY="AIza..."
kalimentor start -t 10.10.10.1 --llm gemini
kalimentor start -t 10.10.10.1 --llm gemini --model gemini-2.5-pro
```

### DeepSeek

```bash
export DEEPSEEK_API_KEY="sk-..."
kalimentor start -t 10.10.10.1 --llm deepseek
kalimentor start -t 10.10.10.1 --llm deepseek --model deepseek-reasoner
```

### OpenAI

```bash
export OPENAI_API_KEY="sk-..."
kalimentor start -t 10.10.10.1 --llm openai
```

### Inline Key (no env var)

```bash
kalimentor start -t 10.10.10.1 --llm gemini --api-key "AIza..."
```

---

## Usage

### Machine (HTB / THM / OSCP)

```bash
# Interactive (approve each step)
kalimentor start -t 10.10.10.1 -o "Gain root access" --llm claude

# Socratic (hints only, you run the commands)
kalimentor start -t 10.10.10.1 -o "Root the box" --llm gemini -m socratic
```

### Web Exploitation

```bash
kalimentor start -u "http://target.htb" -c web -o "Capture the flag" --llm anthropic
```

### Binary Exploitation (Pwn)

```bash
kalimentor start -c pwn -o "Exploit the binary for shell" --llm gemini
```

### Reverse Engineering

```bash
kalimentor start -c reversing -o "Find the flag" --llm deepseek
```

### Cryptography

```bash
kalimentor start -c crypto -o "Decrypt the ciphertext" --llm claude
```

### Digital Forensics

```bash
kalimentor start -c forensics -o "Analyze the PCAP and find the flag" --llm gemini
```

### Active Directory

```bash
kalimentor start -t 10.10.10.1 -c active_directory -o "Compromise the domain" --llm anthropic
```

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `kalimentor start` | Start a new session (opens TUI) |
| `kalimentor resume <id>` | Resume a saved session |
| `kalimentor sessions` | List all saved sessions |
| `kalimentor export <id>` | Export session as Markdown report |
| `kalimentor research <topic>` | Standalone research on any topic |
| `kalimentor providers` | List supported AI providers |

---

## TUI Slash Commands

These commands are available inside the Textual TUI:

| Command | Description |
|---------|-------------|
| `/plan` | Show the current TODO/task list |
| `/memory` | Show session memory (KALIMENTOR.md) |
| `/status` | Show session info |
| `/tools` | List all registered tools |
| `/mode <name>` | Switch interaction mode |
| `/flag <value>` | Record a captured flag |
| `/note <text>` | Add a note to session memory |
| `/undo` | Remove last message pair from history |
| `/compact` | Force context compression |
| `/export` | Export session report |
| `/clear` | Clear the chat log |
| `/quit` | Save and exit |

Keyboard shortcuts:

| Shortcut | Action |
|----------|--------|
| `Ctrl+Q` | Quit |
| `Ctrl+A` | Analyse tmux terminal pane |
| `Page Up / Down` | Scroll chat log |

---

## Agent Modes

| Mode | Behavior |
|------|----------|
| `interactive` | AI proposes, you approve each action (default) |
| `autonomous` | AI runs all tools except DANGEROUS ones automatically |
| `socratic` | AI explains and hints only — you run the commands |
| `yolo` | Everything runs with no confirmations (CTF speedrun) |

```bash
kalimentor start -t 10.10.10.1 -m socratic --llm gemini
kalimentor start -t 10.10.10.1 -m autonomous --llm claude
kalimentor start -t 10.10.10.1 -m yolo --llm deepseek
```

---

## Project Structure

```
kalimentor/
├── setup.sh                 # Automated setup script
├── pyproject.toml           # Python project config + deps
├── .env.example             # API key template
├── config/
│   └── default.yaml         # Default configuration
├── src/
│   ├── cli.py               # Typer CLI entry point
│   ├── core/
│   │   ├── agent.py         # Agentic loop (tool_use cycle)
│   │   ├── llm.py           # AI backends (5 providers)
│   │   ├── session.py       # Session persistence + state
│   │   ├── executor.py      # Safe command execution + timeouts
│   │   ├── parser.py        # Output → structured findings
│   │   ├── planner.py       # LLM-driven planning + prompts
│   │   ├── context.py       # Context window compression
│   │   ├── memory.py        # Session memory (KALIMENTOR.md)
│   │   ├── models.py        # Pydantic data models
│   │   ├── prompts.py       # System prompts per mode/challenge
│   │   └── tools/
│   │       ├── registry.py      # Tool registry + risk levels
│   │       ├── bash_tool.py     # Shell execution tool
│   │       ├── plan_tool.py     # Task plan tracking tool
│   │       ├── memory_tool.py   # Memory read/write tools
│   │       ├── findings_tool.py # Findings capture tool
│   │       ├── file_tools.py    # File read/write tools
│   │       ├── security_tools.py# Security-specific tools
│   │       └── defense.py       # Blue team / DFIR tools
│   └── ui/
│       ├── app.py           # Textual TUI application
│       ├── widgets.py       # ChatLog, StatusBar, ChatInput
│       └── tmux.py          # tmux split layout integration
└── tests/
```

---

## Session Data

Sessions are saved at `~/.kalimentor/sessions/<id>/` and include full command history, findings, flags, and memory. Resume or export at any time:

```bash
kalimentor sessions
kalimentor resume abc123def
kalimentor export abc123def -o report.md
```

---

## tmux Integration

KaliMentor automatically sets up a split tmux layout when run inside tmux — the left pane is the TUI and the right pane is your terminal. Press `Ctrl+A` to send the right pane's output directly to the AI for analysis.

---

## License

MIT
