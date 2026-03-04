# ⚡ KaliMentor — Agentic Cybersecurity Learning Framework

A terminal-based, LLM-augmented tool for Kali Linux that **plans, executes, observes, and teaches** offensive security through an agentic loop.

**Supported AI:** Ollama (local) · Claude · Gemini · DeepSeek · OpenAI

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│                  KaliMentor CLI                   │
│                                                   │
│  ┌───────────┐  ┌──────────┐  ┌──────────────┐  │
│  │  Session   │  │ Planner  │  │  Research    │  │
│  │  Manager   │  │  (LLM)   │  │  Mode        │  │
│  └─────┬──────┘  └────┬─────┘  └──────┬───────┘  │
│        │              │               │           │
│  ┌─────▼──────────────▼───────────────▼────────┐  │
│  │           Agentic Loop Engine               │  │
│  │  Observe → Plan → Propose → Approve → Act   │  │
│  └──────────────────┬──────────────────────────┘  │
│                     │                             │
│  ┌──────────────────▼──────────────────────────┐  │
│  │  Executor (safety · timeouts · audit log)   │  │
│  └──────────────────┬──────────────────────────┘  │
│                     │                             │
│  ┌──────────────────▼──────────────────────────┐  │
│  │  Output Parser → Findings → Session State   │  │
│  └─────────────────────────────────────────────┘  │
│                                                   │
│  AI: Ollama │ Claude │ Gemini │ DeepSeek │ OpenAI │
└───────────────────────────────────────────────────┘
```

---

## Step-by-Step Installation

### Prerequisites

- Kali Linux (2023.x+ recommended) or any Linux with pentest tools
- Python 3.10+
- git

### Step 1 — Clone

```bash
git clone https://github.com/yourorg/kalimentor.git
cd kalimentor
```

### Step 2 — Run Setup Script

```bash
chmod +x setup.sh
./setup.sh
```

This creates a virtualenv, installs all dependencies (including all AI providers), copies config, and checks your Kali tools.

### Step 3 — Activate Environment

```bash
source .venv/bin/activate
```

### Step 4 — Add Your API Key

Edit `.env` with your preferred provider's key:

```bash
nano .env
```

Only ONE provider is needed. Ollama needs no key.

### Step 5 — Verify

```bash
kalimentor --help
kalimentor providers
```

### Manual Install (if you skip setup.sh)

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
# Models: claude-sonnet-4-20250514 (default), claude-haiku-4-5-20251001
kalimentor start -t 10.10.10.1 --llm anthropic
kalimentor start -t 10.10.10.1 --llm claude --model claude-sonnet-4-20250514
```

### Google Gemini

```bash
export GEMINI_API_KEY="AIza..."
# Models: gemini-2.5-flash (default), gemini-2.5-pro
kalimentor start -t 10.10.10.1 --llm gemini
kalimentor start -t 10.10.10.1 --llm gemini --model gemini-2.5-pro
```

### DeepSeek

```bash
export DEEPSEEK_API_KEY="sk-..."
# Models: deepseek-chat (default), deepseek-reasoner
kalimentor start -t 10.10.10.1 --llm deepseek
kalimentor start -t 10.10.10.1 --llm deepseek --model deepseek-reasoner
```

### OpenAI

```bash
export OPENAI_API_KEY="sk-..."
# Models: gpt-4o (default), gpt-4o-mini
kalimentor start -t 10.10.10.1 --llm openai
```

### Inline Key (no env var)

```bash
kalimentor start -t 10.10.10.1 --llm gemini --api-key "AIza..."
```

---

## Usage by Challenge Type

### Machine (HTB / THM / OSCP)

Recon → Enumerate → Exploit → PrivEsc → Root

```bash
# Interactive (approve each step)
kalimentor start -t 10.10.10.1 -o "Gain root access" --llm claude

# Socratic (hints only, you run the commands)
kalimentor start -t 10.10.10.1 -o "Root the box" --llm gemini -m socratic

# Inside the session:
KaliMentor ⚡> next                         # AI proposes next actions
KaliMentor ⚡> auto                         # Auto-run recon phase
KaliMentor ⚡> !nmap -sV -p 80 10.10.10.1  # Direct command
KaliMentor ⚡> hint                         # Socratic hint
KaliMentor ⚡> research CVE-2024-1234       # Deep-dive a CVE
KaliMentor ⚡> flag                         # Record captured flag
KaliMentor ⚡> export                       # Export report
```

### Web Exploitation

Surface map → Endpoints → Injection testing → Logic exploitation

```bash
kalimentor start -u "http://target.htb" -c web -o "Capture the flag" --llm anthropic
```

The AI proposes: `whatweb` → `gobuster`/`ffuf` → `sqlmap`/`dalfox` → manual logic guidance.

### Binary Exploitation (Pwn)

Triage → Static analysis → Dynamic debug → ROP chain

```bash
kalimentor start -c pwn -o "Exploit the binary for shell" --llm gemini
```

The AI proposes: `file`/`checksec` → `objdump`/ghidra → `gdb` → pwntools exploit.

### Reverse Engineering

Behavioral analysis → Decompile → Algorithm reconstruction → Solve

```bash
kalimentor start -c reversing -o "Find the flag" --llm deepseek
```

The AI proposes: `strings`/`ltrace` → ghidra → solve script.

### Cryptography

Algorithm ID → Implementation analysis → Mathematical exploit

```bash
kalimentor start -c crypto -o "Decrypt the ciphertext" --llm claude
```

Use `research` for deep-dives: `research "RSA Wiener attack"`, `research "padding oracle"`.

### Digital Forensics (DFIR)

Artifact ingestion → Filter → Timeline → Payload extraction

```bash
kalimentor start -c forensics -o "Analyze the PCAP and find the flag" --llm gemini
```

The AI proposes: `tshark` filters → `volatility3` → timeline → extraction.

### Active Directory

External access → BloodHound → Lateral movement → Domain Admin

```bash
kalimentor start -t 10.10.10.1 -c active_directory -o "Compromise the domain" --llm anthropic
```

The AI proposes: `responder` → `bloodhound-python` → Pass-the-Hash/Kerberoasting → DCSync.

---

## Commands Reference

### CLI Commands

| Command | Description |
|---------|-------------|
| `kalimentor start` | Start a new session |
| `kalimentor resume <id>` | Resume a saved session |
| `kalimentor sessions` | List all saved sessions |
| `kalimentor export <id>` | Export session as Markdown report |
| `kalimentor research <topic>` | Standalone research on any topic |
| `kalimentor providers` | List supported AI providers |

### In-Session Commands

| Command | Description |
|---------|-------------|
| `next` | AI proposes next actions |
| `auto` | Auto-run a phase (recon/enum/vuln) |
| `hint` | Socratic hint (no direct answers) |
| `research` | Deep-dive a CVE, tool, or technique |
| `status` | Show session status |
| `plan` | Regenerate attack plan |
| `phase` | Manually set current phase |
| `flag` | Record a captured flag |
| `note` | Add a personal note |
| `export` | Export session report |
| `help` | Show command help |
| `!<cmd>` | Execute any command directly |
| `quit` | Save and exit |
| *(free text)* | Ask anything — AI interprets it |

---

## Agent Modes

| Mode | Behavior |
|------|----------|
| `interactive` | AI proposes, you approve each action (default) |
| `semi_auto` | AI runs within a phase, you approve phase transitions |
| `autonomous` | AI runs full phases, you review results |
| `socratic` | AI gives hints and questions only, you execute everything |

```bash
kalimentor start -t 10.10.10.1 -m socratic --llm gemini
kalimentor start -t 10.10.10.1 -m autonomous --llm claude
```

---

## Project Structure

```
kalimentor/
├── setup.sh                 # Automated setup script
├── pyproject.toml           # Python project config + deps
├── .env.example             # API key template
├── .gitignore
├── README.md                # This file
├── config/
│   └── default.yaml         # Default configuration
├── src/
│   ├── __init__.py
│   ├── cli.py               # Typer CLI entry point
│   ├── core/
│   │   ├── __init__.py
│   │   ├── models.py        # Pydantic data models
│   │   ├── llm.py           # AI backends (Claude/Gemini/DeepSeek/OpenAI/Ollama)
│   │   ├── session.py       # Session persistence + state tracking
│   │   ├── executor.py      # Safe command execution + timeouts
│   │   ├── parser.py        # Output → structured findings
│   │   ├── planner.py       # LLM-driven planning + prompts
│   │   └── agent.py         # Agentic loop engine (OODA)
│   ├── modules/
│   │   ├── __init__.py
│   │   └── methodologies.py # Attack patterns per challenge type
│   ├── ui/
│   │   └── __init__.py      # (Future: TUI components)
│   └── utils/
│       └── __init__.py      # (Future: helpers)
├── templates/               # (Future: report templates)
├── docs/                    # (Future: documentation)
└── tests/
    └── __init__.py
```

---

## Session Data

Sessions are saved at `~/.kalimentor/sessions/<id>.json` and include full command history, findings, and flags. Resume any session:

```bash
kalimentor sessions          # List all
kalimentor resume abc123def  # Resume by ID
kalimentor export abc123def -o report.md
```

---

## License

MIT
