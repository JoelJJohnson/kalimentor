#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════
#  KaliMentor — Automated Setup Script
# ═══════════════════════════════════════════════════════════════════════════

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════╗"
echo "║              ⚡ KaliMentor Setup ⚡                   ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Check Python ───────────────────────────────────────────────────────
echo -e "${CYAN}[1/6] Checking Python...${NC}"
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}Python 3 not found. Install with: sudo apt install python3 python3-pip${NC}"
    exit 1
fi

PYVER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo -e "${GREEN}  Python ${PYVER} found${NC}"

# ── Create virtual environment ─────────────────────────────────────────
echo -e "${CYAN}[2/6] Creating virtual environment...${NC}"
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo -e "${GREEN}  Created .venv${NC}"
else
    echo -e "${YELLOW}  .venv already exists, reusing${NC}"
fi

source .venv/bin/activate

# ── Install package ────────────────────────────────────────────────────
echo -e "${CYAN}[3/6] Installing KaliMentor...${NC}"
pip install --upgrade pip setuptools wheel -q
pip install -e ".[all]" -q
echo -e "${GREEN}  Installed with all AI providers${NC}"

# ── Create config directory ────────────────────────────────────────────
echo -e "${CYAN}[4/6] Setting up config...${NC}"
CONFDIR="$HOME/.kalimentor"
mkdir -p "$CONFDIR/sessions"
if [ ! -f "$CONFDIR/config.yaml" ]; then
    cp config/default.yaml "$CONFDIR/config.yaml"
    echo -e "${GREEN}  Config created at $CONFDIR/config.yaml${NC}"
else
    echo -e "${YELLOW}  Config already exists${NC}"
fi

# ── Setup .env if needed ──────────────────────────────────────────────
echo -e "${CYAN}[5/6] Checking API keys...${NC}"
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo -e "${YELLOW}  Created .env — edit it to add your API keys${NC}"
else
    echo -e "${GREEN}  .env exists${NC}"
fi

# ── Check Kali tools ──────────────────────────────────────────────────
echo -e "${CYAN}[6/6] Checking common tools...${NC}"
TOOLS=(nmap gobuster ffuf nikto sqlmap hydra smbclient enum4linux searchsploit)
MISSING=()
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $tool"
    else
        echo -e "  ${RED}✗${NC} $tool"
        MISSING+=("$tool")
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    echo -e "\n${YELLOW}Missing tools: ${MISSING[*]}"
    echo -e "Install with: sudo apt install ${MISSING[*]}${NC}"
fi

# ── Done ───────────────────────────────────────────────────────────────
echo -e "\n${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Setup complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Activate environment:  ${CYAN}source .venv/bin/activate${NC}"
echo ""
echo -e "  Quick start:"
echo -e "    ${CYAN}kalimentor start -t 10.10.10.1 --llm ollama${NC}"
echo -e "    ${CYAN}kalimentor start -t 10.10.10.1 --llm anthropic${NC}"
echo -e "    ${CYAN}kalimentor start -t 10.10.10.1 --llm gemini${NC}"
echo -e "    ${CYAN}kalimentor start -t 10.10.10.1 --llm deepseek${NC}"
echo ""
echo -e "  See all providers:     ${CYAN}kalimentor providers${NC}"
echo -e "  See all commands:      ${CYAN}kalimentor --help${NC}"
echo ""
