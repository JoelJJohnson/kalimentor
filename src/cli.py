"""KaliMentor CLI — main entry point with all commands."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.table import Table

from .core.agent import AgentLoop
from .core.llm import create_backend, list_providers, DEFAULT_MODELS
from .core.session import SessionManager
from .core.tools.registry import ToolRegistry
from .core.tools.bash_tool import register_bash_tool
from .core.tools.memory_tool import register_memory_tools
from .core.tools.findings_tool import register_findings_tool
from .core.tools.file_tools import register_file_tools
from .core.tools.security_tools import register_security_tools
from .core.tools.plan_tool import register_plan_tool

app = typer.Typer(
    name="kalimentor",
    help="⚡ KaliMentor — Agentic Cybersecurity Learning Framework",
    no_args_is_help=True,
)
console = Console()


def _load_env() -> None:
    """Load missing env vars from ~/.kalimentor/.env then ./.env."""
    for env_path in [Path.home() / ".kalimentor" / ".env", Path(".env")]:
        if env_path.exists():
            for line in env_path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                if key and key not in os.environ:
                    os.environ[key] = value.strip().strip('"').strip("'")


def _get_config() -> dict:
    """Read ~/.kalimentor/config.yaml, fallback to empty dict."""
    config_path = Path.home() / ".kalimentor" / "config.yaml"
    if config_path.exists():
        return yaml.safe_load(config_path.read_text()) or {}
    return {}


_load_env()
_CONFIG = _get_config()


# ═══════════════════════════════════════════════════════════════════════════
#  START
# ═══════════════════════════════════════════════════════════════════════════

@app.command()
def start(
    target: str = typer.Option(None, "--target", "-t", help="Target IP address"),
    url: str = typer.Option(None, "--url", "-u", help="Target URL (for web challenges)"),
    objective: str = typer.Option("Gain root/SYSTEM access", "--objective", "-o", help="Session objective"),
    challenge: str = typer.Option("machine", "--challenge", "-c",
        help="Type: machine|web|pwn|reversing|crypto|forensics|active_directory"),
    mode: str = typer.Option("interactive", "--mode", "-m",
        help="Mode: interactive|semi_auto|autonomous|socratic"),
    llm: str = typer.Option(None, "--llm",
        help="Provider: ollama|anthropic|claude|gemini|deepseek|openai"),
    model: str = typer.Option(None, "--model", help="Override model name"),
    api_key: str = typer.Option(None, "--api-key", "-k", help="API key (or use env var)"),
):
    """Start a new learning session."""
    if not target and not url and challenge == "machine":
        console.print("[red]--target or --url required for machine challenges[/red]")
        raise typer.Exit(1)

    llm = llm or _CONFIG.get("llm", {}).get("provider", "ollama")
    model = model or _CONFIG.get("llm", {}).get("model")

    session = SessionManager.new(
        objective=objective,
        target_ip=target,
        target_url=url,
        challenge_type=challenge,
        mode=mode,
        llm_provider=llm,
        llm_model=model or DEFAULT_MODELS.get(llm, ""),
    )

    kwargs = {}
    if model:
        kwargs["model"] = model
    if api_key:
        kwargs["api_key"] = api_key

    from .ui.app import KaliMentorApp
    from .ui.tmux import setup_tmux_layout

    tmux_pane = setup_tmux_layout()

    backend = create_backend(llm, **kwargs)

    session_dir = str(session.session_dir)
    registry = ToolRegistry()
    register_bash_tool(registry, working_dir=session_dir)
    register_memory_tools(registry, session_dir=session_dir)
    register_findings_tool(registry)
    register_file_tools(registry)
    register_security_tools(registry)
    register_plan_tool(registry)

    agent = AgentLoop(
        llm=backend,
        registry=registry,
        mode=mode,
        session_dir=session_dir,
        session_manager=session,
    )

    app = KaliMentorApp(session=session, agent=agent, tmux_pane=tmux_pane)
    app.run()


# ═══════════════════════════════════════════════════════════════════════════
#  RESUME
# ═══════════════════════════════════════════════════════════════════════════

@app.command()
def resume(
    session_id: str = typer.Argument(..., help="Session ID to resume"),
    llm: str = typer.Option(None, "--llm", help="Override LLM provider"),
    model: str = typer.Option(None, "--model"),
    api_key: str = typer.Option(None, "--api-key", "-k"),
):
    """Resume a previous session."""
    try:
        session = SessionManager.load(session_id)
    except FileNotFoundError:
        console.print(f"[red]Session {session_id} not found[/red]")
        raise typer.Exit(1)

    provider = llm or session.state.llm_provider
    kwargs = {}
    if model:
        kwargs["model"] = model
    if api_key:
        kwargs["api_key"] = api_key

    backend = create_backend(provider, **kwargs)

    session_dir = str(session.session_dir)
    registry = ToolRegistry()
    register_bash_tool(registry, working_dir=session_dir)
    register_memory_tools(registry, session_dir=session_dir)
    register_findings_tool(registry)
    register_file_tools(registry)
    register_security_tools(registry)
    register_plan_tool(registry)

    agent = AgentLoop(
        llm=backend,
        registry=registry,
        session_dir=session_dir,
        session_manager=session,
    )
    console.print(f"[green]Resuming: {session_id}[/green]")
    asyncio.run(agent.run_cli())


# ═══════════════════════════════════════════════════════════════════════════
#  SESSIONS
# ═══════════════════════════════════════════════════════════════════════════

@app.command()
def sessions():
    """List all saved sessions."""
    all_s = SessionManager.list_sessions()
    if not all_s:
        console.print("[dim]No sessions found.[/dim]")
        return

    tbl = Table(title="Sessions")
    tbl.add_column("ID", style="cyan")
    tbl.add_column("Objective", max_width=35)
    tbl.add_column("Target", style="green")
    tbl.add_column("Phase", style="yellow")
    tbl.add_column("Access", style="red")
    tbl.add_column("LLM", style="dim")

    for s in all_s:
        tbl.add_row(s["id"], s["objective"][:35], s["target_ip"] or "—", s["phase"], s["access"], s["provider"])
    console.print(tbl)


# ═══════════════════════════════════════════════════════════════════════════
#  EXPORT
# ═══════════════════════════════════════════════════════════════════════════

@app.command()
def export(
    session_id: str = typer.Argument(...),
    output: str = typer.Option(None, "--output", "-o", help="Output file path"),
):
    """Export session as Markdown report."""
    try:
        session = SessionManager.load(session_id)
    except FileNotFoundError:
        console.print(f"[red]Session {session_id} not found[/red]")
        raise typer.Exit(1)

    report = session.export_markdown()
    if output:
        Path(output).write_text(report)
        console.print(f"[green]Written: {output}[/green]")
    else:
        console.print(report)


# ═══════════════════════════════════════════════════════════════════════════
#  RESEARCH
# ═══════════════════════════════════════════════════════════════════════════

@app.command()
def research(
    topic: str = typer.Argument(..., help="CVE, tool, or technique to research"),
    llm: str = typer.Option(None, "--llm"),
    model: str = typer.Option(None, "--model"),
    api_key: str = typer.Option(None, "--api-key", "-k"),
):
    """Research a specific cybersecurity topic."""
    from .core.planner import Planner
    from rich.panel import Panel

    llm = llm or _CONFIG.get("llm", {}).get("provider", "ollama")
    model = model or _CONFIG.get("llm", {}).get("model")

    kwargs = {}
    if model:
        kwargs["model"] = model
    if api_key:
        kwargs["api_key"] = api_key

    backend = create_backend(llm, **kwargs)
    planner = Planner(backend)

    async def _run():
        data = await planner.research_topic(topic)
        console.print(Panel(data.get("summary", ""), title=topic, border_style="magenta"))
        for k, t in [("technical_details", "Details"), ("exploitation", "Exploitation"), ("practice_suggestions", "Practice")]:
            if data.get(k):
                console.print(Panel(data[k], title=t))

    asyncio.run(_run())


# ═══════════════════════════════════════════════════════════════════════════
#  PROVIDERS
# ═══════════════════════════════════════════════════════════════════════════

@app.command()
def providers():
    """List supported AI providers and their configuration."""
    tbl = Table(title="Supported AI Providers")
    tbl.add_column("Provider", style="cyan")
    tbl.add_column("Default Model", style="green")
    tbl.add_column("Env Variable", style="yellow")

    for p in list_providers():
        tbl.add_row(p["provider"], p["default_model"], p["env_var"])
    console.print(tbl)


if __name__ == "__main__":
    app()
