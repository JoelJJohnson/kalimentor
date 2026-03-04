"""Agentic loop engine — OODA-style observe/orient/decide/act cycle."""

from __future__ import annotations

import asyncio
from typing import Any, Protocol, runtime_checkable

from rich.console import Console, RenderableType
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from .executor import ToolExecutor
from .llm import LLMBackend
from .models import (
    ActionResult,
    ActionStatus,
    AgentMode,
    Phase,
    ProposedAction,
    RiskLevel,
)
from .parser import OutputParser
from .planner import Planner
from .session import SessionManager

@runtime_checkable
class UICallback(Protocol):
    """Protocol that the TUI app implements to receive agent output."""
    def append_log(self, renderable: RenderableType) -> None: ...
    def set_status(self, state: str, message: str = "") -> None: ...
    def enable_input(self, enabled: bool) -> None: ...


console = Console()

BANNER = """
[bold cyan]╔═══════════════════════════════════════════════════════╗
║              ⚡ KaliMentor v0.2.0 ⚡                  ║
║       Agentic Cybersecurity Learning Framework        ║
╚═══════════════════════════════════════════════════════╝[/bold cyan]"""

HELP_TEXT = """
[bold]Commands:[/bold]
  [cyan]next[/cyan]      — Get AI-proposed next actions and execute them
  [cyan]status[/cyan]    — Show current session status
  [cyan]hint[/cyan]      — Get a Socratic hint (no direct answers)
  [cyan]research[/cyan]  — Deep-dive into a CVE, tool, or technique
  [cyan]auto[/cyan]      — Auto-run an entire phase (recon/enum/vuln)
  [cyan]plan[/cyan]      — Regenerate the attack plan
  [cyan]note[/cyan]      — Add a personal note to the session
  [cyan]export[/cyan]    — Export session as Markdown report
  [cyan]flag[/cyan]      — Record a captured flag
  [cyan]phase[/cyan]     — Manually set the current phase
  [cyan]help[/cyan]      — Show this help
  [cyan]quit[/cyan]      — Save and exit
  [cyan]![/cyan]<cmd>    — Execute a command directly (e.g. !nmap -sV 10.10.10.1)
  [dim]Or type any question/request in natural language[/dim]
"""


class AgentLoop:
    """The agentic loop that drives KaliMentor sessions."""

    def __init__(self, session: SessionManager, llm: LLMBackend, executor: ToolExecutor | None = None):
        self.session = session
        self.planner = Planner(llm)
        self.llm = llm
        self.executor = executor or ToolExecutor()

    async def run(self) -> None:
        console.print(BANNER)
        self._print_status()

        console.print("\n[bold cyan]Generating attack plan...[/bold cyan]")
        try:
            plan = await self.planner.create_initial_plan(self.session)
            self._display_plan(plan)
        except Exception as e:
            console.print(f"[yellow]Plan generation failed ({e}). You can still use manual commands.[/yellow]")

        console.print(HELP_TEXT)

        while True:
            try:
                raw = Prompt.ask("\n[bold green]KaliMentor ⚡[/bold green]", default="next")
                cmd = raw.strip().lower()

                if cmd in ("quit", "exit", "q"):
                    break
                elif cmd == "status":
                    self._print_status()
                elif cmd == "next":
                    await self._propose_and_execute()
                elif cmd == "research":
                    await self._research()
                elif cmd == "hint":
                    await self._hint()
                elif cmd == "auto":
                    await self._auto_phase()
                elif cmd == "plan":
                    plan = await self.planner.create_initial_plan(self.session)
                    self._display_plan(plan)
                elif cmd == "note":
                    self._add_note()
                elif cmd == "export":
                    self._export()
                elif cmd == "flag":
                    flag = Prompt.ask("Flag value")
                    self.session.add_flag(flag)
                    console.print(f"[green]Flag recorded! Total: {len(self.session.state.flags)}[/green]")
                elif cmd == "phase":
                    self._set_phase()
                elif cmd == "help":
                    console.print(HELP_TEXT)
                elif raw.startswith("!"):
                    await self._direct_exec(raw[1:].strip())
                else:
                    await self._propose_and_execute(raw)

            except KeyboardInterrupt:
                console.print("\n[yellow]Ctrl+C — type 'quit' to exit.[/yellow]")
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")

        self.session.save()
        console.print(f"\n[green]Session saved: {self.session.state.id}[/green]")

    # ── Core Cycle ─────────────────────────────────────────────────────

    async def _propose_and_execute(self, user_input: str = "") -> None:
        console.print("\n[cyan]Analyzing...[/cyan]")
        data = await self.planner.propose_next_actions(self.session, user_input)

        if analysis := data.get("analysis"):
            console.print(Panel(analysis, title="Analysis", border_style="blue"))
        if notes := data.get("learning_notes"):
            console.print(Panel(notes, title="💡 Learning Note", border_style="green"))

        actions_data = data.get("actions", [])
        if not actions_data:
            console.print("[yellow]No actions proposed.[/yellow]")
            return

        proposed = []
        tbl = Table(title="Proposed Actions", show_lines=True)
        tbl.add_column("#", width=3, style="bold")
        tbl.add_column("Tool", style="cyan")
        tbl.add_column("Command", max_width=65)
        tbl.add_column("Risk", style="yellow")

        for i, a in enumerate(actions_data, 1):
            action = ProposedAction(
                phase=data.get("phase_recommendation", self.session.state.current_phase),
                tool=a["tool"], command=a["command"],
                rationale=a["rationale"],
                expected_outcome=a.get("expected_outcome", ""),
                risk_level=a.get("risk_level", "low"),
                alternatives=a.get("alternatives", []),
            )
            proposed.append(action)
            rc = {"info": "dim", "low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}.get(action.risk_level, "white")
            tbl.add_row(str(i), action.tool, action.command[:65], f"[{rc}]{action.risk_level}[/]")

        console.print(tbl)

        # Show rationales
        for i, a in enumerate(proposed, 1):
            console.print(f"  [dim]{i}. {a.rationale}[/dim]")

        if self.session.state.mode == AgentMode.SOCRATIC:
            console.print("[dim]Socratic mode — review proposals and execute yourself.[/dim]")
            return

        sel = Prompt.ask("Execute? (1, 1,3, all, none)", default="1")
        if sel.lower() == "none":
            return

        indices = list(range(len(proposed))) if sel.lower() == "all" else [int(x.strip()) - 1 for x in sel.split(",")]

        for idx in indices:
            if 0 <= idx < len(proposed):
                action = proposed[idx]
                if action.risk_level in ("high", "critical"):
                    if not Confirm.ask(f"[red]⚠ {action.risk_level.upper()} RISK:[/red] {action.command}\nProceed?", default=False):
                        continue
                await self._run_action(action)

    async def _run_action(self, action: ProposedAction) -> None:
        console.print(f"\n[bold]▶[/bold] {action.command}")
        console.print(f"[dim]↳ {action.rationale}[/dim]")

        result = await self.executor.execute(action.command)

        if result.blocked:
            console.print(f"[red]BLOCKED: {result.block_reason}[/red]")
            self.session.record_action(action, ActionResult(action_id=action.id, status=ActionStatus.FAILED, stderr=result.block_reason))
            return

        if result.stdout:
            display = result.stdout[:4000]
            if len(result.stdout) > 4000:
                display += f"\n... ({len(result.stdout)} total chars)"
            console.print(Panel(display, title="Output", border_style="white"))

        if result.stderr and result.exit_code != 0:
            console.print(Panel(result.stderr[:1000], title="Errors", border_style="red"))

        tool = action.tool.split("/")[-1].split()[0]
        findings = OutputParser.parse(tool, result.stdout, action.id)

        if findings:
            ft = Table(title=f"Findings ({len(findings)})")
            ft.add_column("Category", style="cyan")
            ft.add_column("Key")
            ft.add_column("Value", style="green")
            for f in findings[:25]:
                ft.add_row(f.category, f.key, f.value[:60])
            console.print(ft)

        status = ActionStatus.COMPLETED if result.exit_code == 0 else ActionStatus.FAILED
        ar = ActionResult(
            action_id=action.id, status=status,
            stdout=result.stdout, stderr=result.stderr,
            exit_code=result.exit_code, duration_seconds=result.duration_seconds,
            findings=findings,
        )
        self.session.record_action(action, ar)

        if result.stdout and len(result.stdout) > 100:
            if Confirm.ask("Explain output?", default=False):
                exp = await self.planner.explain_output(tool, action.command, result.stdout, self.session)
                console.print(Panel(Markdown(exp), title="Explanation", border_style="green"))

        console.print(f"[dim]{result.duration_seconds}s | exit {result.exit_code}[/dim]")

    async def _direct_exec(self, command: str) -> None:
        if not command:
            return
        if self.executor.is_high_risk(command):
            if not Confirm.ask("[red]⚠ High-risk command. Proceed?[/red]", default=False):
                return
        action = ProposedAction(
            phase=self.session.state.current_phase, tool=command.split()[0],
            command=command, rationale="Direct user command",
            expected_outcome="User-defined", risk_level=RiskLevel.MEDIUM,
        )
        await self._run_action(action)

    async def _auto_phase(self) -> None:
        phase = Prompt.ask("Phase to auto-run", choices=["recon", "enum", "vuln"], default="recon")
        phase_map = {"recon": Phase.RECON, "enum": Phase.ENUM, "vuln": Phase.VULN_ANALYSIS}
        target = phase_map[phase]
        console.print(f"\n[bold cyan]Auto-running {target.value}...[/bold cyan]")

        for i in range(8):
            data = await self.planner.propose_next_actions(self.session)
            for a in data.get("actions", []):
                if a.get("risk_level", "low") in ("high", "critical"):
                    console.print(f"[yellow]Skipping high-risk: {a['command'][:60]}[/yellow]")
                    continue
                action = ProposedAction(
                    phase=target, tool=a["tool"], command=a["command"],
                    rationale=a["rationale"], expected_outcome=a.get("expected_outcome", ""),
                    risk_level=a.get("risk_level", "low"),
                )
                await self._run_action(action)

        console.print("[green]Auto-phase complete.[/green]")
        self._print_status()

    async def _research(self) -> None:
        topic = Prompt.ask("Research topic")
        console.print(f"[cyan]Researching: {topic}...[/cyan]")
        data = await self.planner.research_topic(topic, self.session.get_context_summary())
        console.print(Panel(data.get("summary", ""), title=f"Research: {topic}", border_style="magenta"))
        for key, title in [("technical_details", "Technical Details"), ("exploitation", "Exploitation"), ("mitigation", "Mitigation"), ("practice_suggestions", "Practice")]:
            if data.get(key):
                console.print(Panel(data[key], title=title))
        if refs := data.get("references"):
            console.print(Panel("\n".join(refs), title="References"))

    async def _hint(self) -> None:
        q = Prompt.ask("What are you stuck on?")
        hint = await self.planner.get_socratic_hint(self.session, q)
        console.print(Panel(Markdown(hint), title="💡 Hint", border_style="yellow"))

    # ── UI Helpers ─────────────────────────────────────────────────────

    def _print_status(self) -> None:
        s = self.session.state
        tbl = Table(title="Session Status", show_lines=True)
        tbl.add_column("", style="cyan", width=16)
        tbl.add_column("")
        tbl.add_row("Session", s.id)
        tbl.add_row("Objective", s.objective)
        tbl.add_row("Target", s.target.ip or s.target.url or "N/A")
        tbl.add_row("Type", s.target.challenge_type)
        tbl.add_row("Phase", s.current_phase.value)
        tbl.add_row("Mode", s.mode)
        tbl.add_row("LLM", f"{s.llm_provider} ({s.llm_model or 'default'})")
        tbl.add_row("Access", s.access_level)
        tbl.add_row("Ports", ", ".join(s.open_ports) or "—")
        tbl.add_row("Findings", str(len(s.findings)))
        tbl.add_row("Actions", str(len(s.action_history)))
        tbl.add_row("Flags", str(len(s.flags)))
        console.print(tbl)

    def _display_plan(self, plan) -> None:
        tbl = Table(title=f"Attack Plan: {plan.methodology}", show_lines=True)
        tbl.add_column("#", width=3)
        tbl.add_column("Phase", style="cyan")
        tbl.add_column("Description")
        tbl.add_column("Tools", style="green")
        for i, step in enumerate(plan.steps, 1):
            tbl.add_row(str(i), step.phase, step.description, ", ".join(step.tools))
        console.print(tbl)
        if plan.notes:
            console.print(f"[dim]Note: {plan.notes}[/dim]")

    def _add_note(self) -> None:
        note = Prompt.ask("Note")
        self.session.add_note(note)
        console.print("[green]Saved.[/green]")

    def _set_phase(self) -> None:
        phases = [p.value for p in Phase]
        console.print(f"Available: {', '.join(phases)}")
        p = Prompt.ask("Phase", choices=phases)
        self.session.advance_phase(Phase(p))
        console.print(f"[green]Phase set to {p}[/green]")

    def _export(self) -> None:
        report = self.session.export_markdown()
        path = self.session.save().parent / f"{self.session.state.id}_report.md"
        path.write_text(report)
        console.print(f"[green]Exported: {path}[/green]")
