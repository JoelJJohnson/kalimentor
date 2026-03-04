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


class ConsoleUI:
    """Fallback UI that prints to the Rich console (non-TUI mode)."""
    def __init__(self):
        self._console = Console()

    def append_log(self, renderable: RenderableType) -> None:
        self._console.print(renderable)

    def set_status(self, state: str, message: str = "") -> None:
        icons = {
            "thinking": "[cyan]⠋[/cyan]",
            "analyzing": "[cyan]⠙[/cyan]",
            "running": "[yellow]⠹[/yellow]",
            "processing": "[yellow]⠸[/yellow]",
            "done": "[green]✓[/green]",
            "error": "[red]✗[/red]",
            "ready": "[dim]●[/dim]",
        }
        icon = icons.get(state, "●")
        if message:
            self._console.print(f"{icon}  {message}", highlight=False)

    def enable_input(self, enabled: bool) -> None:
        pass  # No-op for console mode


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

    def __init__(
        self,
        session: SessionManager,
        llm: LLMBackend,
        executor: ToolExecutor | None = None,
        ui: UICallback | None = None,
    ):
        self.session = session
        self.planner = Planner(llm)
        self.llm = llm
        self.executor = executor or ToolExecutor()
        self.ui: UICallback = ui or ConsoleUI()
        self.tui_mode: bool = False

    async def run(self) -> None:
        self.ui.append_log(BANNER)
        self._print_status()

        self.ui.set_status("thinking", "Connecting to LLM...")
        try:
            plan = await self.planner.create_initial_plan(self.session)
            self._display_plan(plan)
        except Exception as e:
            self.ui.append_log(f"[yellow]Plan generation failed ({e}). You can still use manual commands.[/yellow]")

        self.ui.append_log(HELP_TEXT)

        if not self.tui_mode:
            # CLI mode: interactive prompt loop
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
                        self.ui.append_log(f"[green]Flag recorded! Total: {len(self.session.state.flags)}[/green]")
                    elif cmd == "phase":
                        self._set_phase()
                    elif cmd == "help":
                        self.ui.append_log(HELP_TEXT)
                    elif raw.startswith("!"):
                        await self._direct_exec(raw[1:].strip())
                    else:
                        await self._propose_and_execute(raw)

                except KeyboardInterrupt:
                    self.ui.append_log("\n[yellow]Ctrl+C — type 'quit' to exit.[/yellow]")
                except Exception as e:
                    self.ui.set_status("error", str(e))

            self.session.save()
            self.ui.append_log(f"\n[green]Session saved: {self.session.state.id}[/green]")
        else:
            # TUI mode: Textual events drive input — just signal ready and return
            self.ui.set_status("ready")
            self.ui.enable_input(True)

    # ── Core Cycle ─────────────────────────────────────────────────────

    async def _propose_and_execute(self, user_input: str = "") -> None:
        self.ui.set_status("thinking", "Waiting for LLM...")
        self.ui.enable_input(False)
        data = await self.planner.propose_next_actions(self.session, user_input)
        self.ui.set_status("analyzing", "Analysing response...")

        if analysis := data.get("analysis"):
            self.ui.append_log(Panel(analysis, title="Analysis", border_style="blue"))
        if notes := data.get("learning_notes"):
            self.ui.append_log(Panel(notes, title="💡 Learning Note", border_style="green"))

        actions_data = data.get("actions", [])
        if not actions_data:
            self.ui.append_log("[yellow]No actions proposed.[/yellow]")
            self.ui.set_status("ready")
            self.ui.enable_input(True)
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

        self.ui.append_log(tbl)

        # Show rationales
        for i, a in enumerate(proposed, 1):
            self.ui.append_log(f"  [dim]{i}. {a.rationale}[/dim]")

        if self.session.state.mode == AgentMode.SOCRATIC:
            self.ui.append_log("[dim]Socratic mode — review proposals and execute yourself.[/dim]")
            self.ui.set_status("ready")
            self.ui.enable_input(True)
            return

        if self.tui_mode:
            # TUI: auto-execute action 1; skip high/critical risk without prompting
            sel = "1"
        else:
            sel = Prompt.ask("Execute? (1, 1,3, all, none)", default="1")

        if sel.lower() == "none":
            self.ui.set_status("ready")
            self.ui.enable_input(True)
            return

        indices = list(range(len(proposed))) if sel.lower() == "all" else [int(x.strip()) - 1 for x in sel.split(",")]

        for idx in indices:
            if 0 <= idx < len(proposed):
                action = proposed[idx]
                if action.risk_level in ("high", "critical"):
                    if self.tui_mode:
                        self.ui.append_log(
                            f"[red]⚠ {action.risk_level.upper()} RISK skipped (confirm in CLI mode): {action.command[:60]}[/red]"
                        )
                        continue
                    if not Confirm.ask(f"[red]⚠ {action.risk_level.upper()} RISK:[/red] {action.command}\nProceed?", default=False):
                        continue
                await self._run_action(action)

        self.ui.set_status("ready")
        self.ui.enable_input(True)

    async def _run_action(self, action: ProposedAction) -> None:
        self.ui.append_log(f"\n[bold]▶[/bold] {action.command}")
        self.ui.append_log(f"[dim]↳ {action.rationale}[/dim]")
        self.ui.set_status("running", action.command[:60])

        self.ui.set_status("running", f"Running: {action.tool}...")
        result = await self.executor.execute(action.command)

        if result.blocked:
            self.ui.append_log(f"[red]BLOCKED: {result.block_reason}[/red]")
            self.session.record_action(action, ActionResult(action_id=action.id, status=ActionStatus.FAILED, stderr=result.block_reason))
            return

        if result.stdout:
            display = result.stdout[:4000]
            if len(result.stdout) > 4000:
                display += f"\n... ({len(result.stdout)} total chars)"
            self.ui.append_log(Panel(display, title="Output", border_style="white"))

        self.ui.set_status("processing", "Processing results...")

        if result.stderr and result.exit_code != 0:
            self.ui.append_log(Panel(result.stderr[:1000], title="Errors", border_style="red"))

        tool = action.tool.split("/")[-1].split()[0]
        findings = OutputParser.parse(tool, result.stdout, action.id)

        if findings:
            ft = Table(title=f"Findings ({len(findings)})")
            ft.add_column("Category", style="cyan")
            ft.add_column("Key")
            ft.add_column("Value", style="green")
            for f in findings[:25]:
                ft.add_row(f.category, f.key, f.value[:60])
            self.ui.append_log(ft)

        status = ActionStatus.COMPLETED if result.exit_code == 0 else ActionStatus.FAILED
        ar = ActionResult(
            action_id=action.id, status=status,
            stdout=result.stdout, stderr=result.stderr,
            exit_code=result.exit_code, duration_seconds=result.duration_seconds,
            findings=findings,
        )
        self.session.record_action(action, ar)

        if result.stdout and len(result.stdout) > 100:
            explain = False if self.tui_mode else Confirm.ask("Explain output?", default=False)
            if explain:
                exp = await self.planner.explain_output(tool, action.command, result.stdout, self.session)
                self.ui.append_log(Panel(Markdown(exp), title="Explanation", border_style="green"))

        self.ui.append_log(f"[dim]{result.duration_seconds}s | exit {result.exit_code}[/dim]")

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
        self.ui.set_status("running", f"Auto-running {target.value}...")

        for i in range(8):
            data = await self.planner.propose_next_actions(self.session)
            for a in data.get("actions", []):
                if a.get("risk_level", "low") in ("high", "critical"):
                    self.ui.append_log(f"[yellow]Skipping high-risk: {a['command'][:60]}[/yellow]")
                    continue
                action = ProposedAction(
                    phase=target, tool=a["tool"], command=a["command"],
                    rationale=a["rationale"], expected_outcome=a.get("expected_outcome", ""),
                    risk_level=a.get("risk_level", "low"),
                )
                await self._run_action(action)

        self.ui.append_log("[green]Auto-phase complete.[/green]")
        self._print_status()

    async def _research(self) -> None:
        topic = Prompt.ask("Research topic")
        self.ui.set_status("thinking", f"Researching: {topic}...")
        data = await self.planner.research_topic(topic, self.session.get_context_summary())
        self.ui.append_log(Panel(data.get("summary", ""), title=f"Research: {topic}", border_style="magenta"))
        for key, title in [("technical_details", "Technical Details"), ("exploitation", "Exploitation"), ("mitigation", "Mitigation"), ("practice_suggestions", "Practice")]:
            if data.get(key):
                self.ui.append_log(Panel(data[key], title=title))
        if refs := data.get("references"):
            self.ui.append_log(Panel("\n".join(refs), title="References"))
        self.ui.set_status("ready")
        self.ui.enable_input(True)

    async def _hint(self) -> None:
        q = Prompt.ask("What are you stuck on?")
        hint = await self.planner.get_socratic_hint(self.session, q)
        self.ui.append_log(Panel(Markdown(hint), title="💡 Hint", border_style="yellow"))
        self.ui.set_status("ready")
        self.ui.enable_input(True)

    async def _analyse_terminal_output(self, terminal_text: str) -> None:
        """Analyse terminal output from the right pane via LLM."""
        self.ui.set_status("analyzing", "Analysing terminal output...")
        self.ui.enable_input(False)
        try:
            ctx = self.session.get_context_summary()
            result = await self.planner.analyse_terminal_output(terminal_text, ctx)
            self.ui.append_log(Panel(Markdown(result), title="🔍 Terminal Analysis", border_style="magenta"))
            self.ui.set_status("done", "Analysis complete")
        except Exception as e:
            self.ui.set_status("error", str(e))
        finally:
            self.ui.enable_input(True)
            self.ui.set_status("ready")

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
        self.ui.append_log(tbl)

    def _display_plan(self, plan) -> None:
        tbl = Table(title=f"Attack Plan: {plan.methodology}", show_lines=True)
        tbl.add_column("#", width=3)
        tbl.add_column("Phase", style="cyan")
        tbl.add_column("Description")
        tbl.add_column("Tools", style="green")
        for i, step in enumerate(plan.steps, 1):
            tbl.add_row(str(i), step.phase, step.description, ", ".join(step.tools))
        self.ui.append_log(tbl)
        if plan.notes:
            self.ui.append_log(f"[dim]Note: {plan.notes}[/dim]")

    def _add_note(self) -> None:
        note = Prompt.ask("Note")
        self.session.add_note(note)
        self.ui.append_log("[green]Saved.[/green]")

    def _set_phase(self) -> None:
        phases = [p.value for p in Phase]
        self.ui.append_log(f"Available: {', '.join(phases)}")
        p = Prompt.ask("Phase", choices=phases)
        self.session.advance_phase(Phase(p))
        self.ui.append_log(f"[green]Phase set to {p}[/green]")

    def _export(self) -> None:
        report = self.session.export_markdown()
        path = self.session.save().parent / f"{self.session.state.id}_report.md"
        path.write_text(report)
        self.ui.append_log(f"[green]Exported: {path}[/green]")
