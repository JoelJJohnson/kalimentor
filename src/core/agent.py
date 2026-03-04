"""Agentic loop — single-threaded tool_use loop modelled after Claude Code's architecture.

Replaces the old JSON-plan-and-pick loop with a native tool_use cycle:

  user input → LLM (with tools) → tool calls → tool results → LLM → … → text reply

Interaction modes
-----------------
interactive  All CONFIRM/DANGEROUS tools pause for user approval. SAFE run automatically.
autonomous   All tools run automatically except DANGEROUS. (Claude Code "auto-accept".)
socratic     LLM is instructed to explain what it would do but call NO tools. User executes.
yolo         Everything runs. No confirmations. CTF speedrun mode. Warns heavily.
"""

from __future__ import annotations

import asyncio
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.status import Status
from rich.table import Table

from .llm import (
    LLMBackend,
    LLMResponse,
    ToolCall,
    assistant_message,
    tool_result_message,
    user_message,
)
from .tools.registry import ToolRegistry, ToolRiskLevel
from .tools.plan_tool import get_plan_store, set_plan_store, PlanStore
from .session import SessionManager
from .context import compress, needs_compression
from .memory import read_session_memory, ensure_memory

console = Console()

BANNER = """\
[bold cyan]
╔═══════════════════════════════════════════════════════╗
║              KaliMentor  —  Agentic Mode              ║
║       Native tool_use loop  |  5-provider LLM        ║
╚═══════════════════════════════════════════════════════╝
[/bold cyan]"""

HELP_TEXT = """\
[bold]Slash commands:[/bold]
  [cyan]/plan[/cyan]    Show the current TODO list
  [cyan]/memory[/cyan]  Show KALIMENTOR.md session memory
  [cyan]/status[/cyan]  Show session info
  [cyan]/tools[/cyan]   List all registered tools
  [cyan]/mode[/cyan]    Switch interaction mode
  [cyan]/compact[/cyan] Force context compression now  [dim](Phase 2)[/dim]
  [cyan]/export[/cyan]  Export session report  [dim](Phase 4)[/dim]
  [cyan]/flag[/cyan]    Record a captured flag
  [cyan]/note[/cyan]    Add a note to memory
  [cyan]/undo[/cyan]    Remove last message pair from history
  [cyan]/help[/cyan]    Show this help
  [cyan]/clear[/cyan]   Clear screen
  [cyan]/quit[/cyan]    Save and exit

[dim]Or type any natural language — the agent will act.[/dim]
"""


# ─────────────────────────────────────────────────────────────────────────────
#  Agent loop
# ─────────────────────────────────────────────────────────────────────────────

class AgentLoop:
    """The new single-threaded tool_use agentic loop.

    Args:
        llm:          Any LLMBackend instance.
        registry:     ToolRegistry with all tools registered.
        system:       System prompt string.
        mode:         "interactive" | "autonomous" | "socratic" | "yolo"
        session_dir:  Path to session directory (for memory / history).
    """

    def __init__(
        self,
        llm: LLMBackend,
        registry: ToolRegistry,
        system: str = "",
        mode: str = "interactive",
        session_dir: str = "/tmp/kalimentor",
        session_manager: SessionManager | None = None,
    ) -> None:
        self.llm = llm
        self.registry = registry
        self.system = system
        self.mode = mode
        self.session_dir = session_dir
        self._session_manager = session_manager
        # Load persisted history if a session manager is provided
        if session_manager is not None:
            self._messages: list[dict[str, Any]] = session_manager.load_messages()
            self.session_dir = str(session_manager.session_dir)
        else:
            self._messages: list[dict[str, Any]] = []
        self._flags: list[str] = []
        self._notes: list[str] = []
        # Each AgentLoop gets its own PlanStore; register it as the active module store
        self._plan_store = PlanStore()
        set_plan_store(self._plan_store)

    # ── Public entry points ───────────────────────────────────────────────

    async def run_cli(self) -> None:
        """Start the interactive CLI loop (blocking)."""
        console.print(BANNER)
        console.print(f"[dim]Mode: {self.mode}  |  LLM: {self.llm}[/dim]")
        console.print(HELP_TEXT)

        while True:
            try:
                raw = await asyncio.get_running_loop().run_in_executor(
                    None,
                    lambda: Prompt.ask("\n[bold green]KaliMentor ⚡[/bold green]"),
                )
                raw = raw.strip()
                if not raw:
                    continue

                # Slash commands
                if raw.startswith("/"):
                    handled = await self._handle_slash(raw)
                    if handled == "quit":
                        break
                    continue

                # Natural language → agent loop
                await self.run(raw)

            except KeyboardInterrupt:
                console.print("\n[yellow]Ctrl+C — type /quit to exit.[/yellow]")
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")

    async def run(self, user_input: str) -> str:
        """Process one user turn through the agentic loop.

        Runs until the LLM produces a text-only reply (no more tool calls).
        Returns the final text response.
        """
        user_msg = user_message(user_input)
        self._messages.append(user_msg)
        self._persist_message(user_msg)

        while True:
            # Compress context if approaching the window limit
            if needs_compression(self._messages, self.llm.provider):
                await self._do_compression()

            # Build the system prompt with plan reminder appended
            system = self._build_system()

            # Get tool schemas in the right format for this provider
            tools = self.registry.get_schemas(fmt=self.llm.provider)

            # ── LLM call (streaming if supported, else blocking) ─────────
            response = await self._call_llm(
                messages=self._messages,
                system=system,
                tools=tools if self.mode != "socratic" else None,
            )

            # Append assistant turn to history
            asst_msg = assistant_message(response)
            self._messages.append(asst_msg)
            self._persist_message(asst_msg)

            # Display any text the LLM produced
            if response.text:
                console.print(Panel(Markdown(response.text), border_style="blue"))

            # ── No tool calls → LLM is done ─────────────────────────────
            if not response.tool_calls:
                return response.text

            # ── Execute tool calls ───────────────────────────────────────
            tool_results = await self._execute_tool_calls(response.tool_calls)

            # Append tool results to history
            tr_msg = tool_result_message(tool_results)
            self._messages.append(tr_msg)
            self._persist_message(tr_msg)

    # ── LLM call with optional streaming ─────────────────────────────────

    async def _call_llm(
        self,
        messages: list[dict[str, Any]],
        system: str,
        tools: list[dict[str, Any]] | None,
    ) -> LLMResponse:
        """Call the LLM, streaming output if the backend supports it.

        Falls back to blocking create_message() when stream_message() is absent.
        Returns a fully-assembled LLMResponse.
        """
        from .stream import TextChunk, ToolCallEvent, UsageEvent
        from rich.live import Live
        from rich.text import Text

        if not hasattr(self.llm, "stream_message"):
            with Status("[cyan]Thinking…[/cyan]", console=console):
                return await self.llm.create_message(
                    messages=messages,
                    system=system,
                    tools=tools,
                )

        # ── Streaming path ───────────────────────────────────────────────
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        input_tokens = 0
        output_tokens = 0
        stop_reason = "end_turn"

        live_text = Text()

        with Live(live_text, console=console, refresh_per_second=20) as live:
            async for event in self.llm.stream_message(
                messages=messages,
                system=system,
                tools=tools,
            ):
                if isinstance(event, TextChunk):
                    text_parts.append(event.text)
                    live_text.append(event.text)
                    live.update(live_text)
                elif isinstance(event, ToolCallEvent):
                    tool_calls.append(event.tool_call)
                    stop_reason = "tool_use"
                elif isinstance(event, UsageEvent):
                    input_tokens = event.input_tokens
                    output_tokens = event.output_tokens

        full_text = "".join(text_parts)

        # Show token usage
        if input_tokens or output_tokens:
            console.print(
                f"[dim]↑ {input_tokens} tokens in | ↓ {output_tokens} tokens out[/dim]"
            )

        return LLMResponse(
            text=full_text,
            tool_calls=tool_calls,
            stop_reason=stop_reason,
            raw=None,
        )

    # ── Context compression ───────────────────────────────────────────────

    async def _do_compression(self) -> None:
        """Compress conversation history and update messages.jsonl."""
        before = len(self._messages)
        with Status("[magenta]Compressing context…[/magenta]", console=console):
            self._messages = await compress(
                self._messages,
                self.llm,
                session_manager=self._session_manager,
            )
        after = len(self._messages)
        console.print(
            f"[dim]Context compressed: {before} → {after} messages.[/dim]"
        )

    # ── Session persistence ───────────────────────────────────────────────

    def _persist_message(self, message: dict[str, Any]) -> None:
        """Append a single message to the session's messages.jsonl."""
        if self._session_manager is not None:
            self._session_manager.append_message(message)

    # ── Tool execution ────────────────────────────────────────────────────

    async def _execute_tool_calls(
        self, tool_calls: list[ToolCall]
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        for tc in tool_calls:
            result_content = await self._execute_one(tc)
            results.append({"tool_use_id": tc.id, "content": result_content})

        return results

    async def _execute_one(self, tc: ToolCall) -> str:
        """Execute a single tool call, applying mode-based risk gates."""
        from .tools.bash_tool import get_shell, _is_blocked, _get_timeout, _truncate
        from rich.live import Live
        from rich.text import Text

        risk = self.registry.effective_risk(tc.name, tc.input)
        needs_confirm = self._mode_requires_confirm(risk)

        self._display_tool_call(tc, risk)

        if needs_confirm:
            approved = await self._ask_confirmation(tc)
            if not approved:
                msg = f"[User declined {tc.name}]"
                console.print(f"[yellow]{msg}[/yellow]")
                return msg

        # ── Bash streaming path ──────────────────────────────────────────
        if tc.name == "bash":
            command = tc.input.get("command", "")
            timeout = tc.input.get("timeout") or _get_timeout(command)
            blocked, reason = _is_blocked(command)
            if blocked:
                result_str = f"[BLOCKED] {reason}"
                self._display_tool_result(tc.name, result_str)
                return result_str

            shell = getattr(self, "_bash_shell", None) or get_shell(self.session_dir)
            on_line: asyncio.Queue[str] = asyncio.Queue()
            live_lines: list[str] = []
            live_text = Text()

            async def drain_queue(live: Live) -> None:
                while True:
                    try:
                        line = on_line.get_nowait()
                        live_lines.append(line)
                        visible = live_lines[-20:]
                        live_text.plain = "\n".join(visible)
                        live.update(
                            Panel(live_text, title=f"[yellow]bash: {command[:50]}[/yellow]", border_style="yellow")
                        )
                    except asyncio.QueueEmpty:
                        await asyncio.sleep(0.05)

            with Live(
                Panel("", title=f"[yellow]bash: {command[:50]}[/yellow]", border_style="yellow"),
                console=console,
                refresh_per_second=20,
            ) as live:
                drain_task = asyncio.create_task(drain_queue(live))
                try:
                    output, exit_code = await shell.run(command, timeout=timeout, on_line=on_line)
                finally:
                    drain_task.cancel()
                    try:
                        await drain_task
                    except asyncio.CancelledError:
                        pass

            output = _truncate(output)
            result_str = f"{output}\n[exit {exit_code}]".strip() if exit_code != 0 else output.strip()
            self._display_tool_result(tc.name, result_str)
            return result_str

        # ── Generic tool path (spinner) ──────────────────────────────────
        with Status(f"[yellow]Running {tc.name}…[/yellow]", console=console):
            try:
                result = await self.registry.execute(tc.name, tc.input)
                result_str = str(result)
            except KeyError as e:
                result_str = f"[ERROR] Unknown tool: {e}"
            except Exception as e:
                result_str = f"[ERROR] Tool execution failed: {e}"

        self._display_tool_result(tc.name, result_str)
        return result_str

    def _mode_requires_confirm(self, risk: ToolRiskLevel) -> bool:
        """Determine whether this risk level requires confirmation given current mode."""
        if self.mode == "yolo":
            return False
        if self.mode == "autonomous":
            # Only DANGEROUS needs confirmation in autonomous mode
            return risk == ToolRiskLevel.DANGEROUS
        # interactive / socratic — CONFIRM and DANGEROUS both need approval
        return risk in (ToolRiskLevel.CONFIRM, ToolRiskLevel.DANGEROUS)

    async def _ask_confirmation(self, tc: ToolCall) -> bool:
        """Ask the user to approve a tool call. Returns True if approved."""
        prompt_str = f"Allow [bold cyan]{tc.name}[/bold cyan]?"
        return await asyncio.get_running_loop().run_in_executor(
            None,
            lambda: Confirm.ask(prompt_str, default=False),
        )

    # ── Display helpers ───────────────────────────────────────────────────

    def _display_tool_call(self, tc: ToolCall, risk: ToolRiskLevel) -> None:
        risk_color = {
            ToolRiskLevel.SAFE: "green",
            ToolRiskLevel.CONFIRM: "yellow",
            ToolRiskLevel.DANGEROUS: "red",
        }.get(risk, "white")

        # Format input for display
        input_lines = "\n".join(f"  {k}: {v}" for k, v in tc.input.items())
        console.print(
            Panel(
                input_lines or "(no input)",
                title=f"[{risk_color}]Tool: {tc.name}[/{risk_color}]  "
                      f"[dim](risk: {risk.value})[/dim]",
                border_style=risk_color,
            )
        )

    def _display_tool_result(self, name: str, result: str) -> None:
        # Truncate long results for display (full result still goes to LLM)
        display = result if len(result) <= 3000 else result[:3000] + "\n[…truncated for display]"
        console.print(
            Panel(display, title=f"[dim]Result: {name}[/dim]", border_style="dim")
        )

    # ── System prompt construction ────────────────────────────────────────

    def _build_system(self) -> str:
        parts = [self.system]

        # Prepend KALIMENTOR.md so the LLM always has the latest session memory
        memory_text = self._read_memory()
        if memory_text:
            parts.append(f"\n\n---\n[Session Memory — KALIMENTOR.md]\n{memory_text}\n---")

        plan_reminder = self._plan_store.as_reminder()
        if plan_reminder:
            parts.append(f"\n\n{plan_reminder}")

        if self.mode == "socratic":
            parts.append(
                "\n\n[Socratic mode] Explain what you WOULD do and why, "
                "but do NOT call any tools. The user will execute manually."
            )
        return "\n".join(parts)

    def _read_memory(self) -> str:
        """Return KALIMENTOR.md contents if the session dir is set."""
        from pathlib import Path
        d = Path(self.session_dir)
        mem = d / "KALIMENTOR.md"
        if not mem.exists():
            return ""
        text = mem.read_text(encoding="utf-8", errors="replace").strip()
        # Skip injection if it's just the blank template
        from .memory import MEMORY_TEMPLATE
        if text == MEMORY_TEMPLATE.strip():
            return ""
        return text

    # ── Slash command handler ─────────────────────────────────────────────

    async def _handle_slash(self, raw: str) -> str | None:
        parts = raw.lstrip("/").split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd == "quit":
            if self._session_manager is not None:
                self._session_manager.save()
                console.print(
                    f"[green]Session saved.[/green] "
                    f"[dim]Resume with: kalimentor resume {self._session_manager.state.id}[/dim]"
                )
            console.print("[green]Goodbye.[/green]")
            return "quit"

        elif cmd == "clear":
            console.clear()

        elif cmd == "help":
            console.print(HELP_TEXT)

        elif cmd == "plan":
            console.print(self._plan_store.as_table())

        elif cmd == "memory":
            await self._show_memory()

        elif cmd == "status":
            self._show_status()

        elif cmd == "tools":
            self._show_tools()

        elif cmd == "mode":
            if arg in ("interactive", "autonomous", "socratic", "yolo"):
                self.mode = arg
                console.print(f"[green]Mode switched to: {self.mode}[/green]")
                if self.mode == "yolo":
                    console.print(
                        "[bold red]WARNING: YOLO mode — all confirmations disabled. "
                        "Use only in CTF environments.[/bold red]"
                    )
            else:
                console.print(
                    "[yellow]Available modes: interactive, autonomous, socratic, yolo[/yellow]"
                )

        elif cmd == "flag":
            flag = arg or await asyncio.get_running_loop().run_in_executor(
                None, lambda: Prompt.ask("Flag value")
            )
            if flag:
                self._flags.append(flag)
                console.print(f"[green]Flag recorded: {flag}[/green]")

        elif cmd == "note":
            note = arg or await asyncio.get_running_loop().run_in_executor(
                None, lambda: Prompt.ask("Note")
            )
            if note:
                self._notes.append(note)
                # Also write to memory via the tool if registered
                if self.registry.get("write_memory"):
                    memory_tool = self.registry.get("write_memory")
                    if memory_tool:
                        pass  # User notes appended to memory in Phase 2
                console.print("[green]Note saved.[/green]")

        elif cmd == "undo":
            # Remove last user + assistant message pair
            if len(self._messages) >= 2:
                self._messages = self._messages[:-2]
                console.print("[yellow]Last message pair removed from history.[/yellow]")
            else:
                console.print("[yellow]Nothing to undo.[/yellow]")

        elif cmd == "compact":
            if not self._messages:
                console.print("[yellow]No messages to compress.[/yellow]")
            else:
                await self._do_compression()

        elif cmd == "export":
            console.print("[dim]/export will be available in Phase 4.[/dim]")

        else:
            console.print(f"[yellow]Unknown command: /{cmd}. Type /help for options.[/yellow]")

        return None

    # ── Info display helpers ──────────────────────────────────────────────

    async def _show_memory(self) -> None:
        read_tool = self.registry.get("read_memory")
        if read_tool:
            content = await read_tool.handler()
            console.print(Panel(content, title="KALIMENTOR.md", border_style="magenta"))
        else:
            console.print("[yellow]Memory tool not registered.[/yellow]")

    def _show_status(self) -> None:
        tbl = Table(title="Session Status", show_lines=True)
        tbl.add_column("", style="cyan", width=16)
        tbl.add_column("")
        tbl.add_row("LLM", str(self.llm))
        tbl.add_row("Mode", self.mode)
        tbl.add_row("Messages", str(len(self._messages)))
        tbl.add_row("Tools", str(len(self.registry.list_tools())))
        tbl.add_row("Flags", str(len(self._flags)))
        tbl.add_row("Notes", str(len(self._notes)))
        tbl.add_row("Session dir", self.session_dir)
        console.print(tbl)

    def _show_tools(self) -> None:
        tbl = Table(title="Registered Tools", show_lines=True)
        tbl.add_column("Name", style="cyan")
        tbl.add_column("Risk", width=10)
        tbl.add_column("Description")
        risk_colors = {
            ToolRiskLevel.SAFE: "green",
            ToolRiskLevel.CONFIRM: "yellow",
            ToolRiskLevel.DANGEROUS: "red",
        }
        for tool in sorted(self.registry.list_tools(), key=lambda t: t.name):
            color = risk_colors.get(tool.risk_level, "white")
            tbl.add_row(
                tool.name,
                f"[{color}]{tool.risk_level.value}[/{color}]",
                tool.description[:80],
            )
        console.print(tbl)
