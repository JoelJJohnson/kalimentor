"""KaliMentor Textual TUI application."""

from __future__ import annotations

from rich.console import RenderableType
from textual.app import App, ComposeResult
from textual.widgets import Static, Input
from textual.containers import Vertical

from ..core.agent import AgentLoop, UICallback
from ..core.session import SessionManager
from .widgets import ChatLog

from .tmux import capture_pane


class TUICallback:
    """UICallback implementation that routes output to Textual widgets."""

    def __init__(self, log: ChatLog, status: Static, input_widget: Input):
        self._log = log
        self._status = status
        self._input = input_widget

    def append_log(self, renderable: RenderableType) -> None:
        self._log.append_log(renderable)

    def set_status(self, state: str, message: str = "") -> None:
        icons = {
            "ready":      ("dim", "●"),
            "thinking":   ("cyan", "⠋"),
            "analyzing":  ("cyan", "⠙"),
            "running":    ("yellow", "⠹"),
            "processing": ("yellow", "⠸"),
            "done":       ("green", "✓"),
            "error":      ("red", "✗"),
        }
        style, icon = icons.get(state, ("dim", "●"))
        labels = {
            "ready":      "Ready",
            "thinking":   "Waiting for LLM...",
            "analyzing":  "LLM processing...",
            "running":    "Running tool...",
            "processing": "Parsing results...",
            "done":       "Done",
            "error":      "Error",
        }
        text = message or labels.get(state, state)
        self._status.update(f"[{style}]{icon}  {text}[/{style}]")

    def enable_input(self, enabled: bool) -> None:
        self._input.disabled = not enabled
        if enabled:
            self._input.focus()


class KaliMentorApp(App):
    """Main Textual TUI — full-width chat pane with inline prompt."""

    BINDINGS = [
        ("ctrl+q", "quit", "Quit"),
        ("ctrl+a", "analyse_terminal", "Analyse Terminal"),
    ]

    CSS = """
    Screen {
        background: #0d1117;
        layout: vertical;
    }
    #header-bar {
        height: 1;
        background: #161b22;
        color: #58a6ff;
        padding: 0 1;
    }
    #chat-pane {
        width: 1fr;
        height: 1fr;
    }
    ChatLog {
        width: 1fr;
        height: 1fr;
    }
    #input-separator-top {
        height: 1;
        background: #0d1117;
        color: #444c56;
        dock: bottom;
        padding: 0 0;
    }
    #prompt-input {
        height: 1;
        border: none;
        background: #161b22;
        color: #e6edf3;
        padding: 0 1;
        dock: bottom;
    }
    #prompt-input:focus {
        border: none;
        background: #161b22;
    }
    #prompt-input:disabled {
        background: #161b22;
        color: #6e7681;
    }
    #input-separator-bottom {
        height: 1;
        background: #0d1117;
        color: #444c56;
        dock: bottom;
        padding: 0 0;
    }
    #status-line {
        height: 1;
        padding: 0 2;
        background: #0d1117;
        color: #6e7681;
        dock: bottom;
    }
    """

    def __init__(self, session: SessionManager, agent: AgentLoop, tmux_pane: str | None = None):
        super().__init__()
        self.session = session
        self.agent = agent
        self.tmux_pane = tmux_pane

    def compose(self) -> ComposeResult:
        s = self.session.state
        target = s.target.ip or s.target.url or "N/A"
        yield Static(
            f"⚡ KaliMentor v0.2.0  │  {s.id}  │  {s.llm_provider}/{s.llm_model or 'default'}  │  Target: {target}",
            id="header-bar",
        )
        with Vertical(id="chat-pane"):
            yield ChatLog(id="chat-log", max_lines=2000, markup=True, highlight=True)
        yield Static("[dim]●  Ready[/dim]", id="status-line")
        yield Static("─" * 200, id="input-separator-bottom")
        yield Input(placeholder="> Ask anything or type a command...", id="prompt-input")
        yield Static("─" * 200, id="input-separator-top")

    def on_mount(self) -> None:
        log = self.query_one(ChatLog)
        status = self.query_one("#status-line", Static)
        prompt = self.query_one("#prompt-input", Input)

        cb = TUICallback(log, status, prompt)
        self.agent.tui_mode = True
        self.agent.ui = cb

        prompt.disabled = True
        self.run_worker(self._start_agent(), exclusive=True)

    async def _start_agent(self) -> None:
        await self.agent.run()

    def on_input_submitted(self, event) -> None:
        if event.input.id == "prompt-input":
            text = event.value.strip()
            event.input.clear()
            if text:
                # Echo user message into the log before processing
                from rich.text import Text
                msg = Text()
                msg.append(" > ", style="bold green")
                msg.append(text, style="bold white")
                self.query_one(ChatLog).append_log(msg)
                self.run_worker(self._handle_input(text), exclusive=True)

    def action_quit(self) -> None:
        self.agent.session.save()
        self.exit()

    def _get_terminal_text(self) -> str | None:
        """Capture visible text from the right tmux pane."""
        if not self.tmux_pane:
            return None
        text = capture_pane(self.tmux_pane)
        return text or None

    async def action_analyse_terminal(self) -> None:
        """Ctrl+A — grab right tmux pane output and send to AI for analysis."""
        if not self.tmux_pane:
            self.query_one(ChatLog).append_log(
                "[yellow]No tmux pane detected. Start kalimentor inside tmux for terminal analysis.[/yellow]"
            )
            return

        terminal_text = self._get_terminal_text()
        if not terminal_text:
            self.query_one(ChatLog).append_log(
                "[yellow]Could not read tmux pane output.[/yellow]"
            )
            return

        self.run_worker(self.agent._analyse_terminal_output(terminal_text), exclusive=True)

    async def _handle_input(self, text: str) -> None:
        prompt = self.query_one("#prompt-input", Input)
        prompt.disabled = True
        try:
            await self.agent._propose_and_execute(text)
        finally:
            prompt.disabled = False
            prompt.focus()
