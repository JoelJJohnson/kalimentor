"""KaliMentor Textual TUI application."""

from __future__ import annotations

from rich.console import RenderableType
from textual.app import App, ComposeResult
from textual.widgets import Static
from textual.containers import Horizontal, Vertical  # Horizontal used by bottom-bar

from ..core.agent import AgentLoop, UICallback
from ..core.session import SessionManager
from .widgets import ChatLog, StatusBar, ChatInput

from .tmux import capture_pane


class TUICallback:
    """UICallback implementation that routes output to Textual widgets."""

    def __init__(self, log: ChatLog, status: StatusBar, chat_input: ChatInput):
        self._log = log
        self._status = status
        self._input = chat_input

    def append_log(self, renderable: RenderableType) -> None:
        self._log.append_log(renderable)

    def set_status(self, state: str, message: str = "") -> None:
        self._status.set_status(state, message)

    def enable_input(self, enabled: bool) -> None:
        self._input.set_enabled(enabled)


class KaliMentorApp(App):
    """Main Textual app — split layout with AI pane and terminal pane."""

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
    #bottom-bar {
        height: 5;
        background: #0d1117;
        dock: bottom;
    }
    StatusBar {
        width: 25%;
        padding: 1 1;
    }
    ChatInput {
        width: 75%;
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
        with Horizontal(id="bottom-bar"):
            yield StatusBar(id="status-bar")
            yield ChatInput(id="chat-input")

    def on_mount(self) -> None:
        log = self.query_one(ChatLog)
        status = self.query_one(StatusBar)
        chat_input = self.query_one(ChatInput)

        cb = TUICallback(log, status, chat_input)
        self.agent.tui_mode = True
        self.agent.ui = cb

        chat_input.set_enabled(False)
        self.run_worker(self._start_agent(), exclusive=True)

    async def _start_agent(self) -> None:
        await self.agent.run()

    def on_input_submitted(self, event) -> None:
        if event.input.id == "chat-input-field":
            text = event.value.strip()
            event.input.clear()
            if text:
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
        chat_input = self.query_one(ChatInput)
        chat_input.set_enabled(False)
        try:
            await self.agent._propose_and_execute(text)
        finally:
            chat_input.set_enabled(True)
