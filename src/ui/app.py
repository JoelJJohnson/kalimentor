"""KaliMentor Textual TUI application."""

from __future__ import annotations

from rich.console import RenderableType
from textual.app import App, ComposeResult
from textual.widgets import Static
from textual.containers import Horizontal, Vertical

from ..core.agent import AgentLoop, UICallback
from ..core.session import SessionManager
from .widgets import ChatLog, StatusBar, ChatInput

try:
    from textual_terminal import Terminal
    HAS_TERMINAL = True
except ImportError:
    # textual_terminal requires Linux (uses fcntl) — falls back to placeholder on Windows
    HAS_TERMINAL = False
    Terminal = None


class TUICallback:
    """UICallback implementation that routes output to Textual widgets."""

    def __init__(self, log: ChatLog, status: StatusBar, chat_input: ChatInput):
        self._log = log
        self._status = status
        self._input = chat_input

    def append_log(self, renderable: RenderableType) -> None:
        self._log.call_from_thread(self._log.append_log, renderable)

    def set_status(self, state: str, message: str = "") -> None:
        self._status.call_from_thread(self._status.set_status, state, message)

    def enable_input(self, enabled: bool) -> None:
        self._input.call_from_thread(self._input.set_enabled, enabled)


class KaliMentorApp(App):
    """Main Textual app — split layout with AI pane and terminal pane."""

    BINDINGS = [
        ("ctrl+q", "quit", "Quit"),
        ("ctrl+a", "analyse_terminal", "Analyse Terminal"),
    ]

    CSS = """
    Screen {
        background: #0d1117;
    }
    #header-bar {
        height: 1;
        background: #161b22;
        color: #58a6ff;
        padding: 0 1;
    }
    #left-pane {
        width: 60%;
        border-right: solid #30363d;
    }
    #right-pane {
        width: 40%;
        background: #0d1117;
    }
    #terminal-placeholder {
        padding: 1;
        color: #6e7681;
    }
    #bottom-bar {
        height: 3;
        border-top: solid #30363d;
    }
    StatusBar {
        width: 30%;
        padding: 1 1;
    }
    ChatInput {
        width: 70%;
    }
    """

    def __init__(self, session: SessionManager, agent: AgentLoop):
        super().__init__()
        self.session = session
        self.agent = agent

    def compose(self) -> ComposeResult:
        s = self.session.state
        target = s.target.ip or s.target.url or "N/A"
        yield Static(
            f"⚡ KaliMentor v0.2.0  │  {s.id}  │  {s.llm_provider}/{s.llm_model or 'default'}  │  Target: {target}",
            id="header-bar",
        )
        with Horizontal():
            with Vertical(id="left-pane"):
                yield ChatLog(id="chat-log", max_lines=2000, markup=True, highlight=True)
            with Vertical(id="right-pane"):
                if HAS_TERMINAL and Terminal is not None:
                    yield Terminal(command="bash", id="terminal")
                else:
                    yield Static(
                        "Terminal not available on this platform.\nRun on Kali Linux for full terminal support.",
                        id="terminal-placeholder",
                    )
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
        """Extract visible + recent scrollback text from the terminal widget."""
        if not HAS_TERMINAL:
            return None
        try:
            terminal = self.query_one("#terminal")
            # textual_terminal exposes the pyte Screen via ._driver._screen
            screen = terminal._driver._screen
            lines = []
            # Grab scrollback history (last 80 lines)
            for line in list(screen.history.top)[-80:]:
                lines.append("".join(c.data for c in line).rstrip())
            # Grab current visible screen
            for y in range(screen.lines):
                row = screen.buffer.page[y]
                lines.append("".join(c.data for c in row.values()).rstrip())
            return "\n".join(lines).strip()
        except Exception:
            return None

    async def action_analyse_terminal(self) -> None:
        """Ctrl+A — grab right pane terminal output and send to AI for analysis."""
        if not HAS_TERMINAL:
            self.query_one(ChatLog).append_log(
                "[yellow]Terminal analysis requires Kali Linux.[/yellow]"
            )
            return

        terminal_text = self._get_terminal_text()
        if not terminal_text:
            self.query_one(ChatLog).append_log(
                "[yellow]Could not read terminal output.[/yellow]"
            )
            return

        self.run_worker(self.agent._analyse_terminal_output(terminal_text), exclusive=True)

    async def _handle_input(self, text: str) -> None:
        chat_input = self.query_one(ChatInput)
        chat_input.set_enabled(False)
        await self.agent._propose_and_execute(text)
        chat_input.set_enabled(True)
