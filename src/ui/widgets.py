"""KaliMentor custom Textual widgets."""

from __future__ import annotations

from rich.console import RenderableType
from textual.app import ComposeResult
from textual.widgets import RichLog, Input, Static
from textual.widget import Widget
from textual.reactive import reactive


class ChatLog(RichLog):
    """Scrollable log pane showing all AI output and tool results."""

    DEFAULT_CSS = """
    ChatLog {
        border: solid #1e3a5f;
        padding: 0 1;
        background: #0d1117;
    }
    """

    def append_log(self, renderable: RenderableType) -> None:
        self.write(renderable)
        self.scroll_end(animate=False)


SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

STATE_STYLES = {
    "ready":      ("dim", "●", "Ready"),
    "thinking":   ("cyan", None, "Thinking..."),
    "analyzing":  ("cyan", None, "Analyzing..."),
    "running":    ("yellow", None, ""),
    "processing": ("yellow", None, "Processing results..."),
    "done":       ("green", "✓", "Done"),
    "error":      ("red", "✗", ""),
}


class StatusBar(Widget):
    """Bottom-left status indicator with animated spinner."""

    state: reactive[str] = reactive("ready")
    message: reactive[str] = reactive("")
    _frame: reactive[int] = reactive(0)

    DEFAULT_CSS = """
    StatusBar {
        height: 1;
        width: auto;
        padding: 0 1;
    }
    """

    def on_mount(self) -> None:
        self.set_interval(0.1, self._tick)

    def _tick(self) -> None:
        if self.state in ("thinking", "analyzing", "running", "processing"):
            self._frame = (self._frame + 1) % len(SPINNER_FRAMES)

    def set_status(self, state: str, message: str = "") -> None:
        self.state = state
        self.message = message
        self._frame = 0

    def render(self) -> RenderableType:
        from rich.text import Text
        style, icon, default_msg = STATE_STYLES.get(self.state, ("dim", "●", ""))
        if icon is None:
            icon = SPINNER_FRAMES[self._frame]
        msg = self.message or default_msg
        t = Text()
        t.append(f"{icon}  {msg}", style=style)
        return t


class ChatInput(Widget):
    """Bottom chat input bar — disabled while agent is working."""

    DEFAULT_CSS = """
    ChatInput {
        height: 3;
        border: tall #58a6ff;
        background: #161b22;
        layout: horizontal;
    }
    ChatInput Input {
        width: 1fr;
        border: none;
        background: #161b22;
        color: #e6edf3;
    }
    ChatInput Input:disabled {
        color: #6e7681;
    }
    ChatInput #send-hint {
        width: auto;
        padding: 1 1;
        color: #58a6ff;
    }
    """

    def compose(self) -> ComposeResult:
        yield Input(placeholder="> Ask anything or type a command...", id="chat-input-field")
        yield Static("Enter ↵", id="send-hint")

    def set_enabled(self, enabled: bool) -> None:
        inp = self.query_one("#chat-input-field", Input)
        inp.disabled = not enabled
        if enabled:
            inp.focus()
