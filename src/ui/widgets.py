"""KaliMentor custom Textual widgets."""

from __future__ import annotations

from rich.console import RenderableType
from textual.widgets import RichLog


class ChatLog(RichLog):
    """Scrollable log pane showing all AI output and tool results."""

    DEFAULT_CSS = """
    ChatLog {
        border: none;
        padding: 0 1;
        background: #0d1117;
        scrollbar-color: #58a6ff #161b22;
    }
    """

    def append_log(self, renderable: RenderableType) -> None:
        at_bottom = self.scroll_y >= self.max_scroll_y - 3
        self.write(renderable)
        if at_bottom:
            self.scroll_end(animate=False)
