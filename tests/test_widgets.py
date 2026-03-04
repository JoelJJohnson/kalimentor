import pytest
from textual.app import App, ComposeResult

def test_chat_log_import():
    from src.ui.widgets import ChatLog
    assert ChatLog is not None

@pytest.mark.asyncio
async def test_chat_log_append():
    from src.ui.widgets import ChatLog

    class TestApp(App):
        def compose(self) -> ComposeResult:
            yield ChatLog(id="log")

    async with TestApp().run_test() as pilot:
        log = pilot.app.query_one(ChatLog)
        log.append_log("Hello world")
        assert log is not None

def test_status_bar_import():
    from src.ui.widgets import StatusBar
    assert StatusBar is not None

def test_status_bar_states():
    from src.ui.widgets import STATE_STYLES
    for state in ["ready", "thinking", "analyzing", "running", "processing", "done", "error"]:
        assert state in STATE_STYLES

def test_chat_input_import():
    from src.ui.widgets import ChatInput
    assert ChatInput is not None
