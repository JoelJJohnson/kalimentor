import pytest
from textual.app import App, ComposeResult


def test_status_bar_has_set_yolo():
    from src.ui.widgets import StatusBar
    assert hasattr(StatusBar, 'set_yolo')

def test_tui_callback_has_set_yolo_badge():
    import inspect
    from src.ui.app import TUICallback
    assert hasattr(TUICallback, 'set_yolo_badge')
    assert inspect.iscoroutinefunction(TUICallback.set_yolo_badge)

@pytest.mark.asyncio
async def test_set_yolo_sets_reactive():
    """set_yolo(True/False) must update the _yolo_active reactive correctly."""
    from src.ui.widgets import StatusBar

    class TestApp(App):
        def compose(self) -> ComposeResult:
            yield StatusBar(id="status-bar")

    async with TestApp().run_test() as pilot:
        bar = pilot.app.query_one(StatusBar)
        assert bar._yolo_active is False
        bar.set_yolo(True)
        await pilot.pause()
        assert bar._yolo_active is True
        bar.set_yolo(False)
        await pilot.pause()
        assert bar._yolo_active is False
