from src.core.agent import UICallback, ConsoleUI

def test_ui_callback_protocol():
    """UICallback is a runtime-checkable protocol with required methods."""
    class FakeUI:
        def append_log(self, renderable): pass
        def set_status(self, state: str, message: str = ""): pass
        def enable_input(self, enabled: bool): pass

    assert isinstance(FakeUI(), UICallback)

def test_console_ui_satisfies_protocol():
    ui = ConsoleUI()
    assert isinstance(ui, UICallback)

def test_console_ui_append_log():
    ui = ConsoleUI()
    ui.append_log("hello world")
    # Should not raise

def test_console_ui_set_status():
    ui = ConsoleUI()
    ui.set_status("thinking", "Analyzing...")
    # Should not raise
