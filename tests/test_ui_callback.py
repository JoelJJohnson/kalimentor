from src.core.agent import UICallback

def test_ui_callback_protocol():
    """UICallback is a runtime-checkable protocol with required methods."""
    class FakeUI:
        def append_log(self, renderable): pass
        def set_status(self, state: str, message: str = ""): pass
        def enable_input(self, enabled: bool): pass

    assert isinstance(FakeUI(), UICallback)
