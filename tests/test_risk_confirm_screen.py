def test_risk_confirm_screen_exists():
    from src.ui.app import RiskConfirmScreen
    assert RiskConfirmScreen is not None

def test_tui_callback_has_confirm_risk():
    from src.ui.app import TUICallback
    assert hasattr(TUICallback, 'confirm_risk')

def test_tui_callback_confirm_risk_is_async():
    import inspect
    from src.ui.app import TUICallback
    assert inspect.iscoroutinefunction(TUICallback.confirm_risk)
