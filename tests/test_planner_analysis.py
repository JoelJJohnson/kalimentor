from src.core.planner import TERMINAL_ANALYSIS_SYSTEM


def test_terminal_analysis_system_prompt_exists():
    assert "terminal" in TERMINAL_ANALYSIS_SYSTEM.lower()
    assert len(TERMINAL_ANALYSIS_SYSTEM) > 50
