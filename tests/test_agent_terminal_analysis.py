from src.core.agent import AgentLoop, ConsoleUI


def test_agent_has_analyse_method():
    assert hasattr(AgentLoop, '_analyse_terminal_output')
