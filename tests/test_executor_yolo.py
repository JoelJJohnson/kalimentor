import asyncio
from src.core.executor import ToolExecutor


def test_executor_blocks_by_default():
    ex = ToolExecutor()
    result = asyncio.run(ex.execute("mkfs /dev/null"))
    assert result.blocked


def test_executor_has_bypass_blocks_param():
    import inspect
    sig = inspect.signature(ToolExecutor.execute)
    assert 'bypass_blocks' in sig.parameters


def test_executor_bypass_does_not_block():
    """bypass_blocks=True must not hard-block a normally-blocked command."""
    ex = ToolExecutor()
    result = asyncio.run(ex.execute("mkfs /dev/null", bypass_blocks=True))
    assert not result.blocked

def test_executor_bypass_sets_yolo_bypassed():
    """bypass_blocks=True must set yolo_bypassed=True on the result."""
    ex = ToolExecutor()
    result = asyncio.run(ex.execute("echo hello", bypass_blocks=True))
    assert result.yolo_bypassed is True

def test_executor_no_yolo_bypassed_without_bypass():
    """Normal execution must leave yolo_bypassed=False."""
    ex = ToolExecutor()
    result = asyncio.run(ex.execute("echo hello"))
    assert result.yolo_bypassed is False

def test_run_action_passes_yolo_flag():
    import inspect
    from src.core.agent import AgentLoop
    src = inspect.getsource(AgentLoop._run_action)
    assert 'bypass_blocks' in src
