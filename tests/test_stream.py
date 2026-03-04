from src.core.stream import TextChunk, ToolCallEvent, UsageEvent

def test_text_chunk():
    e = TextChunk(text="hello")
    assert e.text == "hello"

def test_tool_call_event():
    from src.core.llm import ToolCall
    tc = ToolCall(id="1", name="bash", input={"command": "ls"})
    e = ToolCallEvent(tool_call=tc)
    assert e.tool_call.name == "bash"

def test_usage_event():
    e = UsageEvent(input_tokens=100, output_tokens=50)
    assert e.input_tokens == 100
    assert e.output_tokens == 50
