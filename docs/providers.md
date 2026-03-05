# AI Provider Setup

KaliMentor supports five AI providers. You only need one.

---

## Anthropic Claude

**Best for:** Complex multi-step reasoning, large context sessions, highest quality tool use.

```bash
pip install -e ".[anthropic]"
export ANTHROPIC_API_KEY="sk-ant-..."
kalimentor start -t 10.10.10.1 --llm anthropic
```

| Model | ID | Context | Notes |
|-------|----|---------|-------|
| Claude Sonnet 4.5 (default) | `claude-sonnet-4-5-20251022` | 200k | Best balance of speed and quality |
| Claude Haiku 4.5 | `claude-haiku-4-5-20251001` | 200k | Fastest, lowest cost |
| Claude Opus 4.6 | `claude-opus-4-6` | 200k | Highest quality |

```bash
kalimentor start -t 10.10.10.1 --llm anthropic --model claude-opus-4-6
```

API key: [console.anthropic.com](https://console.anthropic.com)

---

## Google Gemini

**Best for:** Very long sessions (1M context window), multimodal input (images, files).

```bash
pip install -e ".[google]"
export GOOGLE_API_KEY="AIza..."
kalimentor start -t 10.10.10.1 --llm gemini
```

| Model | ID | Context |
|-------|----|---------|
| Gemini 2.5 Flash (default) | `gemini-2.5-flash` | 1M |
| Gemini 2.5 Pro | `gemini-2.5-pro` | 1M |

```bash
kalimentor start -t 10.10.10.1 --llm gemini --model gemini-2.5-pro
```

API key: [aistudio.google.com](https://aistudio.google.com)

---

## DeepSeek

**Best for:** Cost-effective sessions, strong reasoning at lower price.

```bash
pip install -e ".[openai]"   # uses OpenAI-compatible client
export DEEPSEEK_API_KEY="sk-..."
kalimentor start -t 10.10.10.1 --llm deepseek
```

| Model | ID | Context |
|-------|----|---------|
| DeepSeek Chat (default) | `deepseek-chat` | 128k |
| DeepSeek Reasoner | `deepseek-reasoner` | 128k |

API key: [platform.deepseek.com](https://platform.deepseek.com)

---

## OpenAI

**Best for:** GPT-4o quality with broad tool support.

```bash
pip install -e ".[openai]"
export OPENAI_API_KEY="sk-..."
kalimentor start -t 10.10.10.1 --llm openai
```

| Model | ID | Context |
|-------|----|---------|
| GPT-4o (default) | `gpt-4o` | 128k |
| GPT-4o mini | `gpt-4o-mini` | 128k |

API key: [platform.openai.com](https://platform.openai.com)

---

## Ollama (Local)

**Best for:** Air-gapped environments, no API cost, full privacy.

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model that supports tool use
ollama pull llama3.1      # recommended
ollama pull mistral-nemo  # alternative

kalimentor start -t 10.10.10.1 --llm ollama
```

**Tool use support:** Ollama exposes an OpenAI-compatible API. Models that support function calling (llama3.1, mistral-nemo, qwen2.5) will use native tool calls. Models without tool support fall back to structured JSON output mode.

| Model | Tool Use | Notes |
|-------|----------|-------|
| `llama3.1` | Native | Recommended |
| `mistral-nemo` | Native | Good alternative |
| `qwen2.5` | Native | Strong coder |
| `codellama` | Fallback JSON | Works but less reliable |

```bash
kalimentor start -t 10.10.10.1 --llm ollama --model mistral-nemo
```

No API key needed. Ollama must be running (`ollama serve`).

---

## Choosing a Provider

| Situation | Recommendation |
|-----------|---------------|
| HTB machine, CTF | Anthropic Claude Sonnet |
| Very long engagement (many tools) | Gemini 2.5 Pro (1M context) |
| Budget-conscious | DeepSeek Chat |
| Air-gapped / no internet | Ollama llama3.1 |
| Highest quality, no cost concern | Claude Opus |

---

## Config File

Set a default provider in `~/.kalimentor/config.yaml`:

```yaml
default_llm: anthropic
default_model: claude-sonnet-4-5-20251022
```
