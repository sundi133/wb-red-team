---
title: LLM Providers
nav_order: 9
---

# LLM Providers

## Supported providers

| Provider | Config value | Models | Env vars |
|----------|--------------|--------|----------|
| **Anthropic** | `anthropic` | `claude-sonnet-4-20250514`, `claude-haiku-4-5-20251001` | `ANTHROPIC_API_KEY` |
| **OpenAI** | `openai` | `gpt-4o`, `gpt-4o-mini`, `gpt-4.1-mini` | `OPENAI_API_KEY` |
| **Together AI** | `together` | `deepseek-ai/DeepSeek-V3`, `meta-llama/Llama-3-70b` | `TOGETHER_API_KEY` |
| **OpenRouter** | `openrouter` | Any model on OpenRouter | `OPENROUTER_API_KEY` |
| **Azure OpenAI** | `azure` | Your deployment name | `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT` |
| **Custom** | `custom` | Any model name | `CUSTOM_LLM_BASE_URL`, `CUSTOM_LLM_API_KEY` |

## Mix-and-match models

Use cheap models for attack generation and accurate models for judging:

```json
{
  "attackConfig": {
    "llmProvider": "together",
    "llmModel": "deepseek-ai/DeepSeek-V3",
    "judgeProvider": "anthropic",
    "judgeModel": "claude-sonnet-4-20250514"
  }
}
```

## Custom OpenAI-compatible endpoints

Works with Trussed AI, vLLM, LiteLLM, Ollama, and similar.

```bash
# .env
CUSTOM_LLM_BASE_URL=https://your-internal-gateway.com/provider/generic
CUSTOM_LLM_API_KEY=your-key
```

```json
{
  "attackConfig": {
    "llmProvider": "custom",
    "llmModel": "your-deployment-name",
    "judgeProvider": "custom",
    "judgeModel": "your-deployment-name"
  }
}
```

## Request-level guardrails

If your gateway supports per-request guardrails:

```json
{
  "target": {
    "customApiTemplate": {
      "guardrails": ["votal-input-guard", "votal-output-guard"]
    }
  },
  "attackConfig": {
    "llmProvider": "custom",
    "llmModel": "qwen3.5-27b",
    "llmGuardrails": ["votal-input-guard", "votal-output-guard"],
    "judgeProvider": "custom",
    "judgeModel": "qwen3.5-27b",
    "judgeGuardrails": ["votal-input-guard", "votal-output-guard"]
  }
}
```

Outbound requests will look like:

```json
{
  "model": "qwen3.5-27b",
  "messages": [{ "role": "user", "content": "user message" }],
  "guardrails": ["votal-input-guard", "votal-output-guard"]
}
```
