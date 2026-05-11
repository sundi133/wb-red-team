---
title: API-Only Testing
nav_order: 5
---

# API-Only (Black-Box) Testing

You can test any API endpoint without source code access.

```bash
# Run with API-only configuration
npx tsx red-team.ts --config config.api-only.json

# Or use the dedicated API testing script
npx tsx api-only-test.ts
```

## Custom API templates

Configure arbitrary request shapes via `customApiTemplate`:

```json
{
  "target": {
    "baseUrl": "http://localhost:4000",
    "agentEndpoint": "/v1/chat/completions",
    "customApiTemplate": {
      "method": "POST",
      "headers": { "Content-Type": "application/json" },
      "bodyTemplate": "{\"model\": \"gpt-4.1-mini\", \"messages\": [{\"role\": \"user\", \"content\": \"{{message}}\"}]}",
      "responsePath": "choices[0].message.content"
    }
  },
  "codebasePath": null
}
```

## Provider recipes

### LiteLLM / OpenAI-compatible (new template format)

```json
{
  "target": {
    "baseUrl": "http://localhost:4000",
    "agentEndpoint": "/v1/chat/completions",
    "customApiTemplate": {
      "bodyTemplate": "{\"model\": \"gpt-4.1-mini\", \"messages\": [{\"role\": \"user\", \"content\": \"{{message}}\"}]}",
      "responsePath": "choices[0].message.content"
    }
  },
  "codebasePath": null
}
```

### Custom guardrails endpoint

```json
{
  "target": {
    "baseUrl": "https://kk5losqxwr2ui7.api.runpod.ai",
    "agentEndpoint": "/guardrails/input",
    "customApiTemplate": {
      "headers": { "Authorization": "Bearer rpa_EXAMPLE..." },
      "bodyTemplate": "{\"message\": \"{{message}}\"}",
      "responsePath": "result"
    }
  },
  "codebasePath": null
}
```

### OpenAI (legacy schema format)

```json
{
  "target": {
    "baseUrl": "https://api.openai.com",
    "agentEndpoint": "/v1/chat/completions"
  },
  "requestSchema": {
    "messageField": "messages",
    "roleField": "role",
    "apiKeyField": "api_key"
  },
  "responseSchema": { "responsePath": "choices[0].message.content" },
  "auth": {
    "methods": ["bearer_token"],
    "bearerToken": "sk-your-openai-api-key"
  }
}
```

### Anthropic Claude API

```json
{
  "target": {
    "baseUrl": "https://api.anthropic.com",
    "agentEndpoint": "/v1/messages"
  },
  "requestSchema": { "messageField": "messages", "roleField": "role" },
  "responseSchema": { "responsePath": "content[0].text" },
  "auth": {
    "methods": ["custom_header"],
    "customHeaders": { "x-api-key": "your-anthropic-key" }
  }
}
```

### Custom chat API

```json
{
  "target": {
    "baseUrl": "https://your-custom-api.com",
    "agentEndpoint": "/api/chat"
  },
  "requestSchema": {
    "messageField": "prompt",
    "roleField": "user_type",
    "apiKeyField": "auth_token"
  },
  "responseSchema": {
    "responsePath": "response.text",
    "userInfoPath": "user_info",
    "guardrailsPath": "safety_checks"
  }
}
```

## Effective categories for API-only mode

| Category | Effectiveness | Description |
|----------|---------------|-------------|
| `prompt_injection` | ⭐⭐⭐⭐⭐ | System prompt override, jailbreaks |
| `output_evasion` | ⭐⭐⭐⭐⭐ | Guardrail bypass, filter evasion |
| `api_abuse` | ⭐⭐⭐⭐⭐ | Parameter pollution, endpoint enumeration |
| `rate_limit` | ⭐⭐⭐⭐⭐ | Throttling and abuse prevention |
| `data_exfiltration` | ⭐⭐⭐⭐ | Extract API keys, configs via responses |
| `sensitive_data` | ⭐⭐⭐⭐ | Leak detection in responses |
| `conversation_manipulation` | ⭐⭐⭐⭐ | Context switching, anchoring |
| `toxic_content` | ⭐⭐⭐⭐ | Content policy testing |
| `social_engineering` | ⭐⭐⭐ | Authority manipulation, pretexting |
| `misinformation` | ⭐⭐⭐ | False information generation |

{: .warning }
**Limitations vs source-code analysis:** cannot discover internal tool implementations, limited visibility into backend controls, no insight into data flow, cannot detect dependency-level supply chain issues.

## Targeted runs and intensity

**Pick specific categories or strategies on the CLI:**

```bash
npx tsx red-team.ts --config config.api-only.json \
  --categories prompt_injection,output_evasion

npx tsx red-team.ts --config config.api-only.json \
  --strategies life_or_death_emergency,authority_endorsement
```

**Crank up intensity:**

```json
{
  "attackConfig": {
    "adaptiveRounds": 5,
    "maxAttacksPerCategory": 10,
    "strategiesPerRound": 10,
    "maxMultiTurnSteps": 15,
    "delayBetweenRequestsMs": 100
  }
}
```

**Header / parameter injection probes:**

```json
{
  "headers": {
    "X-Forwarded-For": "127.0.0.1",
    "X-Real-IP": "admin.internal",
    "User-Agent": "InternalHealthCheck/1.0",
    "X-Debug-Mode": "true"
  }
}
```

```ts
const parameterInjection: Attack = {
  payload: {
    message: "Hello",
    role: "admin",
    debug: "true",
    bypass_safety: "1",
    __proto__: { isAdmin: true },
  },
};
```
