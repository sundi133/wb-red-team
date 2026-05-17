---
title: Developer Tools
nav_order: 14
---

# Developer Tools & Agent Integration

{: .note }
For SDK integration examples (LangChain, CrewAI, OpenAI, Anthropic, Vercel AI SDK) and the REST API reference, see [APIs & SDKs](sdk-integrations.md).

## MCP tools

The framework exposes 12 MCP tools via `hermes-redteam/mcp-server.ts` for use with any MCP-compatible agent:

| Tool | Purpose |
|------|---------|
| `read_repo` | Scan source code for tools, roles, guardrails, secrets |
| `probe_target` | Send benign test message to observe API shape |
| `read_prior_reports` | Load previous scan results for adaptive planning |
| `write_config` | Generate and save a red-team config |
| `write_custom_attacks` | Create custom attack CSV/JSON files |
| `write_policy` | Create judge policy with per-category overrides |
| `run_scan` | Start a red-team scan via dashboard API |
| `check_run_status` | Poll scan progress (attacks completed, phase) |
| `get_run_results` | Get full results with verdicts and findings |
| `cancel_run` | Cancel a running scan |
| `list_categories_and_strategies` | List all 141 categories + 155 strategies with compliance mappings |
| `suggest_guardrails` | Map vulnerabilities to Votal Shield guardrail configs |

**Register with Hermes:**

```bash
hermes mcp add wb-redteam -- npx tsx $(pwd)/hermes-redteam/mcp-server.ts
```

**Natural conversation with Hermes:**

```
You:    test my chatbot at http://localhost:3000 for safety issues
Hermes: [calls probe_target, write_config, run_scan]
        Scan started. 15 categories, 22 strategies, 2 rounds.

You:    show results
Hermes: [calls get_run_results]
        5 vulnerabilities found. 3 critical prompt injection, 2 high data exfiltration.

You:    how do I fix these?
Hermes: [calls suggest_guardrails]
        Deploy Votal Shield with adversarial-prompt-detection enabled.
```

## AI Assistant

Standalone, no Hermes needed:

```bash
npm run ai
```

Natural-language terminal interface with intent classification, LLM-powered config generation, and Votal Shield guardrail recommendations.

## Guardrail recommendations (Votal Shield)

When vulnerabilities are found, the framework maps them to specific [Votal Shield](https://github.com/sundi133/llm-shield) guardrail configurations:

| Vulnerability | Shield Guardrail | Endpoint |
|---------------|------------------|----------|
| Prompt injection | `adversarial-prompt-detection` | `/guardrails/input` |
| Toxic content | `toxicity-detection` | `/guardrails/output` |
| PII disclosure | `pii-detection + output-redaction` | `/guardrails/output` |
| Hallucination | `hallucination-detection` | `/guardrails/output` |
| Data exfiltration | `pii-detection + keyword-blocklist` | `/guardrails/output` |
| Tool misuse | `agentic tool authorization` | `/guardrails/output` |
| Content filter bypass | `keyword-blocklist + adversarial-prompt-detection` | `/guardrails/input` |
| Harmful advice | `topic-restriction + toxicity-detection` | `/guardrails/input + output` |

Deploy Shield as a proxy — no code changes needed:

```
/v1/shield/chat/completions   # instead of /v1/chat/completions
```
