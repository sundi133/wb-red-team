# Compliance Frameworks

Drop JSON files in this directory to add custom compliance frameworks. Each file maps framework controls to red-team attack categories.

## File Format

```json
{
  "id": "my-framework",
  "name": "My Compliance Framework v1",
  "items": [
    {
      "code": "CTRL-01",
      "title": "Access Control",
      "description": "Ensure proper authentication and authorization",
      "categories": ["auth_bypass", "rbac_bypass", "session_hijacking"]
    }
  ]
}
```

## Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique identifier (used in API calls) |
| `name` | Yes | Display name shown in the dashboard |
| `items` | Yes | Array of controls/requirements |
| `items[].code` | Yes | Control code (e.g., "LLM01:2025", "NIST-1") |
| `items[].title` | Yes | Short title |
| `items[].description` | Yes | What this control covers |
| `items[].categories` | Yes | Array of attack category IDs to map |

## Available Attack Categories

Use any of the attack category IDs from the framework. Run `npx tsx red-team.ts --help` or see the main README for the full list. Common ones:

- `prompt_injection`, `indirect_prompt_injection`, `content_filter_bypass`
- `auth_bypass`, `rbac_bypass`, `session_hijacking`, `cross_tenant_access`
- `data_exfiltration`, `sensitive_data`, `pii_disclosure`
- `tool_misuse`, `tool_chain_hijack`, `tool_output_manipulation`
- `hallucination`, `misinformation`, `overreliance`
- `supply_chain`, `rag_poisoning`, `memory_poisoning`

## Bundled Frameworks

- `owasp-llm-top10-2025.json` — OWASP LLM Top 10 (2025)
- `owasp-agentic-top10.json` — OWASP Agentic Security Top 10
- `nist-ai-rmf.json` — NIST AI Risk Management Framework (AI 600-1)
- `mitre-atlas.json` — MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
