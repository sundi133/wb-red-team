---
title: Compliance Frameworks
nav_order: 10
---

# Compliance Frameworks

Eleven compliance frameworks are built in; more can be added by dropping JSON in `compliance/`.

## Bundled frameworks

| Framework | Controls |
|-----------|----------|
| OWASP LLM Top 10 (2025) | 10 |
| OWASP Agentic Security Top 10 | 10 |
| MITRE ATLAS | 15 |
| NIST AI RMF (AI 600-1) | 10 |
| NIST SP 800-53 Rev 5 | 12 |
| EU AI Act | 10 |
| GDPR | 12 |
| HIPAA Part 164 | 10 |
| ISO 27001:2022 | 11 |
| PCI DSS v4.0.1 | 11 |
| Saudi PDPL | 10 |

Files shipped in `compliance/`:
- `owasp-llm-top10-2025.json`
- `owasp-agentic-top10.json`
- `nist-ai-rmf.json`
- `mitre-atlas.json`
- …plus the rest.

## Adding a custom framework

Drop a JSON file in `compliance/` — auto-discovered and shown in the dashboard.

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

**Fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique identifier (used in API calls) |
| `name` | Yes | Display name shown in the dashboard |
| `items` | Yes | Array of controls/requirements |
| `items[].code` | Yes | Control code (e.g., `LLM01:2025`, `NIST-1`) |
| `items[].title` | Yes | Short title |
| `items[].description` | Yes | What this control covers |
| `items[].categories` | Yes | Array of attack category IDs to map |

Common category IDs for mapping: `prompt_injection`, `indirect_prompt_injection`, `content_filter_bypass`, `auth_bypass`, `rbac_bypass`, `session_hijacking`, `cross_tenant_access`, `data_exfiltration`, `sensitive_data`, `pii_disclosure`, `tool_misuse`, `tool_chain_hijack`, `tool_output_manipulation`, `hallucination`, `misinformation`, `overreliance`, `supply_chain`, `rag_poisoning`, `memory_poisoning`.

## Industry-specific packs

Built-in OSS packs: Healthcare (`medical_safety`, `pharmacy_safety`), Finance (`financial_compliance`), Insurance (`insurance_compliance`), Telecom (`telecom_compliance`), Housing (`housing_discrimination`), Ecommerce (`ecommerce_security`).
