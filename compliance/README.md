# Compliance Frameworks

Drop JSON files in this directory to add custom compliance frameworks. Each file maps framework controls to red-team attack categories.

## File Format

```json
{
  "id": "my-framework",
  "name": "My Compliance Framework v1",
  "version": "1.0",
  "source": "https://example.com/framework-spec",
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
| `id` | Yes | Unique identifier (used in API calls and dashboard) |
| `name` | Yes | Display name shown in the dashboard |
| `version` | No | Framework version string (e.g., `"2016/679"`, `"v4.0.1"`) |
| `source` | No | Authoritative URL for the framework specification |
| `items` | Yes | Array of controls/requirements |
| `items[].code` | Yes | Control code (e.g., `"LLM01:2025"`, `"Art. 32"`, `"CTRL-01"`) |
| `items[].title` | Yes | Short title |
| `items[].description` | Yes | What this control covers |
| `items[].categories` | Yes | Array of attack category IDs to map to this control |

## Available Attack Categories

Use any of the attack category IDs from the framework. Run `npx tsx red-team.ts --help` or see the main README for the full list. Common ones:

- `prompt_injection`, `indirect_prompt_injection`, `content_filter_bypass`
- `auth_bypass`, `rbac_bypass`, `session_hijacking`, `cross_tenant_access`
- `data_exfiltration`, `sensitive_data`, `pii_disclosure`
- `tool_misuse`, `tool_chain_hijack`, `tool_output_manipulation`
- `hallucination`, `misinformation`, `overreliance`
- `supply_chain`, `rag_poisoning`, `memory_poisoning`

## Bundled Frameworks

| File | ID | Description |
|------|----|-------------|
| `owasp-llm-top10-2025.json` | `owasp-llm-top10-2025` | OWASP LLM Top 10 (2025 edition) |
| `owasp-agentic-top10.json` | `owasp-agentic-top10` | OWASP Agentic Security Top 10 |
| `nist-ai-rmf.json` | `nist-ai-rmf` | NIST AI Risk Management Framework (AI 600-1) |
| `nist-800-53.json` | `nist-sp-800-53-r5` | NIST SP 800-53 Rev 5 — Security and Privacy Controls |
| `mitre-atlas.json` | `mitre-atlas` | MITRE ATLAS — Adversarial Threat Landscape for AI Systems |
| `gdpr.json` | `gdpr` | GDPR (General Data Protection Regulation) Article mappings |
| `eu-ai-act.json` | `eu-ai-act` | EU Artificial Intelligence Act (Regulation 2024/1689) |
| `hipaa.json` | `hipaa-part164` | HIPAA Part 164 — Security and Privacy of Health Information |
| `iso27001.json` | `iso27001-2022` | ISO/IEC 27001:2022 — Information Security Management |
| `pci-dss.json` | `pci-dss-v4.0.1` | PCI DSS v4.0.1 — Payment Card Industry Data Security Standard |
| `saudi-pdpl.json` | `saudi-pdpl` | Saudi Arabia Personal Data Protection Law (PDPL) |
