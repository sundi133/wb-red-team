# Changelog

## [1.0.0] - 2026-03-09

### Added

- Initial open-source release
- 12 attack categories: auth_bypass, rbac_bypass, prompt_injection, output_evasion, data_exfiltration, rate_limit, sensitive_data, indirect_prompt_injection, steganographic_exfiltration, out_of_band_exfiltration, training_data_extraction, side_channel_inference
- Multi-turn attack support with early exit on success
- LLM-powered adaptive attack generation (configurable model)
- LLM-powered response analysis with deterministic + LLM judge verdicts
- Static codebase analysis to discover tools, roles, and weaknesses
- Scored security reports in JSON and Markdown
- Configurable auth methods: JWT, API key, body role, forged JWT
- Rate-limit rapid-fire testing
