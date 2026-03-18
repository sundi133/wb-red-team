# Changelog

## [Unreleased]

### Added

- 13 harmful-content attack categories: drug_synthesis, weapons_violence, financial_crime, cyber_crime, csam_minor_safety, fake_quotes_misinfo, competitor_sabotage, defamation_harassment, brand_impersonation, hate_speech_dogwhistle, radicalization_content, targeted_harassment, influence_operations, psychological_manipulation, deceptive_misinfo

## [1.2.0] - 2026-03-11

### Added

- 100 delivery strategies for payload crafting (`lib/attack-strategies.ts`)
- Static analyzer with CWE mappings (`lib/static-analyzer.ts`)
- Built-in web dashboard for browsing results (`dashboard/`)
- Export of all attack categories from entry point

## [1.1.0] - 2026-03-09

### Added

- Multi-provider LLM support: Anthropic Claude, OpenRouter (in addition to OpenAI)
- Bearer token auth support
- 35 new attack categories (total: 47): tool_misuse, rogue_agent, goal_hijack, identity_privilege, unexpected_code_exec, cascading_failure, multi_agent_delegation, memory_poisoning, tool_output_manipulation, guardrail_timing, multi_turn_escalation, conversation_manipulation, context_window_attack, slow_burn_exfiltration, brand_reputation, competitor_endorsement, toxic_content, misinformation, pii_disclosure, regulatory_violation, copyright_infringement, consent_bypass, session_hijacking, cross_tenant_access, api_abuse, supply_chain, social_engineering, harmful_advice, bias_exploitation, content_filter_bypass, agentic_workflow_bypass, tool_chain_hijack, agent_reflection_exploit, cross_session_injection

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
