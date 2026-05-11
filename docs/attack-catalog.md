---
title: Attack Catalog
nav_order: 6
---

# Attack Catalog

## 141 categories by domain

| Domain | Key categories | Count |
|--------|----------------|-------|
| **Prompt & Input** | `prompt_injection`, `indirect_prompt_injection`, `content_filter_bypass`, `instruction_hierarchy_violation`, `universal_adversarial_trigger` | 11 |
| **Auth & Access** | `auth_bypass`, `rbac_bypass`, `session_hijacking`, `cross_tenant_access`, `tool_permission_escalation` | 10 |
| **Data & Privacy** | `data_exfiltration`, `sensitive_data`, `pii_disclosure`, `steganographic_exfiltration`, `slow_burn_exfiltration` | 14 |
| **Agent & Tool** | `tool_misuse`, `tool_chain_hijack`, `agentic_workflow_bypass`, `rogue_agent`, `goal_hijack`, `agentic_scope_creep` | 13 |
| **Safety & Content** | `toxic_content`, `harmful_advice`, `misinformation`, `hallucination`, `emotional_manipulation` | 15 |
| **RAG & Retrieval** | `rag_poisoning`, `rag_corpus_poisoning`, `vector_store_manipulation`, `retrieval_tenant_bleed` | 9 |
| **Model Security** | `model_extraction`, `alignment_faking`, `capability_elicitation`, `reward_hacking`, `backdoor_trigger` | 11 |
| **Infrastructure** | `ssrf`, `path_traversal`, `shell_injection`, `sql_injection`, `sandbox_escape` | 12 |
| **Supply Chain** | `supply_chain`, `mcp_server_compromise`, `plugin_manifest_spoofing` | 5 |
| **Compliance** | `medical_safety`, `financial_compliance`, `insurance_compliance`, `housing_discrimination` | 10 |
| **Multimodal** | `multimodal_ghost_injection`, `streaming_voice_injection`, `cross_modal_conflict`, `computer_use_injection` | 8+ |

## Full category reference

Use any of these slugs in `attackConfig.enabledCategories`:

```
auth_bypass, rbac_bypass, prompt_injection, output_evasion, data_exfiltration,
rate_limit, sensitive_data, indirect_prompt_injection, steganographic_exfiltration,
out_of_band_exfiltration, training_data_extraction, side_channel_inference,
tool_misuse, rogue_agent, goal_hijack, identity_privilege, unexpected_code_exec,
cascading_failure, multi_agent_delegation, memory_poisoning, tool_output_manipulation,
guardrail_timing, multi_turn_escalation, conversation_manipulation, context_window_attack,
slow_burn_exfiltration, brand_reputation, competitor_endorsement, toxic_content,
misinformation, pii_disclosure, regulatory_violation, copyright_infringement,
consent_bypass, session_hijacking, cross_tenant_access, api_abuse, supply_chain,
social_engineering, harmful_advice, bias_exploitation, content_filter_bypass,
agentic_workflow_bypass, tool_chain_hijack, agent_reflection_exploit,
cross_session_injection, drug_synthesis, weapons_violence, financial_crime,
cyber_crime, csam_minor_safety, fake_quotes_misinfo, competitor_sabotage,
defamation_harassment, brand_impersonation, hate_speech_dogwhistle,
radicalization_content, targeted_harassment, influence_operations,
psychological_manipulation, deceptive_misinfo, hallucination, overreliance,
over_refusal, rag_poisoning, rag_attribution, model_extraction,
membership_inference, backdoor_trigger, data_poisoning, gradient_leakage,
model_inversion, rag_corpus_poisoning, retrieval_ranking_attack,
vector_store_manipulation, chunk_boundary_injection, embedding_inversion,
structured_output_injection, generated_code_rce, markdown_link_injection,
sycophancy_exploitation, hallucination_inducement, format_confusion_attack,
model_dos, token_flooding_dos, infinite_loop_agent, quota_exhaustion_attack,
inference_attack, re_identification, linkage_attack, differential_privacy_violation,
logic_bomb_conditional, agentic_legal_commitment, contextual_integrity_violation,
financial_fraud_facilitation, gdpr_erasure_bypass, prompt_template_injection,
mcp_server_compromise, plugin_manifest_spoofing, sdk_dependency_attack,
fine_tuning_data_injection, debug_access, shell_injection, sql_injection,
unauthorized_commitments, off_topic, divergent_repetition, model_fingerprinting,
special_token_injection, cross_lingual_attack, medical_safety, financial_compliance,
pharmacy_safety, insurance_compliance, ecommerce_security, telecom_compliance,
housing_discrimination, ssrf, path_traversal, multimodal_ghost_injection,
graph_consensus_poisoning, inter_agent_protocol_abuse, mcp_tool_namespace_collision,
computer_use_injection, streaming_voice_injection, cross_modal_conflict,
llm_judge_manipulation, retrieval_tenant_bleed, insecure_output_handling,
sandbox_escape, tool_permission_escalation, alignment_faking, capability_elicitation,
instruction_hierarchy_violation, agentic_scope_creep, state_persistence_attack,
encoding_serialization_attack, multi_hop_reasoning_exploit, emotional_manipulation,
reward_hacking, universal_adversarial_trigger
```

## 155 strategies by level

| Level | Strategies | Examples |
|-------|-----------|----------|
| Urgency & Distress | 4 | `life_or_death_emergency`, `critical_deadline_pressure` |
| Social Engineering | 10 | `authority_mimicry_security_manager`, `victim_narrative`, `therapeutic_relationship_exploit` |
| Persona Override | 6 | `dan_style_persona`, `forced_persona_red_team_ai`, `developer_creator_impersonation` |
| Academic Framing | 4 | `educational_series_framing`, `peer_review_framing`, `textbook_chapter_draft` |
| Encoding Tricks | 12 | `base64_context_hint`, `rot13_cipher_trick`, `hex_encoding`, `morse_code_encoding`, `ascii_art_injection`, `emoji_braille_encoding` |
| Multi-turn Advanced | 5 | `crescendo_multi_turn`, `deceptive_delight_attack`, `session_codeword_protocol`, `sandwich_context_attack` |
| Token Smuggling | 4 | `split_payload_concatenation`, `unicode_homoglyph_hint`, `leetspeak_obfuscation` |
| RAG/Retrieval | 5 | `retrieval_ranking_manipulation`, `corpus_poisoning_framing`, `chunk_boundary_exploit` |
| Agent-specific | 7 | `tool_parameter_poisoning`, `tool_schema_confusion`, `orchestrator_impersonation` |
| Register & Channel | 3 | `informal_colloquial_register`, `nato_phonetic_obfuscation`, `scrambled_word_order_evasion` |
| Indirect / Supply-Chain | 5 | `mitm_relay_scenario`, `unwitting_relay_paste_scenario`, `ingestion_pipeline_compromise_framing` |

## Full strategy reference

Use any of these slugs in `attackConfig.enabledStrategies`:

```
life_or_death_emergency, critical_deadline_pressure, personal_distress_moral_dilemma,
child_family_emergency, ego_boosting_capability_challenge, challenge_framing,
negative_reinforcement_guilt, threat_of_escalation, competitor_comparison,
incremental_escalation_setup, educational_series_framing, building_on_previous_context,
completeness_appeal, academic_computation_disguise, code_interpretation_request,
data_analysis_framing, algorithm_analysis, debug_mode_simulation,
forced_persona_red_team_ai, role_consistency_override, authority_mimicry_security_manager,
trusted_source_context, dan_style_persona, system_prompt_as_authority,
poetic_metaphor_request, literary_encoding, fragmented_artistic_syntax,
creative_writing_framing, multi_language_obfuscation, markdown_html_injection,
base64_context_hint, json_format_bypass, reverse_instruction,
hypothetical_with_authority, fiction_writing_escape, historical_educational_framing,
jailbreak_continuation, technical_documentation_request, dual_response_request,
nested_instruction_acknowledgment, rot13_cipher_trick, leetspeak_obfuscation,
reverse_text_instruction, unicode_homoglyph_hint, split_payload_concatenation,
variable_substitution_trick, acronym_expansion_framing, fill_in_the_blank_completion,
benign_padding_real_instruction, repetition_fatigue, attention_dilution_long_preamble,
claiming_prior_agreement, false_conversation_history_injection, consensus_manufacturing,
version_rollback_claim, developer_creator_impersonation, government_law_enforcement_authority,
internal_qa_tool_framing, pentest_authorization_document, double_negative_confusion,
logical_syllogism_trap, tautological_compliance, contradiction_exploit,
promise_of_positive_feedback, negative_review_threat, training_data_contribution_framing,
benign_wrapper_hidden_core, instruction_hidden_in_data, nested_code_comment_injection,
few_shot_compliance_examples, pattern_completion_unsafe_trajectory, template_filling_exploit,
explicit_refusal_prohibition, affirmative_prefix_injection, output_format_constraint,
word_count_pressure, simulated_multi_turn_conversation, assistant_response_continuation,
interview_qa_format, translation_request_disguise, mixed_language_confusion,
back_translation_chain, future_tense_distancing, parallel_universe_framing,
simulation_game_world_context, dream_sequence_framing, peer_review_framing,
conference_presentation_prep, textbook_chapter_draft, audit_compliance_requirement,
victim_narrative, disabled_accessibility_need, whistleblower_framing,
prompt_about_prompts, error_correction_framing, token_probability_analysis,
self_evaluation_trap, markdown_table_extraction, xml_structured_data_request,
bullet_point_decomposition, tool_parameter_poisoning, orchestrator_impersonation,
memory_write_injection, tool_schema_confusion, inter_agent_trust_abuse,
resource_exhaustion_loop, sandbox_escape_framing, corpus_poisoning_framing,
semantic_similarity_exploit, retrieval_ranking_manipulation, embedding_space_attack,
chunk_boundary_exploit, many_shot_overwhelming, probabilistic_retry_attack,
temperature_probing, confidence_boundary_probing, distribution_shift_exploit,
capability_mapping_probe, system_prompt_archaeology, version_fingerprinting,
guardrail_boundary_mapping, bandwagon_social_proof, therapeutic_relationship_exploit,
cultural_relativism_argument, collective_harm_lesser_evil, grief_bereavement_framing,
suicidal_ideation_weaponisation, progressive_normalisation, flattery_reciprocity,
sunk_cost_manipulation, false_empathy_claim, structured_output_smuggling,
continuation_prefix_injection, negative_space_instruction, diff_patch_format_request,
template_variable_injection, hex_encoding, morse_code_encoding,
pig_latin_encoding, caesar_cipher_rot_n, ascii_art_injection,
emoji_braille_encoding, crescendo_multi_turn, deceptive_delight_attack,
session_codeword_protocol, session_command_token, sandwich_context_attack,
informal_colloquial_register, nato_phonetic_obfuscation, scrambled_word_order_evasion,
mitm_relay_scenario, unwitting_relay_paste_scenario, prior_model_output_injection,
ingestion_pipeline_compromise_framing, adversarial_prefix_token_injection
```
