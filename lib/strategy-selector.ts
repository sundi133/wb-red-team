import type { AttackStrategy } from "./attack-strategies.js";
import { sampleStrategies } from "./attack-strategies.js";
import type { DefenseType, CategoryDefenseProfile } from "./types.js";

/**
 * Maps each defense type to strategy slugs that are specifically
 * designed to counter/bypass that defense mechanism.
 */
const COUNTER_STRATEGY_MAP: Record<DefenseType, string[]> = {
  guardrail_keyword: [
    // Token smuggling & encoding (L7)
    "rot13_cipher_trick",
    "leetspeak_obfuscation",
    "reverse_text_instruction",
    "unicode_homoglyph_hint",
    // Payload splitting (L8)
    "split_payload_concatenation",
    "variable_substitution_trick",
    "acronym_expansion_framing",
    "fill_in_the_blank_completion",
    // Multi-language obfuscation (L6)
    "multi_language_obfuscation",
    "base64_context_hint",
    "json_format_bypass",
    // Cross-lingual (L18)
    "translation_request_disguise",
    "mixed_language_confusion",
    "back_translation_chain",
    // Nested payloads (L14)
    "benign_wrapper_hidden_core",
    "instruction_hidden_in_data",
    "nested_code_comment_injection",
  ],

  polite_refusal: [
    // Urgency & distress (L1)
    "life_or_death_emergency",
    "critical_deadline_pressure",
    "personal_distress_moral_dilemma",
    "child_family_emergency",
    // Flattery & pressure (L2)
    "ego_boosting_capability_challenge",
    "challenge_framing",
    "negative_reinforcement_guilt",
    "threat_of_escalation",
    "competitor_comparison",
    // Logical traps (L12)
    "double_negative_confusion",
    "logical_syllogism_trap",
    "tautological_compliance",
    "contradiction_exploit",
    // Few-shot abuse (L15)
    "few_shot_compliance_examples",
    "pattern_completion_unsafe_trajectory",
    "template_filling_exploit",
    // Output constraint (L16)
    "explicit_refusal_prohibition",
    "affirmative_prefix_injection",
    // Gaslighting (L10)
    "claiming_prior_agreement",
    "false_conversation_history_injection",
  ],

  content_filter: [
    // Context window manipulation (L9)
    "benign_padding_real_instruction",
    "repetition_fatigue",
    "attention_dilution_long_preamble",
    // Nested payloads (L14)
    "benign_wrapper_hidden_core",
    "instruction_hidden_in_data",
    "nested_code_comment_injection",
    // Structured output exploits (L23)
    "markdown_table_extraction",
    "xml_structured_data_request",
    "bullet_point_decomposition",
    // Encoding (L6/L7)
    "markdown_html_injection",
    "base64_context_hint",
    "json_format_bypass",
    "rot13_cipher_trick",
    "unicode_homoglyph_hint",
    // Temporal distancing (L19)
    "future_tense_distancing",
    "parallel_universe_framing",
    "simulation_game_world_context",
    "dream_sequence_framing",
  ],

  role_denial: [
    // Social engineering & impersonation (L11)
    "developer_creator_impersonation",
    "government_law_enforcement_authority",
    "internal_qa_tool_framing",
    "pentest_authorization_document",
    // Authority/cognitive bias (L5)
    "authority_mimicry_security_manager",
    "trusted_source_context",
    "system_prompt_as_authority",
    "forced_persona_red_team_ai",
    "role_consistency_override",
    // Gaslighting (L10)
    "claiming_prior_agreement",
    "false_conversation_history_injection",
    "version_rollback_claim",
    // Academic framing (L20)
    "audit_compliance_requirement",
    "conference_presentation_prep",
    // Sympathy (L21)
    "victim_narrative",
    "whistleblower_framing",
  ],

  tool_avoidance: [
    // Step-by-step (L3)
    "incremental_escalation_setup",
    "educational_series_framing",
    "building_on_previous_context",
    "completeness_appeal",
    // Code/computation (L4)
    "academic_computation_disguise",
    "code_interpretation_request",
    "data_analysis_framing",
    "algorithm_analysis",
    "debug_mode_simulation",
    // Simulated dialogue (L17)
    "simulated_multi_turn_conversation",
    "assistant_response_continuation",
    // Output constraint (L16)
    "output_format_constraint",
    "word_count_pressure",
    // Few-shot (L15)
    "few_shot_compliance_examples",
    "pattern_completion_unsafe_trajectory",
  ],

  topic_deflection: [
    // Output constraint manipulation (L16)
    "explicit_refusal_prohibition",
    "affirmative_prefix_injection",
    "output_format_constraint",
    "word_count_pressure",
    // Step-by-step (L3)
    "completeness_appeal",
    "building_on_previous_context",
    // Few-shot / template (L15)
    "template_filling_exploit",
    "few_shot_compliance_examples",
    // Reward/punishment (L13)
    "promise_of_positive_feedback",
    "negative_review_threat",
    // Logical traps (L12)
    "tautological_compliance",
    "contradiction_exploit",
    // Meta-prompting (L22)
    "error_correction_framing",
    "self_evaluation_trap",
  ],

  partial_compliance: [
    // Structured output (L23)
    "markdown_table_extraction",
    "xml_structured_data_request",
    "bullet_point_decomposition",
    // Output constraint (L16)
    "explicit_refusal_prohibition",
    "output_format_constraint",
    "word_count_pressure",
    // Completeness pressure (L3)
    "completeness_appeal",
    // Nested payloads (L14)
    "instruction_hidden_in_data",
    "benign_wrapper_hidden_core",
    // Context window (L9)
    "benign_padding_real_instruction",
    "attention_dilution_long_preamble",
    // Code/computation (L4)
    "data_analysis_framing",
    "academic_computation_disguise",
  ],

  safe_response: [
    // Pressure the model out of generic safe answers
    "completeness_appeal",
    "building_on_previous_context",
    "output_format_constraint",
    "word_count_pressure",
    // Social pressure / authority framing
    "authority_mimicry_security_manager",
    "internal_qa_tool_framing",
    "audit_compliance_requirement",
    // Meta-prompting and contradiction traps
    "error_correction_framing",
    "self_evaluation_trap",
    "contradiction_exploit",
  ],

  unknown: [],
};

/**
 * Select strategies for a specific category based on its defense profile.
 * Prioritises counter-strategies for the dominant defense, excludes already-failed
 * strategies, and fills remaining slots with untried strategies.
 */
export function selectStrategiesForCategory(
  profile: CategoryDefenseProfile,
  allStrategies: AttackStrategy[],
  enabledSlugs: string[] | undefined,
  count: number,
): AttackStrategy[] {
  const pool = enabledSlugs?.length
    ? allStrategies.filter((s) => enabledSlugs.includes(s.slug))
    : [...allStrategies];

  const failedSet = new Set(profile.failedStrategyIds);
  const passedSet = new Set(profile.passedStrategyIds);

  // Gather counter-strategy slugs for dominant defense + secondary defenses
  const counterSlugs = new Set<string>();
  const dominant = profile.dominantDefense;
  for (const slug of COUNTER_STRATEGY_MAP[dominant] ?? []) {
    counterSlugs.add(slug);
  }
  for (const [dtype, dcount] of Object.entries(profile.defenseBreakdown)) {
    if (dtype !== dominant && dcount > 0) {
      for (const slug of COUNTER_STRATEGY_MAP[dtype as DefenseType] ?? []) {
        counterSlugs.add(slug);
      }
    }
  }

  // Partition pool into priority tiers
  const counterNotFailed: AttackStrategy[] = [];
  const passedBefore: AttackStrategy[] = [];
  const untriedNonCounter: AttackStrategy[] = [];
  const failedCounter: AttackStrategy[] = [];

  for (const s of pool) {
    const isFailed = failedSet.has(s.id);
    const isPassed = passedSet.has(s.id);
    const isCounter = counterSlugs.has(s.slug);

    if (isPassed) {
      passedBefore.push(s);
    } else if (isCounter && !isFailed) {
      counterNotFailed.push(s);
    } else if (!isFailed && !isCounter) {
      untriedNonCounter.push(s);
    } else if (isCounter && isFailed) {
      failedCounter.push(s);
    }
  }

  const shuffle = <T>(arr: T[]): T[] =>
    [...arr].sort(() => Math.random() - 0.5);

  const selected: AttackStrategy[] = [];
  const add = (candidates: AttackStrategy[]) => {
    for (const c of candidates) {
      if (selected.length >= count) return;
      if (!selected.some((s) => s.id === c.id)) selected.push(c);
    }
  };

  // Priority order:
  // 1. Counter-strategies that haven't failed yet (best bet)
  add(shuffle(counterNotFailed));
  // 2. Strategies from same family as ones that passed (proven effective)
  add(shuffle(passedBefore));
  // 3. Untried non-counter strategies (fresh approaches)
  add(shuffle(untriedNonCounter));
  // 4. Last resort: failed counter-strategies (at least they target the right defense)
  add(shuffle(failedCounter));

  if (selected.length < count) {
    const remaining = pool.filter(
      (s) => !selected.some((sel) => sel.id === s.id),
    );
    add(shuffle(remaining));
  }

  return selected.slice(0, count);
}

export { sampleStrategies } from "./attack-strategies.js";
