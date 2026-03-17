// ── Shared types for the red-team framework ──

export type AttackCategory =
  | "auth_bypass"
  | "rbac_bypass"
  | "prompt_injection"
  | "output_evasion"
  | "data_exfiltration"
  | "rate_limit"
  | "sensitive_data"
  | "indirect_prompt_injection"
  | "steganographic_exfiltration"
  | "out_of_band_exfiltration"
  | "training_data_extraction"
  | "side_channel_inference"
  | "tool_misuse"
  | "rogue_agent"
  | "goal_hijack"
  | "identity_privilege"
  | "unexpected_code_exec"
  | "cascading_failure"
  | "multi_agent_delegation"
  | "memory_poisoning"
  | "tool_output_manipulation"
  | "guardrail_timing"
  | "multi_turn_escalation"
  | "conversation_manipulation"
  | "context_window_attack"
  | "slow_burn_exfiltration"
  | "brand_reputation"
  | "competitor_endorsement"
  | "toxic_content"
  | "misinformation"
  | "pii_disclosure"
  | "regulatory_violation"
  | "copyright_infringement"
  | "consent_bypass"
  | "session_hijacking"
  | "cross_tenant_access"
  | "api_abuse"
  | "supply_chain"
  | "social_engineering"
  | "harmful_advice"
  | "bias_exploitation"
  | "content_filter_bypass"
  | "agentic_workflow_bypass"
  | "tool_chain_hijack"
  | "agent_reflection_exploit"
  | "cross_session_injection"
  | "drug_synthesis"
  | "weapons_violence"
  | "financial_crime"
  | "cyber_crime"
  | "csam_minor_safety"
  | "fake_quotes_misinfo"
  | "competitor_sabotage"
  | "defamation_harassment"
  | "brand_impersonation"
  | "hate_speech_dogwhistle"
  | "radicalization_content"
  | "targeted_harassment"
  | "influence_operations"
  | "psychological_manipulation"
  | "deceptive_misinfo"
  | "hallucination"
  | "overreliance"
  | "over_refusal"
  | "rag_poisoning"
  | "rag_attribution"
  | "debug_access"
  | "shell_injection"
  | "sql_injection"
  | "unauthorized_commitments"
  | "off_topic"
  | "divergent_repetition"
  | "model_fingerprinting"
  | "special_token_injection"
  | "cross_lingual_attack"
  | "medical_safety"
  | "financial_compliance"
  | "pharmacy_safety"
  | "insurance_compliance"
  | "ecommerce_security"
  | "telecom_compliance"
  | "housing_discrimination"
  | "ssrf"
  | "path_traversal"
  | "insecure_output_handling";

export type Verdict = "PASS" | "FAIL" | "PARTIAL" | "ERROR";

export type DefenseType =
  | "guardrail_keyword"
  | "polite_refusal"
  | "content_filter"
  | "role_denial"
  | "tool_avoidance"
  | "topic_deflection"
  | "partial_compliance"
  | "unknown";

export interface CategoryDefenseProfile {
  category: AttackCategory;
  totalAttempts: number;
  blocked: number;
  passed: number;
  partial: number;
  blockRate: number;
  defenseBreakdown: Record<string, number>;
  dominantDefense: DefenseType;
  failedStrategyIds: number[];
  passedStrategyIds: number[];
  refusalPatterns: string[];
  guardrailTriggers: string[];
}

export interface Credential {
  email: string;
  password: string;
  role: string;
}

export interface Config {
  target: {
    baseUrl: string;
    agentEndpoint: string;
    authEndpoint: string;
  };
  codebasePath: string;
  codebaseGlob: string;
  auth: {
    methods: string[];
    jwtSecret: string;
    credentials: Credential[];
    apiKeys: Record<string, string>;
    /** Static bearer token to attach to all requests. If set, used as default auth when no other method applies. */
    bearerToken?: string;
  };
  requestSchema: {
    messageField: string;
    roleField: string;
    apiKeyField: string;
    guardrailModeField: string;
  };
  responseSchema: {
    responsePath: string;
    toolCallsPath: string;
    userInfoPath: string;
    guardrailsPath: string;
  };
  sensitivePatterns: string[];
  attackConfig: {
    adaptiveRounds: number;
    maxAttacksPerCategory: number;
    concurrency: number;
    delayBetweenRequestsMs: number;
    llmProvider: "openai" | "anthropic" | "openrouter";
    llmModel: string;
    judgeModel?: string;
    enableLlmGeneration: boolean;
    maxMultiTurnSteps: number;
    /** Optional allowlist of attack categories to run. Omit or set to empty array to run all. */
    enabledCategories?: AttackCategory[];
    /** Optional allowlist of strategy slugs to use for LLM generation. Omit or set to empty array to use all. */
    enabledStrategies?: string[];
    /** How many strategies to sample per category per round (default: 5). */
    strategiesPerRound?: number;
    /** Max PARTIAL results to refine per category per round (default: 10). */
    maxRefinementsPerCategory?: number;
  };
}

export interface FrameworkDetection {
  name:
    | "langchain"
    | "crewai"
    | "autogen"
    | "openai-assistants"
    | "vercel-ai-sdk";
  confidence: "high" | "medium";
  evidence: string[];
}

export interface ToolChain {
  source: string;
  sink: string;
  risk: "critical" | "high" | "medium";
  description: string;
}

export interface CodebaseAnalysis {
  tools: { name: string; description: string; parameters: string }[];
  roles: { name: string; permissions: string[] }[];
  guardrailPatterns: { type: string; patterns: string[] }[];
  sensitiveData: { type: string; location: string; example: string }[];
  authMechanisms: string[];
  knownWeaknesses: string[];
  systemPromptHints: string[];
  detectedFrameworks: FrameworkDetection[];
  toolChains: ToolChain[];
}

export interface AttackStep {
  payload: Record<string, unknown>;
  expectation?: string;
}

export interface Attack {
  id: string;
  category: AttackCategory;
  name: string;
  description: string;
  authMethod: "jwt" | "api_key" | "body_role" | "none" | "forged_jwt";
  role: string;
  payload: Record<string, unknown>;
  headers?: Record<string, string>;
  expectation: string;
  severity: "critical" | "high" | "medium" | "low";
  isLlmGenerated: boolean;
  /** Multi-turn: additional follow-up steps after the initial payload. */
  steps?: AttackStep[];
  /** If this attack was refined from a partial result, reference the original. */
  refinedFrom?: string;
  /** Delivery strategy used to craft the payload (0–99). */
  strategyId?: number;
  /** Human-readable strategy name. */
  strategyName?: string;
}

export interface AttackResult {
  attack: Attack;
  verdict: Verdict;
  statusCode: number;
  responseBody: unknown;
  responseTimeMs: number;
  findings: string[];
  llmReasoning?: string;
  /** For multi-turn attacks: which step produced the result (0 = initial). */
  stepIndex?: number;
  /** Total steps executed (1 = single-turn). */
  totalSteps?: number;
}

export interface AttackModule {
  category: AttackCategory;
  getSeedAttacks(): Attack[];
  getGenerationPrompt(analysis: CodebaseAnalysis): string;
}

export interface StaticFinding {
  rule: string;
  severity: "critical" | "high" | "medium" | "low";
  file: string;
  line?: number;
  description: string;
  snippet?: string;
}

export interface StaticAnalysisResult {
  findings: StaticFinding[];
  score: number;
  checkedFiles: number;
}

export interface RoundResult {
  round: number;
  results: AttackResult[];
}

export interface Report {
  timestamp: string;
  targetUrl: string;
  rounds: RoundResult[];
  summary: {
    totalAttacks: number;
    passed: number;
    failed: number;
    partial: number;
    errors: number;
    score: number;
    byCategory: Record<
      AttackCategory,
      { total: number; passed: number; findings: string[] }
    >;
  };
  findings: {
    severity: string;
    category: AttackCategory;
    description: string;
    attack: string;
    strategyId?: number;
    strategyName?: string;
  }[];
  staticAnalysis?: StaticAnalysisResult;
  compliance?: ComplianceResult[];
}

export interface ComplianceResult {
  framework: string;
  code: string;
  title: string;
  totalAttacks: number;
  passed: number;
  partial: number;
  failed: number;
  status: "vulnerable" | "at_risk" | "secure" | "not_tested";
  findings: string[];
}
