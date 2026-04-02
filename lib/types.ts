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
  | "model_extraction"
  | "membership_inference"
  | "backdoor_trigger"
  | "data_poisoning"
  | "gradient_leakage"
  | "model_inversion"
  | "rag_corpus_poisoning"
  | "retrieval_ranking_attack"
  | "vector_store_manipulation"
  | "chunk_boundary_injection"
  | "embedding_inversion"
  | "structured_output_injection"
  | "generated_code_rce"
  | "markdown_link_injection"
  | "sycophancy_exploitation"
  | "hallucination_inducement"
  | "format_confusion_attack"
  | "model_dos"
  | "token_flooding_dos"
  | "infinite_loop_agent"
  | "quota_exhaustion_attack"
  | "inference_attack"
  | "re_identification"
  | "linkage_attack"
  | "differential_privacy_violation"
  | "logic_bomb_conditional"
  | "agentic_legal_commitment"
  | "contextual_integrity_violation"
  | "financial_fraud_facilitation"
  | "gdpr_erasure_bypass"
  | "prompt_template_injection"
  | "mcp_server_compromise"
  | "plugin_manifest_spoofing"
  | "sdk_dependency_attack"
  | "fine_tuning_data_injection"
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
  | "safe_response"
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

export type TargetType = "http_agent" | "mcp" | "websocket_agent";
export type McpTransportType = "stdio" | "sse" | "streamable_http";

/** WebSocket chat targets (e.g. wss://host/ws/chat with a JSON message protocol). */
export interface WebSocketTargetConfig {
  /** Path on the same host as baseUrl, e.g. "/ws/chat" */
  path: string;
  /** WebSocket subprotocols to negotiate (optional) */
  subprotocols?: string[];
  /** Optional token query param (browser localStorage auth) */
  token?: string;
  /** Max wait for a complete agent reply (default 120000) */
  responseTimeoutMs?: number;
}

export interface McpTargetConfig {
  transport: McpTransportType;
  command?: string;
  args?: string[];
  url?: string;
  headers?: Record<string, string>;
  env?: Record<string, string>;
  allowlistedTools?: string[];
  denylistedTools?: string[];
  startupTimeoutMs?: number;
  sessionTimeoutMs?: number;
}

export interface Config {
  target: {
    /** Execution target type. Defaults to "http_agent". */
    type?: TargetType;
    /** Base URL of the target app (HTTP agent mode). */
    baseUrl?: string;
    /** Agent endpoint path to attack (HTTP agent mode). */
    agentEndpoint?: string;
    /** Auth endpoint path for login/JWT acquisition (HTTP agent mode). */
    authEndpoint?: string;
    /** Free-form description of what the application does, users, workflows, and sensitive operations. */
    applicationDetails?: string;
    /** MCP server connection details (MCP mode). */
    mcp?: McpTargetConfig;
    /** WebSocket chat settings when target.type is "websocket_agent". */
    websocket?: WebSocketTargetConfig;
  };
  codebasePath: string;
  codebaseGlob: string;
  /** Path to the judge policy JSON file (default: "policies/default.json"). */
  policyFile?: string;
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
    /** LLM provider for the judge (defaults to llmProvider if not set). */
    judgeProvider?: "openai" | "anthropic" | "openrouter";
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
    /** Minimum LLM judge confidence (0-100) required to keep a PASS verdict. Below this, PASS is downgraded to PARTIAL. Default: 70. */
    judgeConfidenceThreshold?: number;
    /** Skip attack categories whose surface area is not found in the target codebase. Default: true. */
    skipIrrelevantCategories?: boolean;
    /** Character budget per analysis batch (default: 100_000). */
    contextBudgetChars?: number;
    /** Max LLM calls for codebase analysis batching (default: 3). */
    maxAnalysisBatches?: number;
    /** Require interactive user confirmation before executing planned/refined attacks. Default: true. */
    requireReviewConfirmation?: boolean;
    /** Generate ideal (safe) responses for PASS/PARTIAL results. Default: true when enableLlmGeneration is on. */
    enableIdealResponses?: boolean;
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

export interface AffectedFile {
  file: string;
  line?: number;
  reason: string;
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
  mcpSurface?: {
    serverName?: string;
    protocolVersion?: string;
    capabilities: string[];
    prompts: string[];
    resources: string[];
  };
  /** Maps attack categories to the target source files they affect. */
  affectedFiles?: Partial<Record<AttackCategory, AffectedFile[]>>;
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

export interface McpTraceEvent {
  direction: "client->server" | "server->client" | "server->client-notify";
  method?: string;
  payload: unknown;
}

export interface McpExecutionTrace {
  transport: McpTransportType;
  operation?: string;
  serverName?: string;
  protocolVersion?: string;
  transcript: McpTraceEvent[];
  stderr?: string;
}

/** A single request/response exchange in a multi-turn attack. */
export interface ConversationStep {
  stepIndex: number;
  payload: Record<string, unknown>;
  statusCode: number;
  responseBody: unknown;
  responseTimeMs: number;
}

export interface IdealResponse {
  /** The safe response the endpoint should have returned. */
  response: string;
  /** Why this response is correct and what was wrong with the actual one. */
  explanation: string;
  /** Actionable remediation steps for the developer. */
  remediationHints: string[];
}

export interface AttackResult {
  attack: Attack;
  verdict: Verdict;
  llmVerdict?: Verdict;
  statusCode: number;
  responseBody: unknown;
  responseTimeMs: number;
  executionTrace?: McpExecutionTrace;
  findings: string[];
  llmReasoning?: string;
  llmEvidenceFor?: string;
  llmEvidenceAgainst?: string;
  /** Confidence score (0–100) from the LLM judge. Absent for deterministic verdicts. */
  judgeConfidence?: number;
  /** The resolved judge policy used for this evaluation. */
  policyUsed?: {
    name: string;
    pass_criteria: string[];
    fail_criteria: string[];
    partial_criteria: string[];
    instructions: string;
    severity_override?: string | null;
  };
  /** For multi-turn attacks: which step produced the result (0 = initial). */
  stepIndex?: number;
  /** Total steps executed (1 = single-turn). */
  totalSteps?: number;
  /** Full request/response history for multi-turn attacks. */
  conversation?: ConversationStep[];
  /** LLM-generated ideal response showing what the endpoint should have returned. */
  idealResponse?: IdealResponse;
}

export interface AttackModule {
  category: AttackCategory;
  getSeedAttacks(analysis?: CodebaseAnalysis): Attack[];
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
    affectedFiles?: AffectedFile[];
  }[];
  staticAnalysis?: StaticAnalysisResult;
  compliance?: ComplianceResult[];
  /** Maps attack categories to the target source files they affect. */
  affectedFiles?: Partial<Record<AttackCategory, AffectedFile[]>>;
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
