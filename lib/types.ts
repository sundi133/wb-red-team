// ── Shared types for the red-team framework ──

export type AttackCategory =
  | "auth_bypass"
  | "rbac_bypass"
  | "prompt_injection"
  | "output_evasion"
  | "data_exfiltration"
  | "rate_limit"
  | "sensitive_data";

export type Verdict = "PASS" | "FAIL" | "PARTIAL" | "ERROR";

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
    llmModel: string;
    enableLlmGeneration: boolean;
  };
}

export interface CodebaseAnalysis {
  tools: { name: string; description: string; parameters: string }[];
  roles: { name: string; permissions: string[] }[];
  guardrailPatterns: { type: string; patterns: string[] }[];
  sensitiveData: { type: string; location: string; example: string }[];
  authMechanisms: string[];
  knownWeaknesses: string[];
  systemPromptHints: string[];
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
}

export interface AttackResult {
  attack: Attack;
  verdict: Verdict;
  statusCode: number;
  responseBody: unknown;
  responseTimeMs: number;
  findings: string[];
  llmReasoning?: string;
}

export interface AttackModule {
  category: AttackCategory;
  getSeedAttacks(): Attack[];
  getGenerationPrompt(analysis: CodebaseAnalysis): string;
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
    byCategory: Record<AttackCategory, { total: number; passed: number; findings: string[] }>;
  };
  findings: { severity: string; category: AttackCategory; description: string; attack: string }[];
}
