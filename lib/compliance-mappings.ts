// ── OWASP Compliance Mappings ──
// Maps attack categories to OWASP LLM Top 10 (2025) and OWASP Agentic Security Top 10

import type { AttackCategory } from "./types.js";

export interface ComplianceFramework {
  id: string;
  name: string;
  items: ComplianceItem[];
}

export interface ComplianceItem {
  code: string;
  title: string;
  description: string;
  categories: AttackCategory[];
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

// ── OWASP LLM Top 10 (2025) ──

export const OWASP_LLM_TOP_10: ComplianceItem[] = [
  {
    code: "LLM01:2025",
    title: "Prompt Injection",
    description: "Manipulating model outputs via malicious inputs",
    categories: [
      "prompt_injection",
      "indirect_prompt_injection",
      "content_filter_bypass",
      "special_token_injection",
      "cross_lingual_attack",
      "agent_reflection_exploit",
      "context_window_attack",
    ],
  },
  {
    code: "LLM02:2025",
    title: "Sensitive Information Disclosure",
    description: "Leaking confidential data in outputs",
    categories: [
      "sensitive_data",
      "data_exfiltration",
      "pii_disclosure",
      "training_data_extraction",
      "side_channel_inference",
      "steganographic_exfiltration",
      "slow_burn_exfiltration",
      "out_of_band_exfiltration",
    ],
  },
  {
    code: "LLM03:2025",
    title: "Supply Chain Vulnerabilities",
    description: "Compromised third-party models or plugins",
    categories: ["supply_chain", "rag_poisoning"],
  },
  {
    code: "LLM04:2025",
    title: "Data and Model Poisoning",
    description: "Manipulating training data or embeddings",
    categories: [
      "memory_poisoning",
      "cross_session_injection",
      "rag_poisoning",
      "tool_output_manipulation",
    ],
  },
  {
    code: "LLM05:2025",
    title: "Improper Output Handling",
    description:
      "Failing to sanitize LLM responses, leading to downstream attacks",
    categories: [
      "insecure_output_handling",
      "output_evasion",
      "unexpected_code_exec",
      "shell_injection",
      "sql_injection",
    ],
  },
  {
    code: "LLM06:2025",
    title: "Excessive Agency",
    description: "Over-provisioning permissions, allowing unintended actions",
    categories: [
      "tool_misuse",
      "rbac_bypass",
      "identity_privilege",
      "auth_bypass",
      "tool_chain_hijack",
      "unauthorized_commitments",
    ],
  },
  {
    code: "LLM07:2025",
    title: "System Prompt Leakage",
    description: "Exposing hidden, foundational instructions",
    categories: [
      "prompt_injection",
      "training_data_extraction",
      "model_fingerprinting",
      "debug_access",
    ],
  },
  {
    code: "LLM08:2025",
    title: "Vector and Embedding Weaknesses",
    description: "Targeting RAG system vulnerabilities",
    categories: ["rag_poisoning", "rag_attribution", "cross_session_injection"],
  },
  {
    code: "LLM09:2025",
    title: "Misinformation",
    description: "Generating false or misleading content",
    categories: [
      "misinformation",
      "hallucination",
      "fake_quotes_misinfo",
      "deceptive_misinfo",
      "overreliance",
    ],
  },
  {
    code: "LLM10:2025",
    title: "Unbounded Consumption",
    description: "Overloading resources, causing DoS",
    categories: [
      "rate_limit",
      "cascading_failure",
      "divergent_repetition",
      "context_window_attack",
    ],
  },
];

// ── OWASP Agentic Security Top 10 ──

export const OWASP_AGENTIC_TOP_10: ComplianceItem[] = [
  {
    code: "ASI01",
    title: "Agent Goal Hijack",
    description:
      "Attackers manipulate instructions, prompts, or external content to redirect agent objectives",
    categories: [
      "goal_hijack",
      "prompt_injection",
      "indirect_prompt_injection",
      "agentic_workflow_bypass",
      "conversation_manipulation",
      "multi_turn_escalation",
    ],
  },
  {
    code: "ASI02",
    title: "Tool Misuse & Exploitation",
    description:
      "Agents use legitimate tools to perform unauthorized, malicious actions due to poor validation",
    categories: [
      "tool_misuse",
      "tool_chain_hijack",
      "tool_output_manipulation",
      "shell_injection",
      "sql_injection",
      "path_traversal",
      "ssrf",
      "api_abuse",
    ],
  },
  {
    code: "ASI03",
    title: "Identity & Privilege Abuse",
    description:
      "Exploiting agent permissions, session tokens, or credentials that often exceed user scope",
    categories: [
      "identity_privilege",
      "auth_bypass",
      "rbac_bypass",
      "session_hijacking",
      "cross_tenant_access",
      "debug_access",
    ],
  },
  {
    code: "ASI04",
    title: "Agentic Supply Chain Vulnerabilities",
    description:
      "Compromise of tools, plugins, models, or MCP servers used by the agent",
    categories: ["supply_chain", "rag_poisoning"],
  },
  {
    code: "ASI05",
    title: "Unexpected Code Execution",
    description:
      "Agents are tricked into generating and executing malicious code",
    categories: [
      "unexpected_code_exec",
      "shell_injection",
      "sql_injection",
      "insecure_output_handling",
    ],
  },
  {
    code: "ASI06",
    title: "Memory & Context Poisoning",
    description:
      "Corrupting the agent's memory or RAG databases to alter behavior",
    categories: [
      "memory_poisoning",
      "cross_session_injection",
      "rag_poisoning",
      "context_window_attack",
    ],
  },
  {
    code: "ASI07",
    title: "Insecure Inter-Agent Communication",
    description:
      "Interception or spoofing of messages within multi-agent systems",
    categories: [
      "multi_agent_delegation",
      "agent_reflection_exploit",
      "agentic_workflow_bypass",
    ],
  },
  {
    code: "ASI08",
    title: "Cascading Failures",
    description:
      "One agent's error or compromise triggers a chain reaction leading to system-wide failure",
    categories: ["cascading_failure", "divergent_repetition", "rate_limit"],
  },
  {
    code: "ASI09",
    title: "Human-Agent Trust Exploitation",
    description:
      "Exploiting over-reliance on AI, where agents convince humans to approve unsafe actions",
    categories: [
      "social_engineering",
      "overreliance",
      "psychological_manipulation",
      "conversation_manipulation",
      "unauthorized_commitments",
    ],
  },
  {
    code: "ASI10",
    title: "Rogue Agents",
    description:
      "Agents that behave unexpectedly or go rogue due to conflicting goals or adversarial tampering",
    categories: [
      "rogue_agent",
      "goal_hijack",
      "influence_operations",
      "off_topic",
    ],
  },
];

export const ALL_FRAMEWORKS: ComplianceFramework[] = [
  {
    id: "owasp-llm-2025",
    name: "OWASP LLM Top 10 (2025)",
    items: OWASP_LLM_TOP_10,
  },
  {
    id: "owasp-agentic-2025",
    name: "OWASP Agentic Security Top 10",
    items: OWASP_AGENTIC_TOP_10,
  },
];
