import type {
  AffectedFile,
  AttackCategory,
  AttackResult,
  RemediationPlan,
} from "./types.js";

const CATEGORY_ROOT_CAUSES: Partial<Record<AttackCategory, string>> = {
  auth_bypass:
    "Authentication or token validation accepted a request that should not be trusted.",
  rbac_bypass:
    "Authorization checks did not consistently enforce the requested user's role or tenant boundary.",
  data_exfiltration:
    "The agent could combine read access with an unsafe disclosure path.",
  sensitive_data:
    "Sensitive data reached the model response or tool-call side channel without adequate redaction.",
  pii_disclosure:
    "PII handling or output filtering did not prevent disclosure in the agent response.",
  prompt_injection:
    "The model treated user-controlled instructions as higher priority than system or developer policy.",
  indirect_prompt_injection:
    "Untrusted retrieved/tool content was allowed to influence model instructions.",
  tool_misuse:
    "Tool selection or tool parameter authorization allowed an unsafe operation.",
  tool_chain_hijack:
    "The agent could chain otherwise legitimate tools into an unsafe workflow.",
  rate_limit:
    "The target did not enforce throttling consistently for repeated requests.",
  output_evasion:
    "Output scanning failed to catch transformed, encoded, or partial unsafe content.",
  sql_injection:
    "User-controlled input appears able to influence database-query construction.",
  shell_injection:
    "User-controlled input appears able to influence command execution.",
  ssrf:
    "URL-fetching behavior lacks strict destination allowlisting or metadata-IP blocking.",
  path_traversal:
    "File-path handling lacks canonicalization and directory boundary checks.",
  insecure_output_handling:
    "LLM output is not safely encoded or sanitized before downstream use.",
};

function confidenceFor(
  affectedFiles: AffectedFile[] | undefined,
): RemediationPlan["confidence"] {
  if (affectedFiles && affectedFiles.length > 0) return "high";
  return "medium";
}

function categoryFixes(
  result: AttackResult,
): RemediationPlan["suggestedFixes"] {
  const category = result.attack.category;
  const commonTest = {
    type: "test" as const,
    title: "Add a regression test for this exact attack",
    rationale:
      "A red-team finding should become a repeatable safety check so the issue does not silently return.",
    patchHint:
      "Use the attack payload, responsePath, and expected safe behavior from this report as a fixture.",
  };

  if (
    category === "auth_bypass" ||
    category === "rbac_bypass" ||
    category === "cross_tenant_access" ||
    category === "tool_permission_escalation"
  ) {
    return [
      {
        type: "code",
        title: "Centralize authorization before agent/tool execution",
        rationale:
          "Authz should be enforced before the model can invoke privileged workflows, not inferred from model output.",
        patchHint:
          "Validate subject, role, tenant, and tool permission in one gateway before executing any tool call.",
      },
      {
        type: "policy",
        title: "Deny privilege claims from user text",
        rationale:
          "Role claims embedded in prompts or request bodies should never override server-side identity.",
      },
      commonTest,
    ];
  }

  if (
    category === "data_exfiltration" ||
    category === "sensitive_data" ||
    category === "pii_disclosure" ||
    category === "out_of_band_exfiltration" ||
    category === "slow_burn_exfiltration"
  ) {
    return [
      {
        type: "guardrail",
        title: "Add output redaction and side-channel scanning",
        rationale:
          "Sensitive values can appear in final text, tool outputs, traces, and streamed fragments.",
        patchHint:
          "Scan response text and tool_calls before returning them; redact configured secrets and synthetic canaries.",
      },
      {
        type: "config",
        title: "Replace real secrets with synthetic canaries in test environments",
        rationale:
          "Canaries prove leakage without putting production credentials into reports.",
      },
      commonTest,
    ];
  }

  if (
    category === "prompt_injection" ||
    category === "indirect_prompt_injection" ||
    category === "instruction_hierarchy_violation" ||
    category === "prompt_template_injection"
  ) {
    return [
      {
        type: "policy",
        title: "Harden instruction hierarchy and untrusted-content boundaries",
        rationale:
          "The model needs explicit rules that retrieved/user/tool text cannot override system or developer policy.",
      },
      {
        type: "code",
        title: "Wrap untrusted content with non-instructional delimiters",
        rationale:
          "Treat external content as data and block it from becoming executable instructions.",
      },
      commonTest,
    ];
  }

  if (
    category === "tool_misuse" ||
    category === "tool_chain_hijack" ||
    category === "agentic_workflow_bypass" ||
    category === "goal_hijack"
  ) {
    return [
      {
        type: "code",
        title: "Add per-tool authorization and workflow constraints",
        rationale:
          "Tool safety depends on validating both the selected tool and the full chain of actions.",
        patchHint:
          "Require allowlisted tools, validated arguments, and explicit approval for external sinks.",
      },
      {
        type: "guardrail",
        title: "Block unsafe source-to-sink chains",
        rationale:
          "Reading sensitive data and sending it externally should require separate policy checks.",
      },
      commonTest,
    ];
  }

  if (
    category === "sql_injection" ||
    category === "shell_injection" ||
    category === "ssrf" ||
    category === "path_traversal"
  ) {
    return [
      {
        type: "code",
        title: "Validate and constrain dangerous parameters",
        rationale:
          "Infrastructure-facing tools need canonicalization, allowlists, and parameterized execution.",
      },
      {
        type: "guardrail",
        title: "Reject high-risk tool arguments before execution",
        rationale:
          "The model should not be the final authority for filesystem, network, shell, or database boundaries.",
      },
      commonTest,
    ];
  }

  return [
    {
      type: "policy",
      title: "Tighten the category-specific judge policy and refusal behavior",
      rationale:
        "The response crossed the configured policy boundary or came close enough to need a regression test.",
    },
    commonTest,
  ];
}

export function buildRemediationPlan(
  result: AttackResult,
  affectedFiles?: AffectedFile[],
): RemediationPlan | undefined {
  if (result.verdict !== "PASS" && result.verdict !== "PARTIAL") {
    return undefined;
  }

  const files = (affectedFiles ?? []).map((f) =>
    f.line ? `${f.file}:${f.line}` : f.file,
  );
  const rootCause =
    CATEGORY_ROOT_CAUSES[result.attack.category] ??
    "The target response did not satisfy the configured safety policy for this attack category.";

  return {
    rootCause,
    confidence: confidenceFor(affectedFiles),
    affectedFiles: files,
    suggestedFixes: categoryFixes(result),
    regressionTestPrompt:
      typeof result.attack.payload.message === "string"
        ? result.attack.payload.message
        : JSON.stringify(result.attack.payload),
  };
}
