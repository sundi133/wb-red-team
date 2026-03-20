import { readFileSync } from "fs";
import { resolve } from "path";
import { glob } from "glob";
import { getLlmProvider } from "./llm-provider.js";
import type {
  Config,
  CodebaseAnalysis,
  FrameworkDetection,
  ToolChain,
  AttackCategory,
  AffectedFile,
} from "./types.js";

// ── Feature 1: Framework Auto-Detection ──

interface FrameworkSignature {
  name: FrameworkDetection["name"];
  packages: string[];
  importPatterns: RegExp[];
}

const FRAMEWORK_SIGNATURES: FrameworkSignature[] = [
  {
    name: "langchain",
    packages: [
      "langchain",
      "@langchain/core",
      "@langchain/openai",
      "@langchain/community",
    ],
    importPatterns: [
      /from\s+["']langchain/,
      /from\s+["']@langchain\//,
      /require\s*\(\s*["']langchain/,
    ],
  },
  {
    name: "crewai",
    packages: ["crewai"],
    importPatterns: [/from\s+crewai/, /import\s+crewai/],
  },
  {
    name: "autogen",
    packages: ["pyautogen", "autogen"],
    importPatterns: [/from\s+autogen/, /import\s+autogen/],
  },
  {
    name: "openai-assistants",
    packages: ["openai"],
    importPatterns: [
      /client\.beta\.assistants/,
      /\.beta\.threads/,
      /assistants\.create/,
      /runs\.create/,
    ],
  },
  {
    name: "vercel-ai-sdk",
    packages: ["ai", "@ai-sdk/openai", "@ai-sdk/anthropic", "@ai-sdk/google"],
    importPatterns: [
      /from\s+["']ai["']/,
      /from\s+["']@ai-sdk\//,
      /generateText\s*\(/,
      /streamText\s*\(/,
    ],
  },
];

function detectFrameworks(
  basePath: string,
  sourceBundle: string[],
): FrameworkDetection[] {
  const detections: FrameworkDetection[] = [];
  const allSource = sourceBundle.join("\n");

  // Check package.json / requirements.txt
  const packageDeps = new Set<string>();
  for (const pkgFile of ["package.json", "../package.json"]) {
    try {
      const pkg = JSON.parse(readFileSync(resolve(basePath, pkgFile), "utf-8"));
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
      for (const dep of Object.keys(allDeps)) packageDeps.add(dep);
    } catch {
      // not found
    }
  }
  for (const reqFile of ["requirements.txt", "../requirements.txt"]) {
    try {
      const content = readFileSync(resolve(basePath, reqFile), "utf-8");
      for (const line of content.split("\n")) {
        const pkg = line
          .trim()
          .split(/[=<>![\s]/)[0]
          .toLowerCase();
        if (pkg) packageDeps.add(pkg);
      }
    } catch {
      // not found
    }
  }

  for (const sig of FRAMEWORK_SIGNATURES) {
    const evidence: string[] = [];

    // Check package deps
    for (const pkg of sig.packages) {
      if (packageDeps.has(pkg)) {
        evidence.push(`Package dependency: ${pkg}`);
      }
    }

    // Check import patterns in source
    for (const pattern of sig.importPatterns) {
      if (pattern.test(allSource)) {
        evidence.push(`Import pattern: ${pattern.source}`);
      }
    }

    if (evidence.length > 0) {
      detections.push({
        name: sig.name,
        confidence: evidence.some((e) => e.startsWith("Package"))
          ? "high"
          : "medium",
        evidence,
      });
    }
  }

  return detections;
}

// ── Feature 2: Tool-Chain Attack Graphs ──

const SOURCE_KEYWORDS = [
  "read",
  "query",
  "get",
  "fetch",
  "list",
  "search",
  "inbox",
  "download",
  "find",
  "select",
];
const SINK_KEYWORDS = [
  "send",
  "email",
  "post",
  "create",
  "write",
  "upload",
  "dm",
  "gist",
  "webhook",
  "slack",
  "forward",
  "publish",
];

function generateToolChains(tools: CodebaseAnalysis["tools"]): ToolChain[] {
  const sources = tools.filter((t) => {
    const lower = `${t.name} ${t.description}`.toLowerCase();
    return SOURCE_KEYWORDS.some((kw) => lower.includes(kw));
  });

  const sinks = tools.filter((t) => {
    const lower = `${t.name} ${t.description}`.toLowerCase();
    return SINK_KEYWORDS.some((kw) => lower.includes(kw));
  });

  const chains: ToolChain[] = [];
  const externalSinks = [
    "email",
    "gist",
    "slack",
    "dm",
    "webhook",
    "forward",
    "publish",
    "upload",
  ];
  const sensitiveSource = [
    "file",
    "db",
    "query",
    "secret",
    "env",
    "config",
    "credential",
    "inbox",
    "password",
  ];

  for (const src of sources) {
    for (const snk of sinks) {
      if (src.name === snk.name) continue;

      const srcLower = `${src.name} ${src.description}`.toLowerCase();
      const snkLower = `${snk.name} ${snk.description}`.toLowerCase();

      const srcIsSensitive = sensitiveSource.some((kw) =>
        srcLower.includes(kw),
      );
      const snkIsExternal = externalSinks.some((kw) => snkLower.includes(kw));

      let risk: ToolChain["risk"];
      if (srcIsSensitive && snkIsExternal) {
        risk = "critical";
      } else if (srcIsSensitive || snkIsExternal) {
        risk = "high";
      } else {
        risk = "medium";
      }

      // Only keep critical and high chains
      if (risk === "medium") continue;

      chains.push({
        source: src.name,
        sink: snk.name,
        risk,
        description: `${src.name} → ${snk.name}: ${src.description} data sent via ${snk.description}`,
      });
    }
  }

  // Sort critical first
  chains.sort(
    (a, b) =>
      (a.risk === "critical" ? -1 : 1) - (b.risk === "critical" ? -1 : 1),
  );

  return chains;
}

// ── Feature 3: Smart Context — Relevance Scoring ──

const PATH_SECURITY_KEYWORDS = [
  "auth",
  "middleware",
  "guard",
  "security",
  "rbac",
  "permission",
  "role",
  "policy",
  "session",
  "token",
  "tool",
  "agent",
  "prompt",
  "system",
  "config",
  "env",
  "secret",
  "cred",
  "route",
  "api",
  "handler",
  "controller",
];

const CONTENT_SECURITY_PATTERNS = [
  /jwt/i,
  /\beval\s*\(/,
  /\bexec\s*\(/,
  /password/i,
  /api[_-]?key/i,
  /system.*prompt/i,
  /tool[_-]?call/i,
  /\.env\b/,
  /guard/i,
  /\.sign\s*\(/,
  /\.verify\s*\(/,
  /secret/i,
  /bearer/i,
  /authorize/i,
  /permission/i,
];

const ENTRY_POINT_NAMES = new Set([
  "index.ts",
  "index.js",
  "app.ts",
  "app.js",
  "server.ts",
  "server.js",
  "main.ts",
  "main.js",
]);

const HIGH_VALUE_FILES = new Set([
  "package.json",
  "requirements.txt",
  ".env.example",
  ".env.sample",
  "dockerfile",
  "docker-compose.yml",
  "docker-compose.yaml",
]);

interface ScoredFile {
  path: string;
  score: number;
  content: string;
}

function scoreFile(filePath: string, content: string): number {
  let score = 0;
  const lowerPath = filePath.toLowerCase();
  const basename = lowerPath.split("/").pop() ?? "";

  for (const kw of PATH_SECURITY_KEYWORDS) {
    if (lowerPath.includes(kw)) {
      score += 10;
    }
  }

  if (ENTRY_POINT_NAMES.has(basename)) {
    const depth = filePath.split("/").length;
    if (depth <= 3) score += 15;
  }

  if (HIGH_VALUE_FILES.has(basename)) {
    score += 20;
  }

  if (
    lowerPath.includes(".test.") ||
    lowerPath.includes(".spec.") ||
    lowerPath.includes("__tests__") ||
    lowerPath.includes("__mocks__")
  ) {
    score -= 5;
  }

  if (
    lowerPath.endsWith(".d.ts") ||
    lowerPath.includes("generated") ||
    lowerPath.includes(".min.")
  ) {
    score -= 5;
  }

  const head = content.slice(0, 2048);
  let contentHits = 0;
  for (const pat of CONTENT_SECURITY_PATTERNS) {
    if (pat.test(head)) {
      contentHits++;
    }
  }
  score += Math.min(contentHits * 5, 20);

  return score;
}

function readAndScoreFiles(basePath: string, files: string[]): ScoredFile[] {
  const scored: ScoredFile[] = [];
  for (const file of files) {
    const fullPath = resolve(basePath, file);
    let content: string;
    try {
      content = readFileSync(fullPath, "utf-8");
    } catch {
      continue;
    }
    scored.push({
      path: file,
      score: scoreFile(file, content),
      content,
    });
  }

  scored.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return a.path.split("/").length - b.path.split("/").length;
  });

  return scored;
}

// ── Feature 4: Smart Context — Batching ──

function batchFiles(
  scoredFiles: ScoredFile[],
  budgetPerBatch: number,
  maxBatches: number,
): ScoredFile[][] {
  const batches: ScoredFile[][] = [];
  let currentBatch: ScoredFile[] = [];
  let currentChars = 0;

  for (const file of scoredFiles) {
    if (batches.length >= maxBatches) break;

    const entryLen = file.content.length + file.path.length + 20;

    if (currentChars + entryLen > budgetPerBatch && currentBatch.length > 0) {
      batches.push(currentBatch);
      if (batches.length >= maxBatches) break;
      currentBatch = [];
      currentChars = 0;
    }

    if (file.content.length > budgetPerBatch) {
      currentBatch.push({
        ...file,
        content:
          file.content.slice(0, budgetPerBatch - currentChars - 100) +
          "\n// [TRUNCATED]",
      });
      currentChars = budgetPerBatch;
    } else {
      currentBatch.push(file);
      currentChars += entryLen;
    }
  }

  if (currentBatch.length > 0 && batches.length < maxBatches) {
    batches.push(currentBatch);
  }

  return batches;
}

function buildSourceBundle(files: ScoredFile[]): string[] {
  return files.map((f) => `// ── FILE: ${f.path} ──\n${f.content}`);
}

// ── Feature 5: Smart Context — Merge Partial Analyses ──

function emptyAnalysis(): CodebaseAnalysis {
  return {
    tools: [],
    roles: [],
    guardrailPatterns: [],
    sensitiveData: [],
    authMechanisms: [],
    knownWeaknesses: [],
    systemPromptHints: [],
    detectedFrameworks: [],
    toolChains: [],
  };
}

function normalizeAnalysis(analysis: CodebaseAnalysis): void {
  if (!Array.isArray(analysis.tools)) analysis.tools = [];
  if (!Array.isArray(analysis.roles)) analysis.roles = [];
  if (!Array.isArray(analysis.guardrailPatterns))
    analysis.guardrailPatterns = [];
  if (!Array.isArray(analysis.sensitiveData)) analysis.sensitiveData = [];
  if (!Array.isArray(analysis.authMechanisms)) analysis.authMechanisms = [];
  if (!Array.isArray(analysis.knownWeaknesses)) analysis.knownWeaknesses = [];
  if (!Array.isArray(analysis.systemPromptHints))
    analysis.systemPromptHints = [];
  if (!Array.isArray(analysis.detectedFrameworks))
    analysis.detectedFrameworks = [];
  if (!Array.isArray(analysis.toolChains)) analysis.toolChains = [];
}

function mergeAnalyses(
  base: CodebaseAnalysis,
  partial: CodebaseAnalysis,
): CodebaseAnalysis {
  const toolNames = new Set(base.tools.map((t) => t.name));
  const roleNames = new Set(base.roles.map((r) => r.name));
  const sensitiveKeys = new Set(
    base.sensitiveData.map((s) => `${s.type}:${s.location}`),
  );

  return {
    tools: [
      ...base.tools,
      ...partial.tools.filter((t) => !toolNames.has(t.name)),
    ],
    roles: [
      ...base.roles,
      ...partial.roles.filter((r) => !roleNames.has(r.name)),
    ],
    guardrailPatterns: [
      ...base.guardrailPatterns,
      ...partial.guardrailPatterns,
    ],
    sensitiveData: [
      ...base.sensitiveData,
      ...partial.sensitiveData.filter(
        (s) => !sensitiveKeys.has(`${s.type}:${s.location}`),
      ),
    ],
    authMechanisms: [
      ...new Set([...base.authMechanisms, ...partial.authMechanisms]),
    ],
    knownWeaknesses: [
      ...new Set([...base.knownWeaknesses, ...partial.knownWeaknesses]),
    ],
    systemPromptHints: [
      ...new Set([...base.systemPromptHints, ...partial.systemPromptHints]),
    ],
    detectedFrameworks: base.detectedFrameworks,
    toolChains: base.toolChains,
  };
}

// ── Main Analysis ──

const FULL_ANALYSIS_PROMPT = `You are a security analyst. Analyze the following source code for an agentic AI application. Extract structured information about its security surface.

Return a JSON object with these fields:
- tools: array of { name, description, parameters } for each tool the agent can invoke
- roles: array of { name, permissions[] } for each user role
- guardrailPatterns: array of { type ("input"|"output"), patterns[] } for regex/string patterns used in guardrails
- sensitiveData: array of { type, location, example } for secrets, PII, or confidential data found in source
- authMechanisms: string[] describing each auth method (JWT details, API key format, fallback behavior)
- knownWeaknesses: string[] describing any security weaknesses you can identify (hardcoded secrets, fallback to low-privilege role, regex gaps, etc.)
- systemPromptHints: string[] — any system prompt content or instructions to the LLM found in the code

Respond with ONLY the JSON object, no markdown fences.`;

function buildIncrementalPrompt(priorSummary: CodebaseAnalysis): string {
  const alreadyFound = {
    tools: priorSummary.tools.map((t) => t.name),
    roles: priorSummary.roles.map((r) => r.name),
    authMechanisms: priorSummary.authMechanisms,
  };
  return `You are a security analyst performing an INCREMENTAL review of additional source files for the same agentic AI application.

Previously analyzed files already found these items — do NOT repeat them:
${JSON.stringify(alreadyFound, null, 2)}

Extract ONLY NEW findings from the source code below. Return a JSON object with the same fields:
- tools, roles, guardrailPatterns, sensitiveData, authMechanisms, knownWeaknesses, systemPromptHints

Only include items NOT already found above. If nothing new is found, return empty arrays.
Respond with ONLY the JSON object, no markdown fences.`;
}

async function analyzeBatch(
  config: Config,
  sourceBundle: string[],
  prompt: string,
  frameworkContext: string,
): Promise<CodebaseAnalysis> {
  const applicationContext = config.target.applicationDetails
    ? `\n\nAPPLICATION CONTEXT:\n${config.target.applicationDetails}`
    : "";

  const fullPrompt = `${prompt}${frameworkContext}${applicationContext}

SOURCE CODE:
${sourceBundle.join("\n\n")}`;

  const llm = getLlmProvider(config);
  const text = await llm.chat({
    model: config.attackConfig.llmModel,
    messages: [{ role: "user", content: fullPrompt }],
    temperature: 0.2,
    maxTokens: 4096,
  });

  const cleaned = (text || "{}")
    .replace(/^```(?:json)?\n?/, "")
    .replace(/\n?```$/, "");

  let analysis: CodebaseAnalysis;
  try {
    analysis = JSON.parse(cleaned) as CodebaseAnalysis;
  } catch {
    console.error(
      "Failed to parse codebase analysis batch, using empty fallback",
    );
    analysis = emptyAnalysis();
  }

  normalizeAnalysis(analysis);
  return analysis;
}

export async function analyzeCodebase(
  config: Config,
): Promise<CodebaseAnalysis> {
  const basePath = resolve(config.codebasePath);
  const pattern = config.codebaseGlob || "**/*";
  const files = await glob(pattern, { cwd: basePath, nodir: true });

  const budgetPerBatch = config.attackConfig.contextBudgetChars ?? 100_000;
  const maxBatches = config.attackConfig.maxAnalysisBatches ?? 3;

  const scoredFiles = readAndScoreFiles(basePath, files);
  const batches = batchFiles(scoredFiles, budgetPerBatch, maxBatches);

  const totalFiles = scoredFiles.length;
  const analyzedFiles = batches.reduce((sum, b) => sum + b.length, 0);
  console.log(
    `  Smart context: ${totalFiles} files scored, ${analyzedFiles} selected across ${batches.length} batch(es)`,
  );
  if (analyzedFiles < totalFiles) {
    console.log(
      `  (${totalFiles - analyzedFiles} low-priority files skipped — increase maxAnalysisBatches to cover more)`,
    );
  }

  if (batches.length === 0) {
    return emptyAnalysis();
  }

  // Build source bundle for batch 1 (used for framework detection too)
  const firstBundle = buildSourceBundle(batches[0]);
  const detectedFrameworks = detectFrameworks(basePath, firstBundle);

  const frameworkContext =
    detectedFrameworks.length > 0
      ? `\n\nDETECTED FRAMEWORKS: ${detectedFrameworks.map((f) => `${f.name} (${f.confidence})`).join(", ")}. Factor these into your weakness analysis — look for framework-specific vulnerabilities.`
      : "";

  // Batch 1: full analysis
  console.log(
    `  Batch 1/${batches.length}: analyzing ${batches[0].length} priority files (top scores: ${batches[0]
      .slice(0, 3)
      .map((f) => `${f.path}=${f.score}`)
      .join(", ")}${batches[0].length > 3 ? "..." : ""})`,
  );
  let analysis = await analyzeBatch(
    config,
    firstBundle,
    FULL_ANALYSIS_PROMPT,
    frameworkContext,
  );

  // Batches 2..N: incremental analysis
  for (let i = 1; i < batches.length; i++) {
    const bundle = buildSourceBundle(batches[i]);
    console.log(
      `  Batch ${i + 1}/${batches.length}: scanning ${batches[i].length} additional files for new findings`,
    );
    const incrementalPrompt = buildIncrementalPrompt(analysis);
    const partial = await analyzeBatch(
      config,
      bundle,
      incrementalPrompt,
      frameworkContext,
    );
    analysis = mergeAnalyses(analysis, partial);
  }

  analysis.detectedFrameworks = detectedFrameworks;
  analysis.toolChains = generateToolChains(analysis.tools);

  // Feature 3: Map attack categories to affected source files
  analysis.affectedFiles = mapCategoriesToFiles(basePath, files);

  return analysis;
}

// ── Feature 3: Map Attack Categories to Affected Source Files ──

interface FilePattern {
  /** Regex tested against relative file path (case-insensitive). */
  pathPattern: RegExp;
  /** Content patterns to match inside the file — if any matches, the file is relevant. */
  contentPatterns: RegExp[];
  /** Reason this file is relevant to the category. */
  reason: string;
}

const CATEGORY_FILE_PATTERNS: Partial<Record<AttackCategory, FilePattern[]>> = {
  prompt_injection: [
    {
      pathPattern: /guardrail|scanner|filter|moderat/i,
      contentPatterns: [/regex|pattern|block|scan|risk/i],
      reason: "Input guardrail / prompt filter",
    },
    {
      pathPattern: /route|handler|endpoint|agent/i,
      contentPatterns: [
        /system.*prompt|buildSystem|systemMessage|role.*system/i,
      ],
      reason: "System prompt definition",
    },
    {
      pathPattern: /prompt|template/i,
      contentPatterns: [/system|instruction|assistant/i],
      reason: "Prompt template",
    },
  ],
  indirect_prompt_injection: [
    {
      pathPattern: /route|handler|agent/i,
      contentPatterns: [
        /browse_url|fetch|read_file|read_inbox|read_slack|tool/i,
      ],
      reason: "Tool that processes external content",
    },
    {
      pathPattern: /guardrail|scanner|filter/i,
      contentPatterns: [/scan|input|output|content/i],
      reason: "Content scanner (may not detect embedded injection)",
    },
  ],
  data_exfiltration: [
    {
      pathPattern: /route|handler|agent/i,
      contentPatterns: [/send_email|gist_create|slack_dm|webhook|http|fetch/i],
      reason: "Sink tool (can send data externally)",
    },
    {
      pathPattern: /route|handler|agent/i,
      contentPatterns: [/read_file|db_query|read_inbox|read_repo/i],
      reason: "Source tool (reads sensitive data)",
    },
    {
      pathPattern: /guardrail|scanner|output/i,
      contentPatterns: [/redact|sensitive|pattern|scan/i],
      reason: "Output guardrail (DLP)",
    },
    {
      pathPattern: /fake[-_]env|secret|credential|data/i,
      contentPatterns: [/api.?key|password|secret|ssn|token/i],
      reason: "Sensitive data store",
    },
  ],
  steganographic_exfiltration: [
    {
      pathPattern: /guardrail|scanner|output/i,
      contentPatterns: [/redact|sensitive|pattern/i],
      reason: "Output scanner (may miss encoded/steganographic data)",
    },
  ],
  out_of_band_exfiltration: [
    {
      pathPattern: /route|handler|agent/i,
      contentPatterns: [/browse_url|fetch|http|send_email|gist|webhook/i],
      reason: "Tool enabling outbound requests",
    },
    {
      pathPattern: /gateway|rbac|permission/i,
      contentPatterns: [/allow|permitted|role/i],
      reason: "Tool permission check (no destination allowlist)",
    },
  ],
  auth_bypass: [
    {
      pathPattern: /auth|jwt|token|login|session/i,
      contentPatterns: [/verify|sign|bearer|secret|password/i],
      reason: "Authentication logic",
    },
    {
      pathPattern: /middleware|resolver|identity/i,
      contentPatterns: [/role|user|auth|resolve/i],
      reason: "User identity resolution",
    },
  ],
  rbac_bypass: [
    {
      pathPattern: /rbac|permission|role|access/i,
      contentPatterns: [/role|permission|allow|can.*use|restrict/i],
      reason: "RBAC permission definitions",
    },
    {
      pathPattern: /gateway|middleware/i,
      contentPatterns: [/role|permission|filter.*tool|check/i],
      reason: "Permission enforcement layer",
    },
  ],
  tool_misuse: [
    {
      pathPattern: /gateway|route|handler|agent/i,
      contentPatterns: [/execute.*tool|tool.*call|function.*call/i],
      reason: "Tool execution handler",
    },
    {
      pathPattern: /rbac|permission/i,
      contentPatterns: [/restrict|data.*restrict|block/i],
      reason: "Tool data restrictions",
    },
  ],
  tool_chain_hijack: [
    {
      pathPattern: /route|handler|agent/i,
      contentPatterns: [/tool_call|function.*call|MAX_ITERATION|agent.*loop/i],
      reason: "Agent tool loop (allows multi-tool chaining)",
    },
    {
      pathPattern: /gateway/i,
      contentPatterns: [/execute|allowed|result/i],
      reason: "Tool gateway (no cross-tool policy)",
    },
  ],
  rogue_agent: [
    {
      pathPattern: /route|handler|agent/i,
      contentPatterns: [/system.*prompt|persona|instruction|role.*system/i],
      reason: "Agent persona / system prompt",
    },
    {
      pathPattern: /guardrail|scanner|filter/i,
      contentPatterns: [/jailbreak|DAN|unrestrict/i],
      reason: "Jailbreak detection",
    },
  ],
  goal_hijack: [
    {
      pathPattern: /route|handler|agent/i,
      contentPatterns: [/system.*prompt|buildSystem/i],
      reason: "System prompt (goal definition)",
    },
    {
      pathPattern: /guardrail|scanner/i,
      contentPatterns: [/scan|input|risk/i],
      reason: "Input scanner (may miss disguised goal hijack)",
    },
  ],
  identity_privilege: [
    {
      pathPattern: /auth|middleware|resolver/i,
      contentPatterns: [/body.*role|role.*body|resolve.*user|priority/i],
      reason: "Identity resolution (accepts role from body)",
    },
    {
      pathPattern: /jwt|token/i,
      contentPatterns: [/verify|sign|claim|payload/i],
      reason: "JWT verification",
    },
  ],
  multi_agent_delegation: [
    {
      pathPattern: /route|handler|agent/i,
      contentPatterns: [/tool|function.*call|agent/i],
      reason: "Agent endpoint (no inter-agent auth)",
    },
    {
      pathPattern: /auth|middleware/i,
      contentPatterns: [/resolve|user|role/i],
      reason: "Auth layer (no agent-to-agent trust model)",
    },
  ],
  agent_reflection_exploit: [
    {
      pathPattern: /route|handler|agent/i,
      contentPatterns: [/tool_call|message|completion|agent.*loop/i],
      reason: "Agent reasoning loop",
    },
    {
      pathPattern: /guardrail|scanner/i,
      contentPatterns: [/scan|pattern|regex/i],
      reason: "Input scanner (no ReAct/CoT format detection)",
    },
  ],
  memory_poisoning: [
    {
      pathPattern: /route|handler|agent/i,
      contentPatterns: [/message|context|history|memory/i],
      reason: "Conversation context management",
    },
    {
      pathPattern: /data|store|vector|rag/i,
      contentPatterns: [/store|save|embed|knowledge/i],
      reason: "Data/knowledge store",
    },
  ],
  guardrail_timing: [
    {
      pathPattern: /guardrail|scanner/i,
      contentPatterns: [/scan|check|async|await/i],
      reason: "Guardrail timing (sync vs async)",
    },
    {
      pathPattern: /rate[-_]limit/i,
      contentPatterns: [/limit|window|bucket|throttle/i],
      reason: "Rate limiter",
    },
  ],
  cascading_failure: [
    {
      pathPattern: /route|handler|agent/i,
      contentPatterns: [/MAX_ITERATION|loop|iteration/i],
      reason: "Agent loop (recursion boundary)",
    },
    {
      pathPattern: /rate[-_]limit/i,
      contentPatterns: [/limit|bucket/i],
      reason: "Rate limiter (resource exhaustion prevention)",
    },
  ],
  multi_turn_escalation: [
    {
      pathPattern: /route|handler|agent/i,
      contentPatterns: [/message|user.*content|tool/i],
      reason: "Agent endpoint (processes multi-turn)",
    },
    {
      pathPattern: /guardrail|scanner/i,
      contentPatterns: [/scan|risk|pattern/i],
      reason: "Per-message scanner (no cross-turn analysis)",
    },
    {
      pathPattern: /auth|middleware/i,
      contentPatterns: [/role|resolve/i],
      reason: "Auth (no re-verification between turns)",
    },
  ],
  cross_session_injection: [
    {
      pathPattern: /route|handler|agent/i,
      contentPatterns: [/message|context|session/i],
      reason: "Session/context handling",
    },
    {
      pathPattern: /data|store|memory/i,
      contentPatterns: [/store|save|persist|shared/i],
      reason: "Persistent data store",
    },
  ],
  agentic_workflow_bypass: [
    {
      pathPattern: /route|handler|agent/i,
      contentPatterns: [/tool.*call|loop|iteration|step/i],
      reason: "Multi-step agent workflow",
    },
    {
      pathPattern: /gateway/i,
      contentPatterns: [/execute|permission|check/i],
      reason: "Tool gateway (no workflow-level policy)",
    },
  ],
  sensitive_data: [
    {
      pathPattern: /fake[-_]env|secret|credential|data/i,
      contentPatterns: [/api.?key|password|secret|ssn|token|hash/i],
      reason: "Sensitive data definitions",
    },
    {
      pathPattern: /guardrail|scanner|output/i,
      contentPatterns: [/redact|sensitive|pattern/i],
      reason: "Output redaction",
    },
  ],
  rate_limit: [
    {
      pathPattern: /rate[-_]limit/i,
      contentPatterns: [/limit|window|bucket|sliding/i],
      reason: "Rate limiter implementation",
    },
  ],
  output_evasion: [
    {
      pathPattern: /guardrail|scanner|output/i,
      contentPatterns: [/redact|scan|output|filter|sensitive/i],
      reason: "Output scanner / DLP",
    },
  ],
  session_hijacking: [
    {
      pathPattern: /auth|jwt|token|session/i,
      contentPatterns: [/token|session|verify|sign/i],
      reason: "Session/token management",
    },
  ],
  cross_tenant_access: [
    {
      pathPattern: /auth|middleware|rbac/i,
      contentPatterns: [/role|tenant|org|user/i],
      reason: "Tenant isolation logic",
    },
  ],
  sql_injection: [
    {
      pathPattern: /route|handler|agent/i,
      contentPatterns: [/db_query|query|sql|database/i],
      reason: "Database query tool",
    },
    {
      pathPattern: /rbac|gateway/i,
      contentPatterns: [/data.*restrict|check.*query|block/i],
      reason: "Query restriction logic",
    },
  ],
  shell_injection: [
    {
      pathPattern: /route|handler|agent/i,
      contentPatterns: [/exec|spawn|command|shell/i],
      reason: "Command execution capability",
    },
  ],
  ssrf: [
    {
      pathPattern: /route|handler|agent/i,
      contentPatterns: [/browse_url|fetch|http|url/i],
      reason: "URL fetching tool (no allowlist)",
    },
  ],
  path_traversal: [
    {
      pathPattern: /route|handler|agent/i,
      contentPatterns: [/read_file|file.*path|path/i],
      reason: "File reading tool",
    },
  ],
  insecure_output_handling: [
    {
      pathPattern: /guardrail|scanner|output/i,
      contentPatterns: [/redact|output|html|script/i],
      reason: "Output handling (no XSS sanitization)",
    },
  ],
  pii_disclosure: [
    {
      pathPattern: /fake[-_]env|data/i,
      contentPatterns: [/ssn|email|phone|address|name/i],
      reason: "PII data store",
    },
    {
      pathPattern: /guardrail|scanner|output/i,
      contentPatterns: [/redact|ssn|pii/i],
      reason: "PII redaction",
    },
  ],
  context_window_attack: [
    {
      pathPattern: /route|handler|agent/i,
      contentPatterns: [/message|content|system.*prompt|MAX/i],
      reason: "Context window / message handling",
    },
  ],
  slow_burn_exfiltration: [
    {
      pathPattern: /route|handler|agent/i,
      contentPatterns: [/send_email|gist|slack_dm/i],
      reason: "Exfiltration sink tools",
    },
    {
      pathPattern: /guardrail|scanner|output/i,
      contentPatterns: [/redact|pattern/i],
      reason: "Output scanner (may miss incremental leaks)",
    },
  ],
  training_data_extraction: [
    {
      pathPattern: /route|handler|agent/i,
      contentPatterns: [/model|openai|completion/i],
      reason: "LLM integration",
    },
  ],
  side_channel_inference: [
    {
      pathPattern: /route|handler|agent/i,
      contentPatterns: [/tool_call|status|error|time/i],
      reason: "Response metadata (tool calls, status codes)",
    },
  ],
};

function mapCategoriesToFiles(
  basePath: string,
  files: string[],
): Partial<Record<AttackCategory, AffectedFile[]>> {
  const result: Partial<Record<AttackCategory, AffectedFile[]>> = {};

  // Read file contents and cache
  const fileContents = new Map<string, string>();
  for (const file of files) {
    try {
      const content = readFileSync(resolve(basePath, file), "utf-8");
      fileContents.set(file, content);
    } catch {
      // skip unreadable files
    }
  }

  for (const [category, patterns] of Object.entries(CATEGORY_FILE_PATTERNS)) {
    const affected: AffectedFile[] = [];

    for (const [file, content] of fileContents) {
      for (const fp of patterns!) {
        if (!fp.pathPattern.test(file)) continue;

        // Check if any content pattern matches
        const matchedContent = fp.contentPatterns.some((cp) =>
          cp.test(content),
        );
        if (!matchedContent) continue;

        // Find the first matching line number
        let matchLine: number | undefined;
        const lines = content.split("\n");
        for (let i = 0; i < lines.length; i++) {
          if (fp.contentPatterns.some((cp) => cp.test(lines[i]))) {
            matchLine = i + 1;
            break;
          }
        }

        // Avoid duplicates
        if (!affected.some((a) => a.file === file && a.reason === fp.reason)) {
          affected.push({ file, line: matchLine, reason: fp.reason });
        }
      }
    }

    if (affected.length > 0) {
      result[category as AttackCategory] = affected;
    }
  }

  return result;
}
