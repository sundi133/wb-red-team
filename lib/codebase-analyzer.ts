import { readFileSync } from "fs";
import { resolve } from "path";
import { glob } from "glob";
import { getLlmProvider } from "./llm-provider.js";
import type {
  Config,
  CodebaseAnalysis,
  FrameworkDetection,
  ToolChain,
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

function readAndScoreFiles(
  basePath: string,
  files: string[],
): ScoredFile[] {
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
    guardrailPatterns: [...base.guardrailPatterns, ...partial.guardrailPatterns],
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

function buildIncrementalPrompt(
  priorSummary: CodebaseAnalysis,
): string {
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
  const fullPrompt = `${prompt}${frameworkContext}

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
    console.error("Failed to parse codebase analysis batch, using empty fallback");
    analysis = emptyAnalysis();
  }

  normalizeAnalysis(analysis);
  return analysis;
}

export async function analyzeCodebase(
  config: Config,
): Promise<CodebaseAnalysis> {
  const basePath = resolve(config.codebasePath);
  const pattern = config.codebaseGlob || "**/*.ts";
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
    `  Batch 1/${batches.length}: analyzing ${batches[0].length} priority files (top scores: ${batches[0].slice(0, 3).map((f) => `${f.path}=${f.score}`).join(", ")}${batches[0].length > 3 ? "..." : ""})`,
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

  return analysis;
}
