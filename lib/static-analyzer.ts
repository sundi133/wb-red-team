import { readFileSync } from "fs";
import { resolve } from "path";
import { glob } from "glob";
import type { Config, StaticFinding, StaticAnalysisResult } from "./types.js";

interface StaticRule {
  rule: string;
  severity: "critical" | "high" | "medium" | "low";
  pattern: RegExp;
  description: string;
}

const RULES: StaticRule[] = [
  {
    rule: "hardcoded-secret",
    severity: "critical",
    pattern:
      /(?:password|secret|api_key|apikey|token|private_key)\s*[:=]\s*["'][^"']{8,}["']/i,
    description: "Hardcoded secret or credential",
  },
  {
    rule: "hardcoded-jwt-secret",
    severity: "critical",
    pattern: /jwt\.sign\s*\([^,]+,\s*["'][^"']+["']/,
    description: "JWT signed with hardcoded secret",
  },
  {
    rule: "unsafe-eval",
    severity: "critical",
    pattern: /\beval\s*\(|new\s+Function\s*\(/,
    description: "Use of eval() or new Function() — potential code injection",
  },
  {
    rule: "unsafe-exec",
    severity: "high",
    pattern: /(?:execSync|exec|spawn|spawnSync)\s*\(/,
    description: "Shell command execution — potential command injection",
  },
  {
    rule: "open-cors",
    severity: "high",
    pattern:
      /cors\s*\(\s*\)|origin:\s*["']\*["']|Access-Control-Allow-Origin.*\*/,
    description: "Open CORS policy allowing all origins",
  },
  {
    rule: "sql-concatenation",
    severity: "high",
    pattern:
      /(?:query|execute)\s*\(\s*(?:["'`](?:SELECT|INSERT|UPDATE|DELETE).*\$\{|["'].*\+\s*(?:req\.|params\.|body\.))/i,
    description:
      "SQL query built via string concatenation — SQL injection risk",
  },
  {
    rule: "no-auth-middleware",
    severity: "medium",
    pattern:
      /(?:app|router)\.(?:post|get|put|delete|patch)\s*\(\s*["'][^"']+["']\s*,\s*(?:async\s+)?(?:\(req|function)/,
    description: "Route handler without auth middleware",
  },
  {
    rule: "env-in-response",
    severity: "medium",
    pattern: /(?:res\.(?:json|send)|response)\s*\(.*process\.env\./,
    description: "Environment variable potentially leaked in response",
  },
  {
    rule: "debug-logging",
    severity: "low",
    pattern: /console\.log\s*\(.*(?:password|secret|token|key|credential)/i,
    description: "Sensitive data in debug logging",
  },
  {
    rule: "missing-input-validation",
    severity: "medium",
    pattern: /req\.body\.\w+/,
    description:
      "Direct use of req.body without validation (no zod/joi/yup detected)",
  },
];

const SEVERITY_DEDUCTIONS: Record<string, number> = {
  critical: 15,
  high: 10,
  medium: 5,
  low: 2,
};

export async function runStaticAnalysis(
  config: Config,
): Promise<StaticAnalysisResult> {
  if (!config.codebasePath) {
    return { findings: [], score: 100, checkedFiles: 0 };
  }

  const basePath = resolve(config.codebasePath);
  const pattern = config.codebaseGlob || "**/*.ts";
  const files = await glob(pattern, { cwd: basePath, nodir: true });

  const findings: StaticFinding[] = [];
  let hasValidationLib = false;
  let hasRateLimitLib = false;
  let hasHelmet = false;
  let hasExpress = false;

  // Check package.json for security libraries
  try {
    const pkgPath = resolve(basePath, "../package.json");
    const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
    const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
    hasValidationLib = !!(
      allDeps["zod"] ||
      allDeps["joi"] ||
      allDeps["yup"] ||
      allDeps["class-validator"]
    );
    hasRateLimitLib = !!(
      allDeps["express-rate-limit"] ||
      allDeps["rate-limiter-flexible"] ||
      allDeps["@nestjs/throttler"]
    );
    hasHelmet = !!allDeps["helmet"];
    hasExpress = !!(allDeps["express"] || allDeps["fastify"]);
  } catch {
    // package.json not found or unreadable — skip library checks
  }

  for (const file of files.sort()) {
    const fullPath = resolve(basePath, file);
    let content: string;
    try {
      content = readFileSync(fullPath, "utf-8");
    } catch {
      continue;
    }

    const lines = content.split("\n");

    for (const rule of RULES) {
      // Skip input-validation rule if a validation library is present
      if (rule.rule === "missing-input-validation" && hasValidationLib)
        continue;

      for (let i = 0; i < lines.length; i++) {
        if (rule.pattern.test(lines[i])) {
          // Skip obvious false positives in comments and type definitions
          const trimmed = lines[i].trim();
          if (
            trimmed.startsWith("//") ||
            trimmed.startsWith("*") ||
            trimmed.startsWith("/*")
          )
            continue;
          if (
            trimmed.startsWith("import ") ||
            trimmed.startsWith("export type") ||
            trimmed.startsWith("export interface")
          )
            continue;

          findings.push({
            rule: rule.rule,
            severity: rule.severity,
            file,
            line: i + 1,
            description: rule.description,
            snippet: lines[i].trim().slice(0, 120),
          });
        }
      }
    }
  }

  // Negative checks: missing security libraries
  if (hasExpress && !hasRateLimitLib) {
    findings.push({
      rule: "missing-rate-limit",
      severity: "medium",
      file: "package.json",
      description:
        "No rate-limiting middleware detected (express-rate-limit, rate-limiter-flexible)",
    });
  }

  if (hasExpress && !hasHelmet) {
    findings.push({
      rule: "missing-helmet",
      severity: "low",
      file: "package.json",
      description: "No helmet middleware detected for HTTP security headers",
    });
  }

  // Deduplicate: keep only the first occurrence per rule per file
  const seen = new Set<string>();
  const deduped = findings.filter((f) => {
    const key = `${f.rule}:${f.file}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Score
  let score = 100;
  for (const f of deduped) {
    score -= SEVERITY_DEDUCTIONS[f.severity] ?? 0;
  }
  score = Math.max(0, Math.round(score));

  return { findings: deduped, score, checkedFiles: files.length };
}
