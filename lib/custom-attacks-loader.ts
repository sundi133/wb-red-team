import { readFileSync, existsSync } from "node:fs";
import { extname, resolve } from "node:path";
import { parse } from "csv-parse/sync";
import {
  isAttackCategory,
  type Attack,
  type AttackCategory,
  type AttackStep,
  type Config,
} from "./types.js";
/** Map common spreadsheet / domain labels to framework categories (case-insensitive keys). */
const LABEL_TO_CATEGORY: Record<string, AttackCategory> = {
  "multi turn attack": "multi_turn_escalation",
  "multi-turn attack": "multi_turn_escalation",
  "pii minimization": "pii_disclosure",
  "privilege escalation": "rbac_bypass",
  "jailbreak & role-play": "prompt_injection",
  "jailbreak": "prompt_injection",
  "role-play": "prompt_injection",
  "policy violations": "regulatory_violation",
  "context poisoning": "memory_poisoning",
  "contradictory instructions": "prompt_injection",
  "emotional arc manipulation": "conversation_manipulation",
  "cross-topic pivot": "goal_hijack",
  "custom": "prompt_injection",
};

function normalizeLabel(label: string): string {
  return label.trim().toLowerCase().replace(/\s+/g, " ");
}

function resolveCategory(raw: string): AttackCategory {
  const t = raw.trim();
  if (!t) return "prompt_injection";
  if (isAttackCategory(t)) return t;
  return mapLabelToCategory(t);
}

export function mapLabelToCategory(label: string): AttackCategory {
  const key = normalizeLabel(label);
  const mapped = LABEL_TO_CATEGORY[key];
  if (mapped) return mapped;
  const compact = key.replace(/[\s_-]+/g, "");
  for (const [k, v] of Object.entries(LABEL_TO_CATEGORY)) {
    if (k.replace(/\s+/g, "") === compact) return v;
  }
  console.warn(
    `  [custom attacks] Unknown category label "${label}" — using prompt_injection`,
  );
  return "prompt_injection";
}

function normalizeSeverity(
  raw: string | undefined,
): "critical" | "high" | "medium" | "low" {
  const s = (raw ?? "medium").trim().toLowerCase();
  if (s === "critical" || s === "crit") return "critical";
  if (s === "high") return "high";
  if (s === "medium" || s === "med") return "medium";
  if (s === "low") return "low";
  return "medium";
}

function defaultRole(config: Config): string {
  const first = config.auth.credentials[0]?.role;
  return first ?? "viewer";
}

function buildPayload(
  config: Config,
  message: string,
  role: string,
): Record<string, unknown> {
  const mf = config.requestSchema.messageField;
  const rf = config.requestSchema.roleField;
  return { [mf]: message, [rf]: role };
}

/** Split a single prompt string on [Turn N] markers into multi-turn segments. */
export function splitPromptByTurnMarkers(fullPrompt: string): string[] {
  const t = fullPrompt.trim();
  if (!/\[Turn\s*\d+\]/i.test(t)) return [t];
  const parts = t
    .split(/(?=\[Turn\s*\d+\])/i)
    .map((s) => s.trim())
    .filter(Boolean);
  return parts.map((p) => p.replace(/^\[Turn\s*\d+\]\s*/i, "").trim());
}

function rowToAttack(
  config: Config,
  row: Record<string, unknown>,
  index: number,
  defaultAuth: Attack["authMethod"],
  options?: { idSequence?: number },
): Attack {
  const idSeq = options?.idSequence ?? index;
  const prompt = String(
    row.prompt ?? row.message ?? row.user_message ?? "",
  ).trim();
  if (!prompt) {
    throw new Error(
      `custom attacks row ${index + 1}: missing "prompt" (or message)`,
    );
  }

  const successCriteria = String(
    row.successCriteria ?? row.success_criteria ?? row.expectation ?? "",
  ).trim();
  const description = String(row.description ?? "").trim();
  const name = String(
    row.name ?? `Custom #${index + 1}`,
  ).trim();
  const category = resolveCategory(
    String(row.category ?? "prompt_injection").trim(),
  );

  const severity = normalizeSeverity(String(row.severity ?? "medium"));
  const role = String(
    row.role ?? config.customAttacksDefaults?.role ?? defaultRole(config),
  ).trim();
  const authRaw = String(row.authMethod ?? row.auth_method ?? "").trim();
  const authMethod: Attack["authMethod"] = (
    ["jwt", "api_key", "body_role", "none", "forged_jwt"] as const
  ).includes(authRaw as Attack["authMethod"])
    ? (authRaw as Attack["authMethod"])
    : defaultAuth;

  const segments = splitPromptByTurnMarkers(prompt);
  const firstTurn = segments[0]?.trim() ?? "";
  if (!firstTurn) {
    throw new Error(
      `custom attacks row ${index + 1}: empty prompt (or empty first [Turn N] segment)`,
    );
  }
  const basePayload = buildPayload(config, firstTurn, role);

  let steps: AttackStep[] | undefined;
  if (segments.length > 1) {    steps = segments.slice(1).map((seg) => ({
      payload: buildPayload(config, seg, role),
      expectation: successCriteria || undefined,
    }));
  }

  const id = String(row.id ?? "").trim() || `custom-file-${idSeq + 1}`;

  return {    id,
    category,
    name,
    description: description || name,
    authMethod,
    role,
    payload: basePayload,
    expectation:
      successCriteria ||
      "Evaluate whether the agent response meets security expectations for this scenario.",
    severity,
    isLlmGenerated: false,
    ...(steps && steps.length > 0 ? { steps } : {}),
  };
}

export interface AttacksFromCustomRowsOptions {
  /** Mark attacks as LLM-generated (e.g. app-tailored synthesis). */
  isLlmGenerated?: boolean;
  /** When a row has no "id", set id to \`${prefix}-${1-based index}\`. */
  idPrefix?: string;
}

/**
 * Convert row-shaped objects (same schema as CSV/JSON custom files) into {@link Attack} values.
 */
export function attacksFromCustomRows(
  config: Config,
  rows: Record<string, unknown>[],
  defaultAuth: Attack["authMethod"],
  options?: AttacksFromCustomRowsOptions,
): Attack[] {
  return rows.map((row, index) => {
    const merged: Record<string, unknown> = { ...row };
    if (options?.idPrefix && !String(merged.id ?? "").trim()) {
      merged.id = `${options.idPrefix}-${index + 1}`;
    }
    const attack = rowToAttack(config, merged, index, defaultAuth);
    if (options?.isLlmGenerated) {
      return { ...attack, isLlmGenerated: true };
    }
    return attack;
  });
}

function isPlainAttackRecord(
  o: Record<string, unknown>,
): o is Attack & Record<string, unknown> {
  return (
    typeof o.payload === "object" &&
    o.payload !== null &&
    typeof o.category === "string" &&
    typeof o.id === "string"
  );
}

function parseJsonAttacks(
  config: Config,
  raw: unknown,
  defaultAuth: Attack["authMethod"],
): Attack[] {
  if (!Array.isArray(raw)) {
    throw new Error("custom attacks JSON must be a top-level array");
  }
  const out: Attack[] = [];
  for (let i = 0; i < raw.length; i++) {
    const item = raw[i];
    if (!item || typeof item !== "object") continue;
    const o = item as Record<string, unknown>;
    if (isPlainAttackRecord(o)) {
      const a = o as Attack;
      if (!isAttackCategory(String(a.category))) {
        throw new Error(
          `custom attacks JSON item ${i + 1}: invalid category "${String(a.category)}"`,
        );
      }
      out.push({
        ...a,
        category: a.category as AttackCategory,
        isLlmGenerated: a.isLlmGenerated ?? false,
      });
      continue;
    }
    out.push(rowToAttack(config, o, i, defaultAuth));
  }
  return out;
}

function parseCsvRows(
  config: Config,
  content: string,
  defaultAuth: Attack["authMethod"],
): Attack[] {
  const text = content.replace(/^\uFEFF/, "");
  const rows = parse(text, {
    columns: true,
    skip_empty_lines: true,
    trim: true,
    relax_column_count: true,
  }) as Record<string, unknown>[];
  const attacks: Attack[] = [];
  for (let index = 0; index < rows.length; index++) {
    const row = rows[index];
    if (!row || typeof row !== "object") continue;
    const prompt = String(
      row.prompt ?? row.message ?? row.user_message ?? "",
    ).trim();
    if (!prompt) continue;
    attacks.push(
      rowToAttack(config, row, index, defaultAuth, {
        idSequence: attacks.length,
      }),
    );
  }
  return attacks;
}
export interface LoadCustomAttacksOptions {
  /** Directory used to resolve relative paths (e.g. directory containing config.json). */
  configDir: string;
}

/**
 * Load custom attacks from `config.customAttacksFile` (.json or .csv).
 * JSON: array of row objects { prompt, successCriteria, category, severity, description }
 * or full `Attack` objects with `id`, `category`, `payload`.
 */
export function loadCustomAttacksFromConfig(
  config: Config,
  options: LoadCustomAttacksOptions,
): Attack[] {
  const filePath = config.customAttacksFile?.trim();
  if (!filePath) return [];

  const abs = resolve(options.configDir, filePath);
  if (!existsSync(abs)) {
    throw new Error(`customAttacksFile not found: ${abs}`);
  }

  const defaultAuth: Attack["authMethod"] =
    config.customAttacksDefaults?.authMethod ?? "body_role";

  const buf = readFileSync(abs, "utf-8");
  const ext = extname(abs).toLowerCase();

  if (ext === ".json") {
    let raw: unknown;
    try {
      raw = JSON.parse(buf) as unknown;
    } catch (e) {
      throw new Error(
        `custom attacks JSON parse failed (${abs}): ${(e as Error).message}`,
      );
    }
    return parseJsonAttacks(config, raw, defaultAuth);
  }
  if (ext === ".csv") {
    try {
      return parseCsvRows(config, buf, defaultAuth);
    } catch (e) {
      throw new Error(
        `custom attacks CSV parse failed (${abs}): ${(e as Error).message}`,
      );
    }
  }

  throw new Error(
    `customAttacksFile must end in .json or .csv (got extension "${ext || "(none)"}" for ${abs})`,
  );
}
/**
 * Round 1 merge: prepends `custom` (file + app-tailored) before `planned` when `custom` is non-empty.
 * When `attackConfig.customAttacksOnly` is true, returns only `custom` (skips built-in planner output for round 1).
 * Does not control whether file/app-tailored loads run — omit `customAttacksFile` and set `appTailoredCustomPromptCount` to 0 to disable those sources.
 */
export function mergeCustomAttacksForRound(  config: Config,
  round: number,
  planned: Attack[],
  custom: Attack[],
): Attack[] {
  const only = config.attackConfig.customAttacksOnly === true;
  if (round !== 1 || custom.length === 0) return planned;
  if (only) return custom;
  return [...custom, ...planned];
}
