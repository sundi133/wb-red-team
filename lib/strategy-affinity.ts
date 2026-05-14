import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { AttackCategory } from "./types.js";
import type { AttackStrategy } from "./attack-strategies.js";

const DEFAULT_AFFINITY_CSV = "data/strategy-category-affinity.csv";
const MIN_AFFINITY_SCORE = 1;
const MAX_AFFINITY_SCORE = 5;

type CategoryAffinityScores = Map<string, number>;
type StrategyAffinityMatrix = Map<AttackCategory, CategoryAffinityScores>;

const cache = new Map<string, StrategyAffinityLookup | null>();

export type StrategyAffinityLookup = (
  category: AttackCategory,
  strategySlug: string,
) => number | undefined;

function parseCsvLine(line: string): string[] {
  const values: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }
    if (char === "," && !inQuotes) {
      values.push(current.trim());
      current = "";
      continue;
    }
    current += char;
  }

  values.push(current.trim());
  return values;
}

function buildLookup(matrix: StrategyAffinityMatrix): StrategyAffinityLookup {
  return (category, strategySlug) => matrix.get(category)?.get(strategySlug);
}

export function getStrategyAffinityScore(
  category: AttackCategory,
  strategySlug: string,
  affinityLookup?: StrategyAffinityLookup,
): number | undefined {
  return affinityLookup?.(category, strategySlug);
}

export function formatStrategyAffinityLabel(score: number | undefined): string {
  return score == null ? "unscored" : `score=${score}/${MAX_AFFINITY_SCORE}`;
}

export function describeStrategiesWithAffinity(
  category: AttackCategory,
  strategies: AttackStrategy[],
  affinityLookup?: StrategyAffinityLookup,
): string {
  return strategies
    .map((strategy) => {
      const score = getStrategyAffinityScore(
        category,
        strategy.slug,
        affinityLookup,
      );
      return `${strategy.slug} (${formatStrategyAffinityLabel(score)})`;
    })
    .join(", ");
}

function loadMatrix(absPath: string): StrategyAffinityLookup | null {
  const raw = readFileSync(absPath, "utf-8");
  const lines = raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  if (lines.length <= 1) {
    return null;
  }

  const matrix: StrategyAffinityMatrix = new Map();
  for (let i = 1; i < lines.length; i++) {
    const [category, strategy, scoreText] = parseCsvLine(lines[i]);
    if (!category || !strategy || !scoreText) continue;

    const score = Number(scoreText);
    if (!Number.isFinite(score)) continue;
    if (score < MIN_AFFINITY_SCORE || score > MAX_AFFINITY_SCORE) {
      console.warn(
        `Ignoring out-of-range strategy affinity score at ${absPath}:${i + 1}. Expected ${MIN_AFFINITY_SCORE}-${MAX_AFFINITY_SCORE}, got ${score}.`,
      );
      continue;
    }

    const categoryKey = category as AttackCategory;
    const categoryScores = matrix.get(categoryKey) ?? new Map<string, number>();
    const existing = categoryScores.get(strategy);
    if (existing != null && existing !== score) {
      categoryScores.set(strategy, Math.max(existing, score));
      console.warn(
        `Duplicate affinity row for ${category}/${strategy} at ${absPath}:${i + 1}; keeping higher score ${Math.max(existing, score)}.`,
      );
    } else {
      categoryScores.set(strategy, score);
    }
    matrix.set(categoryKey, categoryScores);
  }

  return matrix.size > 0 ? buildLookup(matrix) : null;
}

export function getStrategyAffinityLookup(
  configuredPath?: string,
): StrategyAffinityLookup | undefined {
  const trimmed = configuredPath?.trim();
  const absPath = trimmed
    ? resolve(trimmed)
    : resolve(DEFAULT_AFFINITY_CSV);

  if (!existsSync(absPath)) {
    if (trimmed) {
      console.warn(
        `Strategy affinity file not found: ${trimmed}. Falling back to default strategy selection.`,
      );
    }
    return undefined;
  }

  if (cache.has(absPath)) {
    return cache.get(absPath) ?? undefined;
  }

  try {
    const lookup = loadMatrix(absPath);
    cache.set(absPath, lookup);
    if (lookup) {
      console.log(`  Loaded strategy affinity rankings from ${absPath}`);
    }
    return lookup ?? undefined;
  } catch (error) {
    console.warn(
      `Failed to load strategy affinity file ${absPath}: ${(error as Error).message}`,
    );
    cache.set(absPath, null);
    return undefined;
  }
}
