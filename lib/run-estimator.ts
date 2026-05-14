// Estimates the size and duration of an attack run. Has two entry points:
//  - estimatePreRun(): predicts shape from config alone, before planAttacks
//    runs (so users see the forecast immediately when a round begins).
//  - estimateRun():    refines the prediction once the exact attack list is
//    known after planning.
// Static constants are calibrated against observed run telemetry (~34s
// wall-time per attack at concurrency 2, mixed single + predefined multi-
// turn + adaptive multi-turn). Override via EST_* env vars per environment.

import type { Attack, Config } from "./types.js";

// Per-call timing constants (seconds). Calibrated against an observed
// ticketio scan: 65 attacks (50 predefined 3-step + 15 adaptive) at
// concurrency 2 ran in 36m 44s. Override via env vars per environment —
// faster LLMs or local targets will need lower values.
const AVG_HTTP_SEC = num(process.env.EST_HTTP_SEC, 2.5); // target API response
const AVG_JUDGE_SEC = num(process.env.EST_JUDGE_SEC, 8.0); // analyzeResponse LLM call (runs per step in multi-turn)
const AVG_ADAPTIVE_GEN_SEC = num(process.env.EST_ADAPTIVE_GEN_SEC, 6.0); // adaptive follow-up generation
const AVG_IDEAL_SEC = num(process.env.EST_IDEAL_SEC, 8.0); // ideal-response generation
const IDEAL_RATE = num(process.env.EST_IDEAL_RATE, 0.25); // share of attacks that produce PASS/PARTIAL
const REFINEMENT_PARTIAL_RATE = num(process.env.EST_PARTIAL_RATE, 0.15); // share of attacks expected to be PARTIAL
const REFINED_PER_PARTIAL = num(process.env.EST_REFINED_PER_PARTIAL, 2);

// Adaptive multi-turn rarely runs the full `maxAdaptiveTurns`; most stop at
// PASS or hit refusal early. Avg observed across runs is 3-5.
const ADAPTIVE_AVG_TURNS = 4;
const ADAPTIVE_MIN_TURNS = 1;
const ADAPTIVE_MAX_TURNS_CAP = 8; // most runs cap practically here even when config allows 15

// Uncertainty bands applied to the expected estimate.
const MIN_FACTOR = 0.6;
const MAX_FACTOR = 1.6;

function num(v: string | undefined, fallback: number): number {
  const n = v === undefined ? NaN : Number(v);
  return Number.isFinite(n) ? n : fallback;
}

export interface RunEstimate {
  plannedAttacks: number;
  refinedExpected: number;
  totalAttacksExpected: number;
  httpCalls: { min: number; expected: number; max: number };
  attackTypes: { singleTurn: number; predefinedMultiTurn: number; adaptiveMultiTurn: number };
  wallTimeSec: { min: number; expected: number; max: number };
  isPreRun: boolean;
  /** Mode + math breakdown. Populated only for pre-run estimates. */
  mode?: {
    isFullPool: boolean;
    numCategories: number;
    poolLen: number;
    effectiveStrategies: number;
    attacksPerStrategy: number;
    maxAttacksPerCategory: number;
    seedsPerCategory: number;
    adaptiveRounds: number;
    perCategoryRound1: number;
  };
}

const SEEDS_PER_CATEGORY = 3; // approximate seed count from each AttackModule.getSeedAttacks
const FULL_POOL_THRESHOLD = 100;

/**
 * Estimate run size BEFORE planning starts. Uses only the config + counts of
 * eligible categories/strategies (so it's available the moment a run begins
 * — no waiting for planAttacks to finish).
 */
export function estimatePreRun(
  config: Config,
  numCategories: number,
  totalAvailableStrategies: number,
): RunEstimate {
  const ac = config.attackConfig;
  const enabledStratLen = ac.enabledStrategies?.length || totalAvailableStrategies;
  const poolLen = enabledStratLen || totalAvailableStrategies;
  const strategiesPerRound = ac.strategiesPerRound ?? 5;
  const attacksPerStrategy = Math.max(1, ac.attacksPerStrategy ?? 1);
  const maxAttacksPerCategory = ac.maxAttacksPerCategory ?? 5;
  const adaptiveRounds = Math.max(1, ac.adaptiveRounds ?? 1);

  const isFullPool =
    poolLen > 0 &&
    (strategiesPerRound >= FULL_POOL_THRESHOLD || strategiesPerRound >= poolLen);
  const effectiveStrategies = Math.min(strategiesPerRound, poolLen);

  // Round 1 attacks per category = seeds + generated
  const perCatRound1 = isFullPool
    ? SEEDS_PER_CATEGORY + effectiveStrategies * attacksPerStrategy
    : SEEDS_PER_CATEGORY + Math.min(maxAttacksPerCategory, effectiveStrategies);

  // Rounds 2..N skip seeds, just LLM-generated
  const perCatLater = isFullPool
    ? effectiveStrategies * attacksPerStrategy
    : Math.min(maxAttacksPerCategory, effectiveStrategies);

  const plannedAttacks =
    numCategories * (perCatRound1 + (adaptiveRounds - 1) * perCatLater);

  // Synthesize a virtual `attacks` array shaped by multiTurnGenerationRate.
  // multiTurnGenerationRate is the fraction of LLM-generated attacks that
  // will have PREDEFINED steps embedded; adaptive multi-turn applies on top.
  const mtRate = ac.multiTurnGenerationRate ?? 0;
  const adaptiveEnabled =
    !!ac.enableAdaptiveMultiTurn && !!ac.enableMultiTurnGeneration;

  const generatedAttacks = plannedAttacks - numCategories * SEEDS_PER_CATEGORY;
  const predefinedMt = Math.round(generatedAttacks * mtRate);
  const remaining = generatedAttacks - predefinedMt + numCategories * SEEDS_PER_CATEGORY;
  const adaptiveMt = adaptiveEnabled ? remaining : 0;
  const singleTurn = adaptiveEnabled ? 0 : remaining;

  const est = buildEstimate(
    config,
    { singleTurn, predefinedMt, adaptiveMt },
    plannedAttacks,
    true,
  );
  est.mode = {
    isFullPool,
    numCategories,
    poolLen,
    effectiveStrategies,
    attacksPerStrategy,
    maxAttacksPerCategory,
    seedsPerCategory: SEEDS_PER_CATEGORY,
    adaptiveRounds,
    perCategoryRound1: perCatRound1,
  };
  return est;
}

export function estimateRun(attacks: Attack[], config: Config): RunEstimate {
  const maxMultiTurnSteps = config.attackConfig.maxMultiTurnSteps ?? 5;
  const adaptiveEnabled =
    !!config.attackConfig.enableAdaptiveMultiTurn &&
    !!config.attackConfig.enableMultiTurnGeneration;

  let singleTurn = 0;
  let predefinedMt = 0;
  let adaptiveMt = 0;
  let predefinedHttp = 0;

  for (const a of attacks) {
    if (a.steps && a.steps.length > 0) {
      predefinedMt += 1;
      predefinedHttp += Math.min(1 + a.steps.length, maxMultiTurnSteps);
    } else if (adaptiveEnabled) {
      adaptiveMt += 1;
    } else {
      singleTurn += 1;
    }
  }

  return buildEstimate(
    config,
    { singleTurn, predefinedMt, adaptiveMt, predefinedHttp },
    attacks.length,
    false,
  );
}

function buildEstimate(
  config: Config,
  shape: {
    singleTurn: number;
    predefinedMt: number;
    adaptiveMt: number;
    predefinedHttp?: number;
  },
  plannedAttacks: number,
  isPreRun: boolean,
): RunEstimate {
  const concurrency = Math.max(1, config.attackConfig.concurrency || 1);
  const delaySec = (config.attackConfig.delayBetweenRequestsMs || 0) / 1000;
  const maxMultiTurnSteps = config.attackConfig.maxMultiTurnSteps ?? 5;
  const adaptiveCap = Math.min(
    config.attackConfig.maxAdaptiveTurns ?? 15,
    ADAPTIVE_MAX_TURNS_CAP,
  );

  const { singleTurn, predefinedMt, adaptiveMt } = shape;
  // Predefined multi-turn HTTP = avg ~3 steps per attack when shape is predicted;
  // when called from estimateRun, real step counts are passed in.
  const predefinedHttp =
    shape.predefinedHttp ??
    predefinedMt * Math.min(3, maxMultiTurnSteps);

  const httpMin = singleTurn + predefinedHttp + adaptiveMt * ADAPTIVE_MIN_TURNS;
  const httpExpected = singleTurn + predefinedHttp + adaptiveMt * ADAPTIVE_AVG_TURNS;
  const httpMax = singleTurn + predefinedHttp + adaptiveMt * adaptiveCap;

  // Refinement adds ~REFINEMENT_PARTIAL_RATE × REFINED_PER_PARTIAL extra attacks.
  // These are nearly always adaptive multi-turn, so cost is similar to adaptiveMt.
  const refinedExpected = Math.round(
    plannedAttacks * REFINEMENT_PARTIAL_RATE * REFINED_PER_PARTIAL,
  );
  const refinedHttpExpected = refinedExpected * ADAPTIVE_AVG_TURNS;

  // Total work time (seconds). Judge runs per HTTP step in multi-turn paths.
  const totalHttpExpected = httpExpected + refinedHttpExpected;
  const httpTime = totalHttpExpected * AVG_HTTP_SEC;
  const judgeTime = totalHttpExpected * AVG_JUDGE_SEC;
  const adaptiveGenTime =
    (adaptiveMt + refinedExpected) * (ADAPTIVE_AVG_TURNS - 1) * AVG_ADAPTIVE_GEN_SEC;
  const totalAttacks = plannedAttacks + refinedExpected;
  const idealTime = totalAttacks * IDEAL_RATE * AVG_IDEAL_SEC;
  const delayTime = totalHttpExpected * delaySec;

  const workSec = httpTime + judgeTime + adaptiveGenTime + idealTime + delayTime;
  const wallExpected = workSec / concurrency;

  return {
    plannedAttacks,
    refinedExpected,
    totalAttacksExpected: totalAttacks,
    httpCalls: {
      min: httpMin,
      expected: httpExpected + refinedHttpExpected,
      max: httpMax + refinedHttpExpected,
    },
    attackTypes: {
      singleTurn,
      predefinedMultiTurn: predefinedMt,
      adaptiveMultiTurn: adaptiveMt,
    },
    wallTimeSec: {
      min: Math.round(wallExpected * MIN_FACTOR),
      expected: Math.round(wallExpected),
      max: Math.round(wallExpected * MAX_FACTOR),
    },
    isPreRun,
  };
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  if (m < 60) return s > 0 ? `${m}m ${s}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const mm = m % 60;
  return mm > 0 ? `${h}h ${mm}m` : `${h}h`;
}

/** Pad a label to a fixed width so values line up in column form. */
function row(label: string, value: string, width = 16): string {
  return `${label.padEnd(width)}${value}`;
}

export function formatEstimate(est: RunEstimate, concurrency: number): string[] {
  const t = est.attackTypes;
  const lines: string[] = [];
  const tilde = est.isPreRun ? "~" : "";

  // ── Mode + math (pre-run only) ───────────────────────
  if (est.isPreRun && est.mode) {
    const m = est.mode;
    const round1Total = m.numCategories * m.perCategoryRound1;
    if (m.isFullPool) {
      const variantWord = m.attacksPerStrategy === 1 ? "variant" : "variants";
      lines.push(
        row("Mode", `full-pool — every strategy runs ${m.attacksPerStrategy}× ${variantWord}`),
      );
      lines.push(
        row(
          "Per category",
          `${m.effectiveStrategies} ${plural(m.effectiveStrategies, "strategy", "strategies")} × ${m.attacksPerStrategy}/strategy + ${m.seedsPerCategory} seeds = ~${m.perCategoryRound1} attacks`,
        ),
      );
    } else {
      const generated = Math.min(m.maxAttacksPerCategory, m.effectiveStrategies);
      lines.push(
        row("Mode", `batch — sample ${m.effectiveStrategies} of ${m.poolLen} strategies/category`),
      );
      lines.push(
        row(
          "Per category",
          `${generated} LLM attacks + ${m.seedsPerCategory} seeds = ~${m.perCategoryRound1} attacks`,
        ),
      );
    }
    lines.push(
      row(
        "Round 1 total",
        `${m.numCategories} ${plural(m.numCategories, "category", "categories")} × ${m.perCategoryRound1} = ~${round1Total} attacks`,
      ),
    );
    if (m.adaptiveRounds > 1) {
      lines.push(row("Rounds", `${m.adaptiveRounds} adaptive rounds (round 2+ skips seeds)`));
    }
    lines.push(""); // blank line separator before totals
  }

  // ── Totals ───────────────────────────────────────────
  const attacksLine =
    est.refinedExpected > 0
      ? `${tilde}${est.plannedAttacks} attacks  +  ~${est.refinedExpected} refined  =  ~${est.totalAttacksExpected} total`
      : `${tilde}${est.plannedAttacks} attacks`;
  lines.push(row(est.isPreRun ? "Attacks" : "Planned", attacksLine));

  // ── Type mix ─────────────────────────────────────────
  const breakdown: string[] = [];
  if (t.singleTurn) breakdown.push(`${tilde}${t.singleTurn} single-turn`);
  if (t.predefinedMultiTurn) breakdown.push(`${tilde}${t.predefinedMultiTurn} predefined multi-turn`);
  if (t.adaptiveMultiTurn) breakdown.push(`${tilde}${t.adaptiveMultiTurn} adaptive multi-turn`);
  if (breakdown.length > 0) {
    lines.push(row("Types", breakdown.join(", ")));
  }

  lines.push(""); // blank line separator before requests/time

  // ── Cost ─────────────────────────────────────────────
  lines.push(
    row(
      "HTTP",
      `~${est.httpCalls.expected} requests  (range ${est.httpCalls.min}–${est.httpCalls.max})`,
    ),
  );
  lines.push(
    row(
      "Wall time",
      `~${formatDuration(est.wallTimeSec.expected)}  (range ${formatDuration(est.wallTimeSec.min)} – ${formatDuration(est.wallTimeSec.max)}, concurrency ${concurrency})`,
    ),
  );

  if (est.isPreRun) {
    lines.push("");
    lines.push("(numbers will firm up after planning completes)");
  }
  return lines;
}

function plural(n: number, singular: string, pluralForm: string): string {
  return n === 1 ? singular : pluralForm;
}
