import { describe, expect, it } from "vitest";
import { ALL_STRATEGIES } from "../lib/attack-strategies.js";
import {
  selectStrategiesForCategory,
  selectStrategiesForCategoryIntelligently,
} from "../lib/strategy-selector.js";
import type { CategoryDefenseProfile } from "../lib/types.js";

describe("strategy selector affinity ranking", () => {
  it("prefers higher affinity scores for a category in non-adaptive mode", () => {
    const lookup = (category: string, slug: string): number | undefined => {
      if (category !== "prompt_injection") return undefined;
      return {
        challenge_framing: 60,
        life_or_death_emergency: 85,
        poetic_metaphor_request: 10,
      }[slug];
    };

    const selected = selectStrategiesForCategoryIntelligently(
      "prompt_injection",
      ALL_STRATEGIES,
      [
        "challenge_framing",
        "poetic_metaphor_request",
        "life_or_death_emergency",
      ],
      2,
      lookup,
    );

    expect(selected.map((strategy) => strategy.slug)).toEqual([
      "life_or_death_emergency",
      "challenge_framing",
    ]);
  });

  it("uses affinity scores inside adaptive tiers without ignoring defense history", () => {
    const lookup = (category: string, slug: string): number | undefined => {
      if (category !== "content_filter_bypass") return undefined;
      return {
        rot13_cipher_trick: 85,
        json_format_bypass: 70,
        life_or_death_emergency: 99,
      }[slug];
    };

    const profile: CategoryDefenseProfile = {
      category: "content_filter_bypass",
      totalAttempts: 2,
      blocked: 2,
      passed: 0,
      partial: 0,
      blockRate: 100,
      defenseBreakdown: {
        content_filter: 2,
      },
      dominantDefense: "content_filter",
      failedStrategyIds: [],
      passedStrategyIds: [],
      refusalPatterns: [],
      guardrailTriggers: [],
    };

    const selected = selectStrategiesForCategory(
      profile,
      ALL_STRATEGIES,
      [
        "rot13_cipher_trick",
        "json_format_bypass",
        "life_or_death_emergency",
      ],
      2,
      lookup,
    );

    expect(selected.map((strategy) => strategy.slug)).toEqual([
      "rot13_cipher_trick",
      "json_format_bypass",
    ]);
  });

  it("keeps unscored strategies after scored buckets", () => {
    const lookup = (category: string, slug: string): number | undefined => {
      if (category !== "prompt_injection") return undefined;
      return {
        challenge_framing: 4,
        life_or_death_emergency: 5,
      }[slug];
    };

    const selected = selectStrategiesForCategoryIntelligently(
      "prompt_injection",
      ALL_STRATEGIES,
      [
        "poetic_metaphor_request",
        "challenge_framing",
        "life_or_death_emergency",
      ],
      3,
      lookup,
    );

    expect(selected.slice(0, 2).map((strategy) => strategy.slug)).toEqual([
      "life_or_death_emergency",
      "challenge_framing",
    ]);
    expect(selected[2]?.slug).toBe("poetic_metaphor_request");
  });
});
