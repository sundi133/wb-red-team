import { describe, expect, it } from "vitest";
import { ALL_STRATEGIES } from "../lib/attack-strategies.js";
import { loadConfig } from "../lib/config-loader.js";

function duplicateValues<T>(values: T[]): T[] {
  const counts = new Map<T, number>();
  for (const value of values) {
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return [...counts.entries()]
    .filter(([, count]) => count > 1)
    .map(([value]) => value);
}

describe("registry integrity", () => {
  it("attack strategy IDs are unique", () => {
    expect(duplicateValues(ALL_STRATEGIES.map((s) => s.id))).toEqual([]);
  });

  it("attack strategy slugs are unique", () => {
    expect(duplicateValues(ALL_STRATEGIES.map((s) => s.slug))).toEqual([]);
  });

  it("configured enabled categories are unique", () => {
    const config = loadConfig("config.json");
    expect(duplicateValues(config.attackConfig.enabledCategories ?? [])).toEqual(
      [],
    );
  });

  it("configured enabled strategies are unique", () => {
    const config = loadConfig("config.json");
    expect(duplicateValues(config.attackConfig.enabledStrategies ?? [])).toEqual(
      [],
    );
  });
});
