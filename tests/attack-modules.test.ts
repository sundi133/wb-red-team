import { describe, it, expect } from "vitest";

// Import all attack modules
import { authBypassModule } from "../attacks/auth-bypass.js";
import { rbacBypassModule } from "../attacks/rbac-bypass.js";
import { promptInjectionModule } from "../attacks/prompt-injection.js";
import { outputEvasionModule } from "../attacks/output-evasion.js";
import { dataExfiltrationModule } from "../attacks/data-exfiltration.js";
import { rateLimitModule } from "../attacks/rate-limit.js";
import { sensitiveDataModule } from "../attacks/sensitive-data.js";
import { indirectPromptInjectionModule } from "../attacks/indirect-prompt-injection.js";
import { steganographicExfiltrationModule } from "../attacks/steganographic-exfiltration.js";
import { outOfBandExfiltrationModule } from "../attacks/out-of-band-exfiltration.js";
import { trainingDataExtractionModule } from "../attacks/training-data-extraction.js";
import { sideChannelInferenceModule } from "../attacks/side-channel-inference.js";
import type { AttackModule, CodebaseAnalysis } from "../lib/types.js";

const ALL_MODULES: AttackModule[] = [
  authBypassModule,
  rbacBypassModule,
  promptInjectionModule,
  outputEvasionModule,
  dataExfiltrationModule,
  rateLimitModule,
  sensitiveDataModule,
  indirectPromptInjectionModule,
  steganographicExfiltrationModule,
  outOfBandExfiltrationModule,
  trainingDataExtractionModule,
  sideChannelInferenceModule,
];

const mockAnalysis: CodebaseAnalysis = {
  tools: [{ name: "read_file", description: "Read a file", parameters: "path: string" }],
  roles: [{ name: "admin", permissions: ["*"] }],
  guardrailPatterns: [],
  sensitiveData: [{ type: "api_key", location: ".env", example: "sk-..." }],
  authMechanisms: ["jwt"],
  knownWeaknesses: [],
  systemPromptHints: [],
};

describe("Attack modules", () => {
  for (const mod of ALL_MODULES) {
    describe(mod.category, () => {
      it("has a valid category string", () => {
        expect(mod.category).toBeTruthy();
        expect(typeof mod.category).toBe("string");
      });

      it("returns at least 1 seed attack", () => {
        const seeds = mod.getSeedAttacks();
        expect(seeds.length).toBeGreaterThanOrEqual(1);
      });

      it("seed attacks have required fields", () => {
        const seeds = mod.getSeedAttacks();
        for (const attack of seeds) {
          expect(attack.id).toBeTruthy();
          expect(attack.category).toBe(mod.category);
          expect(attack.name).toBeTruthy();
          expect(attack.description).toBeTruthy();
          expect(["jwt", "api_key", "body_role", "none", "forged_jwt"]).toContain(attack.authMethod);
          expect(attack.role).toBeTruthy();
          expect(attack.payload).toBeDefined();
          expect(attack.payload.message || attack.payload._rapidFire).toBeTruthy();
          expect(attack.expectation).toBeTruthy();
          expect(["critical", "high", "medium", "low"]).toContain(attack.severity);
          expect(attack.isLlmGenerated).toBe(false);
        }
      });

      it("seed attacks have unique IDs", () => {
        const seeds = mod.getSeedAttacks();
        const ids = seeds.map((a) => a.id);
        expect(new Set(ids).size).toBe(ids.length);
      });

      it("returns a non-empty generation prompt", () => {
        const prompt = mod.getGenerationPrompt(mockAnalysis);
        expect(prompt).toBeTruthy();
        expect(prompt.length).toBeGreaterThan(50);
      });
    });
  }

  it("all modules have unique categories", () => {
    const categories = ALL_MODULES.map((m) => m.category);
    expect(new Set(categories).size).toBe(categories.length);
  });

  it("all seed attack IDs are globally unique", () => {
    const allIds = ALL_MODULES.flatMap((m) => m.getSeedAttacks().map((a) => a.id));
    expect(new Set(allIds).size).toBe(allIds.length);
  });
});
