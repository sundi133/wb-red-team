import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { loadEnvFile } from "../lib/env-loader.js";

describe("loadEnvFile", () => {
  it("loads values from .env and overrides existing env vars", () => {
    const dir = mkdtempSync(join(tmpdir(), "redteam-env-"));
    const envPath = join(dir, ".env");
    const original = process.env.ANTHROPIC_API_KEY;

    try {
      writeFileSync(envPath, "ANTHROPIC_API_KEY=from-dot-env\n");
      process.env.ANTHROPIC_API_KEY = "from-shell";

      loadEnvFile({ envPath });

      expect(process.env.ANTHROPIC_API_KEY).toBe("from-dot-env");
    } finally {
      if (original === undefined) {
        delete process.env.ANTHROPIC_API_KEY;
      } else {
        process.env.ANTHROPIC_API_KEY = original;
      }
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
