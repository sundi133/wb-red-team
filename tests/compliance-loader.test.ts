import { describe, expect, it } from "vitest";
import { loadComplianceFrameworks, listComplianceFrameworks } from "../lib/compliance-loader.js";

describe("compliance loader", () => {
  it("loads GDPR framework with populated controls", () => {
    const frameworks = loadComplianceFrameworks();
    const gdpr = frameworks.find((fw) => fw.id === "gdpr");

    expect(gdpr).toBeDefined();
    expect(gdpr?.name).toContain("GDPR");
    expect(gdpr?.items.length).toBeGreaterThanOrEqual(10);
    expect(gdpr?.items.some((item) => item.code === "Art. 32")).toBe(true);
    expect(gdpr?.items.some((item) => item.code === "Art. 17")).toBe(true);
  });

  it("exposes GDPR in framework listing metadata", () => {
    const frameworks = listComplianceFrameworks();
    const gdpr = frameworks.find((fw) => fw.id === "gdpr");

    expect(gdpr).toBeDefined();
    expect(gdpr?.controlCount).toBeGreaterThanOrEqual(10);
  });
});
