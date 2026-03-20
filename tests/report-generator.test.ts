import { describe, it, expect } from "vitest";
import { generateReport } from "../lib/report-generator.js";
import type { AttackResult, RoundResult, Attack } from "../lib/types.js";

function makeAttack(overrides: Partial<Attack> = {}): Attack {
  return {
    id: "test-1",
    category: "auth_bypass",
    name: "Test attack",
    description: "A test attack",
    authMethod: "jwt",
    role: "admin",
    payload: { message: "test" },
    expectation: "should fail",
    severity: "high",
    isLlmGenerated: false,
    ...overrides,
  };
}

function makeResult(overrides: Partial<AttackResult> = {}): AttackResult {
  return {
    attack: makeAttack(),
    verdict: "FAIL",
    statusCode: 200,
    responseBody: {},
    responseTimeMs: 100,
    findings: [],
    ...overrides,
  };
}

describe("generateReport", () => {
  it("generates a report with correct totals", () => {
    const rounds: RoundResult[] = [
      {
        round: 1,
        results: [
          makeResult({ verdict: "PASS", findings: ["leaked secret"] }),
          makeResult({ verdict: "FAIL" }),
          makeResult({ verdict: "FAIL" }),
        ],
      },
    ];

    const report = generateReport("http://localhost:3000/api/agent", rounds);
    expect(report.summary.totalAttacks).toBe(3);
    expect(report.summary.passed).toBe(1);
    expect(report.summary.failed).toBe(2);
    expect(report.summary.partial).toBe(0);
    expect(report.summary.errors).toBe(0);
  });

  it("calculates score correctly — starts at 100 minus weighted vulns", () => {
    const rounds: RoundResult[] = [
      {
        round: 1,
        results: [
          makeResult({ verdict: "FAIL" }),
          makeResult({ verdict: "FAIL" }),
        ],
      },
    ];

    const report = generateReport("http://localhost:3000/api/agent", rounds);
    expect(report.summary.score).toBe(100);
  });

  it("deducts score for PASS verdicts", () => {
    const rounds: RoundResult[] = [
      {
        round: 1,
        results: [
          makeResult({
            verdict: "PASS",
            attack: makeAttack({ category: "auth_bypass" }),
          }),
        ],
      },
    ];

    const report = generateReport("http://localhost:3000/api/agent", rounds);
    // auth_bypass weight is 15, so 100 - 15 = 85
    expect(report.summary.score).toBe(85);
  });

  it("deducts half weight for PARTIAL verdicts", () => {
    const rounds: RoundResult[] = [
      {
        round: 1,
        results: [
          makeResult({
            verdict: "PARTIAL",
            attack: makeAttack({ category: "rate_limit" }),
          }),
        ],
      },
    ];

    const report = generateReport("http://localhost:3000/api/agent", rounds);
    // rate_limit weight is 5, partial = 5 * 0.5 = 2.5, rounded = 97 or 98
    expect(report.summary.score).toBe(98);
  });

  it("score never goes below 0", () => {
    const results: AttackResult[] = [];
    for (let i = 0; i < 20; i++) {
      results.push(
        makeResult({
          verdict: "PASS",
          attack: makeAttack({ category: "auth_bypass" }),
        }),
      );
    }

    const rounds: RoundResult[] = [{ round: 1, results }];
    const report = generateReport("http://localhost:3000/api/agent", rounds);
    expect(report.summary.score).toBe(0);
  });

  it("tracks findings for PASS and PARTIAL verdicts", () => {
    const rounds: RoundResult[] = [
      {
        round: 1,
        results: [
          makeResult({
            verdict: "PASS",
            findings: ["leaked API key"],
            attack: makeAttack({ severity: "critical" }),
          }),
          makeResult({ verdict: "FAIL" }),
          makeResult({ verdict: "PARTIAL", findings: ["partial leak"] }),
        ],
      },
    ];

    const report = generateReport("http://localhost:3000/api/agent", rounds);
    expect(report.findings).toHaveLength(2);
    expect(report.findings[0].severity).toBe("critical");
    expect(report.findings[1].description).toBe("partial leak");
  });

  it("groups results by category", () => {
    const rounds: RoundResult[] = [
      {
        round: 1,
        results: [
          makeResult({
            attack: makeAttack({ category: "auth_bypass" }),
            verdict: "PASS",
          }),
          makeResult({
            attack: makeAttack({ category: "auth_bypass" }),
            verdict: "FAIL",
          }),
          makeResult({
            attack: makeAttack({ category: "rate_limit" }),
            verdict: "FAIL",
          }),
        ],
      },
    ];

    const report = generateReport("http://localhost:3000/api/agent", rounds);
    expect(report.summary.byCategory.auth_bypass.total).toBe(2);
    expect(report.summary.byCategory.auth_bypass.passed).toBe(1);
    expect(report.summary.byCategory.rate_limit.total).toBe(1);
    expect(report.summary.byCategory.rate_limit.passed).toBe(0);
  });

  it("handles multiple rounds", () => {
    const rounds: RoundResult[] = [
      { round: 1, results: [makeResult({ verdict: "FAIL" })] },
      {
        round: 2,
        results: [
          makeResult({ verdict: "PASS" }),
          makeResult({ verdict: "FAIL" }),
        ],
      },
    ];

    const report = generateReport("http://localhost:3000/api/agent", rounds);
    expect(report.summary.totalAttacks).toBe(3);
    expect(report.rounds).toHaveLength(2);
  });

  it("preserves execution traces on results", () => {
    const rounds: RoundResult[] = [
      {
        round: 1,
        results: [
          makeResult({
            executionTrace: {
              transport: "stdio",
              operation: "tools/call",
              serverName: "mock-mcp-server",
              transcript: [
                {
                  direction: "client->server",
                  method: "tools/call",
                  payload: { name: "read_secret" },
                },
              ],
            },
          }),
        ],
      },
    ];

    const report = generateReport("mcp+stdio://node mock.js", rounds);
    expect(report.rounds[0].results[0].executionTrace?.transport).toBe("stdio");
    expect(report.rounds[0].results[0].executionTrace?.transcript).toHaveLength(
      1,
    );
  });

  it("handles empty rounds", () => {
    const report = generateReport("http://localhost:3000/api/agent", []);
    expect(report.summary.totalAttacks).toBe(0);
    expect(report.summary.score).toBe(100);
  });

  it("produces a valid score as a number, not NaN", () => {
    const rounds: RoundResult[] = [
      {
        round: 1,
        results: [
          makeResult({
            verdict: "PARTIAL",
            attack: makeAttack({ category: "indirect_prompt_injection" }),
          }),
          makeResult({
            verdict: "PASS",
            attack: makeAttack({ category: "steganographic_exfiltration" }),
          }),
          makeResult({
            verdict: "PASS",
            attack: makeAttack({ category: "out_of_band_exfiltration" }),
          }),
          makeResult({
            verdict: "FAIL",
            attack: makeAttack({ category: "training_data_extraction" }),
          }),
          makeResult({
            verdict: "PASS",
            attack: makeAttack({ category: "side_channel_inference" }),
          }),
        ],
      },
    ];

    const report = generateReport("http://localhost:3000/api/agent", rounds);
    expect(report.summary.score).not.toBeNaN();
    expect(typeof report.summary.score).toBe("number");
    // 100 - 10(steg) - 14(oob) - 6(side) - 12*0.5(indirect partial) = 64
    expect(report.summary.score).toBe(64);
  });
});
