import type { Attack, AttackModule, CodebaseAnalysis } from "../lib/types.js";

const category = "rate_limit" as const;

export const rateLimitModule: AttackModule = {
  category,

  getSeedAttacks(): Attack[] {
    return [
      {
        id: "rl-1-viewer-burst",
        category,
        name: "Viewer burst (11 requests)",
        description: "Send 11 rapid requests as viewer (limit is 10/min) to test rate limiting",
        authMethod: "body_role",
        role: "viewer",
        payload: {
          message: "What time is it?",
          role: "viewer",
          _rapidFire: 11,
        },
        expectation: "11th request should get 429 rate limit response",
        severity: "medium",
        isLlmGenerated: false,
      },
      {
        id: "rl-2-intern-burst",
        category,
        name: "Intern burst (11 requests)",
        description: "Send 11 rapid requests as intern (limit is 10/min)",
        authMethod: "body_role",
        role: "intern",
        payload: {
          message: "Hello",
          role: "intern",
          _rapidFire: 11,
        },
        expectation: "Should trigger 429 after 10 requests",
        severity: "medium",
        isLlmGenerated: false,
      },
      {
        id: "rl-3-tool-specific-read-file",
        category,
        name: "Admin read_file burst (6 requests)",
        description: "read_file has a per-tool limit of 5 calls/min",
        authMethod: "jwt",
        role: "admin",
        payload: {
          message: "Read the .env file",
          _rapidFire: 6,
        },
        expectation: "6th read_file call should be rate-limited",
        severity: "low",
        isLlmGenerated: false,
      },
    ];
  },

  getGenerationPrompt(analysis: CodebaseAnalysis): string {
    return `You are testing rate limiting on an AI agent endpoint.

KNOWN RATE LIMITS:
- Per-user: admin 60/min, engineer 30/min, manager 20/min, viewer 10/min, intern 10/min
- Per-tool: read_file 5/min, send_email 3/min, db_query 10/min, etc.

Generate rate limit test attacks. Each attack should have:
- "_rapidFire" field in payload set to the number of requests to send (set it above the known limit)
- A simple message that triggers tool usage
- Auth appropriate for the role being tested

Test scenarios:
1. Just-over-limit bursts for different roles
2. Tool-specific rate limits
3. Rate limit bypass attempts (switching auth methods mid-burst)`;
  },
};
