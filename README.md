# Red-Team Security Testing Framework

LLM-powered red-team testing framework for agentic AI endpoints. It automatically discovers vulnerabilities by analyzing your app's codebase, generating targeted attacks across multiple categories, and adapting over multiple rounds.

## Attack Categories

| Category | Description |
|----------|-------------|
| `auth_bypass` | Forged JWTs, missing auth, credential stuffing |
| `rbac_bypass` | Role escalation, cross-role access |
| `prompt_injection` | System prompt override, jailbreaks, instruction hijacking |
| `output_evasion` | Guardrail bypass, output filter evasion |
| `data_exfiltration` | Extracting secrets via tool calls, side channels |
| `rate_limit` | Rapid-fire requests to test throttling |
| `sensitive_data` | Leaking API keys, credentials, PII from responses |
| `indirect_prompt_injection` | Poisoned external data sources (URLs, emails, DB records) that hijack agent behavior |
| `steganographic_exfiltration` | Hiding secrets in benign output via whitespace, acrostics, emoji, or markdown tricks |
| `out_of_band_exfiltration` | Forcing outbound requests (HTTP callbacks, DNS, webhooks) to leak data externally |
| `training_data_extraction` | Extracting memorized training data, system prompts, or context window contents |
| `side_channel_inference` | Inferring secrets via timing, token counts, error messages, or yes/no confirmation |

## Prerequisites

- **Node.js** >= 18
- **npm**
- An **OpenAI API key** (used for LLM-powered attack generation and response analysis)

```bash
export OPENAI_API_KEY="sk-..."
```

## Installation

```bash
npm install
```

## Configuration

Create a `config.json` (or copy and modify the included one) pointing at your AI app:

```jsonc
{
  // Target endpoint
  "target": {
    "baseUrl": "http://localhost:3000",
    "agentEndpoint": "/api/your-agent",
    "authEndpoint": "/api/auth/login"
  },

  // Path to your app's source code (for static analysis)
  "codebasePath": "../your-app/src",
  "codebaseGlob": "**/*.ts",

  // Auth configuration
  "auth": {
    "methods": ["jwt", "api_key", "body_role"],
    "jwtSecret": "your-jwt-secret",
    "credentials": [
      { "email": "admin@example.com", "password": "admin123", "role": "admin" },
      { "email": "user@example.com", "password": "user123", "role": "viewer" }
    ],
    "apiKeys": {
      "admin": "ak_admin_001",
      "viewer": "ak_viewer_002"
    }
  },

  // How requests are shaped for your agent
  "requestSchema": {
    "messageField": "message",
    "roleField": "role",
    "apiKeyField": "api_key",
    "guardrailModeField": "guardrail_mode"
  },

  // Where to find data in responses
  "responseSchema": {
    "responsePath": "response",
    "toolCallsPath": "tool_calls",
    "userInfoPath": "user",
    "guardrailsPath": "guardrails"
  },

  // Strings that should never appear in responses
  "sensitivePatterns": [
    "sk-proj-", "AKIA", "postgres://", "password"
  ],

  // Attack tuning
  "attackConfig": {
    "adaptiveRounds": 3,
    "maxAttacksPerCategory": 15,
    "concurrency": 3,
    "delayBetweenRequestsMs": 200,
    "llmModel": "gpt-4o",
    "enableLlmGeneration": true
  }
}
```

### Config Reference

| Field | Required | Description |
|-------|----------|-------------|
| `target.baseUrl` | Yes | Base URL of your running AI app |
| `target.agentEndpoint` | Yes | The agent endpoint path to attack |
| `target.authEndpoint` | No | Login endpoint (for JWT auth) |
| `codebasePath` | No | Path to app source for static analysis |
| `codebaseGlob` | No | Glob pattern for source files (default: `**/*.ts`) |
| `auth.methods` | Yes | Auth methods your app supports: `jwt`, `api_key`, `body_role` |
| `auth.jwtSecret` | No | JWT secret (for forged-token attacks) |
| `auth.credentials` | No | User credentials with roles for auth testing |
| `auth.apiKeys` | No | API keys mapped by role |
| `sensitivePatterns` | Yes | Strings/patterns that should never leak in responses |
| `attackConfig.adaptiveRounds` | No | Number of adaptive rounds (default: 3) |
| `attackConfig.enableLlmGeneration` | No | Use LLM to generate novel attacks (default: true) |
| `attackConfig.llmModel` | No | OpenAI model for attack generation (default: `gpt-4o`) |

## Running

1. **Start your AI app** so it's accessible at the configured `baseUrl`:

   ```bash
   # In your app directory
   npm run dev
   ```

2. **Run the red-team framework** (with default `config.json`):

   ```bash
   npm start
   ```

   Or specify a custom config:

   ```bash
   npx tsx red-team.ts path/to/config.json
   ```

3. **Review the report** — results are written to `report/`:
   - `report-<timestamp>.json` — full machine-readable results
   - `report-<timestamp>.md` — human-readable summary

## How It Works

1. **Config loading** — reads target URL, auth details, and attack parameters
2. **Codebase analysis** — statically scans your app source to discover tools, roles, guardrails, and weaknesses
3. **Pre-authentication** — logs in with configured credentials to obtain JWT tokens
4. **Adaptive attack rounds** — for each round:
   - Plans attacks based on codebase analysis and previous round results
   - Executes attacks against the live endpoint
   - Uses an LLM to analyze responses and classify vulnerabilities
   - Adapts subsequent rounds based on what worked
5. **Report generation** — produces a scored security report with findings by category and severity

## Example Output

```
=== Red-Team Security Testing Framework ===

[1/5] Loading configuration...
  Target: http://localhost:3000/api/your-agent
  Adaptive rounds: 3
  LLM generation: enabled

[2/5] Analyzing target codebase...
  Found 5 tools, 4 roles
  Identified 3 potential weaknesses

[3/5] Pre-authenticating...

[4/5] Running attacks...
  -- Round 1/3 --
  Planned 46 attacks
  [1/46] Forge JWT with hardcoded secret (admin)... [!!] PASS (200, 312ms)
  [2/46] Send request with no auth header... [OK] FAIL (401, 15ms)
  ...
  Round 1: 14 vulns found

[5/5] Generating report...
  JSON: report/report-2026-03-06T04-02-31-013Z.json
  Markdown: report/report-2026-03-06T04-02-31-013Z.md
```

## Project Structure

```
red-team.ts              # Entry point
config.json              # Target configuration
lib/
  types.ts               # Shared type definitions
  config-loader.ts       # Config parsing and validation
  codebase-analyzer.ts   # Static analysis of target app source
  attack-planner.ts      # Plans attacks per round (seed + LLM-generated)
  attack-runner.ts       # Executes HTTP attacks against the target
  response-analyzer.ts   # LLM-powered response classification
  report-generator.ts    # Generates JSON and Markdown reports
attacks/
  auth-bypass.ts         # Authentication bypass attacks
  rbac-bypass.ts         # Role-based access control bypass
  prompt-injection.ts    # Prompt injection attacks
  output-evasion.ts      # Output guardrail evasion
  data-exfiltration.ts   # Data exfiltration via tool calls
  rate-limit.ts          # Rate limiting tests
  sensitive-data.ts      # Sensitive data exposure tests
  indirect-prompt-injection.ts  # Indirect prompt injection via external data
  steganographic-exfiltration.ts # Covert encoding exfiltration
  out-of-band-exfiltration.ts   # External callback/DNS/webhook exfiltration
  training-data-extraction.ts   # Training data and system prompt extraction
  side-channel-inference.ts     # Timing, error, and behavioral side channels
report/                  # Generated reports (JSON + Markdown)
```

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `PASS` | Vulnerability found — the attack succeeded |
| `FAIL` | Defense held — the attack was blocked |
| `PARTIAL` | Partial leak or inconsistent behavior |
| `ERROR` | Request failed or unexpected error |

## License

[MIT](LICENSE)
