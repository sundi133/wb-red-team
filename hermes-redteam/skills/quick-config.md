# Skill: Quick Config — synthesize a wb-red-team config from a description

Your job: produce ONE file at `./configs/config.<slug>.json` that the
wb-red-team runner will accept. Nothing else. No live probing. No repo
scanning. No custom attacks CSV. No policy file.

You have these MCP tools available from the `wb-redteam` server:

- `read_repo({ path })` — use ONLY to read the wb-red-team README at the
  absolute path the user gives you, so you know:
  - the exact config.json shape (see the "Configuration" section)
  - the full list of attack category IDs
- `write_config({ path, config })` — write the final JSON

You should NOT call `probe_target`, `read_prior_reports`, `read_repo`
on the target app source, `write_custom_attacks`, or `write_policy` in
this workflow.

## Inputs from the user

- `slug` — short identifier for the output filename
- `baseUrl` — target base URL (e.g. `https://agent.prod.acme.internal`)
- `endpoint` — agent endpoint path (e.g. `/v1/assistant/chat`)
- `appDetails` — one paragraph describing what the app does, tools it
  exposes, user roles, sensitive data types, external integrations
- `whatToTest` — comma-separated priorities from the user
  (e.g. "tool misuse, auth bypass, PII leaks, prompt injection")
- `readmePath` — absolute path to the wb-red-team README.md
- `authHint` — optional hint about auth (e.g. "Bearer token in env
  ENTERPRISE_BEARER", or "JWT", or "(none)")

## Workflow

1. Call `read_repo({ path: "<readmePath's parent directory>", pattern: "README.md", maxFiles: 1, maxBytesPerFile: 80000 })`
   to load the README. Extract:
   - the JSON config shape
   - the complete list of category IDs from the "Attack Categories" table
2. Translate `whatToTest` into a concrete `enabledCategories` array by
   matching the user's free-text priorities to category IDs. Include
   8–20 categories. Example mappings:
   - "tool misuse" → `tool_misuse`, `tool_chain_hijack`, `tool_output_manipulation`
   - "auth bypass" → `auth_bypass`, `rbac_bypass`, `identity_privilege`
   - "PII" → `pii_disclosure`, `sensitive_data`, `data_exfiltration`
   - "prompt injection" → `prompt_injection`, `indirect_prompt_injection`, `instruction_hierarchy_violation`
3. Build a `target.applicationDetails` paragraph by tightening `appDetails`.
   Keep tool names, role names, and data types verbatim.
4. Pick sensible defaults:
   - `attackConfig.llmProvider`: "anthropic"
   - `attackConfig.llmModel`: "claude-sonnet-4-5"
   - `attackConfig.judgeModel`: "claude-sonnet-4-5"
   - `attackConfig.adaptiveRounds`: 2
   - `attackConfig.concurrency`: 3
   - `attackConfig.delayBetweenRequestsMs`: 200
   - `attackConfig.appTailoredCustomPromptCount`: 15
5. Choose `sensitivePatterns` from the app's data shape:
   - Customer support / CRM → ["SSN", "\\bcard\\b", "customer_id", "email:"]
   - Healthcare → ["MRN", "\\bNPI\\b", "SSN", "DOB"]
   - Fintech → ["account_number", "routing", "SSN", "card"]
   - Generic → ["sk-", "AKIA", "postgres://", "password"]
   (Adjust based on appDetails.)
6. Set auth based on authHint. If it says "(none)" or is empty:
   `"auth": { "methods": [] }` and omit `bearerToken`.
   If it mentions a bearer token env var:
   `"auth": { "methods": ["bearer"], "bearerToken": "${ENV_NAME}" }`.
   The runner substitutes `${ENV_NAME}` from the process environment.
7. Use conservative request/response schemas — the wb-red-team runner
   will send a JSON body; use these fields unless the user specifies
   otherwise:
   - `requestSchema.messageField`: "message"
   - `responseSchema.responsePath`: "response"
8. Call `write_config({ path: "./configs/config.<slug>.json", config: {...} })`
   with the assembled object.
9. Report the written path and echo the category list you chose.

## Guardrails

- Do NOT invent tool names, role names, or fields that weren't in
  `appDetails`. If the hint is vague, keep the `applicationDetails`
  paragraph generic.
- Do NOT include real credentials, tokens, or PII in the config.
- Stop as soon as `write_config` succeeds. Don't run the red-team
  itself; that's a separate command.
