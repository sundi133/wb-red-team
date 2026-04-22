/**
 * Generate a wb-red-team config.json directly from app details, an endpoint,
 * and what the user wants to test — no Hermes, no probing, no repo scan.
 *
 * This is the minimal path the user actually wanted: one LLM call that
 * synthesizes a config given the inputs + the README (for category IDs
 * and config shape).
 *
 * Usage:
 *   SLUG=acme \
 *     BASE_URL=https://agent.prod.acme.internal \
 *     ENDPOINT=/v1/assistant/chat \
 *     APP_DETAILS="Customer-support copilot, multi-tenant, CRM + order tools" \
 *     WHAT_TO_TEST="tool misuse, auth bypass, PII leaks" \
 *     AUTH_HINT="Bearer token in env ENTERPRISE_BEARER" \
 *     npm run gen:config
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import OpenAI from "openai";
import type { ChatCompletionCreateParamsNonStreaming } from "openai/resources/chat/completions";

const ANTHROPIC_MODEL = process.env.MODEL || "claude-sonnet-4-5";
const PROVIDER = (process.env.PROVIDER || "anthropic").toLowerCase();

const REPO_ROOT = resolve(process.cwd());
const SLUG = process.env.SLUG || process.argv[2] || "demo";
const BASE_URL = process.env.BASE_URL || "http://localhost:3000";
const ENDPOINT = process.env.ENDPOINT || "/api/exfil-test-agent";
const APP_DETAILS =
  process.env.APP_DETAILS ||
  "Internal support copilot with mocked tools (read_file, db_query, send_email, slack_dm); JWT auth; returns fake PII from fixtures.";
const WHAT_TO_TEST =
  process.env.WHAT_TO_TEST ||
  "tool misuse, auth bypass, PII leaks, prompt injection, data exfiltration";
const AUTH_HINT = process.env.AUTH_HINT || "(none)";

const OUT_PATH = resolve(REPO_ROOT, `configs/config.${SLUG}.json`);
const README_PATH = resolve(REPO_ROOT, "README.md");

const SYSTEM_PROMPT = `You are a security-engineering assistant that produces wb-red-team config JSON.

Return ONLY valid JSON for a single wb-red-team config object. No prose, no markdown fences, no comments. The object must be directly parseable with JSON.parse.

Follow the config shape documented in the wb-red-team README the user will paste.
Follow these rules strictly:
- Pick 8 to 20 attack category IDs for attackConfig.enabledCategories, matching the user's whatToTest priorities against the README's category table.
- Do NOT invent category IDs that are not in the README.
- Do NOT include real credentials, tokens, or PII anywhere.
- For auth, if authHint is "(none)" or empty, set {"methods":[]}; if it mentions an env var, use {"methods":["bearer"],"bearerToken":"\${ENV_NAME}"} verbatim.
- Use sensible defaults for attackConfig: llmProvider=anthropic, llmModel=claude-sonnet-4-5, judgeModel=claude-sonnet-4-5, adaptiveRounds=2, concurrency=3, delayBetweenRequestsMs=200, appTailoredCustomPromptCount=15.
- Use requestSchema.messageField="message" and responseSchema.responsePath="response" unless appDetails indicates otherwise.
- target.applicationDetails should be a concise paragraph synthesized from appDetails, preserving any tool names / role names / data types verbatim.
- sensitivePatterns should reflect the data types named in appDetails (e.g. SSN, card, email, postgres://, sk-, AKIA, etc.).`;

async function callAnthropic(messages: { role: "user" | "assistant"; content: string }[], system: string): Promise<string> {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) throw new Error("ANTHROPIC_API_KEY not set");
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": key,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: ANTHROPIC_MODEL,
      max_tokens: 4096,
      system,
      messages,
    }),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Anthropic ${res.status}: ${err}`);
  }
  const data = (await res.json()) as any;
  const text = (data.content ?? []).map((b: any) => b.text ?? "").join("").trim();
  if (!text) throw new Error("Empty response from Anthropic");
  return text;
}

async function callOpenAI(messages: { role: "system" | "user" | "assistant"; content: string }[]): Promise<string> {
  const key = process.env.OPENAI_API_KEY;
  if (!key) throw new Error("OPENAI_API_KEY not set");
  const client = new OpenAI({ apiKey: key });
  const req: ChatCompletionCreateParamsNonStreaming = {
    model: ANTHROPIC_MODEL.startsWith("claude") ? "gpt-4o" : ANTHROPIC_MODEL,
    messages,
    max_tokens: 4096,
    temperature: 0,
    response_format: { type: "json_object" },
  };
  const r = await client.chat.completions.create(req);
  return r.choices[0]?.message?.content ?? "";
}

function stripJsonFences(s: string): string {
  return s
    .replace(/^\s*```(?:json|jsonc)?\s*/i, "")
    .replace(/\s*```\s*$/i, "")
    .trim();
}

async function main() {
  const readme = await readFile(README_PATH, "utf8");

  const user = `wb-red-team README (ground truth for config shape and category IDs):

<README>
${readme}
</README>

Inputs:
- slug: ${SLUG}
- baseUrl: ${BASE_URL}
- endpoint: ${ENDPOINT}
- appDetails: ${APP_DETAILS}
- whatToTest: ${WHAT_TO_TEST}
- authHint: ${AUTH_HINT}

Produce a single wb-red-team config JSON object for this target. JSON only.`;

  let raw: string;
  if (PROVIDER === "anthropic") {
    raw = await callAnthropic([{ role: "user", content: user }], SYSTEM_PROMPT);
  } else if (PROVIDER === "openai") {
    raw = await callOpenAI([
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: user },
    ]);
  } else {
    throw new Error(`unsupported PROVIDER=${PROVIDER}. Use anthropic or openai.`);
  }

  const cleaned = stripJsonFences(raw);
  let config: unknown;
  try {
    config = JSON.parse(cleaned);
  } catch (e) {
    console.error("Model did not return valid JSON. Raw response:\n");
    console.error(raw);
    throw e;
  }

  await mkdir(dirname(OUT_PATH), { recursive: true });
  await writeFile(OUT_PATH, JSON.stringify(config, null, 2));
  console.log(`✓ wrote ${OUT_PATH}`);
  console.log();
  const cfg = config as any;
  const cats = cfg?.attackConfig?.enabledCategories ?? [];
  console.log(`enabledCategories (${cats.length}): ${cats.join(", ")}`);
  console.log();
  console.log(`next: npx tsx red-team.ts ${OUT_PATH.replace(REPO_ROOT + "/", "")}`);
}

main().catch((e) => {
  console.error("gen-config failed:", e.message ?? e);
  process.exit(1);
});
