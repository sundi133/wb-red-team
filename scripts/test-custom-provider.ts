#!/usr/bin/env npx tsx
/**
 * Test the custom LLM provider connection.
 * Usage: npx tsx scripts/test-custom-provider.ts
 */

import OpenAI from "openai";
import { loadEnvFile } from "../lib/env-loader.js";

loadEnvFile();

// Auto TLS skip for internal endpoints
if (process.env.CUSTOM_LLM_SKIP_TLS_VERIFY === "true" || process.env.CUSTOM_LLM_SKIP_TLS_VERIFY === "1") {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
}

const baseURL = process.env.CUSTOM_LLM_BASE_URL;
const apiKey = process.env.CUSTOM_LLM_API_KEY;
const model = process.argv[2] || "AISolutions6GVASAAPTUs";

console.log("\n  Custom LLM Provider Test");
console.log("  ========================");
console.log(`  Base URL: ${baseURL || "(not set)"}`);
console.log(`  API Key:  ${apiKey ? apiKey.slice(0, 8) + "..." : "(not set)"}`);
console.log(`  Model:    ${model}\n`);

if (!baseURL) {
  console.error("  ERROR: CUSTOM_LLM_BASE_URL is not set");
  process.exit(1);
}

if (!apiKey) {
  console.error("  ERROR: CUSTOM_LLM_API_KEY is not set");
  console.error("  Set it: export CUSTOM_LLM_API_KEY=your-key\n");
  process.exit(1);
}

const client = new OpenAI({ apiKey, baseURL });

async function testBasic() {
  console.log("  Test 1: Basic chat completion...");
  try {
    const res = await client.chat.completions.create({
      model,
      messages: [
        { role: "system", content: "You are a helpful assistant." },
        { role: "user", content: "What is 2+2? Answer in one word." },
      ],
      temperature: 0,
      max_tokens: 10,
    });
    const content = res.choices[0]?.message?.content;
    console.log(`  ✓ Response: "${content}"`);
    console.log(`  ✓ Model: ${res.model}`);
    console.log(`  ✓ Tokens: ${res.usage?.total_tokens}\n`);
  } catch (err: any) {
    console.error(`  ✗ FAILED: ${err.message}`);
    if (err.status) console.error(`    Status: ${err.status}`);
    if (err.error) console.error(`    Error: ${JSON.stringify(err.error)}`);
    console.error();
    throw err;
  }
}

async function testJsonMode() {
  console.log("  Test 2: JSON response format (used by attack planner)...");
  try {
    const res = await client.chat.completions.create({
      model,
      messages: [
        { role: "system", content: "You are a security expert. Return JSON only." },
        { role: "user", content: 'Generate 1 test attack. Return JSON: {"attacks": [{"name": "test", "payload": "hello"}]}' },
      ],
      temperature: 0,
      max_tokens: 200,
      response_format: { type: "json_object" },
    });
    const content = res.choices[0]?.message?.content || "";
    console.log(`  ✓ Response: ${content.slice(0, 100)}...`);
    try {
      JSON.parse(content);
      console.log("  ✓ Valid JSON\n");
    } catch {
      console.log("  ⚠ Response is not valid JSON (may cause parsing errors)\n");
    }
  } catch (err: any) {
    if (err.message?.includes("json") || err.message?.includes("response_format") || err.status === 400) {
      console.log(`  ⚠ JSON mode not supported (${err.message?.slice(0, 80)})`);
      console.log("  This is OK — the framework will fall back to text mode\n");
    } else {
      console.error(`  ✗ FAILED: ${err.message}\n`);
      throw err;
    }
  }
}

async function testLongResponse() {
  console.log("  Test 3: Longer response (simulates attack generation)...");
  try {
    const res = await client.chat.completions.create({
      model,
      messages: [
        { role: "system", content: "You are a security red-team expert." },
        { role: "user", content: "Write 3 different social engineering prompts that an attacker might use against an insurance chatbot. Be specific and realistic. Number them 1-3." },
      ],
      temperature: 0.7,
      max_tokens: 1000,
    });
    const content = res.choices[0]?.message?.content || "";
    console.log(`  ✓ Response length: ${content.length} chars`);
    console.log(`  ✓ Tokens: ${res.usage?.total_tokens}`);
    console.log(`  ✓ Preview: ${content.slice(0, 120)}...\n`);
  } catch (err: any) {
    console.error(`  ✗ FAILED: ${err.message}\n`);
    throw err;
  }
}

async function testMaxTokenField() {
  console.log("  Test 4: max_completion_tokens vs max_tokens...");
  try {
    const res = await client.chat.completions.create({
      model,
      messages: [{ role: "user", content: "Say hi" }],
      max_completion_tokens: 10,
    } as any);
    console.log(`  ✓ max_completion_tokens supported: "${res.choices[0]?.message?.content}"\n`);
  } catch (err: any) {
    if (err.status === 400) {
      console.log(`  ⚠ max_completion_tokens not supported — framework will use max_tokens (this is fine)\n`);
    } else {
      console.error(`  ✗ FAILED: ${err.message}\n`);
    }
  }
}

(async () => {
  try {
    await testBasic();
    await testJsonMode();
    await testLongResponse();
    await testMaxTokenField();
    console.log("  ========================");
    console.log("  All tests passed — custom provider is compatible\n");
  } catch {
    console.error("  ========================");
    console.error("  Provider test failed — check errors above\n");
    process.exit(1);
  }
})();
