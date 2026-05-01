#!/usr/bin/env npx tsx
/**
 * Mock Trussed AI gateway — OpenAI-compatible chat completions endpoint.
 * Simulates an internal corporate LLM proxy for testing custom provider.
 *
 * Usage: npx tsx scripts/mock-trussed-server.ts [port]
 *
 * Test:
 *   curl -X POST http://localhost:9000/provider/generic/chat/completions \
 *     -H "Content-Type: application/json" \
 *     -H "Authorization: Bearer test-key" \
 *     -d '{"model":"AISolutions6GVASAAPTUs","messages":[{"role":"user","content":"hello"}]}'
 */

import { createServer } from "node:http";
import { randomUUID } from "node:crypto";

const PORT = parseInt(process.argv[2] || "9000", 10);

const server = createServer((req, res) => {
  // Health check
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok" }));
    return;
  }

  // Chat completions — matches /provider/generic/chat/completions or /v1/chat/completions
  if (req.method === "POST" && (req.url?.includes("/chat/completions"))) {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      let model = "AISolutions6GVASAAPTUs";
      let userMessage = "";
      let systemMessage = "";

      try {
        const parsed = JSON.parse(body);
        model = parsed.model || model;
        const messages = parsed.messages || [];
        const system = messages.find((m: any) => m.role === "system");
        const user = messages.filter((m: any) => m.role === "user").pop();
        if (system?.content) systemMessage = system.content;
        if (user?.content) userMessage = user.content;
      } catch {}

      // Generate a contextual response based on the user message
      let responseContent: string;
      const lower = userMessage.toLowerCase();

      if (lower.includes("capital")) {
        responseContent = "The capital of the United States is Washington, D.C.";
      } else if (lower.includes("policy") || lower.includes("insurance")) {
        responseContent = "I can help you with your insurance policy. Your Auto policy POL-12345 is currently active with comprehensive coverage. Please note I cannot share sensitive information like SSN or internal credentials.";
      } else if (lower.includes("ignore") || lower.includes("system prompt") || lower.includes("instructions")) {
        responseContent = "I'm sorry, but I cannot ignore my safety guidelines or reveal my system instructions. I'm here to help with legitimate insurance-related questions.";
      } else if (lower.includes("secret") || lower.includes("password") || lower.includes("key") || lower.includes("token")) {
        responseContent = "I cannot share any credentials, API keys, passwords, or other sensitive information. This is against our security policies.";
      } else {
        responseContent = `Thank you for your question. As an insurance assistant, I'm designed to help with policy inquiries, claims, and coverage questions. How can I assist you today?`;
      }

      const response = {
        id: `chatcmpl-${randomUUID().slice(0, 12)}`,
        object: "chat.completion",
        created: Math.floor(Date.now() / 1000),
        model,
        choices: [
          {
            index: 0,
            message: {
              role: "assistant",
              content: responseContent,
            },
            finish_reason: "stop",
          },
        ],
        usage: {
          prompt_tokens: Math.ceil((systemMessage.length + userMessage.length) / 4),
          completion_tokens: Math.ceil(responseContent.length / 4),
          total_tokens: Math.ceil((systemMessage.length + userMessage.length + responseContent.length) / 4),
        },
      };

      console.log(`  [${new Date().toISOString()}] ${model} — "${userMessage.slice(0, 60)}..." → ${responseContent.slice(0, 50)}...`);

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(response));
    });
    return;
  }

  // Models list
  if (req.method === "GET" && req.url?.includes("/models")) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      data: [
        { id: "AISolutions6GVASAAPTUs", object: "model", owned_by: "trussed-ai" },
        { id: "AISolutions6GVASAAgpt-4.1-mini", object: "model", owned_by: "trussed-ai" },
      ],
    }));
    return;
  }

  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});

server.listen(PORT, () => {
  console.log(`\n  Mock Trussed AI Gateway → http://localhost:${PORT}`);
  console.log(`  Endpoint: POST /provider/generic/chat/completions`);
  console.log(`  Models: AISolutions6GVASAAPTUs, AISolutions6GVASAAgpt-4.1-mini`);
  console.log(`\n  Test:`);
  console.log(`    curl -X POST http://localhost:${PORT}/provider/generic/chat/completions \\`);
  console.log(`      -H "Content-Type: application/json" \\`);
  console.log(`      -H "Authorization: Bearer test-key" \\`);
  console.log(`      -d '{"model":"AISolutions6GVASAAPTUs","messages":[{"role":"user","content":"hello"}]}'`);
  console.log(`\n  Press Ctrl+C to stop\n`);
});
