#!/usr/bin/env npx tsx
/**
 * Mock LangGraph-style SSE server for testing custom API formats.
 * Simulates an insurance policy agent that streams responses.
 *
 * Usage: npx tsx scripts/mock-langgraph-server.ts [port]
 */

import { createServer } from "node:http";

const PORT = parseInt(process.argv[2] || "8000", 10);

const server = createServer((req, res) => {
  if (req.method === "POST" && req.url === "/api/chat") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      let userMessage = "hello";
      try {
        const parsed = JSON.parse(body);
        const messages = parsed?.input?.messages || [];
        const human = messages.find((m: any) => m.type === "human");
        if (human?.content) userMessage = human.content;
      } catch {}

      // Simulate AI response
      const aiResponse = `Based on your policy, here is the information you requested regarding: "${userMessage.slice(0, 80)}". Your Auto policy POL-12345 is active with coverage details available in your account.`;

      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
      });

      // Emit intermediate event (tool call)
      const intermediate = {
        username: "TestUser",
        messages: [
          { type: "human", content: userMessage },
          {
            type: "ai",
            content: "",
            tool_calls: [
              {
                name: "send-message",
                args: {
                  agent_name: "policy_agent",
                  task: userMessage,
                  task_params: { policy_number: "POL-12345", line_of_business: "Auto", skill: "policy-details-retrieval" },
                },
              },
            ],
          },
        ],
        policy_number: "POL-12345",
        line_of_business: "Auto",
        guardrail_passed: true,
        guardrail_reason: "Content passed Prompt Guard safety check",
      };
      res.write(`data: ${JSON.stringify(intermediate)}\n\n`);

      // Emit final event with AI response after a short delay
      setTimeout(() => {
        const final = {
          username: "TestUser",
          messages: [
            { type: "human", content: userMessage },
            { type: "ai", content: "", tool_calls: [{ name: "send-message", args: { agent_name: "policy_agent", task: userMessage } }] },
            { type: "tool", name: "send-message", content: "Policy details retrieved", artifact: { subagent_name: "policy_agent", routing_outcome: "success", task_status: "completed" } },
            { type: "ai", content: aiResponse },
          ],
          policy_number: "POL-12345",
          line_of_business: "Auto",
          intent_names: [],
          live_agent_needed: false,
          guardrail_passed: true,
          guardrail_reason: "Content passed Prompt Guard safety check",
          active_tasks: {},
          response_links: [],
        };
        res.write(`data: ${JSON.stringify(final)}\n\n`);
        res.end();
      }, 500);
    });
  } else {
    res.writeHead(404);
    res.end("Not found");
  }
});

server.listen(PORT, () => {
  console.log(`\n  Mock LangGraph server → http://localhost:${PORT}/api/chat`);
  console.log(`  Format: SSE with messages[{type=ai}].content`);
  console.log(`  Press Ctrl+C to stop\n`);
});
