import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer, Server } from "http";
import { executeAttack } from "../lib/attack-runner.js";
import type { Config, Attack } from "../lib/types.js";

let server: Server;
let port: number;

beforeAll(
  () =>
    new Promise<void>((resolve) => {
      server = createServer(() => {
        // never respond — client must time out
      });
      server.listen(0, "127.0.0.1", () => {
        port = (server.address() as { port: number }).port;
        resolve();
      });
    }),
);

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

describe("executeAttack timeout", () => {
  it("aborts a hanging target request within targetTimeoutMs", async () => {
    const config = {
      target: {
        type: "http_agent",
        baseUrl: `http://127.0.0.1:${port}`,
        agentEndpoint: "/",
        authEndpoint: "/login",
      },
      auth: { methods: [], jwtSecret: "", credentials: [], apiKeys: {} },
      attackConfig: { targetTimeoutMs: 150 },
    } as unknown as Config;

    const attack: Attack = {
      id: "t",
      category: "auth_bypass",
      name: "t",
      description: "t",
      authMethod: "none",
      role: "",
      payload: { message: "hi" },
      expectation: "",
      severity: "low",
      isLlmGenerated: false,
    };

    const start = Date.now();
    const result = await executeAttack(config, attack);
    const elapsed = Date.now() - start;

    expect(result.statusCode).toBe(0);
    expect(elapsed).toBeGreaterThanOrEqual(140);
    expect(elapsed).toBeLessThan(2000);
  });
});
