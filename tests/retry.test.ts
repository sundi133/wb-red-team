import { describe, it, expect, vi, afterEach } from "vitest";
import { fetchWithRetry } from "../lib/attack-runner.js";

// Mock global fetch
const originalFetch = globalThis.fetch;

describe("fetchWithRetry", () => {
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("returns immediately on success (no retries needed)", async () => {
    const mockResponse = new Response(JSON.stringify({ ok: true }), {
      status: 200,
    });
    globalThis.fetch = vi.fn().mockResolvedValue(mockResponse);

    const result = await fetchWithRetry("http://test.com", {}, 3, 10);
    expect(result.status).toBe(200);
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });

  it("returns 4xx errors without retrying", async () => {
    const mockResponse = new Response("Not Found", { status: 404 });
    globalThis.fetch = vi.fn().mockResolvedValue(mockResponse);

    const result = await fetchWithRetry("http://test.com", {}, 3, 10);
    expect(result.status).toBe(404);
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });

  it("retries on 500 server errors", async () => {
    const fail = new Response("Internal Server Error", { status: 500 });
    const success = new Response(JSON.stringify({ ok: true }), { status: 200 });

    globalThis.fetch = vi
      .fn()
      .mockResolvedValueOnce(fail)
      .mockResolvedValueOnce(fail)
      .mockResolvedValueOnce(success);

    const result = await fetchWithRetry("http://test.com", {}, 3, 10);
    expect(result.status).toBe(200);
    expect(globalThis.fetch).toHaveBeenCalledTimes(3);
  });

  it("retries on network errors", async () => {
    const success = new Response(JSON.stringify({ ok: true }), { status: 200 });

    globalThis.fetch = vi
      .fn()
      .mockRejectedValueOnce(new Error("fetch failed"))
      .mockResolvedValueOnce(success);

    const result = await fetchWithRetry("http://test.com", {}, 3, 10);
    expect(result.status).toBe(200);
    expect(globalThis.fetch).toHaveBeenCalledTimes(2);
  });

  it("throws after exhausting all retry attempts", async () => {
    globalThis.fetch = vi
      .fn()
      .mockRejectedValue(new Error("ECONNREFUSED"));

    await expect(
      fetchWithRetry("http://test.com", {}, 2, 10),
    ).rejects.toThrow("ECONNREFUSED");
    // 1 initial + 2 retries = 3 total attempts
    expect(globalThis.fetch).toHaveBeenCalledTimes(3);
  });

  it("throws after exhausting retries on persistent 500s", async () => {
    const fail = new Response("Server Error", { status: 500 });
    globalThis.fetch = vi.fn().mockResolvedValue(fail);

    await expect(
      fetchWithRetry("http://test.com", {}, 2, 10),
    ).rejects.toThrow("Server error: 500");
    expect(globalThis.fetch).toHaveBeenCalledTimes(3);
  });

  it("works with zero retries (single attempt)", async () => {
    globalThis.fetch = vi
      .fn()
      .mockRejectedValue(new Error("timeout"));

    await expect(
      fetchWithRetry("http://test.com", {}, 0, 10),
    ).rejects.toThrow("timeout");
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });

  it("applies exponential backoff between retries", async () => {
    const fail = new Response("Error", { status: 503 });
    const success = new Response("OK", { status: 200 });

    globalThis.fetch = vi
      .fn()
      .mockResolvedValueOnce(fail)
      .mockResolvedValueOnce(fail)
      .mockResolvedValueOnce(success);

    const start = Date.now();
    await fetchWithRetry("http://test.com", {}, 3, 50);
    const elapsed = Date.now() - start;

    // 50ms + 100ms = 150ms minimum for two retries with exponential backoff
    expect(elapsed).toBeGreaterThanOrEqual(100);
    expect(globalThis.fetch).toHaveBeenCalledTimes(3);
  });
});
