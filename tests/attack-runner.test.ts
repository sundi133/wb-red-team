import { describe, it, expect } from "vitest";
import { runWithConcurrency, sleep } from "../lib/attack-runner.js";

describe("runWithConcurrency", () => {
  it("runs all tasks and returns results in order", async () => {
    const tasks = [1, 2, 3, 4, 5].map(
      (n) => () => Promise.resolve(n * 10),
    );
    const results = await runWithConcurrency(tasks, 3);
    expect(results).toEqual([10, 20, 30, 40, 50]);
  });

  it("respects concurrency limit", async () => {
    let running = 0;
    let maxRunning = 0;

    const tasks = Array.from({ length: 10 }, () => async () => {
      running++;
      maxRunning = Math.max(maxRunning, running);
      await sleep(10);
      running--;
      return maxRunning;
    });

    await runWithConcurrency(tasks, 3);
    expect(maxRunning).toBeLessThanOrEqual(3);
  });

  it("handles concurrency limit greater than task count", async () => {
    const tasks = [1, 2].map((n) => () => Promise.resolve(n));
    const results = await runWithConcurrency(tasks, 100);
    expect(results).toEqual([1, 2]);
  });

  it("handles empty task list", async () => {
    const results = await runWithConcurrency([], 5);
    expect(results).toEqual([]);
  });

  it("handles concurrency of 1 (sequential)", async () => {
    const order: number[] = [];
    const tasks = [1, 2, 3].map((n) => async () => {
      order.push(n);
      return n;
    });
    const results = await runWithConcurrency(tasks, 1);
    expect(results).toEqual([1, 2, 3]);
    expect(order).toEqual([1, 2, 3]);
  });

  it("propagates errors from tasks", async () => {
    const tasks = [
      () => Promise.resolve("ok"),
      () => Promise.reject(new Error("boom")),
    ];
    await expect(runWithConcurrency(tasks, 2)).rejects.toThrow("boom");
  });
});
