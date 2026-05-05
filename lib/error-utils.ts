/**
 * Walk the full error cause chain and extract every detail available.
 * Produces a self-contained error message — no server logs needed.
 */
export function formatErrorDetails(err: unknown): string {
  if (!err) return "Unknown error";

  const lines: string[] = [];
  let current: unknown = err;
  const seen = new Set<unknown>();
  let depth = 0;

  while (current && !seen.has(current)) {
    seen.add(current);
    const e = current as Error & {
      code?: string;
      status?: number;
      errno?: number;
      syscall?: string;
      address?: string;
      port?: number;
      hostname?: string;
      type?: string;
      url?: string;
      baseURL?: string;
      headers?: Record<string, string>;
      body?: unknown;
      response?: { status?: number; statusText?: string; url?: string };
    };

    const prefix = depth === 0 ? "" : `  [cause ${depth}] `;
    const meta: string[] = [];

    if (e.message) meta.push(e.message);
    if (e.code) meta.push(`code=${e.code}`);
    if (e.status) meta.push(`status=${e.status}`);
    if (e.type && e.type !== "system") meta.push(`type=${e.type}`);
    if (e.syscall) meta.push(`syscall=${e.syscall}`);
    if (e.hostname) meta.push(`hostname=${e.hostname}`);
    if (e.address) meta.push(`address=${e.address}:${e.port ?? ""}`);
    if (e.url) meta.push(`url=${e.url}`);
    if (e.errno && e.errno !== -1) meta.push(`errno=${e.errno}`);

    // Capture HTTP response details if available
    if (e.response) {
      const r = e.response;
      if (r.status) meta.push(`response_status=${r.status} ${r.statusText ?? ""}`);
      if (r.url) meta.push(`response_url=${r.url}`);
    }

    // Capture response body for API errors (auth failures, etc.)
    if (e.body && typeof e.body === "object") {
      try {
        const bodyStr = JSON.stringify(e.body);
        if (bodyStr.length < 500) meta.push(`body=${bodyStr}`);
      } catch {}
    }

    if (meta.length > 0) {
      lines.push(`${prefix}${meta.join(" | ")}`);
    }

    const next = (current as any).cause ?? (current as any).error;
    current = next;
    depth++;
  }

  // Add env context so the user knows what was configured (skip if already embedded)
  const topErr = err as any;
  const baseUrl = process.env.CUSTOM_LLM_BASE_URL;
  if (baseUrl && !topErr.skipConfig && !lines.some(l => l.includes("CUSTOM_LLM_BASE_URL"))) {
    lines.push(`  [config] CUSTOM_LLM_BASE_URL=${baseUrl}`);
  }

  let result = lines.join("\n");

  // Clean up trailing "reason: " (OpenAI SDK bug)
  result = result.replace(/,?\s*reason:\s*$/gm, "").trim();

  if (!result || result === "Connection error." || result === "Connection error") {
    return `Connection error — CUSTOM_LLM_BASE_URL=${baseUrl ?? "<not set>"} is unreachable. Check network, proxy, SSL certs, and firewall.`;
  }

  return result;
}
