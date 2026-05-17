/**
 * Global proxy bootstrap — call once at app startup.
 * Configures Node's global fetch dispatcher to route through
 * HTTP_PROXY / HTTPS_PROXY when set, while respecting NO_PROXY
 * for internal endpoints (targets, databases, etc.).
 */
import { EnvHttpProxyAgent, setGlobalDispatcher } from "undici";

export function bootstrapProxy(): void {
  const proxyUrl =
    process.env.HTTPS_PROXY ||
    process.env.https_proxy ||
    process.env.HTTP_PROXY ||
    process.env.http_proxy;

  if (!proxyUrl) return;

  // EnvHttpProxyAgent reads HTTP_PROXY, HTTPS_PROXY, and NO_PROXY
  // automatically — internal targets listed in NO_PROXY bypass the proxy.
  const agent = new EnvHttpProxyAgent();
  setGlobalDispatcher(agent);

  const noProxy = process.env.NO_PROXY || process.env.no_proxy || "(none)";
  console.log(`  [proxy] Global fetch dispatcher set → ${proxyUrl}`);
  console.log(`  [proxy] NO_PROXY → ${noProxy}`);
}
