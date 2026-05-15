/**
 * Global proxy bootstrap — call once at app startup.
 * Configures Node's global fetch dispatcher to route through
 * HTTP_PROXY / HTTPS_PROXY when set, so the OpenAI SDK and
 * raw fetch() calls respect corporate proxies.
 */
import { ProxyAgent, setGlobalDispatcher } from "undici";

export function bootstrapProxy(): void {
  const proxyUrl =
    process.env.HTTPS_PROXY ||
    process.env.https_proxy ||
    process.env.HTTP_PROXY ||
    process.env.http_proxy;

  if (!proxyUrl) return;

  const agent = new ProxyAgent(proxyUrl);
  setGlobalDispatcher(agent);
  console.log(`  [proxy] Global fetch dispatcher set → ${proxyUrl}`);
}
