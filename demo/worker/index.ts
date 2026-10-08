/**
 * The `oaath-demo.taek.tech` edge: serves the demo SPA, its runtime config, and
 * the demo's only paths to a chain.
 *
 * - `/`, `/callback`, `/assets/*`: built assets (GET/HEAD only), strict CSP.
 * - `/config.json`: issuer, client id and chain settings from Worker vars, so
 *   the client id changes without a rebuild.
 * - `/rpc/chain`, `/rpc/bundler`: Arbitrum Sepolia JSON-RPC and ERC-4337
 *   bundler proxies (`rpc.ts`).
 * - `/paymaster/421614`: the ERC-7677 sponsorship proxy to Pimlico; it
 *   sponsors only the demo's own call (`rpc.ts`).
 * - `/automation/session`: a verified login becomes a session at the
 *   automation service (`automation.ts`).
 *
 * Every proxy route is same-origin only, allow-listed, budgeted per IP, and
 * forwards each request exactly once with no fallback.
 *
 * @author taek <leekt216@gmail.com>
 */

import { type AutomationEnv, automationSession, automationUrl } from "./automation.js";
import { DEMO_CHAIN_ID, DEMO_SELECTOR, DEMO_TARGET, type ProxyEnv, proxy } from "./rpc.js";

interface Fetcher {
  fetch(request: Request): Promise<Response>;
}

/** The automation definition the demo schedules (`automation/demo-ping.automation.json`). */
export const DEMO_AUTOMATION = "demo.ping.v1";

export interface Env extends ProxyEnv, AutomationEnv {
  /** Workers static assets (`dist/`). */
  readonly ASSETS: Fetcher;
  /** The demo's public origin, e.g. `https://oaath-demo.taek.tech`. */
  readonly DEMO_ORIGIN: string;
  /** The OAAth issuer (portal) origin. */
  readonly OAATH_ISSUER: string;
  /** The demo's registered OAuth client. */
  readonly OAATH_CLIENT_ID: string;
  /** Transaction page prefix, e.g. `https://sepolia.arbiscan.io/tx/`. */
  readonly EXPLORER_TX_URL?: string;
}

function policy(issuer: string, automation: string | null): string {
  const services = [issuer, ...(automation === null ? [] : [automation])];
  return [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    `connect-src 'self' ${services.map((url) => new URL(url).origin).join(" ")}`,
    "img-src 'self' data:",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "upgrade-insecure-requests",
  ].join("; ");
}

function failure(status: number, error: string): Response {
  return Response.json({ error }, { status, headers: { "Cache-Control": "no-store" } });
}

function secured(response: Response, extra: Record<string, string>): Response {
  const headers = new Headers(response.headers);
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Strict-Transport-Security", "max-age=31536000");
  for (const [name, value] of Object.entries(extra)) headers.set(name, value);
  return new Response(response.body, { status: response.status, headers });
}

const ROLES = {
  "/rpc/chain": "chain",
  "/rpc/bundler": "bundler",
  [`/paymaster/${DEMO_CHAIN_ID}`]: "paymaster",
} as const;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.origin !== env.DEMO_ORIGIN) return failure(421, "Unknown host");
    const reading = request.method === "GET" || request.method === "HEAD";

    const role = ROLES[url.pathname as keyof typeof ROLES];
    if (role || url.pathname === "/automation/session") {
      const site = request.headers.get("sec-fetch-site");
      if (
        (site !== null && site !== "same-origin") ||
        request.headers.get("origin") !== env.DEMO_ORIGIN
      )
        return failure(403, "Cross-site request refused");
      return secured(
        role ? await proxy(role, request, env) : await automationSession(request, env),
        {},
      );
    }

    if (url.pathname === "/config.json" && reading)
      return secured(
        Response.json({
          issuer: env.OAATH_ISSUER,
          clientId: env.OAATH_CLIENT_ID,
          chainId: DEMO_CHAIN_ID,
          target: DEMO_TARGET,
          selector: DEMO_SELECTOR,
          explorerTxUrl: env.EXPLORER_TX_URL ?? null,
          // Without a key the paymaster answers 503 and the page asks for funding instead.
          sponsored: Boolean(env.PIMLICO_API_KEY),
          // Without a service and credential the automation section stays hidden.
          automation:
            automationUrl(env) === null ? null : { url: automationUrl(env), id: DEMO_AUTOMATION },
        }),
        { "Cache-Control": "no-store" },
      );

    const page = url.pathname === "/" || url.pathname === "/callback";
    const asset = /^\/assets\/[A-Za-z0-9][\w.-]*\.(?:js|css)$/u.test(url.pathname);
    if (!reading || (!page && !asset)) return failure(404, "Not found");
    const served = await env.ASSETS.fetch(
      new Request(
        `${env.DEMO_ORIGIN}${url.pathname === "/" ? "/index.html" : url.pathname === "/callback" ? "/callback.html" : url.pathname}`,
        { method: request.method },
      ),
    );
    return secured(
      served,
      page
        ? {
            "Content-Security-Policy": policy(env.OAATH_ISSUER, automationUrl(env)),
            "X-Frame-Options": "DENY",
            "Cache-Control": "no-store",
          }
        : { "Cache-Control": served.ok ? "public, max-age=31536000, immutable" : "no-store" },
    );
  },
};
