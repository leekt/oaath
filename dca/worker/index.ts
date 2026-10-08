/**
 * The `dca.taek.tech` edge: serves the DCA example page, its runtime config,
 * chain and bundler proxies, and the automation session handoff.
 *
 * - `/`, `/callback`, `/assets/*`: built assets (GET/HEAD only), strict CSP.
 * - `/config.json`: issuer, client id and chain settings from Worker vars, so
 *   the client id changes without a rebuild.
 * - `/rpc/chain`, `/rpc/bundler`: allow-listed, per-IP budgeted Arbitrum
 *   Sepolia JSON-RPC, and the ERC-4337 proxy to the gas-paying bundle_rs relay
 *   over the `BUNDLER` VPC binding, which relays only a test tUSD mint (`rpc.ts`).
 * - `/automation/session`: a verified login becomes a session at the
 *   automation service (`automation.ts`).
 *
 * The plan itself lives at the automation service: the page creates, authorizes
 * and watches it there with the session token, and the service sends every
 * operation. The page's "Mint 1,000 tUSD" button sends one operation from the
 * user's account under a grant the user approved. This Worker never signs.
 *
 * @author taek <leekt216@gmail.com>
 */

import { type AutomationEnv, automationSession, automationUrl } from "./automation.js";
import { DCA_CHAIN_ID, MINT_AMOUNT, mintToken, type ProxyEnv, proxy } from "./rpc.js";

const ROLES = {
  "/rpc/chain": "chain",
  "/rpc/bundler": "bundler",
} as const;

interface Fetcher {
  fetch(request: Request): Promise<Response>;
}

/** Definition ids the page offers: `examples/dca/dca-arbsep.automation.json`. */
export const DCA_AUTOMATION_PREFIX = "dca.arbsep.";

export interface Env extends ProxyEnv, AutomationEnv {
  /** Workers static assets (`dist/`). */
  readonly ASSETS: Fetcher;
  /** The app's public origin, e.g. `https://dca.taek.tech`. */
  readonly DCA_ORIGIN: string;
  /** The OAAth issuer (portal) origin. */
  readonly OAATH_ISSUER: string;
  /** The app's registered OAuth client. */
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

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.origin !== env.DCA_ORIGIN) return failure(421, "Unknown host");
    const reading = request.method === "GET" || request.method === "HEAD";

    const role = ROLES[url.pathname as keyof typeof ROLES];
    if (role || url.pathname === "/automation/session") {
      const site = request.headers.get("sec-fetch-site");
      if (
        (site !== null && site !== "same-origin") ||
        request.headers.get("origin") !== env.DCA_ORIGIN
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
          chainId: DCA_CHAIN_ID,
          explorerTxUrl: env.EXPLORER_TX_URL ?? null,
          // The relay-paid test tUSD mint; null hides the mint button.
          mint:
            mintToken(env) === null
              ? null
              : { token: mintToken(env), amount: MINT_AMOUNT.toString() },
          // Without a service and credential the page says the app is not configured.
          automation:
            automationUrl(env) === null
              ? null
              : { url: automationUrl(env), prefix: DCA_AUTOMATION_PREFIX },
        }),
        { "Cache-Control": "no-store" },
      );

    const page = url.pathname === "/" || url.pathname === "/callback";
    const asset = /^\/assets\/[A-Za-z0-9][\w.-]*\.(?:js|css|woff2)$/u.test(url.pathname);
    if (!reading || (!page && !asset)) return failure(404, "Not found");
    const served = await env.ASSETS.fetch(
      new Request(
        `${env.DCA_ORIGIN}${url.pathname === "/" ? "/index.html" : url.pathname === "/callback" ? "/callback.html" : url.pathname}`,
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
