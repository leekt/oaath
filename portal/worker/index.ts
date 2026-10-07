/**
 * The `oaath.taek.tech` edge: serves the portal SPA and forwards protocol and
 * portal API traffic to the relay through one Workers VPC service binding.
 *
 * - `/`, `/authorize`, `/link/{id}`, `/requests/{id}`, `/accounts`, `/assets/*`: built assets
 *   (GET/HEAD only).
 * - `/oauth/*`, `/.well-known/*`: public OAuth surface; cross-site allowed with
 *   credential-free CORS, because dapps call it from their own origins.
 * - `/portal/*`: the portal's private API; same-origin only. Its session
 *   cookie (`Path=/portal`) is forwarded both ways.
 * - `/rpc/421614`: same-origin, budgeted, read-only chain reads (`rpc.ts`).
 * - Client registration, PAR, signer registration and sign-in challenges
 *   spend a per-IP `WRITE_LIMIT` budget before they reach the relay.
 *
 * Only an allow-list of request headers reaches the relay, so client-supplied
 * forwarding headers (`x-forwarded-*`, `forwarded`, `cf-*`) never do, and
 * request bodies are capped before they are forwarded. The OAuth surface never
 * carries a cookie in either direction.
 *
 * @author taek <leekt216@gmail.com>
 */

import { proxyRpc, type RateLimit, type RpcEnv } from "./rpc.js";

interface Fetcher {
  fetch(request: Request): Promise<Response>;
}

export interface Env extends RpcEnv {
  /** Workers static assets (`dist/`). */
  readonly ASSETS: Fetcher;
  /** Workers VPC service: the relay on the VM's loopback. */
  readonly RELAY: Fetcher;
  /** Workers rate-limiting binding: the per-IP budget for unauthenticated writes. */
  readonly WRITE_LIMIT?: RateLimit;
}

/**
 * Unauthenticated writes that create relay state. Each POST spends one unit of
 * the per-IP `WRITE_LIMIT` budget before it reaches the relay; an exhausted or
 * missing budget refuses it.
 */
const BUDGETED_WRITES = new Set([
  "/oauth/clients",
  "/oauth/par",
  "/portal/signers",
  "/portal/sessions/challenge",
]);

async function overBudget(request: Request, url: URL, env: Env, cors: boolean) {
  if (request.method !== "POST" || !BUDGETED_WRITES.has(url.pathname)) return null;
  if (!env.WRITE_LIMIT) return failure(503, "OAAth is temporarily unavailable", cors);
  const key = request.headers.get("cf-connecting-ip") ?? "unknown";
  if (!(await env.WRITE_LIMIT.limit({ key })).success)
    return failure(429, "Too many requests. Try again in a minute.", cors);
  return null;
}

export const ORIGIN = "https://oaath.taek.tech";
export const MAX_BODY_BYTES = 64 * 1024;

const PAGE_POLICY = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "connect-src 'self'",
  "img-src 'self' data:",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "upgrade-insecure-requests",
].join("; ");

const FORWARDED_HEADERS = [
  "accept",
  "authorization",
  "content-type",
  "dpop",
  "origin",
  "sec-fetch-site",
  "user-agent",
];

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "authorization, content-type, dpop",
  "Access-Control-Max-Age": "600",
} as const;

function failure(status: number, error: string, cors = false): Response {
  return Response.json(
    { error },
    { status, headers: { "Cache-Control": "no-store", ...(cors ? CORS_HEADERS : {}) } },
  );
}

function secured(response: Response, extra: Record<string, string>): Response {
  const headers = new Headers(response.headers);
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Strict-Transport-Security", "max-age=31536000");
  for (const [name, value] of Object.entries(extra)) headers.set(name, value);
  return new Response(response.body, { status: response.status, headers });
}

async function cappedBody(request: Request): Promise<Uint8Array<ArrayBuffer> | null | undefined> {
  if (!request.body) return undefined;
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (declared > MAX_BODY_BYTES) return null;
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const chunk = await reader.read();
    if (chunk.done) break;
    size += chunk.value.byteLength;
    if (size > MAX_BODY_BYTES) {
      await reader.cancel();
      return null;
    }
    chunks.push(chunk.value);
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

/** `cors` marks the public OAuth surface; anything else is the portal API. */
async function forward(request: Request, url: URL, env: Env, cors: boolean): Promise<Response> {
  const reading = request.method === "GET" || request.method === "HEAD";
  const body = reading ? undefined : await cappedBody(request);
  if (body === null) return failure(413, "Request too large", cors);
  const headers = new Headers();
  for (const name of cors ? FORWARDED_HEADERS : [...FORWARDED_HEADERS, "cookie"]) {
    const value = request.headers.get(name);
    if (value) headers.set(name, value);
  }
  let upstream: Response;
  try {
    // The binding pins the destination; this URL only sets the Host the relay sees.
    upstream = await env.RELAY.fetch(
      new Request(`http://oaath.taek.tech${url.pathname}${url.search}`, {
        method: request.method,
        headers,
        body: body ?? null,
        redirect: "manual",
        signal: AbortSignal.timeout(30_000),
      }),
    );
  } catch {
    return failure(503, "OAAth is temporarily unavailable", cors);
  }
  if (upstream.status >= 300 && upstream.status < 400)
    return failure(502, "Unexpected relay redirect", cors);
  const response = secured(upstream, {
    "Cache-Control": "no-store",
    ...(cors ? CORS_HEADERS : {}),
  });
  if (cors) response.headers.delete("set-cookie");
  return response;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.origin !== ORIGIN) return failure(421, "Unknown host");
    const reading = request.method === "GET" || request.method === "HEAD";

    if (url.pathname.startsWith("/oauth/") || url.pathname.startsWith("/.well-known/")) {
      if (request.method === "OPTIONS")
        return new Response(null, { status: 204, headers: CORS_HEADERS });
      if (!reading && request.method !== "POST") return failure(405, "Unsupported method", true);
      return (await overBudget(request, url, env, true)) ?? forward(request, url, env, true);
    }

    if (url.pathname.startsWith("/portal/")) {
      const site = request.headers.get("sec-fetch-site");
      if (site !== null && site !== "same-origin")
        return failure(403, "Cross-site request refused");
      if (!reading && request.headers.get("origin") !== ORIGIN)
        return failure(403, "Request origin does not match");
      if (!reading && !["POST", "PUT", "DELETE"].includes(request.method))
        return failure(405, "Unsupported method");
      return (await overBudget(request, url, env, false)) ?? forward(request, url, env, false);
    }

    if (url.pathname === "/rpc/421614") {
      const site = request.headers.get("sec-fetch-site");
      if ((site !== null && site !== "same-origin") || request.headers.get("origin") !== ORIGIN)
        return failure(403, "Cross-site request refused");
      return secured(await proxyRpc(request, env), {});
    }

    const page =
      url.pathname === "/" ||
      url.pathname === "/authorize" ||
      url.pathname === "/accounts" ||
      /^\/(?:link|requests)\/[A-Za-z0-9._~-]{1,256}$/u.test(url.pathname);
    const asset = /^\/assets\/[A-Za-z0-9][\w.-]*\.(?:js|css|woff2?|svg|png|ico)$/u.test(
      url.pathname,
    );
    if (!reading || (!page && !asset)) return failure(404, "Not found");
    // Every page is the one SPA document; the query string stays with the browser.
    const served = await env.ASSETS.fetch(
      new Request(page ? `${ORIGIN}/` : `${ORIGIN}${url.pathname}`, { method: request.method }),
    );
    return secured(
      served,
      page
        ? {
            "Content-Security-Policy": PAGE_POLICY,
            "X-Frame-Options": "DENY",
            "Cache-Control": "no-store",
          }
        : {
            "Cache-Control": served.ok ? "public, max-age=31536000, immutable" : "no-store",
          },
    );
  },
};
