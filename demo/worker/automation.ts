/**
 * The demo's backend for the automation service: it turns a verified OAAth
 * login into a one-hour automation session for exactly that signer and
 * account. The application credential (`AUTOMATION_APP_TOKEN`) never reaches
 * the page; the page talks to the service directly with the session token.
 *
 * The id_token is verified against the issuer's JWKS (ES256, issuer, this
 * client as audience, expiry) before anything is asked of the service. Each
 * request spends the per-IP `RPC_LIMIT` budget once and is forwarded once.
 *
 * @author taek <leekt216@gmail.com>
 */
import { createAutomationServer } from "@oaath/automation/server";
import { createRemoteJWKSet, jwtVerify } from "jose";
import type { RateLimit } from "./rpc.js";

export interface AutomationEnv {
  readonly OAATH_ISSUER: string;
  readonly OAATH_CLIENT_ID: string;
  /** The automation service's base URL. */
  readonly AUTOMATION_URL?: string;
  /** Secret: the demo's application credential at that service. Unset: the section is off. */
  readonly AUTOMATION_APP_TOKEN?: string;
  readonly RPC_LIMIT?: RateLimit;
}

/** The service URL the page may call, or null when automation is not configured. */
export function automationUrl(env: AutomationEnv): string | null {
  return env.AUTOMATION_URL && env.AUTOMATION_APP_TOKEN ? env.AUTOMATION_URL : null;
}

const keySets = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function reply(status: number, body: unknown): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

export async function automationSession(request: Request, env: AutomationEnv): Promise<Response> {
  const url = automationUrl(env);
  if (url === null) return reply(503, { error: "automation_unconfigured" });
  if (request.method !== "POST") return reply(405, { error: "method_not_allowed" });
  const ip = request.headers.get("cf-connecting-ip") ?? "local";
  if (!env.RPC_LIMIT || !(await env.RPC_LIMIT.limit({ key: `automation:${ip}` })).success)
    return reply(429, { error: "rate_limited" });
  let idToken: unknown;
  try {
    ({ idToken } = (await request.json()) as { idToken?: unknown });
  } catch {
    return reply(400, { error: "request_invalid" });
  }
  if (typeof idToken !== "string" || idToken.length > 8192)
    return reply(400, { error: "request_invalid" });
  let subject: string;
  let signer: string;
  try {
    let keys = keySets.get(env.OAATH_ISSUER);
    if (!keys) {
      keys = createRemoteJWKSet(new URL(`${env.OAATH_ISSUER}/oauth/jwks`));
      keySets.set(env.OAATH_ISSUER, keys);
    }
    const { payload } = await jwtVerify(idToken, keys, {
      issuer: env.OAATH_ISSUER,
      audience: env.OAATH_CLIENT_ID,
      algorithms: ["ES256"],
    });
    const claimed = payload.signer as { id?: unknown } | undefined;
    if (
      typeof payload.sub !== "string" ||
      !/^0x[0-9a-f]{40}$/u.test(payload.sub) ||
      typeof claimed?.id !== "string"
    )
      throw new Error("claims");
    subject = payload.sub;
    signer = claimed.id;
  } catch {
    return reply(401, { error: "login_invalid" });
  }
  try {
    const session = await createAutomationServer({
      baseUrl: url,
      token: env.AUTOMATION_APP_TOKEN as string,
      timeoutMs: 15_000,
    }).createSession({ userId: signer, account: subject as `0x${string}` });
    return reply(200, {
      token: session.token,
      expiresAt: session.expiresAt,
      account: session.account,
    });
  } catch (error) {
    const code = (error as { code?: unknown }).code;
    return reply(502, {
      error: code === "request_outcome_unknown" ? "automation_unavailable" : "automation_refused",
    });
  }
}
