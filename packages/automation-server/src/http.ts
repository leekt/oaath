/**
 * The HTTP API. JSON in and out, bounded bodies, structured error codes only,
 * CORS for the configured browser origins, and no caching.
 *
 * | Route | Caller |
 * | --- | --- |
 * | `GET /health` | anyone |
 * | `GET /v1/automations` | application or session |
 * | `POST /v1/sessions`, `POST /v1/application` | application credential |
 * | `POST /v1/plans`, `GET /v1/plans`, `GET /v1/plans/{id}`, `GET /v1/plans/{id}/runs` | session (list/get: application too) |
 * | `POST /v1/plans/{id}/{authorize,pause,resume,cancel}` | session |
 * | `GET /v1/oauth/callback` | the issuer's redirect |
 *
 * @author taek <leekt216@gmail.com>
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { AutomationError } from "@oaath/automation";
import { type ServiceContext, ServiceError } from "./context.js";
import { completeAuthorization, startAuthorization } from "./oauth.js";
import {
  cancelPlan,
  createPlan,
  listPlans,
  listRuns,
  ownPlan,
  pausePlan,
  projectPlan,
  resumePlan,
} from "./plans.js";
import {
  authenticate,
  configureApplication,
  createSession,
  requireApplication,
} from "./sessions.js";

const MAX_BODY = 32 * 1024;

async function readBody(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw new ServiceError("request_too_large", 413);
    chunks.push(chunk as Buffer);
  }
  if (size === 0) return {};
  let value: unknown;
  try {
    value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new ServiceError("request_invalid", 400);
  }
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new ServiceError("request_invalid", 400);
  return value as Record<string, unknown>;
}

function send(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

/** A same-origin-list return target, or null. */
function returnTarget(context: ServiceContext, value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") throw new ServiceError("return_to_invalid", 422);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ServiceError("return_to_invalid", 422);
  }
  if (!context.config.allowedOrigins.includes(url.origin) || url.username || url.password)
    throw new ServiceError("return_to_invalid", 422);
  return url.href;
}

async function callback(context: ServiceContext, url: URL, response: ServerResponse) {
  let outcome: Awaited<ReturnType<typeof completeAuthorization>>;
  try {
    outcome = await completeAuthorization(context, url.searchParams);
  } catch (error) {
    const code = error instanceof ServiceError ? error.code : "authorization_unavailable";
    outcome = { planId: null, status: "invalid", returnTo: null };
    response.writeHead(409, { "content-type": "text/plain; charset=utf-8" });
    response.end(`Authorization could not be completed (${code}). Return to the application.`);
    return;
  }
  if (outcome.returnTo !== null) {
    const target = new URL(outcome.returnTo);
    if (outcome.planId !== null) target.searchParams.set("automation_plan", outcome.planId);
    target.searchParams.set("automation_status", outcome.status);
    response.writeHead(303, { location: target.href });
    response.end();
    return;
  }
  response.writeHead(outcome.status === "invalid" ? 400 : 200, {
    "content-type": "text/plain; charset=utf-8",
  });
  response.end(`Authorization ${outcome.status}. You can close this window.`);
}

async function route(
  context: ServiceContext,
  request: IncomingMessage,
  response: ServerResponse,
): Promise<void> {
  const url = new URL(request.url ?? "/", "http://service");
  const method = request.method ?? "GET";
  const path = url.pathname;
  if (method === "GET" && path === "/health")
    return send(response, 200, { status: "ok", version: "oaath.automation-api/v1" });
  if (method === "GET" && path === "/v1/oauth/callback") return callback(context, url, response);

  if (method === "POST" && path === "/v1/sessions") {
    const appId = requireApplication(context, request.headers);
    return send(response, 200, await createSession(context, appId, await readBody(request)));
  }
  if (method === "POST" && path === "/v1/application") {
    const appId = requireApplication(context, request.headers);
    return send(response, 200, await configureApplication(context, appId, await readBody(request)));
  }

  const principal = await authenticate(context, request.headers);
  if (method === "GET" && path === "/v1/automations")
    return send(response, 200, { automations: [...context.definitions.values()] });
  if (path === "/v1/plans") {
    if (method === "GET") return send(response, 200, await listPlans(context, principal));
    if (method === "POST") {
      const { created, plan } = await createPlan(context, principal, await readBody(request));
      return send(response, created ? 201 : 200, await projectPlan(context, plan));
    }
  }
  const match = /^\/v1\/plans\/(0x[0-9a-f]{64})(?:\/(runs|authorize|pause|resume|cancel))?$/u.exec(
    path,
  );
  if (match) {
    const plan = await ownPlan(context, principal, match[1] as string);
    const action = match[2];
    if (method === "GET" && action === undefined)
      return send(response, 200, await projectPlan(context, plan));
    if (method === "GET" && action === "runs")
      return send(response, 200, await listRuns(context, plan, url.searchParams));
    if (method === "POST" && action !== undefined && action !== "runs") {
      if (principal.user === null) throw new ServiceError("user_session_required", 403);
      const body = await readBody(request);
      if (action === "authorize") {
        const consenting = plan.status === "draft" || plan.status === "awaiting_consent";
        const authorizationUrl = consenting
          ? await startAuthorization(context, plan, returnTarget(context, body.returnTo))
          : null;
        const current = await ownPlan(context, principal, plan.id);
        return send(response, 200, { plan: await projectPlan(context, current), authorizationUrl });
      }
      if (action === "pause") await pausePlan(context, plan);
      if (action === "resume") await resumePlan(context, plan);
      if (action === "cancel") await cancelPlan(context, plan);
      return send(
        response,
        200,
        await projectPlan(context, await ownPlan(context, principal, plan.id)),
      );
    }
  }
  throw new ServiceError("route_not_found", 404);
}

export function createHttpServer(context: ServiceContext): Server {
  return createServer(async (request, response) => {
    const origin = request.headers.origin;
    response.setHeader("cache-control", "no-store");
    response.setHeader("x-content-type-options", "nosniff");
    if (origin !== undefined) {
      if (!context.config.allowedOrigins.includes(origin)) {
        send(response, 403, { error: { code: "origin_denied" } });
        return;
      }
      response.setHeader("access-control-allow-origin", origin);
      response.setHeader("vary", "origin");
      response.setHeader("access-control-allow-methods", "GET, POST, OPTIONS");
      response.setHeader("access-control-allow-headers", "authorization, content-type");
      if (request.method === "OPTIONS") {
        response.writeHead(204);
        response.end();
        return;
      }
    }
    try {
      await route(context, request, response);
    } catch (error) {
      if (response.headersSent) return response.end();
      if (error instanceof ServiceError)
        return send(response, error.status, { error: { code: error.code } });
      if (error instanceof AutomationError)
        return send(response, 422, { error: { code: error.code } });
      send(response, 503, { error: { code: "service_unavailable" } });
    }
  });
}
