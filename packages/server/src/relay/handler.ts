/**
 * Fetch-standard relay handler.
 *
 * Every wire input is exact-captured once here and handed to a use case as typed
 * data. Every failure leaves as a structured code projected to a status; no
 * message text, driver output, or internal detail reaches a response body.
 *
 * Endpoints:
 *
 * ```text
 * POST /authorization/requests                       client  create request
 * GET  /authorization/requests/{requestId}           owner   fetch request
 * POST /authorization/requests/{requestId}/decision  owner   approve or reject
 * POST /authorization/codes/consume                  client  one-time code consume
 * POST /authorization/artifacts/{artifactId}/claim   client  one-time artifact claim
 * POST /authorization/resume                         client  fresh auth + recovery read
 * ```
 *
 * @author taek <leekt216@gmail.com>
 */

import { type CaptureContext, captureRecord, exactCapturedRecord } from "@oaath/protocol";
import { claimEncryptedArtifact } from "../artifact/claim.js";
import { consumeAuthorizationCode } from "../authorization/code.js";
import type { AuthorizationDecisionCommand } from "../authorization/decision.js";
import { submitAuthorizationDecision } from "../authorization/decision.js";
import {
  type AuthorizationState,
  createAuthorizationRequest,
  fetchAuthorizationRequest,
} from "../authorization/request.js";
import { resumeAuthorization } from "../authorization/resume.js";
import type { RelayClock } from "../clock.js";
import {
  authenticateCaller,
  type RelayAuthentication,
  type RelayCaller,
  type RelayCallerRole,
} from "../security/authentication.js";
import type { RelayKms } from "../security/kms.js";
import { assertWithinRateLimit, type RelayRateLimiter } from "../security/rate-limit.js";
import type { RelayStore } from "../store/interface.js";
import { boundedText, canonicalIdentifier, RELAY_LIMITS, timestamp } from "../store/records.js";
import { jsonResponse, relayErrorCode, relayErrorResponse, relayFailure } from "./errors.js";

const DEFAULT_REQUEST_TTL_MS = 300_000;
const DEFAULT_CODE_TTL_MS = 60_000;
const DEFAULT_MAX_BODY_BYTES = 65_536;
const MAX_TTL_MS = 86_400_000;
/** RFC 6749 ceiling, matching `MAX_AUTHORIZATION_CODE_LIFETIME` in @oaath/protocol. */
const MAX_CODE_TTL_MS = 600_000;

const INVALID = "relay_request_invalid" as const;

export interface RelayHandlerOptions {
  readonly store: RelayStore;
  readonly authentication: RelayAuthentication;
  readonly kms: RelayKms;
  readonly clock: RelayClock;
  /** Optional. There is no default limiter. */
  readonly rateLimit?: RelayRateLimiter;
  readonly requestTtlMs?: number;
  readonly codeTtlMs?: number;
  readonly maxBodyBytes?: number;
}

export type RelayHandler = (request: Request) => Promise<Response>;

const OPTION_KEYS: readonly string[] = [
  "store",
  "authentication",
  "kms",
  "clock",
  "rateLimit",
  "requestTtlMs",
  "codeTtlMs",
  "maxBodyBytes",
];

/**
 * Ports may be class instances, so only their required capabilities are checked.
 * Narrowing follows the runtime check.
 */
function requirePort<Port>(value: unknown, methods: readonly string[], label: string): Port {
  if (!value || typeof value !== "object") {
    return relayFailure("relay_internal", `${label} must be an object`);
  }
  for (const method of methods) {
    if (typeof (value as Record<string, unknown>)[method] !== "function") {
      return relayFailure("relay_internal", `${label} must implement ${method}()`);
    }
  }
  return value as Port;
}

function duration(value: unknown, fallback: number, label: string, maximum = MAX_TTL_MS): number {
  if (value === undefined) return fallback;
  const milliseconds = timestamp(value, label, "relay_internal");
  if (milliseconds < 1 || milliseconds > maximum) {
    return relayFailure("relay_internal", `${label} must be a bounded positive duration`);
  }
  return milliseconds;
}

interface CapturedOptions {
  readonly store: RelayStore;
  readonly authentication: RelayAuthentication;
  readonly kms: RelayKms;
  readonly clock: RelayClock;
  readonly rateLimit: RelayRateLimiter | undefined;
  readonly requestTtlMs: number;
  readonly codeTtlMs: number;
  readonly maxBodyBytes: number;
}

function captureOptions(value: unknown): CapturedOptions {
  const context: CaptureContext = new WeakSet();
  const record = captureRecord(value, "relay handler options", context, (message) =>
    relayFailure("relay_internal", message),
  );
  for (const key of Object.keys(record)) {
    if (!OPTION_KEYS.includes(key)) {
      relayFailure("relay_internal", "relay handler options contain an unknown field");
    }
  }
  return Object.freeze({
    store: requirePort<RelayStore>(record.store, ["begin", "close"], "store"),
    authentication: requirePort<RelayAuthentication>(
      record.authentication,
      ["authenticate"],
      "authentication",
    ),
    kms: requirePort<RelayKms>(record.kms, ["encrypt", "decrypt"], "kms"),
    clock: requirePort<RelayClock>(record.clock, ["now"], "clock"),
    rateLimit:
      record.rateLimit === undefined
        ? undefined
        : requirePort<RelayRateLimiter>(record.rateLimit, ["check"], "rateLimit"),
    requestTtlMs: duration(record.requestTtlMs, DEFAULT_REQUEST_TTL_MS, "requestTtlMs"),
    codeTtlMs: duration(record.codeTtlMs, DEFAULT_CODE_TTL_MS, "codeTtlMs", MAX_CODE_TTL_MS),
    maxBodyBytes: duration(record.maxBodyBytes, DEFAULT_MAX_BODY_BYTES, "maxBodyBytes"),
  });
}

function requireMethod(request: Request, expected: "GET" | "POST"): void {
  if (request.method !== expected) {
    relayFailure("relay_method_not_allowed", "route does not accept this method");
  }
}

async function bodyRecord(
  request: Request,
  maxBodyBytes: number,
): Promise<Record<string, unknown>> {
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    relayFailure(INVALID, "request body must be application/json");
  }
  let text: string;
  try {
    text = await request.text();
  } catch {
    return relayFailure(INVALID, "request body is unreadable");
  }
  if (new TextEncoder().encode(text).byteLength > maxBodyBytes) {
    return relayFailure(INVALID, "request body exceeds its bound");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    return relayFailure(INVALID, "request body is not JSON");
  }
  const context: CaptureContext = new WeakSet();
  return captureRecord(parsed, "request body", context, (message) =>
    relayFailure(INVALID, message),
  );
}

function exactBody(
  record: Record<string, unknown>,
  keys: readonly string[],
): Record<string, unknown> {
  return exactCapturedRecord(record, keys, "request body", (message) =>
    relayFailure(INVALID, message),
  );
}

function decisionCommand(record: Record<string, unknown>): AuthorizationDecisionCommand {
  if (record.outcome === "approved") {
    const exact = exactBody(record, ["outcome", "artifact"]);
    return Object.freeze({
      outcome: "approved",
      artifact: boundedText(exact.artifact, RELAY_LIMITS.artifactPlaintext, "artifact", INVALID),
    });
  }
  if (record.outcome === "rejected") {
    exactBody(record, ["outcome"]);
    return Object.freeze({ outcome: "rejected" });
  }
  return relayFailure(INVALID, "decision outcome is unsupported");
}

function stateBody(state: AuthorizationState): unknown {
  return {
    requestId: state.requestId,
    clientId: state.clientId,
    redirectUri: state.redirectUri,
    requestedScope: state.requestedScope,
    expiresAt: state.expiresAt,
    expired: state.expired,
    decision: state.decision,
  };
}

export function createRelayHandler(options: RelayHandlerOptions): RelayHandler {
  const captured = captureOptions(options);

  const authenticate = async (
    request: Request,
    role: RelayCallerRole,
    route: string,
  ): Promise<RelayCaller> => {
    const caller = await authenticateCaller(captured.authentication, request, role);
    // Limiting happens after authentication so a deployment can key on clientId.
    // The authentication port owns unauthenticated abuse.
    await assertWithinRateLimit(captured.rateLimit, { route, clientId: caller.clientId });
    return caller;
  };

  const route = async (request: Request): Promise<Response> => {
    const segments = new URL(request.url).pathname.split("/").filter((part) => part.length > 0);
    if (segments[0] !== "authorization") {
      relayFailure("relay_not_found", "route does not exist");
    }
    const [, group, third, fourth] = segments;

    if (segments.length === 2 && group === "requests") {
      requireMethod(request, "POST");
      const caller = await authenticate(request, "client", "authorization.create");
      const body = exactBody(await bodyRecord(request, captured.maxBodyBytes), [
        "redirectUri",
        "codeChallenge",
        "requestedScope",
      ]);
      const created = await createAuthorizationRequest({
        store: captured.store,
        clock: captured.clock,
        caller,
        redirectUri: boundedText(
          body.redirectUri,
          RELAY_LIMITS.redirectUri,
          "redirectUri",
          INVALID,
        ),
        codeChallenge: boundedText(
          body.codeChallenge,
          RELAY_LIMITS.codeChallenge,
          "codeChallenge",
          INVALID,
        ),
        requestedScope: boundedText(
          body.requestedScope,
          RELAY_LIMITS.requestedScope,
          "requestedScope",
          INVALID,
        ),
        requestTtlMs: captured.requestTtlMs,
      });
      return jsonResponse(201, created);
    }

    if (segments.length === 3 && group === "requests") {
      requireMethod(request, "GET");
      const caller = await authenticate(request, "owner", "authorization.fetch");
      const state = await fetchAuthorizationRequest({
        store: captured.store,
        clock: captured.clock,
        caller,
        requestId: canonicalIdentifier(third, "requestId", INVALID),
      });
      return jsonResponse(200, stateBody(state));
    }

    if (segments.length === 4 && group === "requests" && fourth === "decision") {
      requireMethod(request, "POST");
      const caller = await authenticate(request, "owner", "authorization.decide");
      const command = decisionCommand(await bodyRecord(request, captured.maxBodyBytes));
      const decided = await submitAuthorizationDecision({
        store: captured.store,
        clock: captured.clock,
        kms: captured.kms,
        caller,
        requestId: canonicalIdentifier(third, "requestId", INVALID),
        command,
        codeTtlMs: captured.codeTtlMs,
      });
      return jsonResponse(200, decided);
    }

    if (segments.length === 3 && group === "codes" && third === "consume") {
      requireMethod(request, "POST");
      const caller = await authenticate(request, "client", "authorization.consume");
      const body = exactBody(await bodyRecord(request, captured.maxBodyBytes), [
        "code",
        "codeVerifier",
        "redirectUri",
      ]);
      const consumed = await consumeAuthorizationCode({
        store: captured.store,
        clock: captured.clock,
        caller,
        code: canonicalIdentifier(body.code, "code", INVALID),
        codeVerifier: boundedText(
          body.codeVerifier,
          RELAY_LIMITS.codeVerifier,
          "codeVerifier",
          INVALID,
        ),
        redirectUri: boundedText(
          body.redirectUri,
          RELAY_LIMITS.redirectUri,
          "redirectUri",
          INVALID,
        ),
      });
      return jsonResponse(200, consumed);
    }

    if (segments.length === 4 && group === "artifacts" && fourth === "claim") {
      requireMethod(request, "POST");
      const caller = await authenticate(request, "client", "authorization.claim");
      const claimed = await claimEncryptedArtifact({
        store: captured.store,
        clock: captured.clock,
        kms: captured.kms,
        caller,
        artifactId: canonicalIdentifier(third, "artifactId", INVALID),
      });
      return jsonResponse(200, claimed);
    }

    if (segments.length === 2 && group === "resume") {
      requireMethod(request, "POST");
      const caller = await authenticate(request, "client", "authorization.resume");
      const body = exactBody(await bodyRecord(request, captured.maxBodyBytes), ["requestId"]);
      const state = await resumeAuthorization({
        store: captured.store,
        clock: captured.clock,
        caller,
        requestId: canonicalIdentifier(body.requestId, "requestId", INVALID),
      });
      return jsonResponse(200, stateBody(state));
    }

    return relayFailure("relay_not_found", "route does not exist");
  };

  return async (request: Request): Promise<Response> => {
    try {
      return await route(request);
    } catch (error) {
      return relayErrorResponse(relayErrorCode(error));
    }
  };
}
