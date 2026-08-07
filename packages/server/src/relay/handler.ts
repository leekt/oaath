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
 * GET  /authorization/requests/{requestId}/code      client  released-code pickup
 * POST /authorization/codes/consume                  client  one-time code consume
 * POST /authorization/artifacts/{artifactId}/claim   client  one-time artifact claim
 * POST /authorization/resume                         client  fresh auth + recovery read
 * GET  /bootstrap                                    client  URL-only service context
 * POST /invalidations                                client  capability invalidation
 * POST /chains/{chainId}/{port}                      client  chain execution relay,
 *                                                            port in reads |
 *                                                            observation | bundler |
 *                                                            quote | submissions | usage
 * POST /chains/{chainId}/paymaster/{method}           client  registered paymaster proxy,
 *                                                            method in stub-data | data
 * ```
 *
 * EXPERIMENTAL PREVIEW routes for the owner-phone approval surface. Preview
 * means: no stability guarantee and no production qualification. Their wire
 * shapes are pinned field-for-field by the strict Swift decoders in
 * `native/ios/Sources/OwnerPhone/{Projection,Decision}.swift`.
 *
 * ```text
 * GET  /native/projections/{operationId}             owner   consent projection
 * POST /native/decisions/{operationId}               owner   approve or reject saga
 * ```
 *
 * @author taek <leekt216@gmail.com>
 */

import {
  type CaptureContext,
  captureDenseArray,
  captureRecord,
  exactCapturedRecord,
  OAATH_SERVICE_BOOTSTRAP_VERSION,
  parseServiceBootstrap,
  type ServiceBootstrap,
} from "@oaath/protocol";
import { claimEncryptedArtifact } from "../artifact/claim.js";
import { consumeAuthorizationCode } from "../authorization/code.js";
import type { AuthorizationDecisionCommand } from "../authorization/decision.js";
import { submitAuthorizationDecision } from "../authorization/decision.js";
import { fetchAuthorizationCode } from "../authorization/pickup.js";
import {
  type AuthorizationState,
  createAuthorizationRequest,
  fetchAuthorizationRequest,
} from "../authorization/request.js";
import { resumeAuthorization } from "../authorization/resume.js";
import { type RelayClock, relayNow } from "../clock.js";
import { submitOwnerPhoneDecision } from "../native/decision.js";
import { projectOwnerPhoneRequest } from "../native/projection.js";
import {
  authenticateCaller,
  type RelayAuthentication,
  type RelayCaller,
  type RelayCallerRole,
} from "../security/authentication.js";
import type { RelayKms } from "../security/kms.js";
import { assertWithinRateLimit, type RelayRateLimiter } from "../security/rate-limit.js";
import type { RelaySessionSignerProvider } from "../session-signer/kms-provider.js";
import { type RelayStore, withRelayTransaction } from "../store/interface.js";
import {
  boundedText,
  canonicalIdentifier,
  OAATH_CAPABILITY_INVALIDATION_RECORD_VERSION,
  RELAY_LIMITS,
  timestamp,
} from "../store/records.js";
import { jsonResponse, relayErrorCode, relayErrorResponse, relayFailure } from "./errors.js";

const DEFAULT_REQUEST_TTL_MS = 300_000;
const DEFAULT_CODE_TTL_MS = 60_000;
const DEFAULT_MAX_BODY_BYTES = 65_536;
const MAX_TTL_MS = 86_400_000;
/** RFC 6749 ceiling, matching `MAX_AUTHORIZATION_CODE_LIFETIME` in @oaath/protocol. */
const MAX_CODE_TTL_MS = 600_000;
const MAX_PAYMASTER_REQUEST_TIMEOUT_MS = 30_000;
const HASH = /^0x[0-9a-f]{64}$/u;

const INVALID = "relay_request_invalid" as const;

/**
 * One deployment-injected chain execution surface the relay serves to clients.
 * Each port takes exactly one captured request value and answers with the
 * evidence it owns; the relay never interprets the payload beyond exact wire
 * hygiene, so port meaning stays with its SDK owner.
 */
export interface RelayChainPort {
  readonly chainId: number;
  readonly reads: (request: unknown) => Promise<unknown>;
  readonly observation: (request: unknown) => Promise<unknown>;
  readonly bundler: (request: unknown) => Promise<unknown>;
  readonly quote: (request: unknown) => Promise<unknown>;
  /** Opens, sends, and settles one submission in one call; never retried here. */
  readonly submission: (request: unknown) => Promise<unknown>;
  /** Finalized per-grant usage evidence, or null when this chain serves none. */
  readonly usage: ((request: unknown) => Promise<unknown>) | null;
  readonly feePayer: Readonly<{ address: `0x${string}`; balance: string }> | null;
  /** Authenticated commitment to one exact ERC-7902 static paymaster, or null. */
  readonly staticPaymasterConfigurationHash: `0x${string}` | null;
}

/** The identity facts `GET /bootstrap` serves; chains derive from `chains`. */
export interface RelayBootstrapConfiguration {
  readonly application: unknown;
  readonly userHandle: string;
  readonly account: unknown;
  readonly ownerValidator: `0x${string}` | null;
}

/**
 * Remote session-key custody, declared once for the deployment: the mode and
 * provider identity are served through the bootstrap document, and the same
 * provider answers the `/session-signers` routes. For `oaath_hosted` the
 * provider is typically `createKmsSessionSignerProvider`; for
 * `application_backend` it is the deployment's own authenticated port to the
 * integrating application's signer — never a client-supplied endpoint.
 */
export interface RelaySessionSignerConfiguration {
  readonly mode: "application_backend" | "oaath_hosted";
  readonly providerId: string;
  readonly provider: Readonly<RelaySessionSignerProvider>;
}

/** Authenticated identity and one opaque ERC-7677 params tuple. */
export interface RelayPaymasterServiceRequest {
  readonly caller: Readonly<{ clientId: string; subject: string }>;
  readonly params: unknown;
  readonly signal: AbortSignal;
}

/**
 * One deployment-owned paymaster provider. The relay exposes only these two
 * closed ERC-7677 operations and invokes the selected method once.
 */
export interface RelayPaymasterServiceProvider {
  readonly getPaymasterStubData: (
    request: Readonly<RelayPaymasterServiceRequest>,
  ) => Promise<unknown>;
  readonly getPaymasterData: (request: Readonly<RelayPaymasterServiceRequest>) => Promise<unknown>;
}

export interface RelayPaymasterServiceConfiguration {
  readonly chainId: number;
  readonly providerId: string;
  /** Hard response deadline; the provider also receives its abort signal. */
  readonly requestTimeoutMs: number;
  readonly provider: Readonly<RelayPaymasterServiceProvider>;
}

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
  /** Optional URL-only bootstrap surface; requires `chains` as well. */
  readonly bootstrap?: Readonly<RelayBootstrapConfiguration>;
  /** Optional chain execution relays; required when `bootstrap` is served. */
  readonly chains?: readonly Readonly<RelayChainPort>[];
  /** Optional remote session-key custody; requires `bootstrap` as well. */
  readonly sessionSigner?: Readonly<RelaySessionSignerConfiguration>;
  /**
   * Optional deployment-owned paymaster services, at most one per chain.
   * Configuration requires both bootstrap and a deployment rate limiter.
   */
  readonly paymasterServices?: readonly Readonly<RelayPaymasterServiceConfiguration>[];
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
  "bootstrap",
  "chains",
  "sessionSigner",
  "paymasterServices",
];

const CHAIN_PORT_NAMES = ["reads", "observation", "bundler", "quote", "submission"] as const;
type ChainPortName = (typeof CHAIN_PORT_NAMES)[number] | "usage";

/**
 * The Grant a chain port request acts for, where the port's contract names
 * one: a submission's prepared operation and a usage read both carry it.
 * Reading it here is bounded extraction for the invalidation gate, not
 * interpretation — the port's own owner still captures the payload exactly.
 */
function chainRequestGrantId(name: ChainPortName, request: unknown): string | null {
  try {
    if (name === "usage") {
      const grantId = (request as { readonly grantId?: unknown } | null)?.grantId;
      return typeof grantId === "string" && grantId.length > 0 ? grantId : null;
    }
    if (name === "submission") {
      const prepared = (request as { readonly prepared?: unknown } | null)?.prepared;
      const grantId = (prepared as { readonly grantId?: unknown } | null)?.grantId;
      return typeof grantId === "string" && grantId.length > 0 ? grantId : null;
    }
  } catch {
    // A hostile getter reads as absent; the port's exact capture still owns
    // whether such a payload is usable at all.
  }
  return null;
}

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
  /** The exact parsed document `GET /bootstrap` serves, or null when unserved. */
  readonly bootstrap: Readonly<ServiceBootstrap> | null;
  readonly sessionSigner: Readonly<RelaySessionSignerConfiguration> | null;
  readonly chains: ReadonlyMap<number, Readonly<RelayChainPort>>;
  readonly paymasterServices: ReadonlyMap<number, Readonly<RelayPaymasterServiceConfiguration>>;
}

function captureChainPorts(value: unknown): ReadonlyMap<number, Readonly<RelayChainPort>> {
  if (!Array.isArray(value)) {
    return relayFailure("relay_internal", "chains must be an array of chain ports");
  }
  const chains = new Map<number, Readonly<RelayChainPort>>();
  for (const entry of value) {
    const port = requirePort<RelayChainPort>(entry, [...CHAIN_PORT_NAMES], "chain port");
    if (
      typeof port.chainId !== "number" ||
      !Number.isSafeInteger(port.chainId) ||
      port.chainId < 1
    ) {
      return relayFailure("relay_internal", "chain port chainId must be a positive integer");
    }
    if (port.usage !== null && typeof port.usage !== "function") {
      return relayFailure("relay_internal", "chain port usage must be a function or null");
    }
    if (
      port.staticPaymasterConfigurationHash !== null &&
      (typeof port.staticPaymasterConfigurationHash !== "string" ||
        !HASH.test(port.staticPaymasterConfigurationHash))
    ) {
      return relayFailure(
        "relay_internal",
        "chain port static paymaster commitment must be a lowercase hash or null",
      );
    }
    if (chains.has(port.chainId)) {
      return relayFailure("relay_internal", "chain ports repeat a chainId");
    }
    chains.set(port.chainId, port);
  }
  return chains;
}

function capturePaymasterServices(
  value: unknown,
  context: CaptureContext,
  chains: ReadonlyMap<number, Readonly<RelayChainPort>>,
): ReadonlyMap<number, Readonly<RelayPaymasterServiceConfiguration>> {
  if (value === undefined) return new Map();
  const entries = captureDenseArray(value, "paymaster services", context, (message) =>
    relayFailure("relay_internal", message),
  );
  const services = new Map<number, Readonly<RelayPaymasterServiceConfiguration>>();
  for (const entry of entries) {
    const service = exactCapturedRecord(
      captureRecord(entry, "paymaster service", context, (message) =>
        relayFailure("relay_internal", message),
      ),
      ["chainId", "providerId", "requestTimeoutMs", "provider"],
      "paymaster service",
      (message) => relayFailure("relay_internal", message),
    );
    const chainId = service.chainId;
    if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId < 1) {
      relayFailure("relay_internal", "paymaster service chainId must be a positive integer");
    }
    if (!chains.has(chainId)) {
      relayFailure("relay_internal", "paymaster service chain is not configured");
    }
    if (services.has(chainId)) {
      relayFailure("relay_internal", "paymaster services repeat a chainId");
    }
    if (service.requestTimeoutMs === undefined) {
      relayFailure("relay_internal", "paymaster requestTimeoutMs is required");
    }
    services.set(
      chainId,
      Object.freeze({
        chainId,
        providerId: canonicalIdentifier(
          service.providerId,
          "paymaster providerId",
          "relay_internal",
        ),
        requestTimeoutMs: duration(
          service.requestTimeoutMs,
          0,
          "paymaster requestTimeoutMs",
          MAX_PAYMASTER_REQUEST_TIMEOUT_MS,
        ),
        provider: requirePort<RelayPaymasterServiceProvider>(
          service.provider,
          ["getPaymasterStubData", "getPaymasterData"],
          "paymaster provider",
        ),
      }),
    );
  }
  return services;
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
  const chains =
    record.chains === undefined
      ? new Map<number, Readonly<RelayChainPort>>()
      : captureChainPorts(record.chains);
  const rateLimit =
    record.rateLimit === undefined
      ? undefined
      : requirePort<RelayRateLimiter>(record.rateLimit, ["check"], "rateLimit");
  const paymasterServices = capturePaymasterServices(record.paymasterServices, context, chains);
  if (paymasterServices.size > 0) {
    if (record.bootstrap === undefined) {
      relayFailure("relay_internal", "a paymaster service requires a bootstrap surface");
    }
    if (rateLimit === undefined) {
      relayFailure("relay_internal", "a paymaster service requires a rate limiter");
    }
  }
  let sessionSigner: Readonly<RelaySessionSignerConfiguration> | null = null;
  if (record.sessionSigner !== undefined) {
    if (record.bootstrap === undefined) {
      relayFailure("relay_internal", "a session signer requires a bootstrap surface");
    }
    const custody = captureRecord(
      record.sessionSigner,
      "relay session signer configuration",
      context,
      (message) => relayFailure("relay_internal", message),
    );
    if (custody.mode !== "application_backend" && custody.mode !== "oaath_hosted") {
      relayFailure("relay_internal", "session signer mode is unsupported");
    }
    if (typeof custody.providerId !== "string" || custody.providerId.length < 1) {
      relayFailure("relay_internal", "session signer providerId is invalid");
    }
    sessionSigner = Object.freeze({
      mode: custody.mode as "application_backend" | "oaath_hosted",
      providerId: custody.providerId,
      provider: requirePort<RelaySessionSignerProvider>(
        custody.provider,
        ["credential", "sign"],
        "session signer provider",
      ),
    });
  }
  let bootstrap: Readonly<ServiceBootstrap> | null = null;
  if (record.bootstrap !== undefined) {
    if (chains.size === 0) {
      relayFailure("relay_internal", "a bootstrap surface requires chain ports");
    }
    const identity = captureRecord(
      record.bootstrap,
      "relay bootstrap configuration",
      context,
      (message) => relayFailure("relay_internal", message),
    );
    // The exact protocol parser owns document meaning; a misconfigured
    // deployment fails at construction, never at a client's request.
    try {
      bootstrap = parseServiceBootstrap({
        version: OAATH_SERVICE_BOOTSTRAP_VERSION,
        application: identity.application,
        userHandle: identity.userHandle,
        account: identity.account,
        ownerValidator: identity.ownerValidator,
        chains: [...chains.values()].map((port) => {
          const paymasterService = paymasterServices.get(port.chainId);
          return {
            chainId: port.chainId,
            usage: port.usage !== null,
            feePayer: port.feePayer,
            paymasterService:
              paymasterService === undefined ? null : { providerId: paymasterService.providerId },
            staticPaymasterConfigurationHash: port.staticPaymasterConfigurationHash,
          };
        }),
        // The one custody declaration serves both the document and the
        // signing routes; they can never disagree.
        sessionSigner:
          sessionSigner === null
            ? { mode: "frontend", providerId: null }
            : { mode: sessionSigner.mode, providerId: sessionSigner.providerId },
      });
    } catch {
      relayFailure("relay_internal", "relay bootstrap configuration is invalid");
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
    rateLimit,
    requestTtlMs: duration(record.requestTtlMs, DEFAULT_REQUEST_TTL_MS, "requestTtlMs"),
    codeTtlMs: duration(record.codeTtlMs, DEFAULT_CODE_TTL_MS, "codeTtlMs", MAX_CODE_TTL_MS),
    maxBodyBytes: duration(record.maxBodyBytes, DEFAULT_MAX_BODY_BYTES, "maxBodyBytes"),
    bootstrap,
    sessionSigner,
    chains,
    paymasterServices,
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

async function invokePaymasterService(
  service: Readonly<RelayPaymasterServiceConfiguration>,
  method: "stub-data" | "data",
  caller: Readonly<RelayCaller>,
  params: unknown,
): Promise<unknown> {
  const controller = new AbortController();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    const deadline = new Promise<never>((_resolve, reject) => {
      timeout = setTimeout(() => {
        controller.abort();
        reject(new Error("paymaster request deadline elapsed"));
      }, service.requestTimeoutMs);
    });
    const capability =
      method === "stub-data"
        ? service.provider.getPaymasterStubData
        : service.provider.getPaymasterData;
    const request: Readonly<RelayPaymasterServiceRequest> = Object.freeze({
      caller: Object.freeze({ clientId: caller.clientId, subject: caller.subject }),
      params,
      signal: controller.signal,
    });
    return await Promise.race([
      Promise.resolve(Reflect.apply(capability, undefined, [request])),
      deadline,
    ]);
  } catch {
    return relayFailure("relay_chain_unavailable", "paymaster provider did not answer");
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
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

/**
 * EXPERIMENTAL PREVIEW — the phone decision body: `{command, artifact?}`.
 * `approve` hands over the artifact the client will claim once; `reject`
 * carries nothing else. The saga answers the stored outcome on a replay.
 */
function phoneDecisionCommand(record: Record<string, unknown>): AuthorizationDecisionCommand {
  if (record.command === "approve") {
    const exact = exactBody(record, ["command", "artifact"]);
    return Object.freeze({
      outcome: "approved",
      artifact: boundedText(exact.artifact, RELAY_LIMITS.artifactPlaintext, "artifact", INVALID),
    });
  }
  if (record.command === "reject") {
    exactBody(record, ["command"]);
    return Object.freeze({ outcome: "rejected" });
  }
  return relayFailure(INVALID, "decision command is unsupported");
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
    role: RelayCallerRole | readonly RelayCallerRole[],
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
    const [head, group, third, fourth] = segments;

    // EXPERIMENTAL PREVIEW — owner-phone approval routes. Same wire hygiene as
    // every relay route: exact capture, structured codes, no-store responses.
    if (head === "native") {
      if (segments.length === 3 && group === "projections") {
        requireMethod(request, "GET");
        const caller = await authenticate(request, "owner", "native.project");
        const projection = await projectOwnerPhoneRequest({
          store: captured.store,
          clock: captured.clock,
          caller,
          requestId: canonicalIdentifier(third, "operationId", INVALID),
        });
        return jsonResponse(200, projection);
      }
      if (segments.length === 3 && group === "decisions") {
        requireMethod(request, "POST");
        const caller = await authenticate(request, "owner", "native.decide");
        const command = phoneDecisionCommand(await bodyRecord(request, captured.maxBodyBytes));
        const decided = await submitOwnerPhoneDecision({
          store: captured.store,
          clock: captured.clock,
          kms: captured.kms,
          caller,
          operationId: canonicalIdentifier(third, "operationId", INVALID),
          command,
          codeTtlMs: captured.codeTtlMs,
        });
        return jsonResponse(200, decided);
      }
      return relayFailure("relay_not_found", "route does not exist");
    }

    if (head === "bootstrap" && segments.length === 1) {
      requireMethod(request, "GET");
      await authenticate(request, "client", "bootstrap.fetch");
      if (captured.bootstrap === null) {
        return relayFailure("relay_not_found", "route does not exist");
      }
      return jsonResponse(200, captured.bootstrap);
    }

    if (head === "session-signers") {
      // Remote session-key custody routes, served exactly when the deployment
      // declared it. The caller's authenticated identity — never anything the
      // body claims — names the key: one (clientId, subject, deviceId)
      // identity holds one credential, so a different credential can never
      // sign under an approval that bound this one (the rotation invariant).
      const custody = captured.sessionSigner;
      if (custody === null) return relayFailure("relay_not_found", "route does not exist");
      if (segments.length === 1) {
        requireMethod(request, "POST");
        const caller = await authenticate(request, "client", "session-signers.credential");
        const body = exactBody(await bodyRecord(request, captured.maxBodyBytes), ["deviceId"]);
        const deviceId = boundedText(body.deviceId, 256, "session signer deviceId", INVALID);
        let credential: unknown;
        try {
          credential = await custody.provider.credential({
            clientId: caller.clientId,
            subject: caller.subject,
            deviceId,
          });
        } catch {
          return relayFailure("relay_internal", "session signer provider did not answer");
        }
        return jsonResponse(200, { operatorCredential: credential });
      }
      if (segments.length === 2 && group === "signatures") {
        requireMethod(request, "POST");
        const caller = await authenticate(request, "client", "session-signers.sign");
        const body = exactBody(await bodyRecord(request, captured.maxBodyBytes), [
          "deviceId",
          "hash",
        ]);
        const deviceId = boundedText(body.deviceId, 256, "session signer deviceId", INVALID);
        // One exact 32-byte hash; the provider signs an identity, never a
        // message it interprets.
        if (typeof body.hash !== "string" || !/^0x[0-9a-f]{64}$/u.test(body.hash)) {
          return relayFailure(INVALID, "session signer hash must be one exact 32-byte hash");
        }
        let signature: unknown;
        try {
          signature = await custody.provider.sign({
            clientId: caller.clientId,
            subject: caller.subject,
            deviceId,
            hash: body.hash as `0x${string}`,
          });
        } catch {
          return relayFailure("relay_internal", "session signer provider did not answer");
        }
        return jsonResponse(200, { signature });
      }
      return relayFailure("relay_not_found", "route does not exist");
    }

    if (head === "invalidations" && segments.length === 1) {
      requireMethod(request, "POST");
      const caller = await authenticate(request, "client", "invalidations.create");
      const body = exactBody(await bodyRecord(request, captured.maxBodyBytes), [
        "grantId",
        "capabilityHash",
      ]);
      const grantId = canonicalIdentifier(body.grantId, "grantId", INVALID);
      const capabilityHash = boundedText(body.capabilityHash, 66, "capabilityHash", INVALID);
      if (!/^0x[0-9a-f]{64}$/u.test(capabilityHash)) {
        return relayFailure(INVALID, "capabilityHash must be a lowercase 32-byte hash");
      }
      // Durable and enforced: from the committed record on, every chain
      // execution route below refuses this Grant, so the evidence states an
      // enforced fact — this service will no longer act for the capability.
      // Consuming the on-chain install nonce stays the chain-local revocation
      // operation's separate evidence. Replays answer the stored record, so
      // one Grant has exactly one invalidation time.
      const record = await withRelayTransaction(captured.store, async (transaction) => {
        const existing = await transaction.lockCapabilityInvalidation(grantId);
        if (existing) {
          if (existing.clientId !== caller.clientId) {
            // Reported as absence: not an existence oracle for another
            // client's Grant.
            return relayFailure("relay_not_found", "grant does not exist");
          }
          return existing;
        }
        const created = Object.freeze({
          version: OAATH_CAPABILITY_INVALIDATION_RECORD_VERSION,
          grantId,
          clientId: caller.clientId,
          capabilityHash,
          invalidatedAt: relayNow(captured.clock),
        });
        if (!(await transaction.insertCapabilityInvalidation(created))) {
          return relayFailure("relay_internal", "capability invalidation did not commit");
        }
        return created;
      });
      const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(
          `oaath-relay-invalidation:v1:${record.clientId}:${record.grantId}:${record.capabilityHash}:${record.invalidatedAt}`,
        ),
      );
      const evidenceHash = `0x${[...new Uint8Array(digest)]
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("")}`;
      // The evidence is protocol-facing, so it speaks the protocol's seconds
      // domain rather than the relay's millisecond records.
      return jsonResponse(200, {
        evidenceHash,
        invalidatedAt: Math.floor(record.invalidatedAt / 1_000),
      });
    }

    if (head === "chains" && segments.length === 4 && third === "paymaster") {
      requireMethod(request, "POST");
      const service = captured.paymasterServices.get(Number(group));
      const method = fourth === "stub-data" || fourth === "data" ? fourth : null;
      if (service === undefined || method === null) {
        return relayFailure("relay_not_found", "route does not exist");
      }
      const caller = await authenticate(request, "client", `chains.paymaster.${method}`);
      // The route selects the deployment-owned provider. An application URL
      // is never accepted in this body and therefore can never become a fetch
      // target here.
      const body = exactBody(await bodyRecord(request, captured.maxBodyBytes), ["params"]);
      const result = await invokePaymasterService(service, method, caller, body.params);
      return jsonResponse(
        200,
        result === undefined ? { present: false, result: null } : { present: true, result },
      );
    }

    if (head === "chains") {
      if (segments.length !== 3) return relayFailure("relay_not_found", "route does not exist");
      requireMethod(request, "POST");
      const port = captured.chains.get(Number(group));
      const name: ChainPortName | null =
        third === "submissions"
          ? "submission"
          : third === "reads" ||
              third === "observation" ||
              third === "bundler" ||
              third === "quote" ||
              third === "usage"
            ? third
            : null;
      if (!port || name === null) {
        return relayFailure("relay_not_found", "route does not exist");
      }
      // Submissions also accept the owner role: the owner-signed revocation
      // operation is what removes an installed chain permission, so the
      // owner's console must be able to submit it after the capability died.
      const caller = await authenticate(
        request,
        name === "submission" ? ["client", "owner"] : "client",
        `chains.${name}`,
      );
      const body = exactBody(await bodyRecord(request, captured.maxBodyBytes), ["request"]);
      const capability = name === "usage" ? port.usage : port[name];
      if (capability === null) {
        return relayFailure("relay_not_found", "route does not exist");
      }
      // Recorded invalidations are enforced here: a submission or usage read
      // that names an invalidated Grant is refused before its port runs. The
      // ports whose requests carry no Grant identity are chain reads, which
      // grant nothing. This guards the honest capability; the on-chain install
      // nonce is what a hostile holder must still be cut off from, by the
      // chain-local revocation operation.
      //
      // The one pass through the gate is the caller's PROVEN owner role —
      // never a payload claim, which any gated client could spoof to keep
      // spending relay, RPC, and fee-payer budget after invalidation.
      const grantId = caller.role === "owner" ? null : chainRequestGrantId(name, body.request);
      if (grantId !== null) {
        const invalidated = await withRelayTransaction(captured.store, (transaction) =>
          transaction.lockCapabilityInvalidation(grantId),
        );
        if (invalidated !== undefined) {
          return relayFailure(
            "relay_capability_invalidated",
            "the Grant's capability is invalidated",
          );
        }
      }
      let result: unknown;
      try {
        result = await capability(body.request);
      } catch {
        // Port meaning stays with its SDK owner; the relay reports only that
        // this chain surface did not answer. Nothing here retries.
        return relayFailure("relay_chain_unavailable", "chain port did not answer");
      }
      // JSON cannot carry `undefined`, and several ports mean it ("no such
      // fact"), so the envelope states presence explicitly.
      return jsonResponse(
        200,
        result === undefined ? { present: false, result: null } : { present: true, result },
      );
    }

    if (head !== "authorization") {
      relayFailure("relay_not_found", "route does not exist");
    }

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

    if (segments.length === 4 && group === "requests" && fourth === "code") {
      requireMethod(request, "GET");
      const caller = await authenticate(request, "client", "authorization.code");
      const fetched = await fetchAuthorizationCode({
        store: captured.store,
        clock: captured.clock,
        kms: captured.kms,
        caller,
        requestId: canonicalIdentifier(third, "requestId", INVALID),
      });
      return jsonResponse(200, fetched);
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
