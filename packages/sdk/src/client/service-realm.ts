/**
 * The service-approved composition: one OAAth service URL is the only deployment fact
 * an application supplies.
 *
 * ```text
 * createOAAth({ approvals: { kind: "service", url } })
 *                               nothing fetched, nothing trusted yet
 * connect()                     GET /bootstrap  (authenticated, versioned)
 *                               -> exact parse; hostile context fails closed
 *                               -> owner identity from the approved credential
 *                                  (no owner signer ever enters the page)
 *                               -> fresh local session key + device identity,
 *                                  or the caller's optional passkey `session`
 *                               -> chain ports relayed through the service
 *                               -> the ordinary injected realm, composed
 *                                  internally from exactly these facts
 * ```
 *
 * The service is the configuration root, not the authority root: the account
 * and owner credential it serves still have to survive the owner's approval
 * artifact binding, the key/credential proof, and every chain-side check. The
 * application cannot choose a different account, owner, client identity, or
 * chain surface than the deployment registered.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  captureBundlerRejection,
  captureRecord,
  captureValidationGasDiagnostic,
  parseServiceBootstrap,
  parseUserOperationFailure,
  type ServiceBootstrap,
} from "@oaath/protocol";
import { generatePrivateKey, privateKeyToAccount } from "cetane/accounts";
import { OaathRpcError } from "../cetane/rpc.js";
import { credentialKey } from "../kernel/key/credential.js";
import { ecdsaKey } from "../kernel/key/ecdsa.js";
import type { KeyProfile } from "../kernel/types.js";
import type { OaathAuthorizationCapability } from "./connection.js";
import { clientCapability, clientFail, clientFailure, exactClientRecord } from "./errors.js";
import type { OaathChainCapability, OaathChainSponsorship } from "./grant-handle.js";

type Erc7677ChainSponsorship = Extract<OaathChainSponsorship, { kind: "erc7677" }>;

import { deriveOperatorCredentialProfile } from "./key-credential.js";
import {
  loadServiceSession,
  type PersistedServiceSession,
  saveServiceSession,
  serviceSessionKeyId,
} from "./service-session.js";
import {
  captureSession,
  type OaathSession,
  type OaathSessionCustody,
  type SuppliedSession,
  unsupportedSessionCustody,
} from "./session-credential.js";
import { type OaathStoreName, STORE_NAMES } from "./store-configuration.js";
import {
  type CapturedStores,
  captureStores,
  type OaathStores,
  type OwnedStores,
  openStores,
} from "./stores.js";

export const OAATH_DEFAULT_SERVICE_URL = "http://localhost:8787" as const;
const POLL_INTERVAL_MS = 1_000;
/**
 * Sessions resolve the pinned permission signer module; a session key's
 * validator member is never installed or consulted, so this syntactically
 * valid placeholder can never carry authority.
 */
const SESSION_VALIDATOR_PLACEHOLDER = `0x${"01".repeat(20)}` as const;

/** The OAAth service and its owner phone approve Grants. */
export interface OaathServiceApprovals {
  readonly kind: "service";
  /** Defaults to local development: http://localhost:8787. */
  readonly url?: string;
  /** Defaults to the global fetch with the deployment's cookie credentials. */
  readonly fetch?: (request: Request) => Promise<Response>;
  /** Defaults to polling the service for the released authorization code. */
  readonly authorization?: Readonly<OaathAuthorizationCapability>;
}
/**
 * `createOAAth` options whose Grants the service approves. The service
 * selects the account and chains, so neither is configured here.
 */
export interface OaathServiceOptions {
  readonly approvals: Readonly<OaathServiceApprovals>;
  readonly session?: Readonly<OaathSession>;
  /**
   * Defaults to `{ kind: "indexeddb" }`, which fails closed outside a browser.
   * `{ kind: "memory" }` is for tests and non-browser development.
   */
  readonly stores?: OaathStores;
  /** Defaults to the actual browser origin; required outside a browser. */
  readonly origin?: string;
  readonly now?: () => number;
}

interface ServiceRealmInput {
  readonly url: string;
  readonly fetch: ((request: Request) => Promise<Response>) | null;
  readonly origin: string | null;
  readonly authorization: unknown;
  readonly stores: Readonly<CapturedStores>;
  readonly now: (() => number) | null;
  readonly session: Readonly<SuppliedSession> | null;
  readonly custody: OaathSessionCustody | null;
}

/** Remote session-key custody the realm names in every permission request. */
export interface RemoteSessionCustody {
  readonly mode: "application_backend" | "oaath_hosted";
  readonly providerId: string;
}

const DECLARED_CUSTODY: Readonly<
  Record<ServiceBootstrap["sessionSigner"]["mode"], OaathSessionCustody>
> = Object.freeze({
  frontend: "browser",
  application_backend: "application-backend",
  oaath_hosted: "oaath-hosted",
});

/**
 * The service bootstrap owns custody; the application's `session` setting
 * never selects it. A passkey is browser custody the caller holds, and an
 * explicit `custody` is a requirement: either one that differs from the
 * declaration fails closed before any store, key, or further request exists.
 */
function requireDeclaredCustody(
  input: Readonly<ServiceRealmInput>,
  bootstrap: Readonly<ServiceBootstrap>,
): void {
  const declared = DECLARED_CUSTODY[bootstrap.sessionSigner.mode];
  if (input.session !== null && declared !== "browser") {
    unsupportedSessionCustody("a caller-supplied session requires browser session custody");
  }
  if (input.custody !== null && input.custody !== declared) {
    unsupportedSessionCustody("the service declares a different session custody");
  }
}

function captureServiceRealmInput(value: unknown): Readonly<ServiceRealmInput> {
  const fail = clientFailure("oaath_client_input_invalid");
  const initial = captureRecord(value, "OAAth configuration", new WeakSet(), fail);
  const options = ["session", "stores", "origin", "now"].filter((key) =>
    Object.hasOwn(initial, key),
  );
  const top = exactClientRecord(
    initial,
    ["approvals", ...options],
    "OAAth configuration",
    new WeakSet(),
  );
  const initialApprovals = captureRecord(top.approvals, "service approvals", new WeakSet(), fail);
  const approvals = exactClientRecord(
    initialApprovals,
    [
      "kind",
      ...["url", "fetch", "authorization"].filter((key) => Object.hasOwn(initialApprovals, key)),
    ],
    "service approvals",
    new WeakSet(),
  );
  if (approvals.kind !== "service") return fail("service approvals kind is required");
  const record: Readonly<Record<string, unknown>> = { ...top, ...approvals };
  const url = record.url === undefined ? OAATH_DEFAULT_SERVICE_URL : record.url;
  if (typeof url !== "string" || url.length < 1) {
    return clientFail("oaath_client_input_invalid", "OAAth service url must be a string");
  }
  if (record.origin !== undefined && typeof record.origin !== "string") {
    return clientFail("oaath_client_input_invalid", "OAAth origin override must be a string");
  }
  return Object.freeze({
    url,
    fetch:
      record.fetch === undefined
        ? null
        : clientCapability<(request: Request) => Promise<Response>>(record.fetch, "service fetch"),
    origin: record.origin === undefined ? null : record.origin,
    authorization: record.authorization === undefined ? null : record.authorization,
    stores: captureStores(record.stores, STORE_NAMES),
    now: record.now === undefined ? null : clientCapability<() => number>(record.now, "clock"),
    ...(() => {
      const session = captureSession(record.session, new WeakSet());
      return { session: session.supplied, custody: session.custody };
    })(),
  });
}

function serviceTransport(
  input: Readonly<ServiceRealmInput>,
): (request: Request) => Promise<Response> {
  if (input.fetch) return input.fetch;
  const global = globalThis.fetch;
  if (typeof global !== "function") {
    return clientFail("oaath_client_capability_invalid", "fetch is unavailable in this runtime");
  }
  // The deployment's own cookie/session semantics authenticate the client;
  // no token material ever lives in SDK memory.
  return (request: Request) => global(request, { credentials: "include" } as RequestInit);
}

async function fetchJson(
  transport: (request: Request) => Promise<Response>,
  request: Request,
  label: string,
  allowBundlerRejection = false,
): Promise<unknown> {
  let response: Response;
  try {
    response = await transport(request);
  } catch {
    return clientFail("oaath_client_issuer_unavailable", `${label} could not be reached`);
  }
  if (!response.ok) {
    let diagnostic = null;
    let rejection = null;
    let failure = null;
    try {
      const body = (await response.json()) as {
        error?: {
          code?: unknown;
          diagnostic?: unknown;
          bundlerRejection?: unknown;
          failure?: unknown;
        };
      };
      if (body.error?.code === "relay_chain_unavailable") {
        diagnostic = captureValidationGasDiagnostic(body.error.diagnostic);
        failure = parseUserOperationFailure(body.error.failure);
        if (allowBundlerRejection && response.status === 503)
          rejection = captureBundlerRejection(body.error.bundlerRejection);
      }
    } catch {
      /* Preserve the generic failure when the body is absent or unreadable. */
    }
    if (rejection !== null)
      throw new OaathRpcError("oaath_rpc_rejected", rejection.code, diagnostic, { cause: failure });
    return clientFail(
      "oaath_client_issuer_rejected",
      `${label} answered ${response.status}`,
      null,
      diagnostic,
      { cause: failure },
    );
  }
  try {
    return await response.json();
  } catch {
    return clientFail("oaath_client_issuer_unavailable", `${label} answered unreadable JSON`);
  }
}

function jsonRequest(url: string, body: unknown): Request {
  return new Request(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

/**
 * One relayed chain port. The wire envelope states presence explicitly
 * because JSON cannot carry `undefined`, and several ports mean it.
 */
function chainPort(
  transport: (request: Request) => Promise<Response>,
  url: string,
  chainId: number,
  port: "reads" | "observation" | "bundler" | "quote" | "submissions" | "usage",
): (request: unknown) => Promise<unknown> {
  return async (request: unknown) => {
    const envelope = exactClientRecord(
      await fetchJson(
        transport,
        jsonRequest(`${url}/chains/${chainId}/${port}`, { request }),
        `chain ${chainId} ${port}`,
        port === "submissions",
      ),
      ["present", "result"],
      "chain port envelope",
      new WeakSet(),
      "oaath_client_capability_invalid",
    );
    if (typeof envelope.present !== "boolean") {
      return clientFail("oaath_client_capability_invalid", "chain port envelope is invalid");
    }
    return envelope.present ? envelope.result : undefined;
  };
}

function serviceChainCapability(
  transport: (request: Request) => Promise<Response>,
  url: string,
  chain: Readonly<ServiceBootstrap["chains"][number]>,
): Readonly<OaathChainCapability> {
  const port = (name: Parameters<typeof chainPort>[3]) =>
    chainPort(transport, url, chain.chainId, name);
  const submissions = port("submissions");
  const bundler = port("bundler");
  // The chain sponsorship setting holds one kind; a bootstrap naming both is contradictory.
  if (chain.paymasterService !== null && chain.staticPaymasterConfigurationHash !== null) {
    return clientFail(
      "oaath_client_capability_invalid",
      "service chain advertises more than one sponsorship kind",
    );
  }
  const sponsorship: Readonly<OaathChainSponsorship> | null =
    chain.staticPaymasterConfigurationHash !== null
      ? Object.freeze({
          kind: "erc7902-static" as const,
          configurationHash: chain.staticPaymasterConfigurationHash,
        })
      : chain.paymasterService === null
        ? null
        : Object.freeze({
            kind: "erc7677" as const,
            url: `${url}/chains/${chain.chainId}/paymaster`,
            async request(request: Parameters<Erc7677ChainSponsorship["request"]>[0]) {
              const path = request.method === "pm_getPaymasterStubData" ? "stub-data" : "data";
              const envelope = exactClientRecord(
                await fetchJson(
                  transport,
                  jsonRequest(`${url}/chains/${chain.chainId}/paymaster/${path}`, {
                    params: request.params,
                  }),
                  `chain ${chain.chainId} paymaster ${path}`,
                ),
                ["present", "result"],
                "paymaster service envelope",
                new WeakSet(),
                "oaath_client_capability_invalid",
              );
              if (typeof envelope.present !== "boolean") {
                return clientFail(
                  "oaath_client_capability_invalid",
                  "paymaster service envelope is invalid",
                );
              }
              return envelope.present ? envelope.result : undefined;
            },
            estimate: (request: Parameters<Erc7677ChainSponsorship["estimate"]>[0]) =>
              bundler(
                Object.freeze({
                  version: "oaath.erc7677-gas-estimation/v1",
                  prepared: request.prepared,
                  userOperation: request.userOperation,
                }),
              ),
          });
  return Object.freeze({
    chainId: chain.chainId,
    ...(chain.gas === undefined
      ? {}
      : { gas: { enableVerificationGasFloor: BigInt(chain.gas.enableVerificationGasFloor) } }),
    reads: Object.freeze({ read: port("reads") }),
    observation: Object.freeze({ read: port("observation"), close: async () => undefined }),
    // The relay serves one bundler probe; its fee payer, when present, offers handleOps.
    routes: Object.freeze([
      Object.freeze({ kind: "erc4337-bundler" as const, bundler: { probe: bundler } }),
      ...(chain.feePayer === null
        ? []
        : [Object.freeze({ kind: "erc4337-handleops" as const, feePayer: chain.feePayer })]),
    ]),
    submission: Object.freeze({
      // The durable journal marks the attempt before `send` runs; the service
      // settles one submission per call and this session never retries.
      open: async (request: unknown) =>
        Object.freeze({
          send: () => submissions(request),
          close: async () => undefined,
        }),
    }),
    quote: port("quote"),
    usage: chain.usage ? port("usage") : null,
    ...(sponsorship === null ? {} : { sponsorship }),
  }) as Readonly<OaathChainCapability>;
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

/**
 * Default owner-decision capability: the service releases the decided code to
 * the authenticated creating client, so the SDK polls for it until the
 * request's own expiry. Consumption stays guarded by the PKCE verifier only
 * this realm holds, so pickup grants nothing by itself.
 */
function pollingAuthorization(
  transport: (request: Request) => Promise<Response>,
  url: string,
  now: () => number,
): Readonly<{ authorize: (request: unknown) => Promise<unknown> }> {
  return Object.freeze({
    authorize: async (value: unknown) => {
      const request = exactClientRecord(
        value,
        ["requestId", "redirectUri", "expiresAt"],
        "authorization request",
        new WeakSet(),
      );
      const requestId = request.requestId;
      const expiresAt = request.expiresAt;
      if (typeof requestId !== "string" || typeof expiresAt !== "number") {
        return clientFail("oaath_client_input_invalid", "authorization request is invalid");
      }
      for (;;) {
        const state = await fetchJson(
          transport,
          new Request(`${url}/authorization/requests/${encodeURIComponent(requestId)}/code`),
          "authorization code pickup",
        );
        const outcome = (state as { readonly outcome?: unknown } | null)?.outcome;
        if (outcome === "approved") {
          const approved = exactClientRecord(
            state,
            ["outcome", "decidedAt", "code", "codeExpiresAt"],
            "released authorization code",
            new WeakSet(),
            "oaath_client_issuer_rejected",
          );
          if (typeof approved.code !== "string") {
            return clientFail("oaath_client_issuer_rejected", "released code is invalid");
          }
          return Object.freeze({ code: approved.code });
        }
        if (outcome === "rejected") {
          return clientFail(
            "oaath_client_permission_rejected",
            "the owner rejected the permission request",
          );
        }
        if (outcome !== "pending") {
          return clientFail("oaath_client_issuer_rejected", "code pickup answered unusably");
        }
        if (now() >= expiresAt) {
          return clientFail(
            "oaath_client_decision_unavailable",
            "no owner decision arrived before the request expired",
          );
        }
        await sleep(POLL_INTERVAL_MS);
      }
    },
  });
}

function localOrigin(input: Readonly<ServiceRealmInput>): string {
  if (input.origin !== null) return input.origin;
  const location = (globalThis as { readonly location?: { readonly origin?: unknown } }).location;
  if (location && typeof location.origin === "string") return location.origin;
  return clientFail(
    "oaath_client_input_invalid",
    "no browser origin exists in this runtime; pass the origin override",
  );
}

function deviceIdentity(): string {
  const generator = (globalThis as { readonly crypto?: { readonly randomUUID?: () => string } })
    .crypto;
  if (!generator || typeof generator.randomUUID !== "function") {
    return clientFail("oaath_client_capability_invalid", "crypto.randomUUID is unavailable");
  }
  return generator.randomUUID();
}

/**
 * The exact injected configuration one bootstrap document composes to. Kept
 * separate from the fetch so hostile context is refused before any key or
 * store exists, and so tests can exercise it deterministically.
 */
/**
 * The remote session key: the deployment declared backend or hosted custody,
 * so the operator credential comes from the service's registered provider and
 * every signature is one authenticated call for one exact hash. The local
 * profile still self-verifies each returned signature against the served
 * credential, so a provider signing with any other key — a silent rotation —
 * fails closed before a submission exists.
 */
async function remoteSessionKey(
  input: Readonly<ServiceRealmInput>,
  transport: (request: Request) => Promise<Response>,
  deviceId: string,
): Promise<Readonly<{ key: Readonly<KeyProfile>; credential: Readonly<Record<string, unknown>> }>> {
  const served = await fetchJson(
    transport,
    jsonRequest(`${input.url}/session-signers`, { deviceId }),
    "session signer credential",
  );
  const record = exactClientRecord(
    served,
    ["operatorCredential"],
    "session signer credential",
    new WeakSet(),
    "oaath_client_capability_invalid",
  );
  const credential = record.operatorCredential as Record<string, unknown> | null;
  if (
    !credential ||
    credential.kind !== "ecdsa" ||
    typeof credential.address !== "string" ||
    !/^0x[0-9a-f]{40}$/u.test(credential.address)
  ) {
    return clientFail(
      "oaath_client_capability_invalid",
      "the service served an unusable session signer credential",
    );
  }
  const address = credential.address as `0x${string}`;
  return Object.freeze({
    credential: Object.freeze({ ...credential }),
    key: ecdsaKey({
      account: {
        address,
        sign: async ({ hash }: { readonly hash: `0x${string}` }) => {
          const answer = await fetchJson(
            transport,
            jsonRequest(`${input.url}/session-signers/signatures`, { deviceId, hash }),
            "session signer signature",
          );
          return (answer as { readonly signature?: unknown } | null)?.signature;
        },
      },
      validator: SESSION_VALIDATOR_PLACEHOLDER,
    }),
  });
}

async function composeConfiguration(
  input: Readonly<ServiceRealmInput>,
  transport: (request: Request) => Promise<Response>,
  bootstrap: Readonly<ServiceBootstrap>,
  stores: unknown,
  session: Readonly<PersistedServiceSession | SuppliedSession>,
): Promise<Record<string, unknown>> {
  const origin = localOrigin(input);
  const redirectUri = bootstrap.application.redirectUris.find((registered) =>
    registered.startsWith(`${origin}/`),
  );
  if (redirectUri === undefined) {
    return clientFail(
      "oaath_client_capability_invalid",
      "the service registered no redirect URI on this origin",
    );
  }
  const now = input.now ?? (() => Math.floor(Date.now() / 1_000));
  // Custody modes are different trust models and are never silently
  // substituted. Frontend custody is the local non-extractable session key;
  // backend and hosted custody bind the credential the deployment's registered
  // provider serves and route every signature through it. The vocabulary is
  // closed at the bootstrap parser, and requireDeclaredCustody already refused
  // a caller-supplied session under remote custody.
  const supplied = "sessionKey" in session;
  const deviceId = session.deviceId;
  const remote =
    bootstrap.sessionSigner.mode === "frontend"
      ? null
      : await remoteSessionKey(input, transport, deviceId);
  const sessionKey =
    remote?.key ??
    ("sessionKey" in session
      ? session.sessionKey
      : ecdsaKey({
          account: privateKeyToAccount(session.privateKey),
          validator: SESSION_VALIDATOR_PLACEHOLDER,
        }));
  const operatorCredential = remote?.credential ?? deriveOperatorCredentialProfile(sessionKey);
  return {
    binding: {
      issuer: input.url,
      applicationId: bootstrap.application.applicationId,
      applicationName: bootstrap.application.applicationName,
      clientId: bootstrap.application.clientId,
      origin,
      redirectUri,
      deviceId,
      userHandle: bootstrap.userHandle,
      context: bootstrap.context,
      account: bootstrap.account,
      operatorCredential,
    },
    issuer: { url: input.url, fetch: transport, signOut: null },
    authorization: input.authorization ?? pollingAuthorization(transport, input.url, now),
    invalidation: {
      invalidateCapability: (request: unknown) =>
        fetchJson(
          transport,
          jsonRequest(`${input.url}/invalidations`, request),
          "capability invalidation",
        ),
    },
    ownerRevocations: {
      async request(request: Readonly<{ grantId: string; chainId: number }>) {
        await fetchJson(
          transport,
          jsonRequest(
            `${input.url}/grants/${encodeURIComponent(request.grantId)}/revocations/${request.chainId}`,
            {},
          ),
          "owner revocation request",
        );
      },
    },
    stores,
    chains: bootstrap.chains.map((chain) => serviceChainCapability(transport, input.url, chain)),
    signing: {
      owner: credentialKey({
        credential: bootstrap.account.ownerCredential,
        validator: bootstrap.ownerValidator,
      }),
      session: sessionKey,
    },
    // Deleting the wrapping key on disconnect durably orphans the persisted
    // session ciphertext, so `forgetLocal` forgets the session too. A
    // caller-held session has no local custody to forget.
    localKeyIds: supplied ? [] : [serviceSessionKeyId(input.url, origin, bootstrap)],
    now,
  };
}

/**
 * Builds the service-approved realm. `compose` is the ordinary injected composition
 * (`createOAAth`'s full-configuration path), handed in by the caller so this
 * module never imports it back.
 */
export function createServiceRealm<Realm extends object>(
  value: unknown,
  compose: (configuration: unknown, remoteCustody: Readonly<RemoteSessionCustody> | null) => Realm,
): Realm {
  const input = captureServiceRealmInput(value);
  const transport = serviceTransport(input);
  let inner: Realm | null = null;
  let composing: Promise<Realm> | null = null;
  let defaultStoreOwner: Readonly<OwnedStores<OaathStoreName>> | null = null;
  let closing: Promise<void> | null = null;
  let closeRequested = false;
  let closed = false;
  let activeOperations = 0;
  const operationWaiters = new Set<() => void>();

  function releaseOperation(): void {
    activeOperations -= 1;
    if (activeOperations !== 0) return;
    for (const resolve of operationWaiters) resolve();
    operationWaiters.clear();
  }

  function waitForOperations(): Promise<void> {
    if (activeOperations === 0) return Promise.resolve();
    return new Promise((resolve) => operationWaiters.add(resolve));
  }

  async function withOperation<Value>(action: () => Promise<Value>): Promise<Value> {
    if (closeRequested || closed) clientFail("oaath_client_closed", "OAAth realm is closed");
    activeOperations += 1;
    try {
      return await action();
    } finally {
      releaseOperation();
    }
  }

  async function closeDefaultStoreOwner(): Promise<void> {
    const owner = defaultStoreOwner;
    if (owner === null) return;
    await owner.close();
    if (defaultStoreOwner === owner) defaultStoreOwner = null;
  }

  async function ownSession(
    stores: Parameters<typeof loadServiceSession>[0]["stores"],
    origin: string,
    bootstrap: Readonly<ServiceBootstrap>,
  ): Promise<Readonly<PersistedServiceSession>> {
    const continuity = { stores, url: input.url, origin, bootstrap };
    const loaded = await loadServiceSession(continuity);
    if (loaded !== null) return loaded;
    const session = Object.freeze({ deviceId: deviceIdentity(), privateKey: generatePrivateKey() });
    const now = input.now ?? (() => Math.floor(Date.now() / 1_000));
    await saveServiceSession({ ...continuity, session, now }).catch(() => undefined);
    return session;
  }

  async function realm(): Promise<Realm> {
    if (inner) return inner;
    composing ??= (async () => {
      const bootstrap = (() => {
        return fetchJson(transport, new Request(`${input.url}/bootstrap`), "service bootstrap");
      })().then((document) => {
        try {
          return parseServiceBootstrap(document);
        } catch (error) {
          return clientFail(
            "oaath_client_capability_invalid",
            "service bootstrap is invalid",
            error instanceof Error && "code" in error && typeof error.code === "string"
              ? error.code
              : null,
          );
        }
      });
      const selectedBootstrap = await bootstrap;
      requireDeclaredCustody(input, selectedBootstrap);
      defaultStoreOwner = await openStores(input.stores, STORE_NAMES);
      const { stores } = defaultStoreOwner;
      // Continuity, never authority: a persisted session keeps the device
      // identity and the operator key stable across reloads so `resume()`
      // finds a Grant this realm can still sign for. Anything unreadable
      // starts fresh, and a save failure runs this realm ephemeral rather
      // than refusing it — the approval flow re-establishes authority either
      // way.
      const origin = localOrigin(input);
      const session = input.session ?? (await ownSession(stores, origin, selectedBootstrap));
      const declared = selectedBootstrap.sessionSigner;
      inner = compose(
        await composeConfiguration(input, transport, selectedBootstrap, stores, session),
        // The owner approves the custody model with the scope: remote custody
        // is named in every permission request this realm creates.
        declared.mode === "frontend"
          ? null
          : Object.freeze({ mode: declared.mode, providerId: declared.providerId! }),
      );
      return inner;
    })().catch(async (error: unknown) => {
      // A failed bootstrap leaves no realm behind; the next connect retries.
      composing = null;
      await closeDefaultStoreOwner().catch(() => undefined);
      throw error;
    });
    return composing;
  }

  const facade = {
    get binding(): unknown {
      if (!inner) {
        return clientFail(
          "oaath_client_input_invalid",
          "the realm binding exists after connect() bootstraps the service context",
        );
      }
      return (inner as { readonly binding: unknown }).binding;
    },
    async connect(): Promise<unknown> {
      return withOperation(async () => {
        const composed = (await realm()) as { readonly connect: () => Promise<unknown> };
        return composed.connect();
      });
    },
    async disconnect(grant: unknown): Promise<unknown> {
      return withOperation(async () => {
        const composed = (await realm()) as {
          readonly disconnect: (grant: unknown) => Promise<unknown>;
        };
        const result = await composed.disconnect(grant);
        await closeDefaultStoreOwner();
        return result;
      });
    },
    async close(): Promise<void> {
      if (closed) return;
      closeRequested = true;
      closing ??= (async () => {
        await waitForOperations();
        if (composing && !inner) await composing.catch(() => undefined);
        if (!inner && !defaultStoreOwner) {
          closed = true;
          return;
        }
        let failure: unknown;
        if (inner) {
          await (inner as { readonly close: () => Promise<void> })
            .close()
            .catch((error: unknown) => {
              failure = error;
            });
        }
        await closeDefaultStoreOwner().catch((error: unknown) => {
          failure ??= error;
        });
        if (failure !== undefined) throw failure;
        closed = true;
      })();
      try {
        await closing;
      } finally {
        if (!closed) closing = null;
      }
    },
  };
  return Object.freeze(facade) as unknown as Realm;
}
