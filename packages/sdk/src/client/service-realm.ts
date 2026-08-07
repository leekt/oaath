/**
 * The URL-only composition: one OAAth service URL is the only deployment fact
 * an application supplies.
 *
 * ```text
 * createOAAth({ url })          nothing fetched, nothing trusted yet
 * connect()                     GET /bootstrap  (authenticated, versioned)
 *                               -> exact parse; hostile context fails closed
 *                               -> owner identity from the approved credential
 *                                  (no owner signer ever enters the page)
 *                               -> fresh local session key + device identity
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
import { parseServiceBootstrap, type ServiceBootstrap } from "@oaath/protocol";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { credentialOwnerKey } from "../kernel/key/credential-owner.js";
import { ecdsaKey } from "../kernel/key/ecdsa.js";
import type { KeyProfile } from "../kernel/types.js";
import { createIndexedDbCleanupStore } from "../persistence/indexeddb/cleanup-store.js";
import { createIndexedDbContextStore } from "../persistence/indexeddb/context-store.js";
import { openOaathDatabase } from "../persistence/indexeddb/database.js";
import { createIndexedDbGrantStoreAdapter } from "../persistence/indexeddb/grant-store.js";
import { createIndexedDbKeyStore } from "../persistence/indexeddb/key-store.js";
import { createIndexedDbOperationStoreAdapter } from "../persistence/indexeddb/operation-store.js";
import { createIndexedDbPreparedCallStoreAdapter } from "../persistence/indexeddb/prepared-call-store.js";
import { createIndexedDbWalletCallBundleStoreAdapter } from "../persistence/indexeddb/wallet-call-bundle-store.js";
import {
  createMemoryCleanupStore,
  createMemoryContextStore,
  createMemoryGrantStoreAdapter,
  createMemoryKeyStore,
  createMemoryOperationStoreAdapter,
  createMemoryPreparedCallStoreAdapter,
  createMemoryWalletCallBundleStoreAdapter,
} from "../persistence/memory/stores.js";
import { clientCapability, clientFail, exactClientRecord } from "./errors.js";
import type { OaathChainCapability, OaathRegisteredPaymasterService } from "./grant-handle.js";
import {
  loadServiceSession,
  type PersistedServiceSession,
  saveServiceSession,
  serviceSessionKeyId,
} from "./service-session.js";

export const OAATH_DEFAULT_SERVICE_URL = "http://localhost:8787" as const;
const POLL_INTERVAL_MS = 1_000;
/**
 * Sessions resolve the pinned permission signer module; a session key's
 * validator member is never installed or consulted, so this syntactically
 * valid placeholder can never carry authority.
 */
const SESSION_VALIDATOR_PLACEHOLDER = `0x${"01".repeat(20)}` as const;

/** Every URL-mode key; only `url` is a normal production input. */
export const SERVICE_REALM_KEYS: readonly string[] = Object.freeze([
  "url",
  "fetch",
  "origin",
  "authorization",
  "stores",
  "now",
]);

interface ServiceRealmInput {
  readonly url: string;
  readonly fetch: ((request: Request) => Promise<Response>) | null;
  readonly origin: string | null;
  readonly authorization: unknown;
  readonly stores: unknown;
  readonly now: (() => number) | null;
}

function captureServiceRealmInput(
  record: Readonly<Record<string, unknown>>,
): Readonly<ServiceRealmInput> {
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
    stores: record.stores === undefined ? null : record.stores,
    now: record.now === undefined ? null : clientCapability<() => number>(record.now, "clock"),
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
): Promise<unknown> {
  let response: Response;
  try {
    response = await transport(request);
  } catch {
    return clientFail("oaath_client_issuer_unavailable", `${label} could not be reached`);
  }
  if (!response.ok) {
    return clientFail("oaath_client_issuer_rejected", `${label} answered ${response.status}`);
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
  const paymasterService: Readonly<OaathRegisteredPaymasterService> | null =
    chain.paymasterService === null
      ? null
      : Object.freeze({
          url: `${url}/chains/${chain.chainId}/paymaster`,
          async request(request: Parameters<OaathRegisteredPaymasterService["request"]>[0]) {
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
          estimate: (request: Parameters<OaathRegisteredPaymasterService["estimate"]>[0]) =>
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
    reads: Object.freeze({ read: port("reads") }),
    observation: Object.freeze({ read: port("observation"), close: async () => undefined }),
    bundler: Object.freeze({ probe: port("bundler") }),
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
    feePayer: chain.feePayer,
    paymasterService,
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

interface OwnedDefaultStores {
  readonly stores: Readonly<Record<string, unknown>>;
  readonly close: () => Promise<void>;
}

async function defaultStores(): Promise<Readonly<OwnedDefaultStores>> {
  if (typeof indexedDB === "undefined") {
    // A runtime with no IndexedDB keeps everything in memory: nothing durable,
    // nothing resumable, and no authority inferred after a reload.
    return Object.freeze({
      stores: Object.freeze({
        grants: createMemoryGrantStoreAdapter(),
        operations: createMemoryOperationStoreAdapter(),
        walletCallBundles: createMemoryWalletCallBundleStoreAdapter(),
        preparedCallContexts: createMemoryPreparedCallStoreAdapter(),
        keys: createMemoryKeyStore(),
        cleanup: createMemoryCleanupStore(),
        context: createMemoryContextStore(),
      }),
      close: async () => undefined,
    });
  }
  const database = await openOaathDatabase();
  return Object.freeze({
    stores: Object.freeze({
      grants: createIndexedDbGrantStoreAdapter(database),
      operations: createIndexedDbOperationStoreAdapter(database),
      walletCallBundles: createIndexedDbWalletCallBundleStoreAdapter(database),
      preparedCallContexts: createIndexedDbPreparedCallStoreAdapter(database),
      keys: createIndexedDbKeyStore(database),
      cleanup: createIndexedDbCleanupStore(database),
      context: createIndexedDbContextStore(database),
    }),
    close: async () => database.close(),
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
  session: Readonly<PersistedServiceSession>,
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
  // closed at the bootstrap parser, so no other mode can reach here.
  const sessionAccount = privateKeyToAccount(session.privateKey);
  const remote =
    bootstrap.sessionSigner.mode === "frontend"
      ? null
      : await remoteSessionKey(input, transport, session.deviceId);
  const sessionKey =
    remote === null
      ? ecdsaKey({ account: sessionAccount, validator: SESSION_VALIDATOR_PLACEHOLDER })
      : remote.key;
  const operatorCredential =
    remote === null
      ? {
          version: "oaath.operator-credential-profile/v1",
          kind: "ecdsa",
          address: sessionAccount.address.toLowerCase(),
        }
      : remote.credential;
  return {
    binding: {
      issuer: input.url,
      applicationId: bootstrap.application.applicationId,
      applicationName: bootstrap.application.applicationName,
      clientId: bootstrap.application.clientId,
      origin,
      redirectUri,
      deviceId: session.deviceId,
      userHandle: bootstrap.userHandle,
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
    stores,
    chains: bootstrap.chains.map((chain) => serviceChainCapability(transport, input.url, chain)),
    signing: {
      owner: credentialOwnerKey({
        credential: bootstrap.account.ownerCredential,
        validator: bootstrap.ownerValidator,
      }),
      session: sessionKey,
    },
    // The owner approves the custody model with the scope: remote custody is
    // named in every permission request this realm creates.
    ...(remote === null
      ? {}
      : {
          sessionSigner: {
            mode: bootstrap.sessionSigner.mode,
            providerId: bootstrap.sessionSigner.providerId,
          },
        }),
    // Deleting the wrapping key on disconnect durably orphans the persisted
    // session ciphertext, so `forgetLocal` forgets the session too.
    localKeyIds: [serviceSessionKeyId(input.url, origin)],
    now,
  };
}

/**
 * Builds the URL-mode realm. `compose` is the ordinary injected composition
 * (`createOAAth`'s full-configuration path), handed in by the caller so this
 * module never imports it back.
 */
export function createServiceRealm<Realm extends object>(
  record: Readonly<Record<string, unknown>>,
  compose: (configuration: unknown) => Realm,
): Realm {
  const input = captureServiceRealmInput(record);
  const transport = serviceTransport(input);
  let inner: Realm | null = null;
  let composing: Promise<Realm> | null = null;
  let defaultStoreOwner: Readonly<OwnedDefaultStores> | null = null;
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
      // The fetch runs concurrently with session loading below; this keeps a
      // rejection observed during that window. The real `await bootstrap`
      // still throws to the caller.
      bootstrap.catch(() => undefined);
      if (input.stores === null) defaultStoreOwner = await defaultStores();
      const stores = (input.stores ?? defaultStoreOwner?.stores) as {
        readonly context: Parameters<typeof loadServiceSession>[0]["stores"]["context"];
        readonly keys: Parameters<typeof loadServiceSession>[0]["stores"]["keys"];
      };
      // Continuity, never authority: a persisted session keeps the device
      // identity and the operator key stable across reloads so `resume()`
      // finds a Grant this realm can still sign for. Anything unreadable
      // starts fresh, and a save failure runs this realm ephemeral rather
      // than refusing it — the approval flow re-establishes authority either
      // way.
      const origin = localOrigin(input);
      let session = await loadServiceSession({ stores, url: input.url, origin });
      if (session === null) {
        session = Object.freeze({ deviceId: deviceIdentity(), privateKey: generatePrivateKey() });
        const now = input.now ?? (() => Math.floor(Date.now() / 1_000));
        await saveServiceSession({ stores, url: input.url, origin, session, now }).catch(
          () => undefined,
        );
      }
      inner = compose(
        await composeConfiguration(input, transport, await bootstrap, stores, session),
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
