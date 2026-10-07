/**
 * The one opinionated composition.
 *
 * ```ts
 * const oaath = createOAAth(configuration);
 * const connection = await oaath.connect();
 * const grant = await connection.requestPermission({ ... });
 * const operation = await grant.sendCalls({ chain, calls });
 * await operation.wait();
 * await grant.revoke();
 * ```
 *
 * Everything a deployment owns is injected: the issuer transport and its
 * credentials, the owner-decision capability, per-chain reads, observation,
 * bundler probe, submission and quote transports, the durable stores, the
 * signing key profiles, and the clock. There is no preset system, no provider
 * registry, and no hidden network default — the SDK never invents a URL, a fee,
 * a nonce, or a piece of authority evidence.
 *
 * Applications never see a permission id, an enable envelope, an operation
 * journal, a store revision, or a nonce recovery mode.
 *
 * @author taek <leekt216@gmail.com>
 */

import {
  advanceGrant,
  type CaptureContext,
  captureDenseArray,
  captureRecord,
} from "@oaath/protocol";
import { type OaathCleanupResult, runOaathCleanup } from "./cleanup/coordinator.js";
import {
  closeEffect,
  forgetLocalEffect,
  type OaathCleanupEffect,
  revokeEffect,
  signOutEffect,
} from "./cleanup/effects.js";
import {
  captureOaathBinding,
  type OaathBinding,
  type OaathBindingInput,
} from "./client/binding.js";
import { withDefaultChainPorts } from "./client/chain-descriptors.js";
import {
  createConnection,
  forwardApprovedPermission,
  type LocalPermissionAuthorization,
  type OaathConnection,
} from "./client/connection.js";
import { clientCapability, clientFail, clientFailure, exactClientRecord } from "./client/errors.js";
import {
  captureChainCapability,
  grantProviderPort,
  type OaathCapabilityInvalidationCapability,
  type OaathChainCapability,
  type OaathGrantHandle,
} from "./client/grant-handle.js";
import { requireApprovedKeyBinding } from "./client/key-credential.js";
import {
  createLocalRealm,
  type OaathWalletApprovalClient,
  type OaathWalletOptions,
} from "./client/local-realm.js";
import { createOAuthRealm, type OaathOAuthOptions } from "./client/oauth-realm.js";
import {
  createOwnerRealm,
  type OaathOwnerClient,
  type OaathOwnerOptions,
} from "./client/owner-realm.js";
import { captureStoreConfiguration } from "./client/store-configuration.js";
import { isBuiltInKeyKind, isCustomKeyKind, KEY_PROFILE_KEYS } from "./kernel/internal.js";
import type { KeyProfile } from "./kernel/types.js";
import type {
  OaathCleanupCheckpointStore,
  OaathContextStore,
  OaathKeyStore,
  WalletCallBundleStoreAdapter,
} from "./persistence/interfaces.js";
import { persistenceId } from "./persistence/interfaces.js";
import { WalletCallBundleStore } from "./provider/bundle-store.js";
import {
  PreparedCallStore,
  type PreparedCallStoreAdapter,
} from "./provider/prepared-call-store.js";
import { GrantStore, type GrantStoreAdapter, type OperationStoreAdapter } from "./store.js";

const MAX_CHAINS = 32;
const MAX_LOCAL_KEYS = 8;

export interface OaathStoreConfiguration {
  readonly grants: GrantStoreAdapter;
  readonly operations: OperationStoreAdapter;
  readonly walletCallBundles: WalletCallBundleStoreAdapter;
  readonly preparedCallContexts: PreparedCallStoreAdapter;
  readonly keys: OaathKeyStore;
  readonly cleanup: OaathCleanupCheckpointStore;
  readonly context: OaathContextStore;
}

export interface OaathSigningConfiguration {
  /** Root authority for owner-signed operations and account identity. */
  readonly owner: Readonly<KeyProfile>;
  /** Scoped authority for session-signed operations. */
  readonly session: Readonly<KeyProfile>;
}

/**
 * The owner's decision for exactly one reviewed permission request: the
 * canonical protocol decision with its replayable install approval. The SDK
 * verifies everything it returns; it is trusted for nothing.
 */
export type OaathPermissionApproval = LocalPermissionAuthorization;

/**
 * The injected composition: a deployment that owns its own approval path
 * (and deterministic tests) supplies the binding, the approval, and every port.
 * The wallet and OAuth realms build the same composition internally.
 */
export interface OaathConfiguration {
  readonly binding: Readonly<OaathBindingInput>;
  readonly approve: OaathPermissionApproval;
  readonly invalidation: Readonly<OaathCapabilityInvalidationCapability>;
  readonly stores: Readonly<OaathStoreConfiguration>;
  readonly chains: readonly Readonly<OaathChainCapability>[];
  readonly signing: Readonly<OaathSigningConfiguration>;
  /** Key custody ids this realm owns, deleted by the `forgetLocal` effect. */
  readonly localKeyIds: readonly string[];
  /** Unix seconds; the protocol's time domain. */
  readonly now: () => number;
}

export interface Oaath {
  readonly binding: Readonly<OaathBinding>;
  readonly connect: () => Promise<Readonly<OaathConnection>>;
  /**
   * The end-of-session path: revoke, sign out, forget local state, and release
   * resources. Every effect is attempted, and unfinished ones stay retryable
   * through the durable cleanup checkpoint.
   */
  readonly disconnect: (
    grant: Readonly<OaathGrantHandle> | null,
  ) => Promise<Readonly<OaathCleanupResult>>;
  readonly close: () => Promise<void>;
}

const CONFIGURATION_KEYS: readonly string[] = Object.freeze([
  "binding",
  "invalidation",
  "stores",
  "chains",
  "signing",
  "localKeyIds",
  "now",
]);

function storePort<Port>(
  value: unknown,
  methods: readonly string[],
  label: string,
  context: CaptureContext,
): Port {
  const record = exactClientRecord(
    value,
    methods,
    label,
    context,
    "oaath_client_capability_invalid",
  );
  for (const method of methods) clientCapability(record[method], `${label} ${method}`);
  return value as Port;
}

function keyProfile(value: unknown, label: string, context: CaptureContext): Readonly<KeyProfile> {
  const record = exactClientRecord(
    value,
    KEY_PROFILE_KEYS,
    label,
    context,
    "oaath_client_capability_invalid",
  );
  // A reviewed kind or one bounded consumer-authored kind; captureKeyProfile owns
  // the same fact at the composition boundary, and this one keeps a client
  // configuration failure a client code rather than a runtime one.
  if (!isBuiltInKeyKind(record.kind) && !isCustomKeyKind(record.kind)) {
    return clientFail("oaath_client_capability_invalid", `${label} kind is unsupported`);
  }
  // createKernelRuntime captures the profile again at the composition boundary.
  return value as Readonly<KeyProfile>;
}

function chainMap(
  value: unknown,
  context: CaptureContext,
): ReadonlyMap<number, Readonly<OaathChainCapability>> {
  const entries = captureDenseArray(value, "chains", context, (message) =>
    clientFail("oaath_client_capability_invalid", message),
  );
  if (entries.length < 1 || entries.length > MAX_CHAINS) {
    return clientFail("oaath_client_capability_invalid", "chains must hold 1 to 32 entries");
  }
  const chains = new Map<number, Readonly<OaathChainCapability>>();
  for (const entry of entries) {
    const chain = captureChainCapability(entry);
    if (chains.has(chain.chainId)) {
      return clientFail("oaath_client_capability_invalid", "chains repeat a chainId");
    }
    chains.set(chain.chainId, chain);
  }
  return chains;
}

function localKeyIds(value: unknown, context: CaptureContext): readonly string[] {
  const entries = captureDenseArray(value, "localKeyIds", context, (message) =>
    clientFail("oaath_client_input_invalid", message),
  );
  if (entries.length > MAX_LOCAL_KEYS) {
    return clientFail("oaath_client_input_invalid", "localKeyIds must hold at most 8 ids");
  }
  return Object.freeze(
    entries.map((entry) =>
      persistenceId(entry, "localKeyId", (message) =>
        clientFail("oaath_client_input_invalid", message),
      ),
    ),
  );
}

/**
 * One constructor. The approval source is an optional setting:
 *
 * ```ts
 * const chains = { 143: { publicRpcUrls: [rpcUrl], bundlerUrl } };         // default Cetane ports
 * createOAAth({ chains, account });                                        // owner-only execution
 * createOAAth({ chains, account, approvals: { kind: "wallet", owner } });  // wallet-approved Grants
 * createOAAth({ chains, approvals: { kind: "oauth", issuer, clientId, redirectUri } }); // portal-approved
 * ```
 *
 * Omitting `approvals` gives owner-only execution from an existing Kernel
 * account with a connected wallet; no Grant exists. Wallet approvals add
 * durable wallet-approved sessions for that account. OAuth approvals have the
 * account root approve in the issuer's portal. `stores` names a backend,
 * `{ kind: "indexeddb" }` by default or `{ kind: "memory" }` for tests and
 * non-browser development, plus optional per-store adapters such as a
 * PostgreSQL Operation journal. IndexedDB never silently falls back to memory.
 * A configuration carrying `binding` is the injected composition, whose
 * `approve` supplies the owner's decision.
 */
export function createOAAth(options: OaathWalletOptions): Readonly<OaathWalletApprovalClient>;
export function createOAAth(options: OaathOAuthOptions): Readonly<Oaath>;
export function createOAAth(options: OaathOwnerOptions): Readonly<OaathOwnerClient>;
export function createOAAth(configuration: OaathConfiguration): Readonly<Oaath>;
export function createOAAth(value: unknown): Readonly<Oaath | OaathOwnerClient> {
  const record = captureRecord(
    value,
    "OAAth configuration",
    new WeakSet(),
    clientFailure("oaath_client_input_invalid"),
  );
  if (Object.hasOwn(record, "binding")) {
    const { approve, ...composition } = record;
    return composeInjectedRealm(
      composition,
      clientCapability<OaathPermissionApproval>(approve, "OAAth approval"),
    );
  }
  const configuration = withDefaultChainPorts(value, record);
  if (record.approvals === undefined) return createOwnerRealm(configuration);
  const approvals = captureRecord(
    record.approvals,
    "OAAth approvals",
    new WeakSet(),
    clientFailure("oaath_client_input_invalid"),
  );
  if (approvals.kind === "wallet") return createLocalRealm(configuration, composeInjectedRealm);
  if (approvals.kind === "oauth") return createOAuthRealm(configuration, composeInjectedRealm);
  return clientFail("oaath_client_input_invalid", "OAAth approvals kind is unsupported");
}

/**
 * Composes a realm from one approval source: the owner's decision for each
 * reviewed request. Every approval realm and the injected configuration use it.
 */
function composeInjectedRealm(
  configuration: unknown,
  approve: LocalPermissionAuthorization,
): Readonly<Oaath> {
  const context: CaptureContext = new WeakSet();
  const record = exactClientRecord(
    configuration,
    CONFIGURATION_KEYS,
    "OAAth configuration",
    context,
  );
  const binding = captureOaathBinding(record.binding);
  const invalidation = storePort<Readonly<OaathCapabilityInvalidationCapability>>(
    record.invalidation,
    ["invalidateCapability"],
    "capability invalidation",
    context,
  );
  const stores = captureStoreConfiguration(record.stores, context);
  const chains = chainMap(record.chains, context);
  const signing = exactClientRecord(
    record.signing,
    ["owner", "session"],
    "OAAth signing",
    context,
    "oaath_client_capability_invalid",
  );
  const ownerKey = keyProfile(signing.owner, "owner key profile", context);
  const sessionKey = keyProfile(signing.session, "session key profile", context);
  // One approved credential profile identifies one executable key: the realm
  // refuses to compose at all when a signing key is not exactly the credential
  // the binding carries, so approval and execution can never name different
  // authorities.
  requireApprovedKeyBinding({ binding, ownerKey, sessionKey });
  const keyIds = localKeyIds(record.localKeyIds, context);
  const now = clientCapability<() => number>(record.now, "clock");

  const connections: Readonly<OaathConnection>[] = [];
  const ownedStores = [
    stores.grants,
    stores.operations,
    stores.walletCallBundles,
    stores.preparedCallContexts,
    stores.keys,
    stores.context,
  ].map((resource) => ({ resource, closed: false }));
  let closeRequested = false;
  let closed = false;
  let closing: Promise<void> | null = null;

  const connectionStores = Object.freeze({
    grants: Object.freeze({
      get: (grantId: Parameters<GrantStoreAdapter["get"]>[0]) => stores.grants.get(grantId),
      compareAndSwap: (input: Parameters<GrantStoreAdapter["compareAndSwap"]>[0]) =>
        stores.grants.compareAndSwap(input),
      close: async () => undefined,
    }),
    operations: Object.freeze({
      get: (key: Parameters<OperationStoreAdapter["get"]>[0]) => stores.operations.get(key),
      getArchived: (input: Parameters<OperationStoreAdapter["getArchived"]>[0]) =>
        stores.operations.getArchived(input),
      list: (scope: Parameters<OperationStoreAdapter["list"]>[0]) => stores.operations.list(scope),
      compareAndSwap: (input: Parameters<OperationStoreAdapter["compareAndSwap"]>[0]) =>
        stores.operations.compareAndSwap(input),
      close: async () => undefined,
    }),
    walletCallBundles: Object.freeze({
      get: (key: Parameters<WalletCallBundleStoreAdapter["get"]>[0]) =>
        stores.walletCallBundles.get(key),
      compareAndSwap: (input: Parameters<WalletCallBundleStoreAdapter["compareAndSwap"]>[0]) =>
        stores.walletCallBundles.compareAndSwap(input),
      close: async () => undefined,
    }),
    preparedCallContexts: Object.freeze({
      get: (key: Parameters<PreparedCallStoreAdapter["get"]>[0]) =>
        stores.preparedCallContexts.get(key),
      compareAndSwap: (input: Parameters<PreparedCallStoreAdapter["compareAndSwap"]>[0]) =>
        stores.preparedCallContexts.compareAndSwap(input),
      close: async () => undefined,
    }),
    keys: Object.freeze({
      store: (input: Parameters<OaathKeyStore["store"]>[0]) => stores.keys.store(input),
      get: (keyId: Parameters<OaathKeyStore["get"]>[0]) => stores.keys.get(keyId),
      delete: (keyId: Parameters<OaathKeyStore["delete"]>[0]) => stores.keys.delete(keyId),
      close: async () => undefined,
    }),
    context: Object.freeze({
      read: (bindingId: Parameters<OaathContextStore["read"]>[0]) => stores.context.read(bindingId),
      write: (value: Parameters<OaathContextStore["write"]>[0]) => stores.context.write(value),
      clear: (bindingId: Parameters<OaathContextStore["clear"]>[0]) =>
        stores.context.clear(bindingId),
      close: async () => undefined,
    }),
  });

  function open(): Readonly<OaathConnection> {
    if (closeRequested || closed) clientFail("oaath_client_closed", "OAAth realm is closed");
    const inner = createConnection({
      binding,
      approve,
      grants: new GrantStore(connectionStores.grants),
      operations: connectionStores.operations,
      walletCallBundles: new WalletCallBundleStore(connectionStores.walletCallBundles),
      preparedCallContexts: new PreparedCallStore(connectionStores.preparedCallContexts),
      keys: connectionStores.keys,
      contexts: connectionStores.context,
      chains,
      ownerKey,
      sessionKey,
      invalidation,
      now,
    });
    const connection = Object.freeze({
      ...inner,
      async close() {
        await inner.close();
        const index = connections.indexOf(connection);
        if (index >= 0) connections.splice(index, 1);
      },
    });
    forwardApprovedPermission(connection, inner);
    connections.push(connection);
    return connection;
  }

  async function closeAll(): Promise<void> {
    if (closed) return;
    closeRequested = true;
    if (closing) return closing;
    const attempt = (async () => {
      const childFailures: unknown[] = [];
      for (const connection of [...connections]) {
        await connection.close().catch((error: unknown) => childFailures.push(error));
      }
      if (childFailures[0] !== undefined) throw childFailures[0];

      const storeFailures: unknown[] = [];
      for (const owned of ownedStores) {
        if (owned.closed) continue;
        await Promise.resolve()
          .then(() => owned.resource.close())
          .then(() => {
            owned.closed = true;
          })
          .catch((error: unknown) => storeFailures.push(error));
      }
      if (storeFailures[0] !== undefined) throw storeFailures[0];
      closed = true;
    })().finally(() => {
      if (!closed) closing = null;
    });
    closing = attempt;
    return attempt;
  }

  async function revocationIsUnneeded(grant: Readonly<OaathGrantHandle>): Promise<boolean> {
    if (grant.state === "revoked" || grant.state === "expired") return true;
    if (grant.state !== "active") return false;
    const observedAt = now();
    if (!Number.isSafeInteger(observedAt) || observedAt < grant.expiresAt) return false;

    try {
      const grantId = grantProviderPort(grant).grantId;
      const durable = new GrantStore(connectionStores.grants);
      let current = await durable.get(grantId);
      for (let attempt = 0; attempt < 3; attempt += 1) {
        if (current === undefined) return false;
        if (current.value.state === "revoked" || current.value.state === "expired") return true;
        if (current.value.state !== "active" || observedAt < current.value.expiresAt) return false;
        const expired = advanceGrant(current.value, {
          type: "expire",
          identity: current.value.identity,
          expiredAt: Math.max(observedAt, current.value.updatedAt, current.value.expiresAt),
        });
        const result = await durable.compareAndSwap({
          grantId,
          expectedStoreRevision: current.storeRevision,
          next: expired,
        });
        if (result.status === "committed") return true;
        current = result.current;
      }
      if (current === undefined) return false;
      if (current.value.state === "revoked" || current.value.state === "expired") return true;
      return false;
    } catch {
      return false;
    }
  }

  return Object.freeze({
    binding,
    async connect(): Promise<Readonly<OaathConnection>> {
      return open();
    },
    async disconnect(
      grant: Readonly<OaathGrantHandle> | null,
    ): Promise<Readonly<OaathCleanupResult>> {
      if (grant !== null && typeof grant.revoke !== "function") {
        clientFail("oaath_client_input_invalid", "disconnect grant is invalid");
      }
      const revocationUnneeded = grant === null ? true : await revocationIsUnneeded(grant);
      const revokeRequired = grant !== null && !revocationUnneeded;
      // Order: authority first, then authentication, then local state, then
      // resources. `close` is last because it disables the effects before it.
      const effects: OaathCleanupEffect[] = [
        ...(revokeRequired ? [revokeEffect(grant)] : []),
        signOutEffect(async () => {
          for (const connection of [...connections]) await connection.signOut();
        }),
        forgetLocalEffect({
          keys: stores.keys,
          contexts: stores.context,
          bindingId: binding.bindingId,
          keyIds,
        }),
        closeEffect(closeAll),
      ];
      return runOaathCleanup({
        cleanupId: binding.bindingId,
        effects,
        checkpoints: stores.cleanup,
        now,
        primaryError: null,
      });
    },
    close: closeAll,
  });
}
