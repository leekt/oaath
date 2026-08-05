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

import { type CaptureContext, captureDenseArray } from "@oaath/protocol";
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
import {
  captureAuthorizationCapability,
  captureIssuerCapability,
  createConnection,
  type OaathAuthorizationCapability,
  type OaathConnection,
  type OaathIssuerCapability,
} from "./client/connection.js";
import { clientCapability, clientFail, exactClientRecord } from "./client/errors.js";
import { requireApprovedKeyBinding } from "./client/key-credential.js";
import {
  captureChainCapability,
  type OaathCapabilityInvalidationCapability,
  type OaathChainCapability,
  type OaathGrantHandle,
} from "./client/grant-handle.js";
import { isBuiltInKeyKind, isCustomKeyKind, KEY_PROFILE_KEYS } from "./kernel/internal.js";
import type { KeyProfile } from "./kernel/types.js";
import type {
  OaathCleanupCheckpointStore,
  OaathContextStore,
  OaathKeyStore,
} from "./persistence/interfaces.js";
import { persistenceId } from "./persistence/interfaces.js";
import { GrantStore, type GrantStoreAdapter, type OperationStoreAdapter } from "./store.js";

const MAX_CHAINS = 32;
const MAX_LOCAL_KEYS = 8;

export interface OaathStoreConfiguration {
  readonly grants: GrantStoreAdapter;
  readonly operations: OperationStoreAdapter;
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

export interface OaathConfiguration {
  readonly binding: Readonly<OaathBindingInput>;
  readonly issuer: Readonly<OaathIssuerCapability>;
  readonly authorization: Readonly<OaathAuthorizationCapability>;
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
  "issuer",
  "authorization",
  "invalidation",
  "stores",
  "chains",
  "signing",
  "localKeyIds",
  "now",
]);

const STORE_KEYS: readonly string[] = Object.freeze([
  "grants",
  "operations",
  "keys",
  "cleanup",
  "context",
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

export function createOAAth(configuration: unknown): Readonly<Oaath> {
  const context: CaptureContext = new WeakSet();
  const record = exactClientRecord(
    configuration,
    CONFIGURATION_KEYS,
    "OAAth configuration",
    context,
  );
  const binding = captureOaathBinding(record.binding);
  const issuer = captureIssuerCapability(record.issuer);
  if (issuer.url !== binding.issuer.url) {
    clientFail(
      "oaath_client_capability_invalid",
      "the issuer transport does not serve the bound issuer",
    );
  }
  const authorization = captureAuthorizationCapability(record.authorization);
  const invalidation = storePort<Readonly<OaathCapabilityInvalidationCapability>>(
    record.invalidation,
    ["invalidateCapability"],
    "capability invalidation",
    context,
  );
  const storeRecord = exactClientRecord(
    record.stores,
    STORE_KEYS,
    "OAAth stores",
    context,
    "oaath_client_capability_invalid",
  );
  const stores = Object.freeze({
    grants: storePort<GrantStoreAdapter>(
      storeRecord.grants,
      ["get", "compareAndSwap", "close"],
      "Grant store",
      context,
    ),
    operations: storePort<OperationStoreAdapter>(
      storeRecord.operations,
      ["get", "compareAndSwap", "close"],
      "Operation store",
      context,
    ),
    keys: storePort<OaathKeyStore>(
      storeRecord.keys,
      ["store", "get", "delete", "close"],
      "key store",
      context,
    ),
    cleanup: storePort<OaathCleanupCheckpointStore>(
      storeRecord.cleanup,
      ["read", "write", "clear", "close"],
      "cleanup store",
      context,
    ),
    context: storePort<OaathContextStore>(
      storeRecord.context,
      ["read", "write", "clear", "close"],
      "context store",
      context,
    ),
  });
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

  function open(): Readonly<OaathConnection> {
    const connection = createConnection({
      binding,
      issuer,
      authorization,
      grants: new GrantStore(stores.grants),
      operations: stores.operations,
      keys: stores.keys,
      contexts: stores.context,
      chains,
      ownerKey,
      sessionKey,
      invalidation,
      now,
    });
    connections.push(connection);
    return connection;
  }

  async function closeAll(): Promise<void> {
    const failures: unknown[] = [];
    for (const connection of connections.splice(0)) {
      await connection.close().catch((error: unknown) => failures.push(error));
    }
    const failure = failures[0];
    if (failure !== undefined) throw failure;
  }

  return Object.freeze({
    binding,
    async connect(): Promise<Readonly<OaathConnection>> {
      return open();
    },
    disconnect(grant: Readonly<OaathGrantHandle> | null): Promise<Readonly<OaathCleanupResult>> {
      if (grant !== null && typeof grant.revoke !== "function") {
        clientFail("oaath_client_input_invalid", "disconnect grant is invalid");
      }
      const open_ = [...connections];
      // Order: authority first, then authentication, then local state, then
      // resources. `close` is last because it disables the effects before it.
      const effects: OaathCleanupEffect[] = [
        ...(grant === null ? [] : [revokeEffect(grant)]),
        signOutEffect(async () => {
          for (const connection of open_) await connection.signOut();
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
