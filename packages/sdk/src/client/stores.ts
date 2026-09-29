/**
 * The `stores` setting: one named backend plus optional per-store overrides.
 *
 * ```text
 * state and owner     the realm that opened the backend owns its handle; every
 *                     store port, override or backend, is closed by the realm
 * persisted evidence  IndexedDB keeps Grants, Operation journals, keys and
 *                     cleanup checkpoints across reloads; memory keeps nothing
 * resource occupied?  one IndexedDB connection per realm, opened only when a
 *                     required store is not overridden
 * retry positively    a failed open leaves nothing behind; the next connect
 *   safe?             opens again. Memory is never chosen for the caller
 * crash/reload        memory loses every Operation ID: nothing is resubmitted,
 *                     because a missing record never authorizes submission
 * cleanup owner       the opening realm closes the database after its ports
 * ```
 */
import { type CaptureContext, captureRecord } from "@oaath/protocol";
import type { OaathStoreConfiguration } from "../create-oaath.js";
import { createIndexedDbCleanupStore } from "../persistence/indexeddb/cleanup-store.js";
import { createIndexedDbContextStore } from "../persistence/indexeddb/context-store.js";
import { type OaathDatabase, openOaathDatabase } from "../persistence/indexeddb/database.js";
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
import { clientFail, clientFailure, exactClientRecord } from "./errors.js";
import { captureStorePort, type OaathStoreName, STORE_NAMES } from "./store-configuration.js";

/** Where the realm's durable state lives. */
export type OaathStoreBackend =
  | Readonly<{
      /** The browser default: survives reloads. */
      kind: "indexeddb";
      /** Defaults to `globalThis.indexedDB`. */
      factory?: IDBFactory;
      /** Defaults to the one OAAth database name; isolates realms that must not share state. */
      name?: string;
    }>
  | Readonly<{
      /**
       * Tests and non-browser development only: nothing survives the process.
       * An Operation in flight at exit is forgotten and never resubmitted.
       */
      kind: "memory";
    }>;

/** A backend plus any per-store adapter, e.g. a PostgreSQL Operation journal. */
export type OaathStores = OaathStoreBackend & Readonly<Partial<OaathStoreConfiguration>>;

export interface CapturedStores {
  readonly backend: OaathStoreBackend;
  readonly overrides: Readonly<Partial<OaathStoreConfiguration>>;
}

export interface OwnedStores<Name extends OaathStoreName> {
  readonly stores: Readonly<Pick<OaathStoreConfiguration, Name>>;
  /** Releases the backend handle; the realm closes the ports themselves. */
  readonly close: () => Promise<void>;
}

const DEFAULT: Readonly<CapturedStores> = Object.freeze({
  backend: Object.freeze({ kind: "indexeddb" as const }),
  overrides: Object.freeze({}),
});

/** Captures the `stores` option once, before any persistence access. */
export function captureStores(
  value: unknown,
  names: readonly OaathStoreName[],
  context: CaptureContext = new WeakSet(),
): Readonly<CapturedStores> {
  if (value === undefined) return DEFAULT;
  const fail = clientFailure("oaath_client_input_invalid");
  const initial = captureRecord(value, "OAAth stores", new WeakSet(), fail);
  const kind = initial.kind;
  if (kind !== "indexeddb" && kind !== "memory")
    return fail('OAAth stores kind must be "indexeddb" or "memory"');
  const allowed = ["kind", ...(kind === "indexeddb" ? ["factory", "name"] : []), ...names];
  const record = exactClientRecord(
    initial,
    allowed.filter((key) => Object.hasOwn(initial, key)),
    "OAAth stores",
    context,
  );
  const overrides: Partial<Record<OaathStoreName, unknown>> = {};
  for (const name of names) {
    if (record[name] !== undefined) overrides[name] = captureStorePort(name, record[name], context);
  }
  if (kind === "memory") {
    return Object.freeze({
      backend: Object.freeze({ kind }),
      overrides: Object.freeze(overrides) as CapturedStores["overrides"],
    });
  }
  if (record.factory !== undefined && typeof (record.factory as IDBFactory)?.open !== "function")
    return fail("OAAth stores IndexedDB factory is invalid");
  if (record.name !== undefined && typeof record.name !== "string")
    return fail("OAAth stores IndexedDB name must be a string");
  return Object.freeze({
    backend: Object.freeze({
      kind,
      ...(record.factory === undefined ? {} : { factory: record.factory as IDBFactory }),
      ...(record.name === undefined ? {} : { name: record.name }),
    }),
    overrides: Object.freeze(overrides) as CapturedStores["overrides"],
  });
}

const MEMORY: { readonly [Name in OaathStoreName]: () => OaathStoreConfiguration[Name] } = {
  grants: createMemoryGrantStoreAdapter,
  operations: createMemoryOperationStoreAdapter,
  walletCallBundles: () => createMemoryWalletCallBundleStoreAdapter(),
  preparedCallContexts: createMemoryPreparedCallStoreAdapter,
  keys: createMemoryKeyStore,
  cleanup: createMemoryCleanupStore,
  context: createMemoryContextStore,
};

const INDEXEDDB: {
  readonly [Name in OaathStoreName]: (database: OaathDatabase) => OaathStoreConfiguration[Name];
} = {
  grants: createIndexedDbGrantStoreAdapter,
  operations: createIndexedDbOperationStoreAdapter,
  walletCallBundles: (database) => createIndexedDbWalletCallBundleStoreAdapter(database),
  preparedCallContexts: createIndexedDbPreparedCallStoreAdapter,
  keys: createIndexedDbKeyStore,
  cleanup: createIndexedDbCleanupStore,
  context: createIndexedDbContextStore,
};

/**
 * Opens the named stores. The backend fills only stores without an override,
 * and IndexedDB is opened only when one is needed. A missing IndexedDB fails
 * closed: memory is an explicit choice, never a fallback.
 */
export async function openStores<Name extends OaathStoreName>(
  captured: Readonly<CapturedStores>,
  names: readonly Name[],
): Promise<Readonly<OwnedStores<Name>>> {
  const missing = names.filter((name) => captured.overrides[name] === undefined);
  const { backend } = captured;
  let database: OaathDatabase | null = null;
  if (missing.length > 0 && backend.kind === "indexeddb") {
    const factory =
      backend.factory ?? (globalThis as { indexedDB?: IDBFactory | undefined }).indexedDB;
    if (factory === undefined)
      return clientFail(
        "oaath_client_store_unavailable",
        'IndexedDB is unavailable; pass stores: { kind: "memory" } or durable store adapters',
      );
    database = await openOaathDatabase({
      factory,
      ...(backend.name === undefined ? {} : { name: backend.name }),
    });
  }
  const opened = database;
  const stores = Object.fromEntries(
    names.map((name) => [
      name,
      captured.overrides[name] ?? (opened === null ? MEMORY[name]() : INDEXEDDB[name](opened)),
    ]),
  ) as unknown as Pick<OaathStoreConfiguration, Name>;
  return Object.freeze({
    stores: Object.freeze(stores),
    close: async () => opened?.close(),
  });
}

/**
 * The full IndexedDB store set, for the injected `binding` composition. The
 * realm closes the store ports; `close` releases the database afterwards.
 */
export async function openIndexedDbStores(
  input: Readonly<{ factory?: IDBFactory; name?: string }> = {},
): Promise<Readonly<OwnedStores<OaathStoreName>>> {
  const setting = captureRecord(
    input,
    "IndexedDB stores",
    new WeakSet(),
    clientFailure("oaath_client_input_invalid"),
  );
  return openStores(captureStores({ ...setting, kind: "indexeddb" }, []), STORE_NAMES);
}

/** The full memory store set: nothing survives the process. */
export function createMemoryStores(): Readonly<OaathStoreConfiguration> {
  return Object.freeze(
    Object.fromEntries(STORE_NAMES.map((name) => [name, MEMORY[name]()])),
  ) as unknown as Readonly<OaathStoreConfiguration>;
}
