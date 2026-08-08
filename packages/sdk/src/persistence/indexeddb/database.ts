/**
 * One current IndexedDB schema. There is no upgrade reader and no migration:
 * old persisted state is rejected and recreated.
 *
 * ```text
 * state and owner     the numeric database version and exact store set carry
 *                     the one current schema; an upgrade wipes before recreating
 * persisted evidence  grants, operations, wallet-call bundles, prepared-call
 *                     contexts, keys, cleanup, and context object stores
 * resource occupied?  one connection per realm, closed by the realm
 * retry safe?         current-schema opens do not mutate; every upgrade wipes
 *                     all stores before recreating the exact current set
 * crash/reload        a half-created database has the wrong store set, so the
 *                     next open discards and recreates it
 * cleanup owner       the realm that opened the handle closes it; discarded
 *                     databases are deleted here
 * ```
 *
 * Records are moved, never interpreted: every value is handed back as `unknown`
 * to the fact's owner (`GrantStore`, `OperationStore`, `WalletCallBundleStore`,
 * `PreparedCallStore`, `parseCleanupCheckpoint`, `parseClientContext`,
 * `requireNonExtractableKey`).
 *
 * @author taek <leekt216@gmail.com>
 */
import { persistenceFail } from "../interfaces.js";

/**
 * One name, one current schema. Pre-release there is no migration story: a
 * schema change bumps the numeric IndexedDB version below, and the upgrade
 * handler wipes every store — stale data from an older shape is discarded
 * wholesale, never read through the current one (an old-shape journal read
 * through a new key would be silently invisible, which is worse than gone).
 */
export const OAATH_INDEXEDDB_NAME = "oaath.browser-state/v1" as const;
/** Bumped on any schema change; the upgrade wipes, it never migrates. */
export const OAATH_INDEXEDDB_VERSION = 13;

export const OAATH_INDEXEDDB_STORES = Object.freeze({
  grants: "grants",
  operations: "operations",
  walletCallBundles: "walletCallBundles",
  preparedCallContexts: "preparedCallContexts",
  keys: "keys",
  cleanup: "cleanup",
  context: "context",
} as const);

export type OaathObjectStoreName =
  (typeof OAATH_INDEXEDDB_STORES)[keyof typeof OAATH_INDEXEDDB_STORES];

const STORE_NAMES: readonly OaathObjectStoreName[] = Object.freeze(
  Object.values(OAATH_INDEXEDDB_STORES),
);

/** Any database this schema family ever owned, so a retired one can be deleted. */
const RETIRED_NAME = /^oaath\.browser-state\/v\d+$/u;

export interface OpenOaathDatabaseInput {
  /** Defaults to `globalThis.indexedDB`. */
  readonly factory?: IDBFactory;
  /** Defaults to `OAATH_INDEXEDDB_NAME`; tests use it to isolate realms. */
  readonly name?: string;
}

export interface OaathDatabase {
  readonly name: string;
  readonly version: number;
  readonly close: () => void;
  /** Runs one transaction over the named stores and resolves after it commits. */
  readonly transact: <Value>(
    stores: readonly OaathObjectStoreName[],
    mode: "readonly" | "readwrite",
    body: (stores: readonly IDBObjectStore[]) => Promise<Value> | Value,
  ) => Promise<Value>;
}

function requestValue<Value>(request: IDBRequest<Value>): Promise<Value> {
  return new Promise<Value>((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed"));
  });
}

export function readRecord(store: IDBObjectStore, key: IDBValidKey): Promise<unknown> {
  return requestValue(store.get(key));
}

export function putRecord(
  store: IDBObjectStore,
  key: IDBValidKey,
  value: unknown,
): Promise<IDBValidKey> {
  return requestValue(store.put(value, key));
}

export function deleteRecord(store: IDBObjectStore, key: IDBValidKey): Promise<undefined> {
  return requestValue(store.delete(key));
}

/**
 * Whether the stored record is exactly at the revision a compare-and-swap
 * expects. A present but unreadable record never matches, so it is never
 * silently overwritten as if it were absent.
 */
export function matchesExpectedRevision(current: unknown, expected: number | null): boolean {
  if (current === undefined) return expected === null;
  if (!current || typeof current !== "object") return false;
  const revision = (current as { readonly storeRevision?: unknown }).storeRevision;
  return (
    typeof revision === "number" &&
    Number.isSafeInteger(revision) &&
    revision >= 0 &&
    revision === expected
  );
}

const LOWERCASE_32_BYTE_HASH = /^0x[0-9a-f]{64}$/u;

/** Matches one exact revision and immutable generation, or an initial absent insertion. */
export function matchesExpectedRevisionAndGeneration(
  current: unknown,
  expectedRevision: number | null,
  expectedGeneration: string | null,
): boolean {
  if (expectedRevision === null || expectedGeneration === null) {
    return expectedRevision === null && expectedGeneration === null && current === undefined;
  }
  if (
    !LOWERCASE_32_BYTE_HASH.test(expectedGeneration) ||
    current === null ||
    typeof current !== "object"
  ) {
    return false;
  }
  const revisionDescriptor = Object.getOwnPropertyDescriptor(current, "storeRevision");
  if (!revisionDescriptor || !("value" in revisionDescriptor)) return false;
  const revision = revisionDescriptor.value;
  if (
    typeof revision !== "number" ||
    !Number.isSafeInteger(revision) ||
    revision < 0 ||
    revision !== expectedRevision
  ) {
    return false;
  }
  const valueDescriptor = Object.getOwnPropertyDescriptor(current, "value");
  if (!valueDescriptor || !("value" in valueDescriptor)) return false;
  const value = valueDescriptor.value;
  if (value === null || typeof value !== "object") return false;
  const generationDescriptor = Object.getOwnPropertyDescriptor(value, "generation");
  return (
    generationDescriptor !== undefined &&
    "value" in generationDescriptor &&
    generationDescriptor.value === expectedGeneration
  );
}

function requireFactory(input: Readonly<OpenOaathDatabaseInput>): IDBFactory {
  const factory = input.factory ?? globalThis.indexedDB;
  if (!factory || typeof factory.open !== "function") {
    return persistenceFail("persistence_unavailable", "IndexedDB is unavailable in this realm");
  }
  return factory;
}

function openConnection(factory: IDBFactory, name: string): Promise<IDBDatabase> {
  return new Promise<IDBDatabase>((resolve, reject) => {
    const request = factory.open(name, OAATH_INDEXEDDB_VERSION);
    request.onupgradeneeded = () => {
      const database = request.result;
      // No upgrade reader: whatever an earlier build left is dropped, not read.
      for (const existing of Array.from(database.objectStoreNames)) {
        database.deleteObjectStore(existing);
      }
      for (const store of STORE_NAMES) database.createObjectStore(store);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB open failed"));
    request.onblocked = () => reject(new Error("IndexedDB open is blocked by another connection"));
  });
}

function deleteDatabase(factory: IDBFactory, name: string): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const request = factory.deleteDatabase(name);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error ?? new Error("IndexedDB delete failed"));
    // A blocked delete leaves the old realm in place, which fails closed below.
    request.onblocked = () => reject(new Error("IndexedDB delete is blocked"));
  });
}

function hasCurrentSchema(database: IDBDatabase): boolean {
  const present = Array.from(database.objectStoreNames);
  return (
    present.length === STORE_NAMES.length && STORE_NAMES.every((store) => present.includes(store))
  );
}

/** Deletes every retired schema-family database this realm still holds. */
async function discardRetiredRealms(factory: IDBFactory, current: string): Promise<void> {
  if (typeof factory.databases !== "function") return;
  let listed: readonly IDBDatabaseInfo[];
  try {
    listed = await factory.databases();
  } catch {
    return;
  }
  for (const entry of listed) {
    if (typeof entry.name === "string" && entry.name !== current && RETIRED_NAME.test(entry.name)) {
      await deleteDatabase(factory, entry.name);
    }
  }
}

/**
 * Opens the one current schema. A database that does not carry exactly the
 * current object stores — a partially created realm, or one an older build left
 * under this name — is deleted and recreated once, then required to match.
 */
export async function openOaathDatabase(
  input: Readonly<OpenOaathDatabaseInput> = {},
): Promise<OaathDatabase> {
  const factory = requireFactory(input);
  const name = input.name ?? OAATH_INDEXEDDB_NAME;
  if (typeof name !== "string" || name.length < 1 || name.length > 256) {
    return persistenceFail("persistence_input_invalid", "IndexedDB name must be a bounded string");
  }
  await discardRetiredRealms(factory, name);

  let database: IDBDatabase;
  try {
    database = await openConnection(factory, name);
  } catch {
    return persistenceFail("persistence_unavailable", "IndexedDB could not be opened");
  }
  if (!hasCurrentSchema(database)) {
    database.close();
    try {
      await deleteDatabase(factory, name);
      database = await openConnection(factory, name);
    } catch {
      return persistenceFail(
        "persistence_schema_unusable",
        "IndexedDB realm could not be recreated",
      );
    }
    if (!hasCurrentSchema(database)) {
      database.close();
      return persistenceFail(
        "persistence_schema_unusable",
        "IndexedDB schema is not the current one",
      );
    }
  }

  let closed = false;
  return Object.freeze({
    name,
    version: OAATH_INDEXEDDB_VERSION,
    close() {
      if (closed) return;
      closed = true;
      database.close();
    },
    async transact<Value>(
      stores: readonly OaathObjectStoreName[],
      mode: "readonly" | "readwrite",
      body: (opened: readonly IDBObjectStore[]) => Promise<Value> | Value,
    ): Promise<Value> {
      if (closed) persistenceFail("persistence_unavailable", "IndexedDB realm is closed");
      if (stores.length < 1) {
        persistenceFail("persistence_input_invalid", "a transaction needs at least one store");
      }
      let transaction: IDBTransaction;
      try {
        transaction = database.transaction([...stores], mode);
      } catch {
        return persistenceFail("persistence_transaction_failed", "IndexedDB transaction failed");
      }
      const settled = new Promise<void>((resolve, reject) => {
        transaction.oncomplete = () => resolve();
        transaction.onerror = () => reject(transaction.error ?? new Error("transaction failed"));
        transaction.onabort = () => reject(transaction.error ?? new Error("transaction aborted"));
      });
      let value: Value;
      try {
        value = await body(stores.map((store) => transaction.objectStore(store)));
      } catch (error) {
        try {
          transaction.abort();
        } catch {
          // The transaction already settled; its own failure is reported below.
        }
        settled.catch(() => undefined);
        throw error;
      }
      try {
        await settled;
      } catch {
        return persistenceFail(
          "persistence_transaction_failed",
          "IndexedDB transaction did not commit",
        );
      }
      return value;
    },
  });
}
