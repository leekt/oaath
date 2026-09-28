/** Browser persistence shared by the service and local compositions. */
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

export interface OwnedDefaultStores {
  readonly stores: Readonly<Record<string, unknown>>;
  readonly close: () => Promise<void>;
}

export async function defaultStores(): Promise<Readonly<OwnedDefaultStores>> {
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
