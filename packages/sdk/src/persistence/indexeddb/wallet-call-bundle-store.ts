/**
 * Provider-scoped EIP-5792 wallet-call bundles in IndexedDB.
 *
 * The adapter moves opaque envelopes under the exact composite
 * `[providerScopeId, account, id]` key. `WalletCallBundleStore` owns all record
 * parsing and lifecycle rules; this backend only compares the envelope's store
 * revision and conditionally writes or deletes in one transaction.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { StoreRecord } from "../../store.js";
import {
  parseWalletCallBundleKey,
  type WalletCallBundleKey,
  type WalletCallBundleStoreAdapter,
} from "../interfaces.js";
import {
  deleteRecord,
  matchesExpectedRevision,
  OAATH_INDEXEDDB_STORES,
  type OaathDatabase,
  putRecord,
  readRecord,
} from "./database.js";

function bundleKey(value: Readonly<WalletCallBundleKey>): IDBValidKey {
  const key = parseWalletCallBundleKey(value);
  return [key.providerScopeId, key.account, key.id];
}

export function createIndexedDbWalletCallBundleStoreAdapter(
  database: OaathDatabase,
): WalletCallBundleStoreAdapter {
  const walletCallBundles = [OAATH_INDEXEDDB_STORES.walletCallBundles] as const;
  return Object.freeze({
    async get(key: Readonly<WalletCallBundleKey>): Promise<unknown> {
      const compositeKey = bundleKey(key);
      return database.transact(walletCallBundles, "readonly", ([store]) =>
        store === undefined ? undefined : readRecord(store, compositeKey),
      );
    },
    async compareAndSwap(input: {
      readonly key: Readonly<WalletCallBundleKey>;
      readonly expectedStoreRevision: number | null;
      readonly next: Readonly<StoreRecord<unknown>>;
    }): Promise<unknown> {
      const compositeKey = bundleKey(input.key);
      return database.transact(walletCallBundles, "readwrite", async ([store]) => {
        if (store === undefined) return false;
        const current = await readRecord(store, compositeKey);
        if (!matchesExpectedRevision(current, input.expectedStoreRevision)) return false;
        await putRecord(store, compositeKey, input.next);
        return true;
      });
    },
    async compareAndDelete(input: {
      readonly key: Readonly<WalletCallBundleKey>;
      readonly expectedStoreRevision: number;
    }): Promise<unknown> {
      const compositeKey = bundleKey(input.key);
      return database.transact(walletCallBundles, "readwrite", async ([store]) => {
        if (store === undefined) return false;
        const current = await readRecord(store, compositeKey);
        if (!matchesExpectedRevision(current, input.expectedStoreRevision)) return false;
        await deleteRecord(store, compositeKey);
        return true;
      });
    },
    async close(): Promise<unknown> {
      // The realm owns the connection; a record store never closes it.
      return undefined;
    },
  });
}
