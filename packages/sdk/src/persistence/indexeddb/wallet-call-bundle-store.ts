/**
 * Provider-scoped EIP-5792 wallet-call bundles in IndexedDB.
 *
 * The adapter moves opaque envelopes under the exact composite
 * `[providerScopeId, account, id]` key. `WalletCallBundleStore` owns all record
 * parsing and lifecycle rules; this backend only compares the envelope's store
 * revision and generation before conditionally writing in one transaction.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { StoreRecord } from "../../store.js";
import {
  MAX_WALLET_CALL_BUNDLE_RECORDS_PER_SCOPE,
  parseWalletCallBundleKey,
  WALLET_CALL_BUNDLE_SCOPE_CAPACITY_EXHAUSTED,
  type WalletCallBundleKey,
  type WalletCallBundleStoreAdapter,
} from "../interfaces.js";
import {
  matchesExpectedRevisionAndGeneration,
  OAATH_INDEXEDDB_STORES,
  type OaathDatabase,
  putRecord,
  readRecord,
} from "./database.js";

function bundleKey(value: Readonly<WalletCallBundleKey>): IDBValidKey {
  const key = parseWalletCallBundleKey(value);
  return [key.providerScopeId, key.account, key.id];
}

function requestResult<Value>(request: IDBRequest<Value>): Promise<Value> {
  return new Promise<Value>((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed"));
  });
}

async function scopeRecordCount(store: IDBObjectStore, scope: string): Promise<number> {
  const keys = await requestResult(store.getAllKeys());
  let count = 0;
  for (const key of keys) {
    if (Array.isArray(key) && key[0] === scope) count += 1;
  }
  return count;
}

export function createIndexedDbWalletCallBundleStoreAdapter(
  database: OaathDatabase,
  options: Readonly<{ maxRecordsPerScope?: number }> = {},
): WalletCallBundleStoreAdapter {
  const maxRecordsPerScope = options.maxRecordsPerScope ?? MAX_WALLET_CALL_BUNDLE_RECORDS_PER_SCOPE;
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
      readonly expectedGeneration: `0x${string}` | null;
      readonly next: Readonly<StoreRecord<unknown>>;
    }): Promise<unknown> {
      const compositeKey = bundleKey(input.key);
      return database.transact(walletCallBundles, "readwrite", async ([store]) => {
        if (store === undefined) return false;
        const current = await readRecord(store, compositeKey);
        if (
          !matchesExpectedRevisionAndGeneration(
            current,
            input.expectedStoreRevision,
            input.expectedGeneration,
          )
        ) {
          return false;
        }
        if (input.expectedStoreRevision === null && input.expectedGeneration === null) {
          if ((await scopeRecordCount(store, input.key.providerScopeId)) >= maxRecordsPerScope) {
            return WALLET_CALL_BUNDLE_SCOPE_CAPACITY_EXHAUSTED;
          }
        }
        await putRecord(store, compositeKey, input.next);
        return true;
      });
    },
    async close(): Promise<unknown> {
      // The realm owns the connection; a record store never closes it.
      return undefined;
    },
  });
}
