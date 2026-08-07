/**
 * Provider-scoped ERC-7836 prepared-call contexts in IndexedDB.
 *
 * The adapter moves opaque envelopes under the exact
 * `[providerScopeId, contextId]` key. `PreparedCallStore` owns all parsing and
 * lifecycle rules; this backend only compares the envelope revision before a
 * conditional write in one transaction.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type PreparedCallKey,
  type PreparedCallStoreAdapter,
  parsePreparedCallKey,
} from "../../provider/prepared-call-store.js";
import type { StoreRecord } from "../../store.js";
import {
  matchesExpectedRevision,
  OAATH_INDEXEDDB_STORES,
  type OaathDatabase,
  putRecord,
  readRecord,
} from "./database.js";

function preparedContextKey(value: Readonly<PreparedCallKey>): IDBValidKey {
  const key = parsePreparedCallKey(value);
  return [key.providerScopeId, key.contextId];
}

/** Raw prepared-call contexts; PreparedCallStore remains the lifecycle owner. */
export function createIndexedDbPreparedCallStoreAdapter(
  database: OaathDatabase,
): PreparedCallStoreAdapter {
  const preparedCallContexts = [OAATH_INDEXEDDB_STORES.preparedCallContexts] as const;
  return Object.freeze({
    async get(key: Readonly<PreparedCallKey>): Promise<unknown> {
      const compositeKey = preparedContextKey(key);
      return database.transact(preparedCallContexts, "readonly", ([store]) =>
        store === undefined ? undefined : readRecord(store, compositeKey),
      );
    },
    async compareAndSwap(input: {
      readonly key: Readonly<PreparedCallKey>;
      readonly expectedStoreRevision: number | null;
      readonly next: Readonly<StoreRecord<unknown>>;
    }): Promise<unknown> {
      const compositeKey = preparedContextKey(input.key);
      return database.transact(preparedCallContexts, "readwrite", async ([store]) => {
        if (store === undefined) return false;
        const current = await readRecord(store, compositeKey);
        if (!matchesExpectedRevision(current, input.expectedStoreRevision)) return false;
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
