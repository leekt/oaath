/**
 * All-chain Grant records in IndexedDB, with compare-and-swap on the stored
 * revision inside one transaction.
 *
 * `GrantStore` owns the record shape, the revision arithmetic, and the identity
 * rules; this adapter only reads and conditionally writes. The comparison and
 * the write share one `readwrite` transaction, so a concurrent realm cannot land
 * between them.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { GrantStoreAdapter, StoreRecord } from "../../store.js";
import { persistenceId } from "../interfaces.js";
import {
  matchesExpectedRevision,
  OAATH_INDEXEDDB_STORES,
  type OaathDatabase,
  putRecord,
  readRecord,
} from "./database.js";

export function createIndexedDbGrantStoreAdapter(database: OaathDatabase): GrantStoreAdapter {
  const grants = [OAATH_INDEXEDDB_STORES.grants] as const;
  return Object.freeze({
    async get(grantId: string): Promise<unknown> {
      const key = persistenceId(grantId, "IndexedDB grantId");
      return database.transact(grants, "readonly", ([store]) =>
        store === undefined ? undefined : readRecord(store, key),
      );
    },
    async compareAndSwap(input: {
      readonly grantId: string;
      readonly expectedStoreRevision: number | null;
      readonly next: Readonly<StoreRecord<unknown>>;
    }): Promise<unknown> {
      const key = persistenceId(input.grantId, "IndexedDB grantId");
      return database.transact(grants, "readwrite", async ([store]) => {
        if (store === undefined) return false;
        const current = await readRecord(store, key);
        if (!matchesExpectedRevision(current, input.expectedStoreRevision)) return false;
        await putRecord(store, key, input.next);
        return true;
      });
    },
    async close(): Promise<unknown> {
      // The realm owns the connection; a record store never closes it.
      return undefined;
    },
  });
}
