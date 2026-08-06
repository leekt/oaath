/**
 * Per-chain Operation records in IndexedDB.
 *
 * The key is the composite `[grantId, chainId, kind]`, so no separator
 * character in a grantId can make two lanes collide, one chain's journal can
 * never be read or written under another chain's key, and execution and
 * revocation work hold independent lanes. Compare-and-swap on the stored
 * revision happens inside one `readwrite` transaction.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { OperationStoreAdapter, OperationStoreKey, StoreRecord } from "../../store.js";
import { persistenceFail, persistenceId } from "../interfaces.js";
import {
  matchesExpectedRevision,
  OAATH_INDEXEDDB_STORES,
  type OaathDatabase,
  putRecord,
  readRecord,
} from "./database.js";

function laneKey(value: Readonly<OperationStoreKey>): IDBValidKey {
  const chainId = value.chainId;
  if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId < 1) {
    return persistenceFail("persistence_input_invalid", "IndexedDB chainId must be positive");
  }
  if (value.kind !== "execution" && value.kind !== "revocation") {
    return persistenceFail("persistence_input_invalid", "IndexedDB kind must name a lane");
  }
  return [persistenceId(value.grantId, "IndexedDB grantId"), chainId, value.kind];
}

export function createIndexedDbOperationStoreAdapter(
  database: OaathDatabase,
): OperationStoreAdapter {
  const operations = [OAATH_INDEXEDDB_STORES.operations] as const;
  return Object.freeze({
    async get(key: Readonly<OperationStoreKey>): Promise<unknown> {
      const lane = laneKey(key);
      return database.transact(operations, "readonly", ([store]) =>
        store === undefined ? undefined : readRecord(store, lane),
      );
    },
    async compareAndSwap(input: {
      readonly key: Readonly<OperationStoreKey>;
      readonly expectedStoreRevision: number | null;
      readonly next: Readonly<StoreRecord<unknown>>;
    }): Promise<unknown> {
      const lane = laneKey(input.key);
      return database.transact(operations, "readwrite", async ([store]) => {
        if (store === undefined) return false;
        const current = await readRecord(store, lane);
        if (!matchesExpectedRevision(current, input.expectedStoreRevision)) return false;
        await putRecord(store, lane, input.next);
        return true;
      });
    },
    async close(): Promise<unknown> {
      // The realm owns the connection; a record store never closes it.
      return undefined;
    },
  });
}
