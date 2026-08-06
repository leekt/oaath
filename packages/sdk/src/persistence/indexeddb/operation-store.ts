/**
 * Per-chain Operation records in IndexedDB.
 *
 * Current and archived records use namespaced composite keys in one object
 * store. No grantId can collide with a namespace, and archive plus current
 * replacement commits in one `readwrite` transaction.
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

function keyParts(value: Readonly<OperationStoreKey>): readonly [string, number, string] {
  const chainId = value.chainId;
  if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId < 1) {
    return persistenceFail("persistence_input_invalid", "IndexedDB chainId must be positive");
  }
  if (value.kind !== "execution" && value.kind !== "revocation") {
    return persistenceFail("persistence_input_invalid", "IndexedDB kind must name a lane");
  }
  return [persistenceId(value.grantId, "IndexedDB grantId"), chainId, value.kind];
}

function laneKey(value: Readonly<OperationStoreKey>): IDBValidKey {
  return ["lane", ...keyParts(value)];
}

function archiveKey(value: Readonly<OperationStoreKey>, userOperationHash: string): IDBValidKey {
  if (!/^0x[0-9a-f]{64}$/u.test(userOperationHash)) {
    return persistenceFail(
      "persistence_input_invalid",
      "IndexedDB UserOperation hash must be a lowercase 32-byte hash",
    );
  }
  return ["archive", ...keyParts(value), userOperationHash];
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
    async getArchived(
      input: Parameters<OperationStoreAdapter["getArchived"]>[0],
    ): Promise<unknown> {
      const archive = archiveKey(input.key, input.userOperationHash);
      return database.transact(operations, "readonly", ([store]) =>
        store === undefined ? undefined : readRecord(store, archive),
      );
    },
    async compareAndSwap(input: {
      readonly key: Readonly<OperationStoreKey>;
      readonly expectedStoreRevision: number | null;
      readonly next: Readonly<StoreRecord<unknown>>;
      readonly archive: Parameters<OperationStoreAdapter["compareAndSwap"]>[0]["archive"];
    }): Promise<unknown> {
      const lane = laneKey(input.key);
      return database.transact(operations, "readwrite", async ([store]) => {
        if (store === undefined) return false;
        const current = await readRecord(store, lane);
        if (!matchesExpectedRevision(current, input.expectedStoreRevision)) return false;
        if (input.archive !== null) {
          const archive = archiveKey(input.key, input.archive.userOperationHash);
          if (
            JSON.stringify(current) !== JSON.stringify(input.archive.record) ||
            (await readRecord(store, archive)) !== undefined
          ) {
            return false;
          }
          await putRecord(store, archive, input.archive.record);
        }
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
