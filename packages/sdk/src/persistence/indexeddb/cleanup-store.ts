/**
 * Crash-left destructive cleanup checkpoints in IndexedDB.
 *
 * A checkpoint is written only after an effect succeeded, so a record left by a
 * crash names exactly the effects that are already done. Everything absent from
 * it is retryable. `parseCleanupCheckpoint` owns the record shape; this adapter
 * only moves it.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type OaathCleanupCheckpoint,
  type OaathCleanupCheckpointStore,
  persistenceId,
} from "../interfaces.js";
import {
  deleteRecord,
  OAATH_INDEXEDDB_STORES,
  type OaathDatabase,
  putRecord,
  readRecord,
} from "./database.js";

export function createIndexedDbCleanupStore(database: OaathDatabase): OaathCleanupCheckpointStore {
  const cleanup = [OAATH_INDEXEDDB_STORES.cleanup] as const;
  return Object.freeze({
    async read(cleanupId: string): Promise<unknown> {
      const key = persistenceId(cleanupId, "IndexedDB cleanupId");
      return database.transact(cleanup, "readonly", ([store]) =>
        store === undefined ? undefined : readRecord(store, key),
      );
    },
    async write(checkpoint: Readonly<OaathCleanupCheckpoint>): Promise<unknown> {
      const key = persistenceId(checkpoint.cleanupId, "IndexedDB cleanupId");
      return database.transact(cleanup, "readwrite", async ([store]) =>
        store === undefined ? undefined : putRecord(store, key, checkpoint),
      );
    },
    async clear(cleanupId: string): Promise<unknown> {
      const key = persistenceId(cleanupId, "IndexedDB cleanupId");
      return database.transact(cleanup, "readwrite", async ([store]) =>
        store === undefined ? undefined : deleteRecord(store, key),
      );
    },
    async close(): Promise<unknown> {
      // The realm owns the connection; the checkpoint store never closes it.
      return undefined;
    },
  });
}
