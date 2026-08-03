/**
 * The realm's client context in IndexedDB, keyed by binding.
 *
 * One binding realm holds at most one active Grant context in `0.1.0`, so the
 * key is the binding id and a reload needs no application-supplied identifier.
 * `parseClientContext` owns the record shape and its attenuation rule; this
 * adapter only moves it.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type OaathClientContext, type OaathContextStore, persistenceId } from "../interfaces.js";
import {
  deleteRecord,
  OAATH_INDEXEDDB_STORES,
  type OaathDatabase,
  putRecord,
  readRecord,
} from "./database.js";

export function createIndexedDbContextStore(database: OaathDatabase): OaathContextStore {
  const context = [OAATH_INDEXEDDB_STORES.context] as const;
  return Object.freeze({
    async read(bindingId: string): Promise<unknown> {
      const key = persistenceId(bindingId, "IndexedDB bindingId");
      return database.transact(context, "readonly", ([store]) =>
        store === undefined ? undefined : readRecord(store, key),
      );
    },
    async write(value: Readonly<OaathClientContext>): Promise<unknown> {
      const key = persistenceId(value.bindingId, "IndexedDB bindingId");
      return database.transact(context, "readwrite", async ([store]) =>
        store === undefined ? undefined : putRecord(store, key, value),
      );
    },
    async clear(bindingId: string): Promise<unknown> {
      const key = persistenceId(bindingId, "IndexedDB bindingId");
      return database.transact(context, "readwrite", async ([store]) =>
        store === undefined ? undefined : deleteRecord(store, key),
      );
    },
    async close(): Promise<unknown> {
      // The realm owns the connection; the context store never closes it.
      return undefined;
    },
  });
}
