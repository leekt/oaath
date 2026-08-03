/**
 * WebCrypto key custody in IndexedDB.
 *
 * Only a non-extractable `CryptoKey` handle is ever stored, and the store has no
 * export path: the handle goes in, the same kind of handle comes out, and the
 * private material is never represented as bytes anywhere in this module. A
 * persisted value that is not a non-extractable handle fails closed instead of
 * being returned to a signer.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type OaathKeyStore, persistenceId, requireNonExtractableKey } from "../interfaces.js";
import {
  deleteRecord,
  OAATH_INDEXEDDB_STORES,
  type OaathDatabase,
  putRecord,
  readRecord,
} from "./database.js";

export function createIndexedDbKeyStore(database: OaathDatabase): OaathKeyStore {
  const keys = [OAATH_INDEXEDDB_STORES.keys] as const;
  return Object.freeze({
    async store(input: Readonly<{ keyId: string; key: CryptoKey }>): Promise<unknown> {
      const keyId = persistenceId(input.keyId, "IndexedDB keyId");
      const handle = requireNonExtractableKey(input.key);
      return database.transact(keys, "readwrite", async ([store]) =>
        store === undefined ? undefined : putRecord(store, keyId, handle),
      );
    },
    async get(keyId: string): Promise<unknown> {
      const key = persistenceId(keyId, "IndexedDB keyId");
      const stored = await database.transact(keys, "readonly", ([store]) =>
        store === undefined ? undefined : readRecord(store, key),
      );
      return stored === undefined ? undefined : requireNonExtractableKey(stored);
    },
    async delete(keyId: string): Promise<unknown> {
      const key = persistenceId(keyId, "IndexedDB keyId");
      return database.transact(keys, "readwrite", async ([store]) =>
        store === undefined ? undefined : deleteRecord(store, key),
      );
    },
    async close(): Promise<unknown> {
      // The realm owns the connection; key custody never closes it.
      return undefined;
    },
  });
}
