import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import type { OaathStoreConfiguration } from "@oaath/sdk/advanced";
import {
  createIndexedDbCleanupStore,
  createIndexedDbContextStore,
  createIndexedDbGrantStoreAdapter,
  createIndexedDbKeyStore,
  createIndexedDbOperationStoreAdapter,
  createIndexedDbPreparedCallStoreAdapter,
  createIndexedDbWalletCallBundleStoreAdapter,
  openOaathDatabase,
} from "@oaath/sdk/persistence";
import type { IDBFactory } from "fake-indexeddb";
import {
  createSqliteContextStore,
  createSqliteGrantStoreAdapter,
  createSqliteOperationStoreAdapter,
} from "./sqlite-store.js";

/** Only direct Grant/Operation/context persistence is claimed by this test fixture. */
export async function openLocalClientStores(factory: IDBFactory, stateDirectory?: string) {
  if (stateDirectory !== undefined) {
    if (typeof stateDirectory !== "string" || stateDirectory.length === 0)
      throw new Error("local_fixture_storage_invalid");
    await mkdir(stateDirectory, { recursive: true, mode: 0o700 });
  }
  const database = await openOaathDatabase({ factory });
  const owned: Array<{ close: () => Promise<unknown> }> = [];
  let databaseClosed = false;
  function track<T extends { close: () => Promise<unknown> }>(store: T): T {
    let closed = false;
    const port = {
      ...store,
      async close() {
        if (!closed) {
          await store.close();
          closed = true;
        }
      },
    };
    owned.push(port);
    return port;
  }
  async function close() {
    const results = await Promise.allSettled(owned.map((store) => store.close()));
    if (!databaseClosed) {
      database.close();
      databaseClosed = true;
    }
    if (results.some((result) => result.status === "rejected"))
      throw new Error("local_fixture_cleanup_failed");
  }
  try {
    const file = stateDirectory === undefined ? null : join(stateDirectory, "client.sqlite");
    const stores: OaathStoreConfiguration = {
      grants: track(
        file === null
          ? createIndexedDbGrantStoreAdapter(database)
          : createSqliteGrantStoreAdapter(file),
      ),
      operations: track(
        file === null
          ? createIndexedDbOperationStoreAdapter(database)
          : createSqliteOperationStoreAdapter(file),
      ),
      context: track(
        file === null ? createIndexedDbContextStore(database) : createSqliteContextStore(file),
      ),
      walletCallBundles: track(createIndexedDbWalletCallBundleStoreAdapter(database)),
      preparedCallContexts: track(createIndexedDbPreparedCallStoreAdapter(database)),
      keys: track(createIndexedDbKeyStore(database)),
      cleanup: track(createIndexedDbCleanupStore(database)),
    };
    return { stores, close };
  } catch {
    await close().catch(() => undefined);
    throw new Error("local_fixture_storage_unavailable");
  }
}
