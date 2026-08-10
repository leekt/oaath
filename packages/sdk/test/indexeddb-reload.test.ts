/**
 * Full realm recreation over IndexedDB.
 *
 * Every in-memory instance is discarded between the two halves of each test: a
 * new `IDBFactory`-backed connection, new adapters, new stores, a new
 * `createOAAth`, and a new connection. Nothing is injected directly into a
 * store; state comes back only through the persisted records.
 *
 * Evidence limit: `fake-indexeddb` provides the IndexedDB and structured-clone
 * semantics here, including non-extractable `CryptoKey` custody. The
 * real-Chromium extension path is owned by `smoke-packed-extension.mjs`.
 *
 * @author taek <leekt216@gmail.com>
 */
import { IDBFactory } from "fake-indexeddb";
import { afterEach, describe, expect, it } from "vitest";
import { GrantStore, OperationStore } from "../src/advanced.js";
import {
  createIndexedDbCleanupStore,
  createIndexedDbContextStore,
  createIndexedDbGrantStoreAdapter,
  createIndexedDbKeyStore,
  createIndexedDbOperationStoreAdapter,
  createIndexedDbWalletCallBundleStoreAdapter,
  OAATH_INDEXEDDB_NAME,
  OAATH_INDEXEDDB_STORES,
  OAATH_INDEXEDDB_VERSION,
  type OaathDatabase,
  openOaathDatabase,
  requireNonExtractableKey,
} from "../src/persistence.js";
import {
  ACCOUNT,
  CHAIN_ID,
  createChainFixture,
  createClock,
  createRealm,
  createRelay,
  permissionInput,
  type RealmStores,
  sendCallsInput,
} from "./support/browser.js";

const opened: OaathDatabase[] = [];

afterEach(() => {
  for (const database of opened.splice(0)) database.close();
});

async function openRealmDatabase(factory: IDBFactory): Promise<OaathDatabase> {
  const database = await openOaathDatabase({ factory });
  opened.push(database);
  return database;
}

function storesFor(database: OaathDatabase): RealmStores {
  return {
    grants: createIndexedDbGrantStoreAdapter(database),
    operations: createIndexedDbOperationStoreAdapter(database),
    walletCallBundles: createIndexedDbWalletCallBundleStoreAdapter(database),
    keys: createIndexedDbKeyStore(database),
    cleanup: createIndexedDbCleanupStore(database),
    context: createIndexedDbContextStore(database),
  };
}

async function nonExtractableKey(): Promise<CryptoKey> {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]);
  return pair.privateKey;
}

async function readStoreNames(factory: IDBFactory): Promise<readonly string[]> {
  return new Promise<readonly string[]>((resolve, reject) => {
    const request = factory.open(OAATH_INDEXEDDB_NAME, OAATH_INDEXEDDB_VERSION);
    request.onsuccess = () => {
      const database = request.result;
      const names = Array.from(database.objectStoreNames);
      database.close();
      resolve(names);
    };
    request.onerror = () => reject(request.error);
  });
}

describe("IndexedDB realm recreation", () => {
  it("restores an active Grant, its journal, and key custody after full recreation", async () => {
    const factory = new IDBFactory();
    const clock = createClock();
    const relay = createRelay(clock);

    const first = await openRealmDatabase(factory);
    const firstStores = storesFor(first);
    await firstStores.keys.store({ keyId: "session-key", key: await nonExtractableKey() });
    const before = createRealm({ clock, relay, stores: firstStores });
    const connection = await before.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const operation = await grant.sendCalls(sendCallsInput());
    expect((await operation.wait()).status).toBe("finalized");
    const archivedHash = before.chain.sends[0]?.userOperationHash;
    const grantId = before.chain.sends[0]?.grantId;
    if (!archivedHash || !grantId) throw new Error("expected one submitted operation");
    const replacement = await grant.sendCalls(sendCallsInput());
    expect((await replacement.wait()).status).toBe("finalized");
    const currentHash = before.chain.sends[1]?.userOperationHash;
    if (!currentHash) throw new Error("expected one replacing operation");

    // Recreate the whole realm: connection, stores, adapters, and the database.
    await connection.close();
    first.close();
    opened.splice(opened.indexOf(first), 1);

    const second = await openRealmDatabase(factory);
    const secondStores = storesFor(second);
    const after = createRealm({
      clock,
      relay,
      stores: secondStores,
      // The account already executed twice, so its on-chain sequence advanced.
      chain: createChainFixture({ startSequence: 2 }),
    });
    const restored = await (await after.oaath.connect()).resume();
    if (!restored) throw new Error("expected the persisted Grant to resume");
    expect(restored.state).toBe("active");

    // The journal restored the current identity and the exact terminal history.
    const journal = await new OperationStore(secondStores.operations).get({
      grantId,
      chainId: CHAIN_ID,
      kind: "execution",
    });
    expect(journal?.value.state).toBe("finalized");
    expect(journal?.value.identity.userOperationHash).toBe(currentHash);
    const archived = await new OperationStore(secondStores.operations).getExact(
      { grantId, chainId: CHAIN_ID, kind: "execution" },
      archivedHash,
    );
    expect(archived?.value.state).toBe("finalized");
    expect(archived?.value.identity.userOperationHash).toBe(archivedHash);

    // Key custody survived as a non-extractable handle with no export path.
    const handle = await secondStores.keys.get("session-key");
    expect(requireNonExtractableKey(handle).extractable).toBe(false);
    expect(Object.keys(secondStores.keys).sort()).toEqual(["close", "delete", "get", "store"]);

    // A new send after recreation reuses the restored authority and never
    // resubmits the finalized operation.
    const next = await restored.sendCalls(sendCallsInput());
    expect((await next.wait()).status).toBe("finalized");
    expect(after.chain.sends).toHaveLength(1);
    expect(after.chain.sends[0]?.userOperationHash).not.toBe(currentHash);
  });

  it("resumes a revoking Grant and completes its chain revocation after reload", async () => {
    const factory = new IDBFactory();
    const clock = createClock();
    const relay = createRelay(clock);

    // First life: pair and execute, then revoke against a chain that offers no
    // submission route — the capability dies but the installed permission
    // cannot be removed, so the Grant stays durably revoking.
    const first = await openRealmDatabase(factory);
    const before = createRealm({ clock, relay, stores: storesFor(first) });
    const connection = await before.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    expect((await (await grant.sendCalls(sendCallsInput())).wait()).status).toBe("finalized");
    await connection.close();
    first.close();
    opened.splice(opened.indexOf(first), 1);

    const second = await openRealmDatabase(factory);
    const routeless = createRealm({
      clock,
      relay,
      stores: storesFor(second),
      chain: createChainFixture({ startSequence: 1, bundler: "absent" }),
    });
    const stalled = await (await routeless.oaath.connect()).resume();
    if (!stalled) throw new Error("expected the persisted Grant to resume");
    await stalled.revoke();
    expect(stalled.state).toBe("revoking");
    second.close();
    opened.splice(opened.indexOf(second), 1);

    // Second life: resume must return the revoking Grant — it authorizes
    // nothing new, but its handle is the only path to finishing the removal.
    const third = await openRealmDatabase(factory);
    const recovered = createRealm({
      clock,
      relay,
      stores: storesFor(third),
      chain: createChainFixture({ startSequence: 1 }),
    });
    const revoking = await (await recovered.oaath.connect()).resume();
    if (!revoking) throw new Error("expected the revoking Grant to resume");
    expect(revoking.state).toBe("revoking");
    await expect(revoking.sendCalls(sendCallsInput())).rejects.toMatchObject({
      code: "oaath_client_grant_inactive",
    });
    await revoking.revoke();
    expect(revoking.state).toBe("revoked");
    expect(recovered.chain.sends).toHaveLength(1);
    expect(recovered.chain.sends[0]?.kind).toBe("revocation");
  });

  it("observes an accepted revocation after a send-return crash and never resubmits it", async () => {
    const factory = new IDBFactory();
    const clock = createClock();
    const relay = createRelay(clock);
    let crashOnSend = false;
    const chain = createChainFixture({ crashOnSend: () => crashOnSend });

    const first = await openRealmDatabase(factory);
    const firstStores = storesFor(first);
    const before = createRealm({ clock, relay, stores: firstStores, chain });
    const firstConnection = await before.oaath.connect();
    const grant = await firstConnection.requestPermission(permissionInput());
    expect((await (await grant.sendCalls(sendCallsInput())).wait()).status).toBe("finalized");
    const grantId = chain.sends[0]?.grantId;
    if (!grantId) throw new Error("expected the installed Grant identity");

    // The revocation transport accepts the exact operation and then loses the
    // response. The durable journal, not the thrown transport result, owns what
    // may happen after recreation.
    crashOnSend = true;
    await grant.revoke();
    expect(grant.state).toBe("revoking");
    expect(chain.sends).toHaveLength(2);
    expect(chain.sends[1]?.kind).toBe("revocation");
    const attempted = await new OperationStore(firstStores.operations).get({
      grantId,
      chainId: CHAIN_ID,
      kind: "revocation",
    });
    expect(attempted?.value.state).toBe("submission_attempted");
    const revocationHash = attempted?.value.identity.userOperationHash;
    if (!revocationHash) throw new Error("expected the retained revocation identity");

    await firstConnection.close();
    first.close();
    opened.splice(opened.indexOf(first), 1);

    // Recreate the database, every adapter, the realm, connection, and Grant.
    // Recovery may only observe the retained identity; preparing or sending a
    // replacement would make the send count exceed two.
    crashOnSend = false;
    const second = await openRealmDatabase(factory);
    const secondStores = storesFor(second);
    const after = createRealm({ clock, relay, stores: secondStores, chain });
    const secondConnection = await after.oaath.connect();
    const resumed = await secondConnection.resume();
    if (!resumed) throw new Error("expected the revoking Grant to resume");
    expect(resumed.state).toBe("revoking");
    await resumed.revoke();

    expect(resumed.state).toBe("revoked");
    expect(chain.sends).toHaveLength(2);
    const finalized = await new OperationStore(secondStores.operations).get({
      grantId,
      chainId: CHAIN_ID,
      kind: "revocation",
    });
    expect(finalized?.value.state).toBe("finalized");
    expect(finalized?.value.identity.userOperationHash).toBe(revocationHash);
    await secondConnection.close();
  });

  it("fails a compare-and-swap closed when another realm already advanced the record", async () => {
    const factory = new IDBFactory();
    const clock = createClock();
    const relay = createRelay(clock);
    const database = await openRealmDatabase(factory);
    const stores = storesFor(database);
    const realm = createRealm({ clock, relay, stores });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const operation = await grant.sendCalls(sendCallsInput());
    expect((await operation.wait()).status).toBe("finalized");
    const grantId = realm.chain.sends[0]?.grantId;
    if (!grantId) throw new Error("expected a grant id");

    // An independent connection over the same database reads the record, then
    // the first realm advances it, so the second writer holds a stale revision.
    const other = await openRealmDatabase(factory);
    const otherStore = new GrantStore(createIndexedDbGrantStoreAdapter(other));
    const stale = await otherStore.get(grantId);
    if (!stale) throw new Error("expected the persisted Grant");

    await grant.revoke();
    await expect(
      otherStore.compareAndSwap({
        grantId,
        expectedStoreRevision: stale.storeRevision,
        next: stale.value,
      }),
    ).resolves.toMatchObject({ status: "conflict" });
    // The loser wrote nothing: the winning terminal state stands.
    const latest = await otherStore.get(grantId);
    expect(latest?.value.state).toBe("revoked");
    expect(latest?.storeRevision).toBeGreaterThan(stale.storeRevision);
  });

  it("recreates a malformed current-version database with exactly the seven current stores", async () => {
    const factory = new IDBFactory();
    // A partial same-version realm receives no upgrade event, so the explicit
    // schema check must discard it and recreate the complete current schema.
    await new Promise<void>((resolve, reject) => {
      const request = factory.open(OAATH_INDEXEDDB_NAME, OAATH_INDEXEDDB_VERSION);
      request.onupgradeneeded = () => {
        request.result.createObjectStore("legacy-grants").put({ legacy: true }, "old");
      };
      request.onsuccess = () => {
        request.result.close();
        resolve();
      };
      request.onerror = () => reject(request.error);
    });

    const database = await openRealmDatabase(factory);
    expect(database.name).toBe(OAATH_INDEXEDDB_NAME);
    expect(database.version).toBe(13);
    expect(OAATH_INDEXEDDB_VERSION).toBe(13);
    expect(await readStoreNames(factory)).toEqual([
      "cleanup",
      "context",
      "grants",
      "keys",
      "operations",
      "preparedCallContexts",
      "walletCallBundles",
    ]);
    expect(Object.values(OAATH_INDEXEDDB_STORES)).toHaveLength(7);
    // The legacy store is gone, not read and not migrated.
    await expect(
      database.transact(["grants"], "readonly", async ([store]) => store?.name),
    ).resolves.toBe("grants");
    expect(
      (await factory.databases()).filter((entry) => entry.name === OAATH_INDEXEDDB_NAME),
    ).toHaveLength(1);
    const grants = new GrantStore(createIndexedDbGrantStoreAdapter(database));
    expect(await grants.get("old")).toBeUndefined();
  });

  it("wipes every stale v2 store in place and deletes retired-name siblings", async () => {
    const factory = new IDBFactory();
    for (const name of ["oaath.browser-state/v0", "oaath.browser-state/v2"]) {
      await new Promise<void>((resolve, reject) => {
        const request = factory.open(name, 1);
        request.onupgradeneeded = () => {
          const grants = request.result.createObjectStore("grants");
          grants.put({ stale: true }, "old");
        };
        request.onsuccess = () => {
          request.result.close();
          resolve();
        };
        request.onerror = () => reject(request.error);
      });
    }

    // The exact v2 schema held five stores. Every one receives a recognizable
    // stale value so the current open proves wholesale deletion rather than a
    // migration or a selectively preserved store.
    await new Promise<void>((resolve, reject) => {
      const request = factory.open(OAATH_INDEXEDDB_NAME, 2);
      request.onupgradeneeded = () => {
        request.result
          .createObjectStore("grants")
          .put({ source: "v2", store: "grants" }, "stale-grant");
        request.result
          .createObjectStore("operations")
          .put({ source: "v2", store: "operations" }, ["stale-grant", CHAIN_ID, "execution"]);
        request.result.createObjectStore("keys").put({ source: "v2", store: "keys" }, "stale-key");
        request.result
          .createObjectStore("cleanup")
          .put({ source: "v2", store: "cleanup" }, "stale-cleanup");
        request.result
          .createObjectStore("context")
          .put({ source: "v2", store: "context" }, "stale-context");
      };
      request.onsuccess = () => {
        request.result.close();
        resolve();
      };
      request.onerror = () => reject(request.error);
    });

    const database = await openRealmDatabase(factory);
    expect((await factory.databases()).map((entry) => entry.name)).toEqual([OAATH_INDEXEDDB_NAME]);
    expect(database.version).toBe(13);

    const staleBundleKey = {
      providerScopeId: `0x${"51".repeat(32)}` as const,
      account: ACCOUNT,
      id: "stale-bundle",
    };
    await expect(
      Promise.all([
        createIndexedDbGrantStoreAdapter(database).get("stale-grant"),
        createIndexedDbOperationStoreAdapter(database).get({
          grantId: "stale-grant",
          chainId: CHAIN_ID,
          kind: "execution",
        }),
        createIndexedDbKeyStore(database).get("stale-key"),
        createIndexedDbCleanupStore(database).read("stale-cleanup"),
        createIndexedDbContextStore(database).read("stale-context"),
        createIndexedDbWalletCallBundleStoreAdapter(database).get(staleBundleKey),
      ]),
    ).resolves.toEqual([undefined, undefined, undefined, undefined, undefined, undefined]);
  });

  it("wipes v3 operation lane keys instead of reading them through the v5 layout", async () => {
    const factory = new IDBFactory();
    await new Promise<void>((resolve, reject) => {
      const request = factory.open(OAATH_INDEXEDDB_NAME, 3);
      request.onupgradeneeded = () => {
        for (const store of Object.values(OAATH_INDEXEDDB_STORES)) {
          request.result.createObjectStore(store);
        }
        request.transaction
          ?.objectStore(OAATH_INDEXEDDB_STORES.operations)
          .put({ source: "v3" }, ["stale-grant", CHAIN_ID, "execution"]);
      };
      request.onsuccess = () => {
        request.result.close();
        resolve();
      };
      request.onerror = () => reject(request.error);
    });

    const database = await openRealmDatabase(factory);
    expect(database.version).toBe(13);
    await expect(
      createIndexedDbOperationStoreAdapter(database).get({
        grantId: "stale-grant",
        chainId: CHAIN_ID,
        kind: "execution",
      }),
    ).resolves.toBeUndefined();
  });

  it("wipes v6 Grant-scoped bundle keys instead of reading them through the sender scope", async () => {
    const factory = new IDBFactory();
    const providerScopeId = `0x${"61".repeat(32)}` as const;
    const id = "v6-bundle";
    await new Promise<void>((resolve, reject) => {
      const request = factory.open(OAATH_INDEXEDDB_NAME, 6);
      request.onupgradeneeded = () => {
        for (const store of Object.values(OAATH_INDEXEDDB_STORES)) {
          request.result.createObjectStore(store);
        }
        request.transaction
          ?.objectStore(OAATH_INDEXEDDB_STORES.walletCallBundles)
          .put({ source: "v6" }, [providerScopeId, "current-grant", id]);
      };
      request.onsuccess = () => {
        request.result.close();
        resolve();
      };
      request.onerror = () => reject(request.error);
    });

    const database = await openRealmDatabase(factory);
    expect(database.version).toBe(13);
    await expect(
      createIndexedDbWalletCallBundleStoreAdapter(database).get({
        providerScopeId,
        account: ACCOUNT,
        id,
      }),
    ).resolves.toBeUndefined();
  });

  it("wipes v10 wallet-call bundle records before opening the current v12 schema", async () => {
    const factory = new IDBFactory();
    const providerScopeId = `0x${"62".repeat(32)}` as const;
    const id = "v10-bundle";
    await new Promise<void>((resolve, reject) => {
      const request = factory.open(OAATH_INDEXEDDB_NAME, 10);
      request.onupgradeneeded = () => {
        for (const store of Object.values(OAATH_INDEXEDDB_STORES)) {
          request.result.createObjectStore(store);
        }
        request.transaction
          ?.objectStore(OAATH_INDEXEDDB_STORES.walletCallBundles)
          .put({ source: "v10" }, [providerScopeId, ACCOUNT, id]);
      };
      request.onsuccess = () => {
        request.result.close();
        resolve();
      };
      request.onerror = () => reject(request.error);
    });

    const database = await openRealmDatabase(factory);
    expect(database.version).toBe(13);
    await expect(
      createIndexedDbWalletCallBundleStoreAdapter(database).get({
        providerScopeId,
        account: ACCOUNT,
        id,
      }),
    ).resolves.toBeUndefined();
  });

  it("wipes the v8 sender-scoped schema before adding prepared-call contexts in v9", async () => {
    const factory = new IDBFactory();
    const providerScopeId = `0x${"63".repeat(32)}` as const;
    const id = "v8-bundle";
    await new Promise<void>((resolve, reject) => {
      const request = factory.open(OAATH_INDEXEDDB_NAME, 8);
      request.onupgradeneeded = () => {
        for (const store of [
          "grants",
          "operations",
          "walletCallBundles",
          "keys",
          "cleanup",
          "context",
        ]) {
          request.result.createObjectStore(store);
        }
        request.transaction
          ?.objectStore("walletCallBundles")
          .put({ source: "v8" }, [providerScopeId, ACCOUNT, id]);
      };
      request.onsuccess = () => {
        request.result.close();
        resolve();
      };
      request.onerror = () => reject(request.error);
    });

    const database = await openRealmDatabase(factory);
    expect(database.version).toBe(13);
    expect(await readStoreNames(factory)).toEqual([
      "cleanup",
      "context",
      "grants",
      "keys",
      "operations",
      "preparedCallContexts",
      "walletCallBundles",
    ]);
    await expect(
      createIndexedDbWalletCallBundleStoreAdapter(database).get({
        providerScopeId,
        account: ACCOUNT,
        id,
      }),
    ).resolves.toBeUndefined();
  });

  it("refuses an extractable key handle and a persisted value that is not a handle", async () => {
    const factory = new IDBFactory();
    const database = await openRealmDatabase(factory);
    const keys = createIndexedDbKeyStore(database);
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ]);
    await expect(keys.store({ keyId: "bad", key: pair.privateKey })).rejects.toMatchObject({
      name: "OaathPersistenceError",
      code: "persistence_key_invalid",
    });
    await database.transact(["keys"], "readwrite", async ([store]) => {
      store?.put({ pretending: "to be a key" }, "planted");
    });
    await expect(keys.get("planted")).rejects.toMatchObject({
      code: "persistence_key_invalid",
    });
  });

  it("refuses a persisted client context whose approved policy widens the request", async () => {
    const factory = new IDBFactory();
    const clock = createClock();
    const relay = createRelay(clock);
    const database = await openRealmDatabase(factory);
    const stores = storesFor(database);
    const realm = createRealm({ clock, relay, stores });
    const connection = await realm.oaath.connect();
    await connection.requestPermission(permissionInput());
    await connection.close();

    const bindingId = realm.oaath.binding.bindingId;
    const persisted = (await createIndexedDbContextStore(database).read(bindingId)) as {
      readonly approvedPolicy: { readonly perChainOperationLimit: number };
    };
    await database.transact(["context"], "readwrite", async ([store]) => {
      store?.put(
        {
          ...persisted,
          approvedPolicy: { ...persisted.approvedPolicy, perChainOperationLimit: 1_000 },
        },
        bindingId,
      );
    });

    const next = createRealm({ clock, relay, stores: storesFor(database) });
    await expect((await next.oaath.connect()).resume()).rejects.toMatchObject({
      name: "OaathClientError",
      source: "persistence_record_invalid",
    });
  });
});
