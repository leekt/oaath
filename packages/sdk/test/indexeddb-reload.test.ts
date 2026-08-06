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
 * real-Chromium realm is child issue 10's packed-browser smoke.
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
  OAATH_INDEXEDDB_NAME,
  type OaathDatabase,
  openOaathDatabase,
  requireNonExtractableKey,
} from "../src/persistence.js";
import {
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
    const submittedHash = before.chain.sends[0]?.userOperationHash;
    const grantId = before.chain.sends[0]?.grantId;
    if (!submittedHash || !grantId) throw new Error("expected one submitted operation");

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
      // The account already executed once, so its on-chain sequence advanced.
      chain: createChainFixture({ startSequence: 1 }),
    });
    const restored = await (await after.oaath.connect()).resume();
    if (!restored) throw new Error("expected the persisted Grant to resume");
    expect(restored.state).toBe("active");

    // The journal restored the exact submitted identity, still finalized.
    const journal = await new OperationStore(secondStores.operations).get({
      grantId,
      chainId: CHAIN_ID,
      kind: "execution",
    });
    expect(journal?.value.state).toBe("finalized");
    expect(journal?.value.identity.userOperationHash).toBe(submittedHash);

    // Key custody survived as a non-extractable handle with no export path.
    const handle = await secondStores.keys.get("session-key");
    expect(requireNonExtractableKey(handle).extractable).toBe(false);
    expect(Object.keys(secondStores.keys).sort()).toEqual(["close", "delete", "get", "store"]);

    // A new send after recreation reuses the restored authority and never
    // resubmits the finalized operation.
    const next = await restored.sendCalls(sendCallsInput());
    expect((await next.wait()).status).toBe("finalized");
    expect(after.chain.sends).toHaveLength(1);
    expect(after.chain.sends[0]?.userOperationHash).not.toBe(submittedHash);
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

  it("discards a database that does not carry the current schema instead of migrating it", async () => {
    const factory = new IDBFactory();
    // An older build's realm: same name, a schema this version does not read.
    await new Promise<void>((resolve, reject) => {
      const request = factory.open(OAATH_INDEXEDDB_NAME, 1);
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

  it("wipes an older-shaped database in place and deletes retired-name siblings", async () => {
    const factory = new IDBFactory();
    // Pre-release there is no migration: an existing database at an older
    // numeric version — e.g. one whose operation journals used two-part keys
    // that would be silently invisible under the current key shape — is wiped
    // by the upgrade handler, never read. Old versioned names are deleted.
    for (const name of ["oaath.browser-state/v0", "oaath.browser-state/v2", OAATH_INDEXEDDB_NAME]) {
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
    const database = await openRealmDatabase(factory);
    expect((await factory.databases()).map((entry) => entry.name)).toEqual([OAATH_INDEXEDDB_NAME]);
    // The stale record died with the upgrade.
    const grants = new GrantStore(createIndexedDbGrantStoreAdapter(database));
    expect(await grants.get("old")).toBeUndefined();
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
