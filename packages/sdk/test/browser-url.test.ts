/**
 * The URL-only golden path: one service URL, everything else authenticated
 * service context or locally derived.
 *
 * @author taek <leekt216@gmail.com>
 */

import { createKmsSessionSignerProvider } from "@oaath/server";
import { IDBFactory } from "fake-indexeddb";
import { describe, expect, it } from "vitest";
import { createOAAth } from "../src/index.js";
import {
  createIndexedDbCleanupStore,
  createIndexedDbContextStore,
  createIndexedDbGrantStoreAdapter,
  createIndexedDbKeyStore,
  createIndexedDbOperationStoreAdapter,
  createIndexedDbWalletCallBundleStoreAdapter,
  OAATH_INDEXEDDB_NAME,
  type OaathDatabase,
  openOaathDatabase,
} from "../src/persistence.js";

function idbStores(database: OaathDatabase) {
  return {
    grants: createIndexedDbGrantStoreAdapter(database),
    operations: createIndexedDbOperationStoreAdapter(database),
    walletCallBundles: createIndexedDbWalletCallBundleStoreAdapter(database),
    keys: createIndexedDbKeyStore(database),
    cleanup: createIndexedDbCleanupStore(database),
    context: createIndexedDbContextStore(database),
  };
}

import {
  accountProfile,
  CHAIN_ID,
  CLIENT_TOKEN,
  createChainFixture,
  createClock,
  createMemoryStores,
  createRelay,
  createUrlRealm,
  ISSUER_URL,
  ORIGIN,
  permissionInput,
  REDIRECT_URI,
  relayChainPort,
  relayKms,
  sendCallsInput,
  VALIDATOR,
} from "./support/browser.js";

describe("URL-only golden path", () => {
  it("connects, requests permission, sends calls, and revokes from one URL", async () => {
    // The chain's answer to "is the permission still installed", and how far
    // the chain advanced beyond this realm's own submissions — both flip when
    // the owner's console removes the permission out of band.
    let permissionInstalled: boolean | null = null;
    let blockOffset = 0;
    const realm = createUrlRealm({
      chain: createChainFixture({
        permissionInstalled: () => permissionInstalled,
        blockOffset: () => blockOffset,
      }),
    });
    // No binding exists before the service context does.
    expect(() => realm.oaath.binding).toThrowError(
      expect.objectContaining({ name: "OaathClientError" }),
    );

    const connection = await realm.oaath.connect();
    // The binding is the service's registered identity, not a page assertion.
    expect(realm.oaath.binding.application.clientId).toBe("client-a");
    expect(realm.oaath.binding.account.ownerCredential.kind).toBe("ecdsa");
    // The operator credential is the locally generated session key's identity.
    expect(realm.oaath.binding.operatorCredential.kind).toBe("ecdsa");
    expect(realm.fetched[0]).toBe("GET /bootstrap");

    const grant = await connection.requestPermission(permissionInput());
    expect(grant.state).toBe("active");

    const operation = await grant.sendCalls(sendCallsInput());
    expect((await operation.wait()).status).toBe("finalized");
    // The one submission rode the service relay, session-signed.
    expect(realm.chain.sends).toHaveLength(1);
    expect(
      realm.fetched.filter((entry) => entry === `POST /chains/${CHAIN_ID}/submissions`),
    ).toHaveLength(1);

    await grant.revoke();
    // The capability died through the service, but the installed chain
    // permission awaits owner-signed removal: durably revoking, never a
    // claimed revocation no chain observed. This realm holds no owner
    // authority, so nothing rode the submission route a second time.
    expect(grant.state).toBe("revoking");
    expect(realm.invalidations()).toBe(1);
    expect(realm.chain.sends).toHaveLength(1);

    // The owner's console removes the permission out of band; the chain
    // advances and the signer module reads conclusively absent. The next
    // revoke completes from that finalized-anchored evidence alone — still
    // without this realm ever signing owner work.
    permissionInstalled = false;
    blockOffset = 1;
    await grant.revoke();
    expect(grant.state).toBe("revoked");
    expect(realm.chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("survives a reload: a recreated realm resumes the Grant with the same session", async () => {
    // Durable IndexedDB with fresh adapter handles per life, exactly like a
    // browser reload: the data survives, the handles do not.
    const factory = new IDBFactory();
    const life = async () => idbStores(await openOaathDatabase({ factory }));

    // First life: connect, get authority, execute (which materializes the
    // permission on chain for exactly this session key).
    const first = createUrlRealm({ stores: await life() });
    const connection = await first.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    expect((await (await grant.sendCalls(sendCallsInput())).wait()).status).toBe("finalized");
    const operatorBefore = first.oaath.binding.operatorCredential;
    const deviceBefore = first.oaath.binding.subject.deviceId;
    await connection.close();

    // Second life: same durable data and issuer, a brand-new realm — the
    // reload. The persisted session keeps the device identity and operator
    // key stable, so resume() finds a Grant this realm can still sign for,
    // and the next operation validates through the already-installed
    // permission instead of orphaning it.
    const second = createUrlRealm({
      clock: first.clock,
      chain: first.chain,
      stores: await life(),
      relay: first.relay,
    });
    const reconnected = await second.oaath.connect();
    expect(second.oaath.binding.operatorCredential).toEqual(operatorBefore);
    expect(second.oaath.binding.subject.deviceId).toBe(deviceBefore);
    const resumed = await reconnected.resume();
    expect(resumed).not.toBeNull();
    expect(resumed?.state).toBe("active");
    const operation = await resumed?.sendCalls(sendCallsInput());
    expect((await operation?.wait())?.status).toBe("finalized");
    // Standard permission validation: the reload spent no second approval.
    const nonce = BigInt(first.chain.sends[1]?.userOperation.nonce ?? 0n);
    expect((nonce >> 248n) & 0xffn).toBe(0n);
    await reconnected.close();
  });

  it("completes the golden path over the loopback development URL", async () => {
    // The advertised default is `http://localhost:8787`; this proves a valid
    // loopback bootstrap composes and executes, not merely that an invalid
    // one fails there.
    const realm = createUrlRealm({ url: "http://localhost:8787" });
    const connection = await realm.oaath.connect();
    expect(realm.oaath.binding.issuer.url).toBe("http://localhost:8787");
    const grant = await connection.requestPermission(permissionInput());
    const operation = await grant.sendCalls(sendCallsInput());
    expect((await operation.wait()).status).toBe("finalized");
    expect(realm.chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("defaults to the local development service URL", async () => {
    const seen: string[] = [];
    const oaath = createOAAth({
      fetch: async (request: Request) => {
        seen.push(request.url);
        return new Response("{}", { status: 200 });
      },
      origin: "https://app.example",
      now: () => 1_800_000_000,
    });
    await expect(oaath.connect()).rejects.toMatchObject({ name: "OaathClientError" });
    expect(seen).toEqual(["http://localhost:8787/bootstrap"]);
  });

  it("closes the default IndexedDB connection after URL disconnect", async () => {
    const factory = new IDBFactory();
    const previous = Object.getOwnPropertyDescriptor(globalThis, "indexedDB");
    Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: factory });
    const clock = createClock();
    const chain = createChainFixture();
    const relay = createRelay(clock, {
      bootstrap: {
        application: {
          applicationId: "app-a",
          applicationName: "OAAth Example",
          clientId: "client-a",
          redirectUris: [REDIRECT_URI],
        },
        userHandle: "user-1",
        account: accountProfile,
        ownerValidator: VALIDATOR,
      },
      chains: [relayChainPort(chain)],
    });
    const oaath = createOAAth({
      url: ISSUER_URL,
      origin: ORIGIN,
      now: clock.now,
      fetch: (request: Request) => {
        const headers = new Headers(request.headers);
        headers.set("authorization", `Bearer ${CLIENT_TOKEN}`);
        return relay(new Request(request, { headers }));
      },
    });
    try {
      const connection = await oaath.connect();
      expect(connection.binding.issuer.url).toBe(ISSUER_URL);
      await oaath.disconnect(null);
      const deletion = await new Promise<"blocked" | "deleted">((resolve, reject) => {
        const request = factory.deleteDatabase(OAATH_INDEXEDDB_NAME);
        request.onblocked = () => resolve("blocked");
        request.onsuccess = () => resolve("deleted");
        request.onerror = () => reject(request.error ?? new Error("database deletion failed"));
      });
      expect(deletion).toBe("deleted");
    } finally {
      await oaath.close().catch(() => undefined);
      if (previous === undefined) Reflect.deleteProperty(globalThis, "indexedDB");
      else Object.defineProperty(globalThis, "indexedDB", previous);
    }
  });

  it("retains the default IndexedDB owner when inner disconnect fails", async () => {
    const factory = new IDBFactory();
    const previous = Object.getOwnPropertyDescriptor(globalThis, "indexedDB");
    Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: factory });
    const clock = createClock();
    const chain = createChainFixture();
    const relay = createRelay(clock, {
      bootstrap: {
        application: {
          applicationId: "app-a",
          applicationName: "OAAth Example",
          clientId: "client-a",
          redirectUris: [REDIRECT_URI],
        },
        userHandle: "user-1",
        account: accountProfile,
        ownerValidator: VALIDATOR,
      },
      chains: [relayChainPort(chain)],
    });
    const oaath = createOAAth({
      url: ISSUER_URL,
      origin: ORIGIN,
      now: clock.now,
      fetch: (request: Request) => {
        const headers = new Headers(request.headers);
        headers.set("authorization", `Bearer ${CLIENT_TOKEN}`);
        return relay(new Request(request, { headers }));
      },
    });
    try {
      await oaath.connect();
      const failingGrant = {
        async revoke() {
          throw new Error("canonical revocation failure");
        },
      } as unknown as Parameters<typeof oaath.disconnect>[0];
      await expect(oaath.disconnect(failingGrant)).rejects.toMatchObject({
        name: "OaathCleanupError",
      });
      const deletion = await new Promise<"blocked" | "deleted">((resolve, reject) => {
        const request = factory.deleteDatabase(OAATH_INDEXEDDB_NAME);
        request.onblocked = () => resolve("blocked");
        request.onsuccess = () => resolve("deleted");
        request.onerror = () => reject(request.error ?? new Error("database deletion failed"));
      });
      expect(deletion).toBe("blocked");
    } finally {
      await oaath.close().catch(() => undefined);
      if (previous === undefined) Reflect.deleteProperty(globalThis, "indexedDB");
      else Object.defineProperty(globalThis, "indexedDB", previous);
    }
  });

  it("waits for an in-progress URL composition before closing its database", async () => {
    const factory = new IDBFactory();
    const previous = Object.getOwnPropertyDescriptor(globalThis, "indexedDB");
    Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: factory });
    let releaseBootstrap!: () => void;
    const bootstrapReleased = new Promise<void>((resolve) => {
      releaseBootstrap = resolve;
    });
    const oaath = createOAAth({
      url: ISSUER_URL,
      origin: ORIGIN,
      now: () => 1_800_000_000,
      fetch: async () => {
        await bootstrapReleased;
        return new Response("{}", {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      },
    });
    try {
      const connecting = oaath.connect();
      const closing = oaath.close();
      releaseBootstrap();
      await expect(connecting).rejects.toMatchObject({ name: "OaathClientError" });
      await closing;
      await expect(oaath.connect()).rejects.toMatchObject({ code: "oaath_client_closed" });
      const deletion = await new Promise<"blocked" | "deleted">((resolve, reject) => {
        const request = factory.deleteDatabase(OAATH_INDEXEDDB_NAME);
        request.onblocked = () => resolve("blocked");
        request.onsuccess = () => resolve("deleted");
        request.onerror = () => reject(request.error ?? new Error("database deletion failed"));
      });
      expect(deletion).toBe("deleted");
    } finally {
      await oaath.close().catch(() => undefined);
      if (previous === undefined) Reflect.deleteProperty(globalThis, "indexedDB");
      else Object.defineProperty(globalThis, "indexedDB", previous);
    }
  });

  it("drains a successful URL connect and rejects every connect after close", async () => {
    const source = createUrlRealm();
    let enterBootstrap!: () => void;
    let releaseBootstrap!: () => void;
    const bootstrapEntered = new Promise<void>((resolve) => {
      enterBootstrap = resolve;
    });
    const bootstrapReleased = new Promise<void>((resolve) => {
      releaseBootstrap = resolve;
    });
    const realm = createUrlRealm({
      clock: source.clock,
      chain: source.chain,
      stores: createMemoryStores(),
      relay: async (request) => {
        if (request.method === "GET" && new URL(request.url).pathname === "/bootstrap") {
          enterBootstrap();
          await bootstrapReleased;
        }
        return source.relay(request);
      },
    });

    const connecting = realm.oaath.connect();
    await bootstrapEntered;
    let closeSettled = false;
    const closing = realm.oaath.close().then(() => {
      closeSettled = true;
    });
    await Promise.resolve();
    expect(closeSettled).toBe(false);
    releaseBootstrap();
    const connection = await connecting;
    await closing;
    await expect(connection.resume()).rejects.toMatchObject({ code: "oaath_client_closed" });
    await expect(realm.oaath.connect()).rejects.toMatchObject({ code: "oaath_client_closed" });
  });

  it("fails closed on hostile or mismatched service context", async () => {
    for (const tamper of [
      (document: Record<string, unknown>) => ({ ...document, extra: 1 }),
      (document: Record<string, unknown>) => ({
        ...document,
        version: "oaath.service-bootstrap/v1",
      }),
      (document: Record<string, unknown>) => ({ ...document, chains: [] }),
      // A redirect target on another origin never binds this page.
      (document: Record<string, unknown>) => ({
        ...document,
        application: {
          ...(document.application as Record<string, unknown>),
          redirectUris: ["https://other.example/callback"],
        },
      }),
    ]) {
      const realm = createUrlRealm({ bootstrap: tamper });
      await expect(realm.oaath.connect()).rejects.toMatchObject({
        name: "OaathClientError",
        code: "oaath_client_capability_invalid",
      });
    }
  });

  it("runs hosted session custody end to end: the page never holds session key material", async () => {
    const realm = createUrlRealm({
      sessionSigner: {
        mode: "oaath_hosted",
        providerId: "kms-primary",
        provider: createKmsSessionSignerProvider({ kms: relayKms() }),
      },
    });
    const connection = await realm.oaath.connect();
    // The operator credential is the one the deployment's provider served —
    // never a locally minted key.
    expect(realm.oaath.binding.operatorCredential.kind).toBe("ecdsa");
    expect(realm.fetched).toContain("POST /session-signers");

    const grant = await connection.requestPermission(permissionInput());
    expect(grant.state).toBe("active");

    // The execution signature came from the service's signing route; the
    // profile's self-verification proved it matches the served credential —
    // the rotation invariant, enforced per signature.
    const operation = await grant.sendCalls(sendCallsInput());
    expect((await operation.wait()).status).toBe("finalized");
    expect(
      realm.fetched.filter((entry) => entry === "POST /session-signers/signatures").length,
    ).toBeGreaterThan(0);
    await connection.close();
  });

  it("fails closed on custody the service declares but cannot or should not serve", async () => {
    // Declared remote custody with no signing routes composes nothing — the
    // SDK never substitutes a locally minted frontend key.
    const unserved = createUrlRealm({
      bootstrap: (document) => ({
        ...document,
        sessionSigner: { mode: "oaath_hosted", providerId: "kms-primary" },
      }),
    });
    await expect(unserved.oaath.connect()).rejects.toMatchObject({
      name: "OaathClientError",
      code: "oaath_client_issuer_rejected",
    });
    // An unknown custody mode rejects the whole bootstrap document.
    const unknown = createUrlRealm({
      bootstrap: (document) => ({
        ...document,
        sessionSigner: { mode: "owner_hosted", providerId: "kms-primary" },
      }),
    });
    await expect(unknown.oaath.connect()).rejects.toMatchObject({
      name: "OaathClientError",
      code: "oaath_client_capability_invalid",
    });
    // An explicit frontend declaration composes exactly like absence.
    const frontend = createUrlRealm({
      bootstrap: (document) => ({
        ...document,
        sessionSigner: { mode: "frontend", providerId: null },
      }),
    });
    const connection = await frontend.oaath.connect();
    expect(frontend.oaath.binding.operatorCredential.kind).toBe("ecdsa");
    await connection.close();
  });

  it("refuses a chain the service does not advertise", async () => {
    const realm = createUrlRealm();
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    await expect(
      grant.sendCalls({ ...(sendCallsInput() as Record<string, unknown>), chain: 999 }),
    ).rejects.toMatchObject({
      code: "oaath_client_capability_unsupported",
      source: "chain_not_configured",
    });
    expect(realm.chain.sends).toHaveLength(0);
    await connection.close();
  });

  it("refuses an unknown configuration key on the URL mode", () => {
    expect(() => createOAAth({ url: "https://oaath.example", relayUrl: "x" })).toThrowError(
      expect.objectContaining({ code: "oaath_client_input_invalid" }),
    );
  });

  it("denies execution when the service serves no usage evidence", async () => {
    const realm = createUrlRealm({ chain: createChainFixture({ usage: false }) });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    await expect(grant.sendCalls(sendCallsInput())).rejects.toMatchObject({
      code: "oaath_client_scope_denied",
      source: "session_coverage_unreadable",
    });
    await connection.close();
  });
});
