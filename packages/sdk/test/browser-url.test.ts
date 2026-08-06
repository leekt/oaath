/**
 * The URL-only golden path: one service URL, everything else authenticated
 * service context or locally derived.
 *
 * @author taek <leekt216@gmail.com>
 */
import { IDBFactory } from "fake-indexeddb";
import { describe, expect, it } from "vitest";
import { createOAAth } from "../src/index.js";
import {
  createIndexedDbCleanupStore,
  createIndexedDbContextStore,
  createIndexedDbGrantStoreAdapter,
  createIndexedDbKeyStore,
  createIndexedDbOperationStoreAdapter,
  type OaathDatabase,
  openOaathDatabase,
} from "../src/persistence.js";

function idbStores(database: OaathDatabase) {
  return {
    grants: createIndexedDbGrantStoreAdapter(database),
    operations: createIndexedDbOperationStoreAdapter(database),
    keys: createIndexedDbKeyStore(database),
    cleanup: createIndexedDbCleanupStore(database),
    context: createIndexedDbContextStore(database),
  };
}

import {
  CHAIN_ID,
  createChainFixture,
  createUrlRealm,
  permissionInput,
  sendCallsInput,
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

  it("fails closed on hostile or mismatched service context", async () => {
    for (const tamper of [
      (document: Record<string, unknown>) => ({ ...document, extra: 1 }),
      (document: Record<string, unknown>) => ({
        ...document,
        version: "oaath.service-bootstrap/v2",
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
