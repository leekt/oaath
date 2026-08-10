/**
 * Send/return crash around the caller's submission capability.
 *
 * The transport accepts the operation and the answer never comes back. The
 * journal must already say `submission_attempted`, recreating the realm must not
 * submit anything, and observation must finalize the exact same identity.
 *
 * The semantics under test are `operation-runner`'s; this file proves the browser
 * client composes them without weakening any of them.
 *
 * @author taek <leekt216@gmail.com>
 */
import { IDBFactory } from "fake-indexeddb";
import { afterEach, describe, expect, it } from "vitest";
import { OperationStore } from "../src/advanced.js";
import {
  createIndexedDbCleanupStore,
  createIndexedDbContextStore,
  createIndexedDbGrantStoreAdapter,
  createIndexedDbKeyStore,
  createIndexedDbOperationStoreAdapter,
  createIndexedDbWalletCallBundleStoreAdapter,
  type OaathDatabase,
  openOaathDatabase,
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

async function realmStores(factory: IDBFactory): Promise<{
  readonly database: OaathDatabase;
  readonly stores: RealmStores;
}> {
  const database = await openOaathDatabase({ factory });
  opened.push(database);
  return {
    database,
    stores: {
      grants: createIndexedDbGrantStoreAdapter(database),
      operations: createIndexedDbOperationStoreAdapter(database),
      walletCallBundles: createIndexedDbWalletCallBundleStoreAdapter(database),
      keys: createIndexedDbKeyStore(database),
      cleanup: createIndexedDbCleanupStore(database),
      context: createIndexedDbContextStore(database),
    },
  };
}

describe("send/return crash recovery", () => {
  it("does not resubmit after a crash and finalizes the same identity", async () => {
    const factory = new IDBFactory();
    const clock = createClock();
    const relay = createRelay(clock);
    let crash = true;
    // One transport across both realms, so its send count is the whole history.
    const chain = createChainFixture({ crashOnSend: () => crash });

    const first = await realmStores(factory);
    const before = createRealm({ clock, relay, stores: first.stores, chain });
    const connection = await before.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const crashed = await grant.sendCalls(sendCallsInput());

    // The send was attempted exactly once and its outcome is unknown.
    expect(chain.sends).toHaveLength(1);
    expect(crashed.outcome.status).toBe("pending");
    expect(crashed.outcome.reason).toBe("send_ambiguous");
    const identity = chain.sends[0];
    if (!identity) throw new Error("expected one submitted snapshot");

    const journal = new OperationStore(createIndexedDbOperationStoreAdapter(first.database));
    const attempted = await journal.get({
      grantId: identity.grantId,
      chainId: CHAIN_ID,
      kind: "execution",
    });
    expect(attempted?.value.state).toBe("submission_attempted");
    expect(attempted?.value.identity.userOperationHash).toBe(identity.userOperationHash);

    // Recreate every instance: connection, stores, adapters, database.
    await connection.close();
    first.database.close();
    opened.splice(opened.indexOf(first.database), 1);
    crash = false;

    const second = await realmStores(factory);
    const after = createRealm({ clock, relay, stores: second.stores, chain });
    const restored = await (await after.oaath.connect()).resume();
    if (!restored) throw new Error("expected the Grant to resume");

    // The unresolved lane resolves by observation. No second send happens even
    // though the same calls are requested again.
    const resumed = await restored.sendCalls(sendCallsInput());
    const outcome = await resumed.wait();
    expect(outcome.status).toBe("finalized");
    expect(chain.sends).toHaveLength(1);

    const finalized = await new OperationStore(
      createIndexedDbOperationStoreAdapter(second.database),
    ).get({ grantId: identity.grantId, chainId: CHAIN_ID, kind: "execution" });
    expect(finalized?.value.state).toBe("finalized");
    expect(finalized?.value.identity.userOperationHash).toBe(identity.userOperationHash);
    expect(finalized?.value.identity.nonce).toBe(attempted?.value.identity.nonce);
  });

  it("recovers an accepted revocation after full recreation without resubmission", async () => {
    const factory = new IDBFactory();
    const clock = createClock();
    const relay = createRelay(clock);
    let crash = false;
    // One transport across both realms, so its send count is the whole history.
    const chain = createChainFixture({ crashOnSend: () => crash });

    const first = await realmStores(factory);
    const before = createRealm({ clock, relay, stores: first.stores, chain });
    const connection = await before.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    expect((await (await grant.sendCalls(sendCallsInput())).wait()).status).toBe("finalized");
    const grantId = chain.sends[0]?.grantId;
    if (!grantId) throw new Error("expected the installed Grant identity");

    // The uninstall is accepted and its response is lost. The exact attempted
    // identity must occupy the revocation lane before the transport is opened.
    crash = true;
    await grant.revoke();
    expect(grant.state).toBe("revoking");
    expect(chain.sends).toHaveLength(2);
    expect(chain.sends[1]?.kind).toBe("revocation");
    const attempted = await new OperationStore(
      createIndexedDbOperationStoreAdapter(first.database),
    ).get({ grantId, chainId: CHAIN_ID, kind: "revocation" });
    expect(attempted?.value.state).toBe("submission_attempted");
    const revocationHash = attempted?.value.identity.userOperationHash;
    const revocationNonce = attempted?.value.identity.nonce;
    if (!revocationHash || revocationNonce === undefined) {
      throw new Error("expected the retained revocation identity");
    }

    // Recreate every instance: connection, stores, adapters, database, OAAth,
    // and Grant handle. Permission presence remains inconclusive, so only exact
    // operation observation can complete revocation.
    await connection.close();
    first.database.close();
    opened.splice(opened.indexOf(first.database), 1);
    crash = false;

    const second = await realmStores(factory);
    const after = createRealm({ clock, relay, stores: second.stores, chain });
    const secondConnection = await after.oaath.connect();
    const restored = await secondConnection.resume();
    if (!restored) throw new Error("expected the revoking Grant to resume");
    expect(restored.state).toBe("revoking");
    await restored.revoke();

    expect(restored.state).toBe("revoked");
    expect(chain.sends).toHaveLength(2);
    const finalized = await new OperationStore(
      createIndexedDbOperationStoreAdapter(second.database),
    ).get({ grantId, chainId: CHAIN_ID, kind: "revocation" });
    expect(finalized?.value.state).toBe("finalized");
    if (finalized?.value.state !== "finalized") {
      throw new Error("expected the retained revocation to finalize");
    }
    expect(finalized.value.identity.userOperationHash).toBe(revocationHash);
    expect(finalized.value.identity.nonce).toBe(revocationNonce);
    expect(finalized.value.submittedAt).toBeNull();
    await secondConnection.close();
  });

  it("keeps observing without submitting while the receipt is missing", async () => {
    let crash = true;
    let withhold = true;
    const chain = createChainFixture({
      crashOnSend: () => crash,
      withholdReceipt: () => withhold,
    });
    const realm = createRealm({ chain });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const operation = await grant.sendCalls(sendCallsInput());
    expect(chain.sends).toHaveLength(1);
    crash = false;

    // Observation retries: every attempt reads, none submits.
    const pending = await operation.wait({ attempts: 3 });
    expect(pending.status).toBe("pending");
    expect(pending.reason).toBe("receipt_missing");
    expect(chain.sends).toHaveLength(1);

    withhold = false;
    const finalized = await operation.wait();
    expect(finalized.status).toBe("finalized");
    expect(chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("refuses a submission result bound to another identity", async () => {
    const chain = createChainFixture();
    const realm = createRealm({
      chain: {
        ...chain,
        capability: Object.freeze({
          ...chain.capability,
          submission: Object.freeze({
            async open(request: { readonly prepared: { readonly userOperationHash: string } }) {
              chain.sends.push(request.prepared as never);
              return {
                async send() {
                  return { userOperationHash: `0x${"cd".repeat(32)}` };
                },
                async close() {},
              };
            },
          }),
        }),
      },
    });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const operation = await grant.sendCalls(sendCallsInput());
    // A foreign hash never advances the operation to submitted.
    expect(operation.outcome.status).toBe("pending");
    expect(operation.outcome.reason).toBe("identity_mismatch");
    expect(operation.outcome.state).toBe("submission_attempted");
    await connection.close();
  });
});
