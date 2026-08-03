/**
 * The complete browser golden path against the real in-process relay.
 *
 * @author taek <leekt216@gmail.com>
 */
import { describe, expect, it } from "vitest";
import { OperationStore } from "../src/index.js";
import {
  CALL_DATA,
  CHAIN_ID,
  createChainFixture,
  createRealm,
  permissionInput,
  sendCallsInput,
  TARGET,
} from "./support/browser.js";

describe("browser golden path", () => {
  it("connects, requests permission, sends calls, finalizes, and revokes", async () => {
    const realm = createRealm();
    const connection = await realm.oaath.connect();

    // Nothing is persisted before consent.
    expect(await connection.resume()).toBeNull();

    const grant = await connection.requestPermission(permissionInput());
    expect(grant.state).toBe("active");
    expect(realm.ownerCalls).toHaveLength(1);

    const operation = await grant.sendCalls(sendCallsInput());
    expect(realm.chain.sends).toHaveLength(1);
    const prepared = realm.chain.sends[0];
    if (!prepared) throw new Error("expected a submitted snapshot");
    // The submitted snapshot is the exact prepared identity, signed once.
    expect(prepared.chainId).toBe(CHAIN_ID);
    expect(prepared.kind).toBe("execution");
    expect(prepared.userOperation.sender).toMatch(/^0x[0-9a-f]{40}$/u);
    expect(realm.chain.signatures[0]).toMatch(/^0x[0-9a-f]+$/u);
    expect(realm.chain.sends[0]?.userOperationHash).toBe(prepared.userOperationHash);

    const outcome = await operation.wait();
    expect(outcome.status).toBe("finalized");
    expect(outcome.state).toBe("finalized");
    expect(outcome.outcome).toBe("success");
    expect(outcome.transactionHash).toMatch(/^0x[0-9a-f]{64}$/u);
    // Observation never resubmits.
    expect(realm.chain.sends).toHaveLength(1);

    // The durable journal holds exactly one finalized operation for the lane.
    const stored = await new OperationStore(realm.stores.operations).get({
      grantId: prepared.grantId,
      chainId: CHAIN_ID,
    });
    expect(stored?.value.state).toBe("finalized");
    expect(stored?.value.identity.userOperationHash).toBe(prepared.userOperationHash);

    await grant.revoke();
    expect(grant.state).toBe("revoked");
    expect(realm.invalidations()).toBe(1);
    expect(realm.chain.sends).toHaveLength(1);

    await connection.close();
  });

  it("routes an uncovered call to owner authority and a covered call to the session", async () => {
    const uncovered = createRealm();
    const connection = await uncovered.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    // No finalized usage evidence exists, so coverage is inconclusive and the
    // decision table requires owner authority; the send still completes.
    const operation = await grant.sendCalls(sendCallsInput());
    expect((await operation.wait()).status).toBe("finalized");
    await connection.close();

    // With complete usage evidence the same calls are covered and the decision
    // selects the session authority. Composing it fails closed: an approved grant
    // always bounds its validity window, and no reviewed expiry policy module is
    // pinned yet, so the permission cannot express the approved scope. Owner
    // authority is never substituted for the session the owner approved.
    const covered = createRealm({ chain: createChainFixture({ usage: true }) });
    const sessionConnection = await covered.oaath.connect();
    const sessionGrant = await sessionConnection.requestPermission(permissionInput());
    await expect(sessionGrant.sendCalls(sendCallsInput())).rejects.toMatchObject({
      name: "OaathClientError",
      code: "oaath_client_capability_unsupported",
    });
    expect(covered.chain.sends).toHaveLength(0);
    await sessionConnection.close();
  });

  it("fails closed when no submission route is available", async () => {
    const realm = createRealm({
      chain: createChainFixture({ bundler: "absent", feePayer: null }),
    });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    await expect(grant.sendCalls(sendCallsInput())).rejects.toMatchObject({
      name: "OaathClientError",
      code: "oaath_client_route_unavailable",
    });
    expect(realm.chain.sends).toHaveLength(0);
    await connection.close();
  });

  it("submits the same signed operation through handleOps when the bundler conclusively refuses", async () => {
    const realm = createRealm({
      chain: createChainFixture({
        bundler: "absent",
        feePayer: { address: `0x${"77".repeat(20)}`, balance: "1000000000000000000" },
      }),
    });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const operation = await grant.sendCalls(sendCallsInput());
    expect((await operation.wait()).status).toBe("finalized");
    expect(realm.chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("preserves a rejected permission decision and refuses to hand out authority", async () => {
    const realm = createRealm({ owner: { outcome: "reject" } });
    const connection = await realm.oaath.connect();
    await expect(connection.requestPermission(permissionInput())).rejects.toMatchObject({
      name: "OaathClientError",
      code: "oaath_client_permission_rejected",
    });
    // The rejection is durable, so nothing can be resumed as authority.
    expect(await connection.resume()).toBeNull();
    await connection.close();
  });

  it("refuses an owner decision that widens the reviewed policy", async () => {
    const realm = createRealm({
      owner: {
        policy: (requested) => ({
          ...(requested as Record<string, unknown>),
          perChainOperationLimit: 1_000,
        }),
      },
    });
    const connection = await realm.oaath.connect();
    await expect(connection.requestPermission(permissionInput())).rejects.toMatchObject({
      name: "OaathClientError",
      source: "permission_policy_widening",
    });
    await connection.close();
  });

  it("refuses a decision artifact bound to another request", async () => {
    const realm = createRealm({
      owner: { artifact: (decision) => ({ ...decision, requestHash: `0x${"11".repeat(32)}` }) },
    });
    const connection = await realm.oaath.connect();
    await expect(connection.requestPermission(permissionInput())).rejects.toMatchObject({
      name: "OaathClientError",
      source: "permission_decision_binding_mismatch",
    });
    await connection.close();
  });

  it("refuses calls the Grant scope does not name", async () => {
    const realm = createRealm({ chain: createChainFixture({ usage: true }) });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    // A different target is uncovered, so the decision requires owner authority
    // and the send proceeds under root authority the owner already holds.
    const operation = await grant.sendCalls({
      chain: CHAIN_ID,
      calls: [{ target: `0x${"33".repeat(20)}`, value: "0", data: CALL_DATA }],
    });
    expect((await operation.wait()).status).toBe("finalized");
    await connection.close();
  });

  it("keeps the application free of protocol mechanics", async () => {
    const realm = createRealm();
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const operation = await grant.sendCalls(sendCallsInput());

    expect(Object.keys(realm.oaath).sort()).toEqual(["binding", "close", "connect", "disconnect"]);
    expect(Object.keys(connection).sort()).toEqual([
      "binding",
      "close",
      "requestPermission",
      "resume",
      "signOut",
    ]);
    expect(Object.keys(grant).sort()).toEqual([
      "close",
      "expiresAt",
      "revoke",
      "sendCalls",
      "state",
    ]);
    expect(Object.keys(operation).sort()).toEqual([
      "chainId",
      "close",
      "observe",
      "outcome",
      "wait",
    ]);
    // No permission id, enable envelope, journal, revision, or nonce surface.
    for (const surface of [realm.oaath, connection, grant, operation]) {
      const keys = Object.keys(surface).join(",");
      expect(keys).not.toMatch(
        /permissionId|enable|envelope|journal|revision|nonce|grantId|prepared|signature/iu,
      );
    }
    await connection.close();
  });

  it("refuses to act after signOut and after close", async () => {
    const realm = createRealm();
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    await connection.signOut();
    expect(realm.signOutCalls()).toBe(1);
    await expect(connection.requestPermission(permissionInput())).rejects.toMatchObject({
      code: "oaath_client_signed_out",
    });
    await connection.close();
    await expect(grant.sendCalls(sendCallsInput())).rejects.toMatchObject({
      code: "oaath_client_closed",
    });
    await expect(connection.requestPermission(permissionInput())).rejects.toMatchObject({
      code: "oaath_client_closed",
    });
  });

  it("refuses an expired Grant without touching the chain", async () => {
    const realm = createRealm();
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    realm.clock.advance(1_801);
    await expect(grant.sendCalls(sendCallsInput())).rejects.toMatchObject({
      code: "oaath_client_grant_inactive",
      source: "grant_expired",
    });
    expect(realm.chain.sends).toHaveLength(0);
    expect(realm.chain.quotes).toBe(0);
    await connection.close();
  });

  it("refuses a chain that was never configured", async () => {
    const realm = createRealm();
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    await expect(
      grant.sendCalls({
        chain: 11_155_111,
        calls: [{ target: TARGET, value: "0", data: CALL_DATA }],
      }),
    ).rejects.toMatchObject({
      code: "oaath_client_capability_unsupported",
      source: "chain_not_configured",
    });
    await connection.close();
  });
});
