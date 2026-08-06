/**
 * The complete browser golden path against the real in-process relay.
 *
 * @author taek <leekt216@gmail.com>
 */
import { decodeAbiParameters, getAddress, recoverAddress } from "viem";
import { describe, expect, it } from "vitest";
import { OperationStore } from "../src/advanced.js";
import {
  CALL_DATA,
  CHAIN_ID,
  createChainFixture,
  createRealm,
  operatorCredential,
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
    // The replayable capability is dead, so nothing new can materialize, but
    // the installed chain permission still needs owner-signed removal the
    // application cannot mint: the Grant stays durably `revoking` rather than
    // claiming a revocation no chain observed.
    expect(grant.state).toBe("revoking");
    expect(realm.invalidations()).toBe(1);
    expect(realm.chain.sends).toHaveLength(1);
    // A revoking Grant authorizes nothing new.
    await expect(grant.sendCalls(sendCallsInput())).rejects.toMatchObject({
      code: "oaath_client_grant_inactive",
    });

    await connection.close();
  });

  it("denies inconclusive coverage before any probe, quote, or send", async () => {
    // No finalized usage evidence exists, so coverage is inconclusive. A Grant
    // may authorize at most the approved scope, so the send fails closed with
    // scope denial — it is never widened to owner authority — and nothing
    // reaches the quote or submission transports.
    const unreadable = createRealm({ chain: createChainFixture({ usage: false }) });
    const connection = await unreadable.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    await expect(grant.sendCalls(sendCallsInput())).rejects.toMatchObject({
      name: "OaathClientError",
      code: "oaath_client_scope_denied",
      source: "session_coverage_unreadable",
    });
    expect(unreadable.chain.quotes).toBe(0);
    expect(unreadable.chain.sends).toHaveLength(0);
    await connection.close();
  });

  it("materializes on first use, then executes with the standard session authority", async () => {
    // With complete usage evidence the calls are covered and the decision
    // selects the session authority, which composes: every axis the approved
    // policy bounds — calls, value, the validity window, the per-chain operation
    // count — has a pinned reviewed policy module, so the permission expresses the
    // approved scope exactly and the session key signs the operation itself.
    const covered = createRealm({ chain: createChainFixture({ usage: true }) });
    const sessionConnection = await covered.oaath.connect();
    const sessionGrant = await sessionConnection.requestPermission(permissionInput());

    // First covered execution: the owner's replayable install approval is
    // spent in Kernel's enable-replayable mode, so the permission installs and
    // the call executes in one operation.
    const first = await sessionGrant.sendCalls(sendCallsInput());
    expect((await first.wait()).status).toBe("finalized");
    const installOperation = covered.chain.sends[0];
    if (!installOperation) throw new Error("expected the materializing submission");
    expect((BigInt(installOperation.userOperation.nonce) >> 248n) & 0xffn).toBe(0x0cn);
    expect((BigInt(installOperation.userOperation.nonce) >> 240n) & 0xffn).toBe(2n);

    // Second execution: the chain is materialized, so the operation validates
    // through the standard permission path.
    const second = await sessionGrant.sendCalls(sendCallsInput());
    expect((await second.wait()).status).toBe("finalized");
    expect(covered.chain.sends).toHaveLength(2);
    const sessionPrepared = covered.chain.sends[1];
    const envelope = covered.chain.signatures[1];
    if (!sessionPrepared || !envelope) throw new Error("expected one standard submission");
    // Kernel encodes the validation it must use in the nonce key: type 0x02 is a
    // permission, so the chain itself would refuse root authority for this
    // operation. Owner authority is never substituted for the approved session.
    expect((BigInt(sessionPrepared.userOperation.nonce) >> 248n) & 0xffn).toBe(0n);
    expect((BigInt(sessionPrepared.userOperation.nonce) >> 240n) & 0xffn).toBe(2n);
    // The signature is Kernel's permission envelope: an empty slice per installed
    // policy, then the session key's signature last.
    const [slices] = decodeAbiParameters(
      [{ name: "signatures", type: "bytes[]" }],
      envelope as `0x${string}`,
    );
    const signerSlice = slices[slices.length - 1];
    if (!signerSlice) throw new Error("permission envelope carries no signer slice");
    expect(slices.slice(0, -1)).toEqual(slices.slice(0, -1).map(() => "0x"));
    expect(slices.length).toBeGreaterThan(1);
    expect(
      await recoverAddress({
        hash: sessionPrepared.userOperationHash,
        signature: signerSlice,
      }),
    ).toBe(getAddress(operatorCredential.address));
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
    // A different target is conclusively outside the approved scope. The Grant
    // never widens to root authority: the send is denied before any signature
    // or submission exists.
    await expect(
      grant.sendCalls({
        chain: CHAIN_ID,
        calls: [{ target: `0x${"33".repeat(20)}`, value: "0", data: CALL_DATA }],
      }),
    ).rejects.toMatchObject({
      name: "OaathClientError",
      code: "oaath_client_scope_denied",
      source: "session_calls_uncovered",
    });
    expect(realm.chain.quotes).toBe(0);
    expect(realm.chain.sends).toHaveLength(0);
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
      "account",
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
      "receipt",
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
