/**
 * Caller-reserved operation lanes: the forbidden transitions.
 *
 * A lane never enables the permission, never accepts a key outside the
 * runtime's nonce namespace or a quote for another namespace, keeps one
 * unresolved operation, and keeps revocation from reporting completion. The
 * real Kernel and EntryPoint proof lives in @oaath/testing's Anvil suite.
 *
 * @author taek <leekt216@gmail.com>
 */
import { describe, expect, it } from "vitest";
import {
  CHAIN_ID,
  createChainFixture,
  createRealm,
  permissionInput,
  sendCallsInput,
} from "./support/browser.js";

function onLane(nonceKey: unknown, id: unknown = "run_a"): unknown {
  return { ...(sendCallsInput() as object), lane: { id, nonceKey } };
}

async function installedGrant(chain = createChainFixture()) {
  const realm = createRealm({ chain });
  const connection = await realm.oaath.connect();
  const grant = await connection.requestPermission(permissionInput());
  const installing = await grant.sendCalls(sendCallsInput());
  expect((await installing.wait()).status).toBe("finalized");
  return { chain, connection, grant };
}

describe("caller-reserved operation lanes", () => {
  it("refuses a lane before the permission is observed installed", async () => {
    const chain = createChainFixture();
    const realm = createRealm({ chain });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    // Two lanes can never race the first use: only the default lane enables.
    await expect(grant.sendCalls(onLane(17n))).rejects.toMatchObject({
      code: "oaath_client_state_conflict",
      source: "operation_lane_permission_not_installed",
    });
    expect(chain.quotes).toBe(0);
    expect(chain.sends).toHaveLength(0);
    await connection.close();
  });

  it("rejects keys outside the nonce namespace and malformed lanes before any quote", async () => {
    const { chain, connection, grant } = await installedGrant();
    const quotes = chain.quotes;
    for (const nonceKey of [0n, -1n, 65_536n, 17, "17"]) {
      await expect(grant.sendCalls(onLane(nonceKey))).rejects.toMatchObject({
        code: "oaath_client_input_invalid",
      });
    }
    await expect(grant.sendCalls(onLane(17n, " run"))).rejects.toMatchObject({
      code: "oaath_client_input_invalid",
      source: "operation_lane_id_invalid",
    });
    await expect(
      grant.sendCalls({ ...(onLane(17n) as object), signer: "auto" }),
    ).rejects.toMatchObject({ code: "oaath_client_input_invalid" });
    await expect(
      grant.reviewCalls({ ...(sendCallsInput() as object), lane: { id: "run_a", nonceKey: 17n } }),
    ).rejects.toMatchObject({ code: "oaath_client_input_invalid" });
    expect(chain.quotes).toBe(quotes);
    expect(chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("refuses a quote for another nonce namespace without signing or sending", async () => {
    const base = createChainFixture();
    const chain = {
      ...base,
      capability: Object.freeze({
        ...base.capability,
        async quote(request: Parameters<typeof base.capability.quote>[0]) {
          const quoted = (await base.capability.quote(request)) as Record<string, unknown>;
          return { ...quoted, nonceKey: "0" };
        },
      }),
    };
    const realm = createRealm({ chain });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    expect((await (await grant.sendCalls(sendCallsInput())).wait()).status).toBe("finalized");
    await expect(grant.sendCalls(onLane(17n))).rejects.toMatchObject({
      // The runner owns preparation failures; nothing reached signing or sending.
      code: "oaath_client_preparation_failed",
    });
    expect(base.sends).toHaveLength(1);
    await connection.close();
  });

  it("keeps one unresolved operation per lane and exact lookup per lane label", async () => {
    let withhold = false;
    let crash = false;
    const { chain, connection, grant } = await installedGrant(
      createChainFixture({ withholdReceipt: () => withhold, crashOnSend: () => crash }),
    );
    withhold = true;
    crash = true;
    const held = await grant.sendCalls(onLane(17n));
    expect(held.outcome.status).toBe("pending");
    expect(chain.sends).toHaveLength(2);
    const nonce = BigInt(chain.sends[1]?.userOperation.nonce ?? "0");
    expect((nonce >> 64n) & 0xffffn).toBe(17n);

    // The same lane rejects a second send; neither retry path submits again.
    await expect(grant.sendCalls(onLane(17n, "run_b"))).rejects.toMatchObject({
      code: "oaath_client_state_conflict",
    });
    expect(chain.sends).toHaveLength(2);

    // Lookup is exact per lane key and label.
    const lane = { id: "run_a", nonceKey: 17n };
    expect(await grant.getOperation({ chain: CHAIN_ID, id: held.id })).toBeNull();
    expect(
      await grant.getOperation({ chain: CHAIN_ID, id: held.id, lane: { ...lane, id: "run_b" } }),
    ).toBeNull();
    expect(
      await grant.getOperation({ chain: CHAIN_ID, id: held.id, lane: { ...lane, nonceKey: 18n } }),
    ).toBeNull();
    const recovered = await grant.getOperation({ chain: CHAIN_ID, id: held.id, lane });
    expect(recovered?.id).toBe(held.id);
    expect((await recovered?.wait({ attempts: 2 }))?.status).toBe("pending");
    expect(chain.sends).toHaveLength(2);
    await connection.close();
  });

  it("does not report revocation complete while any lane is unresolved", async () => {
    let withhold = false;
    let crash = false;
    const { chain, connection, grant } = await installedGrant(
      createChainFixture({ withholdReceipt: () => withhold, crashOnSend: () => crash }),
    );
    withhold = true;
    crash = true;
    expect((await grant.sendCalls(onLane(17n))).outcome.status).toBe("pending");
    withhold = false;
    crash = false;

    // The chain removal itself finalizes, but the lane's operation is still
    // unresolved, so the Grant stays durably revoking.
    await grant.revoke();
    expect(chain.sends.map((prepared) => prepared.kind)).toEqual([
      "execution",
      "execution",
      "revocation",
    ]);
    expect(grant.state).toBe("revoking");
    await grant.revoke();
    expect(grant.state).toBe("revoking");
    expect(chain.sends).toHaveLength(3);
    await connection.close();
  });
});
