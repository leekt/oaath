/**
 * The viem adapter: one Grant behind an EIP-1193 provider, executing through
 * the real relay and the synthetic chain with every Grant boundary intact.
 *
 * @author taek <leekt216@gmail.com>
 */
import { createWalletClient, custom } from "viem";
import { describe, expect, it } from "vitest";
import { oaathProvider } from "../src/viem.js";
import { CALL_DATA, CHAIN_ID, createRealm, permissionInput, TARGET } from "./support/browser.js";

async function activeGrant() {
  const realm = createRealm();
  const connection = await realm.oaath.connect();
  const grant = await connection.requestPermission(permissionInput());
  return { realm, connection, grant };
}

describe("viem provider over a Grant", () => {
  it("answers identity facts and executes a covered transaction through viem", async () => {
    const { realm, connection, grant } = await activeGrant();
    const provider = oaathProvider({ grant, chain: CHAIN_ID });

    expect(await provider.request({ method: "eth_chainId" })).toBe(`0x${CHAIN_ID.toString(16)}`);
    const [account] = (await provider.request({ method: "eth_requestAccounts" })) as [
      `0x${string}`,
    ];
    // The address is derived through the chain's own factory reads, and it is
    // the Grant's account: the operation below proves it by executing from it.
    expect(account).toMatch(/^0x[0-9a-f]{40}$/u);
    expect(await grant.account(CHAIN_ID)).toBe(account);

    const wallet = createWalletClient({ transport: custom(provider) });
    const hash = await wallet.sendTransaction({
      account,
      chain: null,
      to: TARGET,
      value: 0n,
      data: CALL_DATA,
    });
    // The returned hash is the real inclusion transaction, not the
    // UserOperation hash, so ordinary receipt lookups resolve.
    expect(hash).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(realm.chain.sends).toHaveLength(1);
    expect(realm.chain.sends[0]?.userOperation.sender).toBe(account);
    expect(hash).not.toBe(realm.chain.sends[0]?.userOperationHash);
    await connection.close();
  });

  it("keeps every Grant boundary: uncovered calls deny before any send", async () => {
    const { realm, connection, grant } = await activeGrant();
    const provider = oaathProvider({ grant, chain: CHAIN_ID });
    const account = await grant.account(CHAIN_ID);
    await expect(
      provider.request({
        method: "eth_sendTransaction",
        params: [{ from: account, to: `0x${"33".repeat(20)}`, data: CALL_DATA }],
      }),
    ).rejects.toMatchObject({ code: "oaath_client_scope_denied" });
    expect(realm.chain.sends).toHaveLength(0);
    await connection.close();
  });

  it("refuses foreign senders, malformed transactions, and unsupported methods", async () => {
    const { connection, grant } = await activeGrant();
    const provider = oaathProvider({ grant, chain: CHAIN_ID });
    const account = await grant.account(CHAIN_ID);
    for (const params of [
      undefined,
      [],
      [{ to: TARGET }],
      [{ from: `0x${"99".repeat(20)}`, to: TARGET }],
      [{ from: account }],
      [{ from: account, to: "not-an-address" }],
      [{ from: account, to: TARGET, value: "12" }],
      [{ from: account, to: TARGET, gas: "0x1" }],
    ]) {
      await expect(
        provider.request({ method: "eth_sendTransaction", params }),
      ).rejects.toMatchObject({
        name: expect.stringMatching(/OaathProviderRpcError|OaathClientError/u),
      });
    }
    // Reads and signing are refused, never emulated.
    for (const method of ["eth_call", "personal_sign", "eth_signTypedData_v4"]) {
      await expect(provider.request({ method })).rejects.toMatchObject({
        name: "OaathProviderRpcError",
        code: 4200,
      });
    }
    await connection.close();
  });

  it("executes an EIP-5792 bundle and answers status from evidence", async () => {
    const { realm, connection, grant } = await activeGrant();
    const provider = oaathProvider({ grant, chain: CHAIN_ID });
    const account = await grant.account(CHAIN_ID);

    const capabilities = (await provider.request({ method: "wallet_getCapabilities" })) as Record<
      string,
      unknown
    >;
    expect(capabilities[`0x${CHAIN_ID.toString(16)}`]).toEqual({
      atomic: { status: "supported" },
    });

    const { id } = (await provider.request({
      method: "wallet_sendCalls",
      params: [
        {
          version: "2.0.0",
          chainId: `0x${CHAIN_ID.toString(16)}`,
          from: account,
          atomicRequired: true,
          calls: [{ to: TARGET, data: CALL_DATA }],
        },
      ],
    })) as { id: string };
    expect(id).toMatch(/^0x[0-9a-f]{32}$/u);
    expect(realm.chain.sends).toHaveLength(1);

    const status = (await provider.request({
      method: "wallet_getCallsStatus",
      params: [id],
    })) as {
      status: number;
      atomic: boolean;
      receipts: readonly Record<string, unknown>[];
    };
    expect(status.status).toBe(200);
    expect(status.atomic).toBe(true);
    const receipt = status.receipts[0];
    if (!receipt) throw new Error("expected one receipt");
    // The receipt is read from the chain and bound to the operation's own
    // inclusion evidence — real transaction hash, real block, real logs.
    expect(receipt.status).toBe("0x1");
    expect(receipt.transactionHash).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(receipt.blockNumber).toBe("0x14");
    expect(receipt.gasUsed).toBe("0xa");
    expect(Array.isArray(receipt.logs)).toBe(true);

    // An unknown id is a refusal, not an empty success.
    await expect(
      provider.request({ method: "wallet_getCallsStatus", params: ["0xdeadbeef"] }),
    ).rejects.toMatchObject({ code: -32602 });
    await connection.close();
  });

  it("exposes the terminal receipt on the operation handle, evidence-bound", async () => {
    const { connection, grant } = await activeGrant();
    const operation = await grant.sendCalls({
      chain: CHAIN_ID,
      calls: [{ target: TARGET, value: "0", data: CALL_DATA }],
    });
    await operation.wait();
    const receipt = await operation.receipt();
    expect(receipt.status).toBe("success");
    expect(receipt.blockNumber).toBe("20");
    expect(receipt.gasUsed).toBe("10");
    expect(receipt.transactionHash).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(receipt.logs.length).toBeGreaterThan(0);
    expect(receipt.logs[0]?.topics[0]).toMatch(/^0x[0-9a-f]{64}$/u);
    await connection.close();
  });

  it("fails closed on a hostile provider composition", () => {
    for (const value of [
      { grant: null, chain: CHAIN_ID },
      { grant: {}, chain: CHAIN_ID },
      { chain: CHAIN_ID },
      { grant: {}, chain: 0 },
      { grant: {}, chain: CHAIN_ID, extra: 1 },
    ]) {
      expect(() => oaathProvider(value as never)).toThrowError(
        expect.objectContaining({ name: "OaathClientError" }),
      );
    }
  });
});
