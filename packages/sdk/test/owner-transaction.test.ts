/**
 * Owner transactions through a simulated popup and portal: the PAR carries the
 * exact request, its identity is known before sending, and only the hash
 * released for that same request is returned. `portalWallet` serves the
 * connected-EOA wallet shape.
 */
import { hashOwnerTransactionRequest } from "@oaath/protocol";
import { afterEach, describe, expect, it, vi } from "vitest";
import { portalWallet, requestOwnerTransaction } from "../src/index.js";
import { installOAuthPortal } from "./support/oauth-portal.js";

const FROM = `0x${"11".repeat(20)}` as const;
const HASH = `0x${"7a".repeat(32)}`;
const request = {
  version: "oaath.owner-transaction-request/v1",
  chainId: 8453,
  from: FROM,
  to: null,
  value: "1000000000000000000",
  data: "0x6080",
} as const;

async function portal(sendTransaction: (request: unknown) => Promise<Record<string, unknown>>) {
  const installed = await installOAuthPortal({ sendTransaction });
  const { kind: _, ...login } = installed.approvals;
  return { ...installed, login };
}

afterEach(() => vi.unstubAllGlobals());

describe("requestOwnerTransaction", () => {
  it("returns the hash the wallet sent for exactly this request, with its identity", async () => {
    const { login, pars } = await portal(async (sent) => ({
      request: sent,
      transaction_hash: HASH,
    }));
    const sent = await requestOwnerTransaction({ ...login, request });
    expect(sent.transactionHash).toBe(HASH);
    expect(sent.requestHash).toBe(hashOwnerTransactionRequest(request));
    const [detail] = JSON.parse([...pars.values()][0]!.get("authorization_details")!);
    expect(detail).toEqual({ type: "oaath_transaction", request });
  });

  it("refuses a hash released for another request", async () => {
    const { login } = await portal(async (sent) => ({
      request: { ...(sent as object), value: "1" },
      transaction_hash: HASH,
    }));
    await expect(requestOwnerTransaction({ ...login, request })).rejects.toMatchObject({
      code: "oaath_client_state_conflict",
      source: "oauth_transaction_mismatch",
    });
  });
});

describe("portalWallet", () => {
  it("answers the connected-EOA wallet calls and sends through the portal", async () => {
    const { login, pars, launch } = await portal(async (sent) => ({
      request: sent,
      transaction_hash: HASH,
    }));
    const wallet = portalWallet({ ...login, chainId: 8453, from: FROM, launch });
    expect(await wallet.request({ method: "eth_chainId" })).toBe("0x2105");
    expect(await wallet.request({ method: "eth_accounts" })).toEqual([FROM]);
    const to = `0x${"22".repeat(20)}` as const;
    expect(
      await wallet.request({
        method: "eth_sendTransaction",
        params: [{ from: FROM, to, data: "0x1234", value: "0xde0b6b3a7640000", chainId: "0x2105" }],
      }),
    ).toBe(HASH);
    const [detail] = JSON.parse([...pars.values()][0]!.get("authorization_details")!);
    expect(detail.request).toMatchObject({ to, value: "1000000000000000000", data: "0x1234" });
    await expect(
      wallet.request({
        method: "eth_sendTransaction",
        params: [{ from: `0x${"33".repeat(20)}`, to, data: "0x", value: "0x0" }],
      }),
    ).rejects.toMatchObject({ code: "oaath_client_input_invalid" });
  });
});
