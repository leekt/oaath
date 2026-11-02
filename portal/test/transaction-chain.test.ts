/**
 * The portal sends an owner transaction on a chain the wallet does not know
 * by adding it from the request's own metadata, exactly once, then switching.
 */
import { parseOwnerTransactionRequest } from "@oaath/protocol";
import { describe, expect, it } from "vitest";
import type { Eip1193Provider } from "../src/signers.js";
import { sendOnChain } from "../src/TransactionReview.js";

const HASH = `0x${"7a".repeat(32)}`;
const base = {
  version: "oaath.owner-transaction-request/v1",
  chainId: 4242,
  from: `0x${"11".repeat(20)}`,
  to: `0x${"22".repeat(20)}`,
  value: "0",
  data: "0x",
};
const chain = {
  name: "Example Chain",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: ["https://rpc.example.org/"],
};

/** A wallet that does not know chain 4242 until it is added. */
function wallet() {
  const calls: { method: string; params?: unknown }[] = [];
  let known = false;
  const provider: Eip1193Provider = {
    async request(args) {
      calls.push(args);
      if (args.method === "wallet_switchEthereumChain" && !known)
        throw Object.assign(new Error("unrecognized chain"), { code: 4902 });
      if (args.method === "wallet_addEthereumChain") known = true;
      return args.method === "eth_sendTransaction" ? HASH : null;
    },
  };
  return { provider, calls };
}

describe("sendOnChain", () => {
  it("adds an unknown chain once from the request's metadata, switches, then sends", async () => {
    const { provider, calls } = wallet();
    const request = parseOwnerTransactionRequest({ ...base, chain });
    expect(await sendOnChain(provider, request)).toBe(HASH);
    expect(calls.map((call) => call.method)).toEqual([
      "wallet_switchEthereumChain",
      "wallet_addEthereumChain",
      "wallet_switchEthereumChain",
      "eth_sendTransaction",
    ]);
    expect(calls[1]!.params).toEqual([
      {
        chainId: "0x1092",
        chainName: chain.name,
        nativeCurrency: chain.nativeCurrency,
        rpcUrls: chain.rpcUrls,
      },
    ]);
  });

  it("never adds a chain the request does not describe", async () => {
    const { provider, calls } = wallet();
    await expect(sendOnChain(provider, parseOwnerTransactionRequest(base))).rejects.toMatchObject({
      code: 4902,
    });
    expect(calls.map((call) => call.method)).toEqual(["wallet_switchEthereumChain"]);
  });
});
