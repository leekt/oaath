import { createWalletClient, custom, encodeFunctionData, toHex } from "viem";
import { entryPoint07Abi, toPackedUserOperation } from "viem/account-abstraction";
import { describe, expect, it } from "vitest";
import type { OaathSubmissionRequest } from "../src/advanced.js";
import { OaathRpcError } from "../src/cetane.js";
import { asCetaneUserOperation } from "../src/kernel.js";
import {
  CHAIN_ID,
  createChainFixture,
  createRealm,
  permissionInput,
  sendCallsInput,
} from "./support/browser.js";

const address = `0x${"11".repeat(20)}` as const;
const hash = `0x${"22".repeat(32)}` as const;
describe("Grant connected EOA fallback", () => {
  it.each([
    { name: "direct", create: createRealm, code: -32500 },
    { name: "direct", create: createRealm, code: -32603 },
  ])("keeps one signed identity through $name after rejection $code", async ({ create, code }) => {
    const base = createChainFixture({ withholdReceipt: () => true });
    let submitted: Readonly<OaathSubmissionRequest> | undefined;
    let bundlerSends = 0;
    const realm = create({
      chain: {
        ...base,
        capability: {
          ...base.capability,
          submission: {
            open: async (request) => {
              submitted = request;
              return {
                send: async () => {
                  bundlerSends++;
                  throw new OaathRpcError("oaath_rpc_rejected", code);
                },
                close: async () => {},
              };
            },
          },
        },
      },
    });
    const walletMethods: string[] = [];
    const wallet = createWalletClient({
      account: address,
      transport: custom({
        request: async ({ method, params }) => {
          walletMethods.push(method);
          if (method === "eth_chainId") return toHex(CHAIN_ID);
          if (method === "eth_accounts") return [address];
          expect(method).toBe("eth_sendTransaction");
          if (submitted === undefined) throw new Error("bundler was not attempted first");
          const [transaction] = params as [{ data: `0x${string}` }];
          const expected = encodeFunctionData({
            abi: entryPoint07Abi,
            functionName: "handleOps",
            args: [
              [
                toPackedUserOperation({
                  ...asCetaneUserOperation(submitted.prepared.userOperation),
                  signature: submitted.signature,
                }),
              ],
              address,
            ],
          });
          expect(transaction.data === expected).toBe(true);
          return hash;
        },
      }),
    });
    try {
      const connection = await realm.oaath.connect();
      const grant = await connection.requestPermission(permissionInput());
      const input = {
        ...(sendCallsInput() as Record<string, unknown>),
        payer: { kind: "connected-eoa", wallet },
      };
      const quotes = base.quotes;
      const review = await grant.reviewCalls(input);
      expect(review).toMatchObject({
        signer: "session",
        route: "erc4337-bundler",
        fallback: {
          route: "erc4337-handleops",
          feePayer: address,
          condition: "conclusive_bundler_rejection",
        },
      });
      expect(walletMethods).toEqual([]);
      expect(base.quotes).toBe(quotes);
      const operation = await grant.sendCalls(input);
      expect(operation.outcome.status).toBe("pending");
      expect(bundlerSends).toBe(1);
      expect(walletMethods.filter((method) => method === "eth_sendTransaction")).toHaveLength(
        code === -32500 ? 1 : 0,
      );
      expect(
        await realm.stores.operations.get({
          grantId: review.grantId,
          chainId: CHAIN_ID,
          kind: "execution",
        }),
      ).toMatchObject({
        value: {
          state: code === -32500 ? "submitted" : "submission_attempted",
          submission:
            code === -32500 ? { route: "erc4337-handleops", transactionHash: hash } : null,
        },
      });
      await operation.wait({ attempts: 1 });
      expect(bundlerSends).toBe(1);
      expect(walletMethods.filter((method) => method === "eth_sendTransaction")).toHaveLength(
        code === -32500 ? 1 : 0,
      );
      await expect(grant.sendCalls(input)).rejects.toMatchObject({
        code: "oaath_client_state_conflict",
      });
      expect(bundlerSends).toBe(1);
    } finally {
      await realm.oaath.close();
    }
  });
  it("refuses a payer that mixes sponsorship and connected fallback before wallet or quote work", async () => {
    const realm = createRealm();
    try {
      const connection = await realm.oaath.connect();
      const grant = await connection.requestPermission(permissionInput());
      for (const payer of [
        { kind: "connected-eoa", wallet: {}, url: "https://paymaster.test", context: {} },
        { kind: "paymaster-service", wallet: {}, url: "https://paymaster.test", context: {} },
        { kind: "account" },
      ]) {
        const input = { ...(sendCallsInput() as Record<string, unknown>), payer };
        await expect(grant.reviewCalls(input)).rejects.toMatchObject({
          code: "oaath_client_input_invalid",
        });
        await expect(grant.sendCalls(input)).rejects.toMatchObject({
          code: "oaath_client_input_invalid",
        });
      }
      expect(realm.chain.quotes).toBe(0);
      expect(realm.chain.sends).toHaveLength(0);
    } finally {
      await realm.oaath.close();
    }
  });
});
