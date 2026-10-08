import { encodeAbiParameters, encodeEventTopics, zeroAddress } from "viem";
import { entryPoint07Abi } from "viem/account-abstraction";
import { describe, expect, it } from "vitest";
import { createCetaneChainPorts } from "../src/cetane.js";
import { prepareUserOperation } from "../src/kernel.js";
import { KERNEL_V4_ENTRY_POINT_V09 } from "../src/kernel-v4.js";

const config = {
  143: {
    publicRpcUrls: ["https://public-a.test", "https://public-b.test"],
    bundlerUrl: "https://bundler.test",
    paymasterUrl: "https://paymaster.test",
  },
};
const rpc = (id: number, result: unknown) => Response.json({ jsonrpc: "2.0", id, result });

describe("default viem chain ports", () => {
  it("pins plain v4 permission reads through the default RPC port", async () => {
    const selectors: unknown[] = [];
    const [chain] = createCetaneChainPorts(config, {
      fetch: async (request) => {
        const { id, method, params } = await request.json();
        if (method === "eth_chainId") return rpc(id, "0x8f");
        if (method === "eth_getBlockByNumber") {
          selectors.push(params[0]);
          return rpc(id, { number: "0x10", hash: `0x${"aa".repeat(32)}` });
        }
        expect(method).toBe("eth_call");
        expect(params[1]).toBe("0x10");
        return rpc(id, `0x${"00".repeat(32)}`);
      },
    });
    if (!chain) throw new Error("missing chain");
    expect(
      await chain.reads.read({
        type: "kernel_v4_permission_state",
        chainId: 143,
        blockTag: "finalized",
        account: `0x${"11".repeat(20)}`,
        signer: `0x${"22".repeat(20)}`,
        permissionId: "0x12345678",
        nonce: "0",
      }),
    ).toEqual({ installed: false, installNonce: "0" });
    expect(selectors).toEqual(["finalized", "0x10"]);
  });

  it.each([
    "success",
    "reverted-operation",
    "pending",
    "reverted-transaction",
    "wrong-operation",
    "wrong-entrypoint",
    "duplicate",
    "wrong-transaction",
  ])(
    "locates a direct %s receipt using only public RPC without trusting the hint as inclusion",
    async (scenario) => {
      const hash = `0x${"11".repeat(32)}` as const;
      const transactionHash = `0x${"22".repeat(32)}` as const;
      const blockHash = `0x${"33".repeat(32)}` as const;
      const sender = `0x${"44".repeat(20)}` as const;
      const event = {
        address: scenario === "wrong-entrypoint" ? sender : KERNEL_V4_ENTRY_POINT_V09,
        topics: encodeEventTopics({
          abi: entryPoint07Abi,
          eventName: "UserOperationEvent",
          args: {
            userOpHash: scenario === "wrong-operation" ? blockHash : hash,
            sender,
            paymaster: zeroAddress,
          },
        }),
        data: encodeAbiParameters(
          [{ type: "uint256" }, { type: "bool" }, { type: "uint256" }, { type: "uint256" }],
          [7n, scenario !== "reverted-operation", 9n, 10n],
        ),
      };
      const receipt = {
        transactionHash: scenario === "wrong-transaction" ? blockHash : transactionHash,
        blockHash,
        blockNumber: "0x14",
        status: scenario === "reverted-transaction" ? "0x0" : "0x1",
        logs: scenario === "duplicate" ? [event, event] : [event],
      };
      const [chain] = createCetaneChainPorts(config, {
        fetch: async (request) => {
          expect(new URL(request.url).hostname).toMatch(/^public-/u);
          const { id, method, params } = await request.json();
          if (method === "eth_chainId") return rpc(id, "0x8f");
          expect(method).toBe("eth_getTransactionReceipt");
          expect(params).toEqual([transactionHash]);
          return rpc(id, scenario === "pending" ? null : receipt);
        },
      });
      const result = chain!.observation.read({
        type: "user_operation_receipt",
        chainId: 143,
        userOperationHash: hash,
        transaction: { hash: transactionHash, entryPoint: KERNEL_V4_ENTRY_POINT_V09 },
      });
      if (scenario === "duplicate" || scenario === "wrong-transaction") {
        await expect(result).rejects.toMatchObject({ code: "oaath_rpc_evidence_invalid" });
      } else if (scenario === "success" || scenario === "reverted-operation") {
        await expect(result).resolves.toEqual({
          userOperationHash: hash,
          entryPoint: KERNEL_V4_ENTRY_POINT_V09,
          sender,
          nonce: "0x7",
          paymaster: zeroAddress,
          actualGasCost: "0x9",
          actualGasUsed: "0xa",
          success: scenario === "success",
          transactionHash,
          blockNumber: "0x14",
          blockHash,
        });
      } else await expect(result).resolves.toBeNull();
    },
  );

  it("bounds timeout and concurrency without a queue", async () => {
    let started = 0;
    const [chain] = createCetaneChainPorts(config, {
      retry: { attempts: 1 },
      timeoutMs: 20,
      maxConcurrency: 1,
      fetch: async (request) => {
        started += 1;
        return new Promise<Response>((_, reject) =>
          request.signal.addEventListener("abort", () => reject(new Error("aborted")), {
            once: true,
          }),
        );
      },
    });
    const pending = chain!.reads.read({ type: "chain_id", chainId: 143 });
    // Duplicate chain checks share the request. A distinct pool still needs a
    // separate wire slot and must respect the instance-wide concurrency bound.
    const route = chain!.routes![0]!;
    if (route.kind !== "erc4337-bundler") throw new Error("missing bundler route");
    await expect(
      route.bundler.probe({
        chainId: 143,
        entryPoint: KERNEL_V4_ENTRY_POINT_V09,
      }),
    ).rejects.toMatchObject({
      code: "oaath_rpc_concurrency_exceeded",
    });
    await expect(pending).rejects.toMatchObject({ code: "oaath_rpc_unavailable" });
    expect(started).toBe(1);
  });

  it.each(["timeout", "gateway", "non-json", "rpc-rejection"])(
    "sends exactly once after %s and never uses a public RPC for submission",
    async (failure) => {
      let sends = 0;
      const [chain] = createCetaneChainPorts(config, {
        retry: { attempts: 3, delayMs: 0 },
        timeoutMs: 20,
        fetch: async (request) => {
          expect(new URL(request.url).hostname).toBe("bundler.test");
          const { id, method } = await request.json();
          if (method === "eth_chainId") return rpc(id, "0x8f");
          expect(method).toBe("eth_sendUserOperation");
          sends += 1;
          if (failure === "gateway") return new Response("bad gateway", { status: 502 });
          if (failure === "non-json") return new Response("not json");
          if (failure === "rpc-rejection")
            return Response.json({
              jsonrpc: "2.0",
              id,
              error: { code: -32500, message: "private diagnostic" },
            });
          return new Promise<Response>((_, reject) =>
            request.signal.addEventListener("abort", () => reject(new Error("aborted")), {
              once: true,
            }),
          );
        },
      });
      const prepared = prepareUserOperation({
        kind: "execution",
        grantId: "test",
        chainId: 143,
        entryPoint: { version: "0.9", address: KERNEL_V4_ENTRY_POINT_V09 },
        userOperation: {
          sender: "0x1111111111111111111111111111111111111111",
          nonce: "0",
          callData: "0x",
          factory: null,
          paymaster: null,
          callGasLimit: "100000",
          verificationGasLimit: "200000",
          preVerificationGas: "50000",
          maxFeePerGas: "100",
          maxPriorityFeePerGas: "1",
        },
      });
      const session = (await chain!.submission.open({
        prepared,
        signature: "0x01",
        route: "erc4337-bundler",
        feePayer: null,
      })) as { send(): Promise<unknown>; close(): Promise<void> };
      const failed = session.send().then(
        () => false,
        () => true,
      );
      expect(await failed).toBe(true);
      expect(
        await session.send().then(
          () => false,
          () => true,
        ),
      ).toBe(true);
      expect(sends).toBe(1);
      await session.close();
    },
  );

  it("routes paymaster calls only to their registered URL and never retries them", async () => {
    let calls = 0;
    const [chain] = createCetaneChainPorts(
      { 143: { ...config[143], paymasterUrl: "https://paymaster.test?project=demo" } },
      {
        fetch: async (request) => {
          calls += 1;
          expect(new URL(request.url).hostname).toBe("paymaster.test");
          expect(new URL(request.url).search).toBe("?project=demo");
          const { method } = await request.json();
          expect(method).toBe("pm_getPaymasterStubData");
          return new Response("busy", { status: 429 });
        },
      },
    );
    const sponsorship = chain!.sponsorship;
    if (sponsorship?.kind !== "erc7677") throw new Error("expected ERC-7677 sponsorship");
    expect(sponsorship.url).toBe("https://paymaster.test");
    await expect(
      sponsorship.request({
        method: "pm_getPaymasterStubData",
        params: [
          {
            sender: "0x1111111111111111111111111111111111111111",
            nonce: "0x0",
            callData: "0x",
            callGasLimit: "0x0",
            verificationGasLimit: "0x0",
            preVerificationGas: "0x0",
            maxFeePerGas: "0x1",
            maxPriorityFeePerGas: "0x1",
          },
          KERNEL_V4_ENTRY_POINT_V09,
          "0x8f",
          {},
        ],
      }),
    ).rejects.toMatchObject({ code: "oaath_rpc_unavailable" });
    expect(calls).toBe(1);
  });
  it("fails over non-JSON public RPC failures without sending account reads to the bundler", async () => {
    const calls: string[] = [];
    const [chain] = createCetaneChainPorts(config, {
      retry: { attempts: 3, delayMs: 0 },
      fetch: async (request) => {
        const { id, method } = await request.json();
        calls.push(`${new URL(request.url).hostname}:${method}`);
        if (request.url.includes("public-a")) return new Response("bad gateway", { status: 502 });
        return rpc(id, method === "eth_chainId" ? "0x8f" : "0x6000");
      },
    });
    expect(
      await chain!.reads.read({
        type: "code",
        chainId: 143,
        address: "0x1111111111111111111111111111111111111111",
      }),
    ).toBe("0x6000");
    expect(calls.some((call) => call.startsWith("public-a"))).toBe(true);
    expect(calls.some((call) => call === "public-b.test:eth_getCode")).toBe(true);
    expect(calls.every((call) => call.startsWith("public-"))).toBe(true);
  });

  it("bounds attempts and the lifetime request budget", async () => {
    let calls = 0;
    const [chain] = createCetaneChainPorts(config, {
      retry: { attempts: 3, delayMs: 0 },
      maxRequests: 2,
      fetch: async () => {
        calls += 1;
        return new Response("busy", { status: 429 });
      },
    });
    await expect(chain!.reads.read({ type: "chain_id", chainId: 143 })).rejects.toMatchObject({
      code: "oaath_rpc_budget_exhausted",
    });
    expect(calls).toBe(2);
    await expect(chain!.reads.read({ type: "chain_id", chainId: 143 })).rejects.toMatchObject({
      code: "oaath_rpc_budget_exhausted",
    });
    expect(calls).toBe(2);
  });

  it("fails over a wrong-chain endpoint and preserves nonretryable RPC refusals", async () => {
    const [chain] = createCetaneChainPorts(config, {
      retry: { attempts: 2, delayMs: 0 },
      fetch: async (request) => {
        const { id, method } = await request.json();
        if (request.url.includes("public-a")) return rpc(id, "0x1");
        if (method === "eth_chainId") return rpc(id, "0x8f");
        return Response.json({
          jsonrpc: "2.0",
          id,
          error: { code: -32601, message: "secret provider text" },
        });
      },
    });
    const error = await chain!.reads
      .read({ type: "code", chainId: 143, address: "0x1111111111111111111111111111111111111111" })
      .catch((error: unknown) => error);
    expect(error).toMatchObject({ code: "oaath_rpc_rejected", rpcCode: -32601 });
    expect(JSON.stringify(error).includes("secret")).toBe(false);
  });
});
