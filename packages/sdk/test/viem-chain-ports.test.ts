import { describe, expect, it } from "vitest";
import { KERNEL_V4_ENTRY_POINT_V07, prepareUserOperation } from "../src/kernel.js";
import { createViemChainPorts } from "../src/viem.js";

const config = {
  143: {
    publicRpcUrls: ["https://public-a.test", "https://public-b.test"],
    bundlerUrl: "https://bundler.test",
    paymasterUrl: "https://paymaster.test",
  },
};
const rpc = (id: number, result: unknown) => Response.json({ jsonrpc: "2.0", id, result });

describe("default viem chain ports", () => {
  it("bounds timeout and concurrency without a queue", async () => {
    let started = 0;
    const [chain] = createViemChainPorts(config, {
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
    await expect(chain!.reads.read({ type: "chain_id", chainId: 143 })).rejects.toMatchObject({
      code: "oaath_rpc_concurrency_exceeded",
    });
    await expect(pending).rejects.toMatchObject({ code: "oaath_rpc_unavailable" });
    expect(started).toBe(1);
  });

  it.each(["timeout", "gateway", "non-json", "rpc-rejection"])(
    "sends exactly once after %s and never uses a public RPC for submission",
    async (failure) => {
      let sends = 0;
      const [chain] = createViemChainPorts(config, {
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
        entryPoint: { version: "0.7", address: KERNEL_V4_ENTRY_POINT_V07 },
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
        route: "bundler",
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
    const [chain] = createViemChainPorts(
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
    expect(chain!.paymasterService!.url).toBe("https://paymaster.test");
    await expect(
      chain!.paymasterService!.request({
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
          KERNEL_V4_ENTRY_POINT_V07,
          "0x8f",
          {},
        ],
      }),
    ).rejects.toMatchObject({ code: "oaath_rpc_unavailable" });
    expect(calls).toBe(1);
  });
  it("fails over non-JSON public RPC failures without sending account reads to the bundler", async () => {
    const calls: string[] = [];
    const [chain] = createViemChainPorts(config, {
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
    const [chain] = createViemChainPorts(config, {
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
    const [chain] = createViemChainPorts(config, {
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
