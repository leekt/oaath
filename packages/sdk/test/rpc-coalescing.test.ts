import { describe, expect, it } from "vitest";
import { rpcOwner } from "../src/cetane/rpc.js";

const endpoint = "https://rpc.test";
const address = `0x${"11".repeat(20)}`;
const response = (id: number, result: unknown) => Response.json({ jsonrpc: "2.0", id, result });

describe("RPC in-flight read coalescing", () => {
  it("serves twenty identical reads with one chain check and one read, charging only two requests", async () => {
    const methods: string[] = [];
    const owner = rpcOwner({
      maxRequests: 2,
      maxConcurrency: 1,
      fetch: async (request) => {
        const { id, method } = await request.json();
        methods.push(method);
        return response(id, method === "eth_chainId" ? "0x8f" : "0x6000");
      },
    });
    const read = owner.pool([endpoint], 143, ["eth_getCode"]);
    expect(
      await Promise.all(Array.from({ length: 20 }, () => read("eth_getCode", [address, "latest"]))),
    ).toEqual(Array(20).fill("0x6000"));
    expect(methods).toEqual(["eth_chainId", "eth_getCode"]);
    await expect(read("eth_getCode", [address, "latest"])).rejects.toMatchObject({
      code: "oaath_rpc_budget_exhausted",
    });
    expect(methods).toHaveLength(2);
  });

  it("shares an endpoint's pending chain check across distinct reads and explicit chain checks", async () => {
    const methods: string[] = [];
    const owner = rpcOwner({
      fetch: async (request) => {
        const { id, method } = await request.json();
        methods.push(method);
        return response(id, method === "eth_chainId" ? "0x8f" : "0x6000");
      },
    });
    const read = owner.pool([endpoint], 143, ["eth_getCode", "eth_chainId"]);
    await Promise.all([
      read("eth_getCode", [address, "latest"]),
      read("eth_getCode", [address, "finalized"]),
      read("eth_chainId"),
    ]);
    expect(methods).toEqual(["eth_chainId", "eth_getCode", "eth_getCode"]);
  });

  it("never caches a settled block or a missing receipt, and isolates each caller's result", async () => {
    let calls = 0;
    const owner = rpcOwner({
      fetch: async (request) => {
        const { id } = await request.json();
        return response(
          id,
          ++calls === 1 ? null : { number: "0x1", transactions: [String(calls)] },
        );
      },
    });
    const read = owner.pool(
      [endpoint],
      143,
      ["eth_getTransactionReceipt", "eth_getBlockByNumber"],
      false,
    );
    expect(await read("eth_getTransactionReceipt", ["0x01"])).toBeNull();
    expect(await read("eth_getTransactionReceipt", ["0x01"])).not.toBeNull();
    const [first, second] = (await Promise.all([
      read("eth_getBlockByNumber", ["0x1", false]),
      read("eth_getBlockByNumber", ["0x1", false]),
    ])) as { transactions: string[] }[];
    if (!first || !second) throw new Error("missing read results");
    first.transactions.push("mutated");
    expect(second.transactions).toEqual(["3"]);
    expect(await read("eth_getBlockByNumber", ["0x1", false])).toMatchObject({
      transactions: ["4"],
    });
    expect(calls).toBe(4);
  });

  it("does not reuse settled chain checks when the caller explicitly rechecks the chain", async () => {
    let calls = 0;
    const owner = rpcOwner({
      retry: { attempts: 1 },
      fetch: async (request) => {
        const { id } = await request.json();
        return response(id, ++calls === 1 ? "0x8f" : "0x1");
      },
    });
    const read = owner.pool([endpoint], 143, ["eth_chainId"]);
    expect(await read("eth_chainId")).toBe("0x8f");
    await expect(read("eth_chainId")).rejects.toMatchObject({ code: "oaath_rpc_wrong_chain" });
    expect(calls).toBe(2);
  });

  it("captures parameters before the chain check suspends", async () => {
    const parameters: unknown[] = [];
    const owner = rpcOwner({
      fetch: async (request) => {
        const { id, method, params } = await request.json();
        if (method === "eth_getCode") parameters.push(params);
        return response(id, method === "eth_chainId" ? "0x8f" : "0x6000");
      },
    });
    const read = owner.pool([endpoint], 143, ["eth_getCode"]);
    const params = [address, "latest"];
    const first = read("eth_getCode", params);
    params[1] = "finalized";
    const second = read("eth_getCode", [address, "latest"]);
    await Promise.all([first, second]);
    expect(parameters).toEqual([[address, "latest"]]);
  });

  it("keeps methods, parameters, retry policies, chains, endpoints and headers separate", async () => {
    let calls = 0;
    const owner = rpcOwner({
      maxConcurrency: 8,
      fetch: async (request) => {
        const { id } = await request.json();
        calls++;
        return response(id, request.headers.get("x-fixture") ?? "0x6000");
      },
    });
    const methods = ["eth_getCode", "eth_call"];
    const read = owner.pool([endpoint], 143, methods, false);
    await Promise.all([
      read("eth_getCode", [address, "latest"]),
      read("eth_getCode", [address, "finalized"]),
      read("eth_getCode", [address, "latest"], false),
      read("eth_call", [address, "latest"]),
      owner.pool([endpoint], 1, methods, false)("eth_getCode", [address, "latest"]),
      owner.pool(["https://other.test"], 143, methods, false)("eth_getCode", [address, "latest"]),
      owner.pool([endpoint], 143, methods, false, { "x-fixture": "isolated" })("eth_getCode", [
        address,
        "latest",
      ]),
    ]);
    expect(calls).toBe(7);
  });

  it.each([
    "eth_sendUserOperation",
    "eth_estimateUserOperationGas",
    "pm_getPaymasterStubData",
    "pm_getPaymasterData",
    "unrecognized_method",
  ])("never coalesces %s", async (method) => {
    let calls = 0;
    const owner = rpcOwner({
      fetch: async (request) => {
        const { id } = await request.json();
        calls++;
        return response(id, "0x1");
      },
    });
    const request = owner.pool([endpoint], 143, [method], false);
    await Promise.all([request(method, [], false), request(method, [], false)]);
    expect(calls).toBe(2);
  });

  it("shares the whole bounded retry sequence, then evicts failures for a fresh attempt", async () => {
    let calls = 0;
    const owner = rpcOwner({
      retry: { attempts: 3, delayMs: 0 },
      maxConcurrency: 1,
      fetch: async (request) => {
        const { id } = await request.json();
        return ++calls <= 3 ? new Response(null, { status: 503 }) : response(id, "0x8f");
      },
    });
    const read = owner.pool([endpoint], 143, ["eth_chainId"]);
    const results = await Promise.allSettled(Array.from({ length: 20 }, () => read("eth_chainId")));
    for (const result of results) {
      expect(result.status).toBe("rejected");
      if (result.status === "rejected")
        expect(result.reason).toMatchObject({ code: "oaath_rpc_unavailable" });
    }
    if (results[0]?.status === "rejected" && results[1]?.status === "rejected") {
      expect(results[0].reason).not.toBe(results[1].reason);
    }
    expect(calls).toBe(3);
    expect(await read("eth_chainId")).toBe("0x8f");
    expect(calls).toBe(4);
  });

  it("keeps failures from a shared chain check bound to each operation stage", async () => {
    const owner = rpcOwner({
      retry: { attempts: 1 },
      fetch: async () => new Response(null, { status: 503 }),
    });
    const methods = ["eth_getUserOperationReceipt", "eth_estimateUserOperationGas"];
    const read = owner.pool([endpoint], 143, methods);
    const results = await Promise.all(
      methods.map((method) => read(method).catch((error: unknown) => error)),
    );
    expect(results[0]).toMatchObject({
      code: "oaath_rpc_unavailable",
      failure: { stage: "receipt" },
    });
    expect(results[1]).toMatchObject({
      code: "oaath_rpc_unavailable",
      failure: { stage: "estimate" },
    });
  });

  it("cancels all joined readers without issuing another request", async () => {
    let calls = 0;
    const controller = new AbortController();
    const owner = rpcOwner({
      signal: controller.signal,
      fetch: async () => {
        calls++;
        return new Promise<Response>(() => {});
      },
    });
    const read = owner.pool([endpoint], 143, ["eth_chainId"]);
    const pending = Promise.allSettled(Array.from({ length: 20 }, () => read("eth_chainId")));
    controller.abort();
    for (const result of await pending) {
      expect(result.status).toBe("rejected");
      if (result.status === "rejected")
        expect(result.reason).toMatchObject({ code: "oaath_rpc_aborted" });
    }
    await expect(read("eth_chainId")).rejects.toMatchObject({ code: "oaath_rpc_aborted" });
    expect(calls).toBe(1);
  });
});
