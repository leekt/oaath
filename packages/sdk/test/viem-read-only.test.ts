import { describe, expect, it, vi } from "vitest";
import { createViemChainPorts } from "../src/viem.js";

const rpc = (id: number, result: unknown) => Response.json({ jsonrpc: "2.0", id, result });
const entryPoint = "0x0000000071727de22e5e9d8baf0edac6f37da032";

describe("authenticated read-only chain ports", () => {
  it("captures headers for reads, observes finality and exposes no bundler route", async () => {
    const headers = { authorization: "Basic fixture-only" };
    const methods: string[] = [];
    const [chain] = createViemChainPorts(
      { 143: { publicRpcUrls: ["https://private.test"], headers } },
      {
        fetch: async (request) => {
          expect(request.headers.get("authorization")).toBe("Basic fixture-only");
          expect(request.headers.get("content-type")).toBe("application/json");
          expect(request.redirect).toBe("error");
          const { id, method } = await request.json();
          methods.push(method);
          return rpc(
            id,
            method === "eth_chainId"
              ? "0x8f"
              : {
                  number: "0x1",
                  hash: `0x${"11".repeat(32)}`,
                  parentHash: `0x${"22".repeat(32)}`,
                  transactions: [],
                },
          );
        },
      },
    );
    headers.authorization = "changed";
    expect(chain!.routes).toEqual([]);
    expect(await chain!.reads.read({ type: "chain_id", chainId: 143 })).toBe(143);
    expect(await chain!.observation.read({ type: "finalized_block", chainId: 143 })).toMatchObject({
      number: "0x1",
    });
    const before = methods.length;
    await expect(
      chain!.observation.read({
        type: "user_operation_receipt",
        chainId: 143,
        userOperationHash: `0x${"33".repeat(32)}`,
      }),
    ).rejects.toMatchObject({ code: "oaath_rpc_bundler_unavailable" });
    await expect(chain!.submission.open({} as never)).rejects.toMatchObject({
      code: "oaath_rpc_bundler_unavailable",
    });
    expect(methods).toHaveLength(before);
  });

  it("never forwards read credentials to a bundler or paymaster", async () => {
    const hosts: string[] = [];
    const [chain] = createViemChainPorts(
      {
        143: {
          publicRpcUrls: ["https://private.test"],
          headers: { authorization: "Basic fixture-only" },
          bundlerUrl: "https://bundler.test",
          paymasterUrl: "https://paymaster.test",
        },
      },
      {
        fetch: async (request) => {
          const host = new URL(request.url).hostname;
          hosts.push(host);
          expect(request.headers.get("authorization")).toBe(
            host === "private.test" ? "Basic fixture-only" : null,
          );
          const { id, method } = await request.json();
          return rpc(
            id,
            method === "eth_chainId"
              ? "0x8f"
              : method === "eth_supportedEntryPoints"
                ? [entryPoint]
                : {},
          );
        },
      },
    );
    await chain!.reads.read({ type: "chain_id", chainId: 143 });
    const route = chain!.routes?.[0];
    if (route?.kind !== "erc4337-bundler") throw Error("missing bundler");
    await route.bundler.probe({ chainId: 143, entryPoint });
    const sponsorship = chain!.sponsorship;
    if (sponsorship?.kind !== "erc7677") throw Error("missing paymaster");
    await sponsorship.request({ method: "pm_getPaymasterData", params: [] } as never);
    expect(new Set(hosts)).toEqual(new Set(["private.test", "bundler.test", "paymaster.test"]));
  });

  it("aborts an active read without retries", async () => {
    const controller = new AbortController();
    const cause = new Error("fixture-cancellation");
    let requests = 0,
      cancelled = false;
    const [chain] = createViemChainPorts(
      { 143: { publicRpcUrls: ["https://private.test"] } },
      {
        signal: controller.signal,
        maxConcurrency: 1,
        retry: { attempts: 3 },
        fetch: async (request) => {
          requests++;
          request.signal.addEventListener(
            "abort",
            () => {
              cancelled = true;
            },
            { once: true },
          );
          return new Promise<Response>(() => {}); // Caller transports may ignore abort.
        },
      },
    );
    const pending = chain!.reads.read({ type: "chain_id", chainId: 143 }).catch((error) => error);
    controller.abort(cause);
    const error = await pending;
    expect(error).toMatchObject({ code: "oaath_rpc_aborted" });
    if (!(error instanceof Error)) throw Error("missing cancellation error");
    expect(error.cause).toBe(cause);
    expect(JSON.stringify(error)).not.toContain("fixture-cancellation");
    expect(cancelled).toBe(true);
    await expect(chain!.reads.read({ type: "chain_id", chainId: 143 })).rejects.toMatchObject({
      code: "oaath_rpc_aborted",
    });
    expect(requests).toBe(1);
  });

  it("cancels the retry delay without starting another request", async () => {
    vi.useFakeTimers();
    try {
      const controller = new AbortController();
      const fetch = vi.fn(async () => new Response(null, { status: 503 }));
      const [chain] = createViemChainPorts(
        { 143: { publicRpcUrls: ["https://private.test"] } },
        { signal: controller.signal, retry: { attempts: 3, delayMs: 5000 }, fetch },
      );
      const pending = chain!.reads.read({ type: "chain_id", chainId: 143 }).catch((error) => error);
      await vi.advanceTimersByTimeAsync(0);
      expect(fetch).toHaveBeenCalledTimes(1);
      expect(vi.getTimerCount()).toBe(1);
      controller.abort();
      expect(await pending).toMatchObject({ code: "oaath_rpc_aborted" });
      expect(fetch).toHaveBeenCalledTimes(1);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("rejects invalid headers and signals without a request", () => {
    for (const headers of [
      { "bad\nname": "value" },
      { authorization: "bad\nvalue" },
      { authorization: 1 },
    ]) {
      expect(() =>
        createViemChainPorts({
          143: { publicRpcUrls: ["https://private.test"], headers: headers as never },
        }),
      ).toThrow(expect.objectContaining({ code: "oaath_rpc_config_invalid" }));
    }
    expect(() =>
      createViemChainPorts(
        { 143: { publicRpcUrls: ["https://private.test"] } },
        { signal: {} as never },
      ),
    ).toThrow(expect.objectContaining({ code: "oaath_rpc_config_invalid" }));
  });
});
