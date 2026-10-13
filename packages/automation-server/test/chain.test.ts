import { expect, it } from "vitest";
import { createBudgetedChains } from "../src/chain.js";
import { testConfig } from "./support/fixture.js";

it.each([null, "bundler-test-key"])(
  "uses only the configured bundler credential (%s) and preserves request budgets",
  async (bundlerApiKey) => {
    const config = testConfig("postgres://unused");
    const endpoints = { ...config.chains.get(31337)!, bundlerApiKey };
    const requests: Request[] = [];
    const entryPoint = "0x433709009b8330fda32311df1c2afa402ed8d009";
    const chains = createBudgetedChains(
      { ...config, chains: new Map([[31337, endpoints]]) },
      () => 0,
      (async (request: Request) => {
        requests.push(request);
        const { id, method } = await request.clone().json();
        const result = method === "eth_chainId" ? "0x7a69" : [entryPoint];
        return Response.json({ jsonrpc: "2.0", id, result });
      }) as typeof fetch,
    );
    const port = chains.chain(31337);
    const route = port.routes?.[0];
    if (route?.kind !== "erc4337-bundler") throw new Error("bundler route missing");
    await route.bundler.probe({ chainId: 31337, entryPoint });
    await port.reads.read({ type: "chain_id", chainId: 31337 });
    const bundlerRequests = requests.filter(
      (request) => request.url === `${endpoints.bundlerUrl}/`,
    );
    const rpcRequests = requests.filter((request) => request.url === `${endpoints.rpcUrl}/`);
    expect(bundlerRequests.length).toBeGreaterThan(0);
    expect(rpcRequests.length).toBeGreaterThan(0);
    for (const request of bundlerRequests) {
      expect(request.headers.get("authorization")).toBeNull();
      expect((await request.clone().json()).apiKey).toBe(bundlerApiKey ?? undefined);
      expect(request.redirect).toBe("manual");
    }
    for (const request of rpcRequests) {
      expect(request.headers.get("authorization")).toBeNull();
      expect((await request.clone().json()).apiKey).toBeUndefined();
    }
    expect(chains.snapshot()).toEqual([
      { role: "rpc", used: rpcRequests.length, limit: 10 },
      { role: "bundler", used: bundlerRequests.length, limit: 10 },
      { role: "paymaster", used: 0, limit: 10 },
    ]);
  },
);
