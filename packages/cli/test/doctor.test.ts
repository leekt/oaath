import type { Hex } from "viem";
import { describe, expect, it } from "vitest";
import { doctor } from "../src/doctor.js";
import { components } from "../src/manifest.js";
import { Rpc } from "../src/rpc.js";

describe("runtime readiness", () => {
  it("rejects a wrong chain before reading any deployment", async () => {
    const methods: string[] = [];
    const report = await doctor(143, {
      request: async (method) => {
        methods.push(method);
        return "0x1";
      },
    });
    expect(report.ready).toBe(false);
    expect(report.error).toBe("chain_mismatch");
    expect(methods).toEqual(["eth_chainId"]);
    expect(report.components.every((row) => row.status === "unreadable")).toBe(true);
  });

  it("distinguishes absent, mismatched and unreadable code without provider prose", async () => {
    const manifest = components(143);
    const addresses = new Map(manifest.map((row) => [row.address, row.id]));
    const report = await doctor(143, {
      request: async (method, params) => {
        if (method === "eth_chainId") return "0x8f";
        if (method === "eth_blockNumber") return "0x123";
        if (method === "eth_getCode") {
          expect(params?.[1]).toBe("0x123");
          const id = addresses.get(params?.[0] as Hex);
          if (id === "callPolicy") return "0x6000";
          if (id === "rateLimitPolicy") throw new Error("secret RPC URL or credential");
          if (id === "ecdsaSigner") return null;
          return "0x";
        }
        throw new Error("unexpected RPC");
      },
    });
    expect(report.ready).toBe(false);
    expect(report.components.find((row) => row.id === "kernelUups")?.status).toBe("missing");
    expect(report.components.find((row) => row.id === "callPolicy")?.status).toBe("mismatch");
    expect(report.components.find((row) => row.id === "rateLimitPolicy")?.status).toBe(
      "unreadable",
    );
    expect(report.components.find((row) => row.id === "ecdsaSigner")?.status).toBe("unreadable");
    expect(JSON.stringify(report)).not.toMatch(/secret|credential/u);
  });

  it("labels chain-dependent implementation code as present, not hash-verified", async () => {
    const report = await doctor(143, {
      request: async (method, params) => {
        if (method === "eth_chainId") return "0x8f";
        if (method === "eth_blockNumber") return "0x123";
        const component = components(143).find((row) => row.address === params?.[0]);
        return component?.id === "kernelUups" || component?.id === "kernelImmutableEcdsa"
          ? "0x6000"
          : "0x";
      },
    });
    expect(report.components.find((row) => row.id === "kernelUups")?.status).toBe("present");
    expect(report.ready).toBe(false);
  });
});

describe("RPC bounds", () => {
  it("does not retry failures, leak URLs, or exceed its request budget", async () => {
    let attempts = 0;
    const rpc = new Rpc("https://example.test/private?key=secret", {
      maxRequests: 2,
      fetch: async () => {
        attempts += 1;
        throw new Error("private credential in provider diagnostic");
      },
    });
    await expect(rpc.request("eth_chainId")).rejects.toThrow("rpc_unavailable");
    await expect(rpc.request("eth_chainId")).rejects.toThrow("rpc_unavailable");
    await expect(rpc.request("eth_chainId")).rejects.toThrow("rpc_budget_exhausted");
    expect(attempts).toBe(2);
  });

  it("rejects contradictory RPC envelopes", async () => {
    const rpc = new Rpc("https://example.test", {
      fetch: async () => Response.json({ jsonrpc: "2.0", id: 50, result: "0x8f" }),
    });
    await expect(rpc.request("eth_chainId")).rejects.toThrow("rpc_invalid_response");
  });
});
