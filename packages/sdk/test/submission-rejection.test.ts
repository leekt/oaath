import { toHex } from "viem";
import { describe, expect, it } from "vitest";
import { OaathRpcError } from "../src/cetane/rpc.js";
import { createCetaneChainPorts } from "../src/cetane.js";
import {
  CHAIN_ID,
  createChainFixture,
  createRealm,
  permissionInput,
  SELECTOR,
  sendCallsInput,
  TARGET,
} from "./support/browser.js";

type BundlerAnswer = "rpc-error" | "timeout" | "gateway" | "malformed-error" | "forged";

/**
 * The real Cetane bundler send behind a fixture chain. Only the first send
 * meets the scripted bundler answer; later sends use the accepting fixture.
 */
function rejectingChain(answer: BundlerAnswer) {
  const base = createChainFixture();
  let wireSends = 0;
  let receiptReads = 0;
  const [ports] = createCetaneChainPorts(
    { [CHAIN_ID]: { publicRpcUrls: ["https://public.test"], bundlerUrl: "https://bundler.test" } },
    {
      retry: { attempts: 3, delayMs: 0 },
      timeoutMs: 20,
      fetch: async (request) => {
        const { id, method } = await request.json();
        if (method === "eth_chainId")
          return Response.json({ jsonrpc: "2.0", id, result: toHex(CHAIN_ID) });
        expect(method).toBe("eth_sendUserOperation");
        wireSends += 1;
        if (answer === "gateway") return new Response("bad gateway", { status: 502 });
        if (answer === "malformed-error")
          return Response.json({ jsonrpc: "2.0", id, error: { code: "-32602", message: "x" } });
        if (answer === "rpc-error")
          return Response.json({
            jsonrpc: "2.0",
            id,
            error: { code: -32602, message: "maxFeePerGas must be at least private-detail" },
          });
        return new Promise<Response>((_, reject) =>
          request.signal.addEventListener("abort", () => reject(new Error("aborted")), {
            once: true,
          }),
        );
      },
    },
  );
  let opened = 0;
  const capability = {
    ...base.capability,
    observation: {
      ...base.capability.observation,
      read(request: Parameters<typeof base.capability.observation.read>[0]) {
        if (request.type === "user_operation_receipt") receiptReads += 1;
        return base.capability.observation.read(request);
      },
    },
    submission: {
      async open(request: Parameters<typeof base.capability.submission.open>[0]) {
        opened += 1;
        if (opened > 1) return base.capability.submission.open(request);
        if (answer === "forged") {
          wireSends += 1;
          // A caller-created lookalike carries no captured wire evidence.
          return {
            send: async () => Promise.reject(new OaathRpcError("oaath_rpc_rejected", -32602)),
            close: async () => undefined,
          };
        }
        return ports!.submission.open(request);
      },
    },
  };
  const realm = createRealm({ chain: { ...base, capability } as typeof base });
  return {
    realm,
    base,
    counts: () => ({ wireSends, receiptReads, opened }),
  };
}

describe("bundler answers to the one send", () => {
  it("concludes a JSON-RPC error answer as rejected, observes nothing, and frees the lane", async () => {
    const { realm, base, counts } = rejectingChain("rpc-error");
    try {
      const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
      const error = await grant.sendCalls(sendCallsInput() as never).catch((e: unknown) => e);
      expect(error).toMatchObject({
        name: "OaathClientError",
        code: "oaath_client_submission_rejected",
        source: "operation_runner_submission_rejected",
        rpcCode: -32602,
      });
      expect(String((error as Error).message)).not.toContain("private-detail");
      expect(JSON.stringify(error)).not.toContain("private-detail");
      expect(counts()).toEqual({ wireSends: 1, receiptReads: 0, opened: 1 });

      // The rejected identity is terminal and never resent; the free lane
      // accepts a new operation that prepares, sends and finalizes.
      await expect(grant.sendCalls(sendCallsInput() as never)).rejects.toMatchObject({
        code: "oaath_client_state_conflict",
      });
      const next = await grant.sendCalls({
        chain: CHAIN_ID,
        calls: [{ target: TARGET, value: "0", data: `${SELECTOR}${"0".repeat(63)}1` }],
      } as never);
      expect((await next.wait()).status).toBe("finalized");
      expect(base.sends).toHaveLength(1);
      expect(counts().wireSends).toBe(1);
    } finally {
      await realm.oaath.close();
    }
  });

  it.each(["timeout", "gateway", "malformed-error", "forged"] as const)(
    "keeps %s uncertain and observation-only with zero resubmits",
    async (answer) => {
      const { realm, counts } = rejectingChain(answer);
      try {
        const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
        const handle = await grant.sendCalls(sendCallsInput() as never);
        expect(handle.outcome).toMatchObject({ status: "pending", state: "submission_attempted" });
        expect((await handle.observe()).status).toBe("pending");
        expect(counts().receiptReads).toBeGreaterThan(0);
        // The attempted identity still occupies its lane; nothing resubmits.
        await expect(grant.sendCalls(sendCallsInput() as never)).rejects.toMatchObject({
          code: "oaath_client_state_conflict",
        });
        expect(counts()).toMatchObject({ wireSends: 1, opened: 1 });
      } finally {
        await realm.oaath.close();
      }
    },
  );
});
