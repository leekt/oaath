import type { OaathSubmissionCapability } from "@oaath/sdk/advanced";
import { describe, expect, it } from "vitest";
import { createLocalAnvilFixture } from "../src/anvil.js";
import { startAnvil } from "../src/anvil-process.mjs";

type Open = OaathSubmissionCapability["open"];
type SubmissionRequest = Parameters<Open>[0];

describe.skipIf(process.env.OAATH_REQUIRE_ANVIL !== "1")("caller-reserved Kernel lanes", () => {
  it("mines past the wall-clock second a grant takes validAfter from", async () => {
    // A block stamped before the grant's wall-clock validAfter reverts the
    // install with AA22, which leaves it pending with no receipt (#413).
    const chain = await startAnvil(31_337);
    try {
      await chain.rpc("evm_mine", []);
      const block = await chain.rpc("eth_getBlockByNumber", ["latest", false]);
      expect(Number(BigInt(block.timestamp))).toBeGreaterThan(Math.floor(Date.now() / 1000));
    } finally {
      chain.stop();
    }
  });

  it("lands lane 2 while lane 1 is held, then recovers lane 1 without resubmission", async () => {
    let inner: Open | undefined;
    let holdNext = false;
    let held: SubmissionRequest | undefined;
    let sdkOpens = 0;
    // The SDK's accepted send for lane 1 is held here and never reaches the
    // chain until this test releases the exact signed snapshot itself.
    const fixture = await createLocalAnvilFixture({
      submission: (open) => {
        inner = open;
        return async (request) => {
          sdkOpens += 1;
          if (!holdNext) return open(request);
          holdNext = false;
          held = request;
          return {
            async send() {
              throw new Error("held");
            },
            async close() {},
          };
        };
      },
    });
    try {
      const client = await fixture.openClient();
      const connection = await client.connect();
      const grant = await connection.requestPermission({
        chainScope: "all",
        permissions: [
          {
            calls: [{ target: `0x${"44".repeat(20)}`, selectors: ["0x12345678"], valueLimit: "1" }],
          },
        ],
        expiresIn: 3600,
        perChainOperationLimit: 4,
      });
      const chain = fixture.chainIds[0] ?? 0;
      const calls = [{ target: `0x${"44".repeat(20)}`, data: "0x12345678", value: "1" }];
      const laneA = { id: "run_a", nonceKey: 1n };

      // A lane never enables: the default lane installs the permission first.
      await expect(grant.sendCalls({ chain, calls, lane: laneA })).rejects.toMatchObject({
        source: "operation_lane_permission_not_installed",
      });
      const install = await grant.sendCalls({ chain, calls });
      const installed = await install.wait({ attempts: 3 });
      expect({
        status: installed.status,
        state: installed.state,
        reason: installed.reason,
        failure: installed.failure?.code,
        // Exact match keeps state and reason in the diff: a lagging chain clock
        // shows as submission_attempted/receipt_missing, not a finality delay.
      }).toEqual({ status: "finalized", state: "finalized", reason: null, failure: undefined });

      holdNext = true;
      const a = await grant.sendCalls({ chain, calls, lane: laneA });
      expect(a.outcome.status).toBe("pending");
      const heldRequest = held;
      if (heldRequest === undefined || inner === undefined) throw new Error("lane 1 not held");
      expect((BigInt(heldRequest.prepared.userOperation.nonce) >> 64n) & 0xffffn).toBe(1n);

      // Lane 1 still rejects a second send, and keys outside uint16 never quote.
      await expect(grant.sendCalls({ chain, calls, lane: laneA })).rejects.toMatchObject({
        code: "oaath_client_state_conflict",
      });
      await expect(
        grant.sendCalls({ chain, calls, lane: { id: "run_x", nonceKey: 65_536n } }),
      ).rejects.toMatchObject({ code: "oaath_client_input_invalid" });

      // Lane 2 lands on the real EntryPoint while lane 1 is unresolved.
      const b = await grant.sendCalls({ chain, calls, lane: { id: "run_b", nonceKey: 2n } });
      expect((await b.wait({ attempts: 3 })).status).toBe("finalized");
      expect(await b.execution()).toMatchObject({ calls });
      expect((await a.observe()).status).toBe("pending");
      expect(sdkOpens).toBe(3);

      // Release the exact held snapshot out of band; lane 2 did not consume lane 1's sequence.
      const release = (await inner(heldRequest)) as { send(): Promise<unknown> };
      await release.send();

      // Recreate the client, stores and database over the retained state.
      const reopened = await fixture.openClient();
      const resumed = await (await reopened.connect()).resume();
      if (!resumed) throw new Error("grant did not resume");
      const recovered = await resumed.getOperation({ chain, id: a.id, lane: laneA });
      if (!recovered) throw new Error("lane 1 operation not recovered");
      expect((await recovered.wait({ attempts: 3 })).status).toBe("finalized");
      expect(await recovered.execution()).toMatchObject({ calls });
      expect(sdkOpens).toBe(3);
      expect(fixture.submissionCount).toBe(3);
    } finally {
      await fixture.close();
    }
  }, 90_000);
});
