import { describe, expect, it } from "vitest";
import { createLocalOwnerAnvilFixture } from "../src/anvil-owner.js";

(process.env.OAATH_REQUIRE_ANVIL === "1" ? describe : describe.skip)(
  "existing owner fixture",
  () => {
    it.each(["local", "browser"] as const)(
      "recovers a %s owner operation after a rejected bundler submission",
      async (wallet) => {
        const fixture = await createLocalOwnerAnvilFixture({ wallet, bundler: "reject" });
        try {
          const client = await fixture.openClient();
          const account = client.account(fixture.address);
          const request = {
            chain: fixture.chainId,
            calls: [{ target: `0x${"44".repeat(20)}`, data: "0x", value: "1" }],
            feePayer: { kind: "connected-eoa", wallet: fixture.wallet },
          };
          expect(await account.owner(fixture.wallet).reviewCalls(request)).toMatchObject({
            signer: "owner",
            capacity: { kind: "single-operation" },
          });
          expect(fixture.signatureCount).toBe(0);
          const operation = await account.owner(fixture.wallet).sendCalls(request);
          const saved = { id: operation.id, chain: operation.chainId };
          expect(fixture.signatureCount).toBe(1);
          expect(fixture.bundlerSubmissionCount).toBe(1);
          expect(fixture.fallbackSubmissionCount).toBe(1);
          const recreated = await fixture.openClient();
          const restored = await recreated.account(fixture.address).getOperation(saved);
          if (!restored) throw new Error("saved operation missing");
          expect((await restored.wait({ attempts: 3 })).status).toBe("finalized");
          expect(await restored.execution()).toMatchObject({
            sender: fixture.address,
            route: "entrypoint-handleops",
          });
          expect(fixture.signatureCount).toBe(1);
          expect(fixture.bundlerSubmissionCount).toBe(1);
          expect(fixture.fallbackSubmissionCount).toBe(1);
        } finally {
          await fixture.close();
        }
      },
    );
  },
);
