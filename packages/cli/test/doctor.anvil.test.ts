import { encodeAbiParameters } from "viem";
import { describe, expect, it } from "vitest";
import { createHarness, deployKernelStack, startAnvil } from "../../sdk/test/support/anvil.js";
import { doctor } from "../src/doctor.js";
import { components } from "../src/manifest.js";
import { Rpc } from "../src/rpc.js";

(process.env.OAATH_REQUIRE_ANVIL === "1" || process.env.CI === "true" ? describe : describe.skip)(
  "deployed runtime readiness",
  () => {
    it.each([143, 421614])(
      "verifies the exact deterministic set on chain %i",
      async (chainId) => {
        const chain = await startAnvil(chainId);
        try {
          const missing = await doctor(chainId, new Rpc(chain.url));
          expect(missing.ready).toBe(false);
          expect(missing.components.find((row) => row.id === "entryPoint")?.status).toBe("missing");
          const harness = await createHarness(chain);
          await deployKernelStack(harness);
          for (const component of components(chainId)) {
            if (
              component.required &&
              component.deploymentInput &&
              !(await harness.client.getCode({ address: component.address }))
            )
              await harness.deployCreate2(component.deploymentInput);
          }
          const ready = await doctor(chainId, new Rpc(chain.url));
          expect(ready.ready).toBe(true);
          expect(ready.factoryBinding).toBe("verified");
          expect(ready.components.find((row) => row.id === "kernelUups")?.status).toBe(
            chainId === 143 ? "present" : "verified",
          );
          expect(ready.components.find((row) => row.id === "validityPolicy")?.status).toBe(
            "verified",
          );
          expect(ready.components.find((row) => row.id === "p256Validator")?.status).toBe(
            "missing",
          );

          const rpc = new Rpc(chain.url);
          const wrongBinding = await doctor(chainId, {
            request: (method, params) =>
              method === "eth_call"
                ? Promise.resolve(
                    encodeAbiParameters(
                      [{ type: "address" }],
                      ["0x0000000000000000000000000000000000000001"],
                    ),
                  )
                : rpc.request(method, params),
          });
          expect(wrongBinding.ready).toBe(false);
          expect(wrongBinding.factoryBinding).toBe("mismatch");
          expect((await doctor(chainId + 1, new Rpc(chain.url))).error).toBe("chain_mismatch");
        } finally {
          chain.stop();
        }
      },
      30_000,
    );
  },
);
