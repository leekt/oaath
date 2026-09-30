import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { kernelRuntimeReadiness } from "@oaath/sdk/kernel";
import { concat, type Hex } from "viem";
import { describe, expect, it } from "vitest";
import { createHarness, deployKernelStack, startAnvil } from "../../sdk/test/support/anvil.js";
import { deployRuntime } from "../src/deploy.js";
import { DeploymentJournal } from "../src/journal.js";
import { components } from "../src/manifest.js";
import { Rpc, type RpcReader } from "../src/rpc.js";

const suite =
  process.env.OAATH_REQUIRE_ANVIL === "1" || process.env.CI === "true" ? describe : describe.skip;
suite("runtime deployment and recovery", () => {
  it("requires external prerequisites, plans without a key, deploys only missing code and reruns without signing", async () => {
    const chain = await startAnvil(143);
    const directory = await mkdtemp(join(tmpdir(), "oaath-deploy-proof-"));
    const journal = new DeploymentJournal(join(directory, "state.sqlite"));
    try {
      const network = new Rpc(chain.url, { maxRequests: 512, durationMs: 180_000 });
      const harness = await createHarness(chain);
      let sends = 0,
        keys = 0;
      const rpc: RpcReader = {
        request: async (method, params) => {
          if (method === "eth_sendRawTransaction") {
            sends++;
            const result = await network.request(method, params);
            await network.request("anvil_mine", ["0x40"]);
            return result;
          }
          return network.request(method, params);
        },
      };
      const account = () => {
        keys++;
        return harness.submitter;
      };
      await expect(deployRuntime({ chainId: 143, rpc, journal, account })).rejects.toThrow(
        "deployment_prerequisite_missing",
      );
      expect(keys).toBe(0);
      const entryPoint = JSON.parse(
        await readFile(
          join(process.cwd(), "node_modules", harness.fixture.entryPoint.artifact),
          "utf8",
        ),
      ) as { bytecode: Hex };
      await harness.deployCreate2(
        concat([harness.fixture.entryPoint.deploymentSalt, entryPoint.bytecode]),
      );
      const statuses = async () =>
        (await kernelRuntimeReadiness({ chainId: 143, reads: harness.reads })).modules.map(
          (row) => row.status,
        );
      expect(await statuses()).toEqual(Array.from({ length: 7 }, () => "missing"));
      for (const prerequisite of [
        harness.fixture.callPolicy,
        harness.fixture.rateLimitPolicy,
        harness.fixture.ecdsaSigner,
        harness.fixture.p256Verifier,
      ]) {
        await expect(deployRuntime({ chainId: 143, rpc, journal, account })).rejects.toThrow(
          "deployment_prerequisite_missing",
        );
        expect(keys).toBe(0);
        expect(sends).toBe(0);
        await harness.deployCreate2(prerequisite.deploymentInput);
      }
      const plan = await deployRuntime({ chainId: 143, rpc, journal, account, dryRun: true });
      expect(plan.status).toBe("planned");
      expect(plan.missing).toHaveLength(6);
      expect(plan.missing).toEqual(expect.arrayContaining(["webAuthnSigner"]));
      expect(plan.missing).not.toContain("p256Verifier");
      expect(keys).toBe(0);
      expect(sends).toBe(0);
      const deployed = await deployRuntime({
        chainId: 143,
        rpc,
        journal,
        account,
        observationAttempts: 1,
      });
      expect(deployed.status).toBe("ready");
      expect(deployed.readiness.factoryBinding).toBe("verified");
      expect(deployed.readiness.passkeySessionsReady).toBe(true);
      expect(await statuses()).toEqual(Array.from({ length: 7 }, () => "present"));
      expect(sends).toBe(6);
      expect(keys).toBe(6);
      const again = await deployRuntime({
        chainId: 143,
        rpc: new Rpc(chain.url, { maxRequests: 256 }),
        journal,
        account: () => {
          throw new Error("unexpected signing key request");
        },
      });
      expect(again.status).toBe("ready");
      expect(sends).toBe(6);
    } finally {
      journal.close();
      chain.stop();
      await rm(directory, { recursive: true, force: true });
    }
  }, 30_000);

  it("recovers an accepted transaction after lost reply and reopened journal without a second signature or send", async () => {
    const chain = await startAnvil(143);
    const directory = await mkdtemp(join(tmpdir(), "oaath-deploy-recovery-"));
    const path = join(directory, "state.sqlite");
    let journal = new DeploymentJournal(path);
    try {
      const harness = await createHarness(chain);
      await deployKernelStack(harness);
      for (const prerequisite of [
        harness.fixture.callPolicy,
        harness.fixture.rateLimitPolicy,
        harness.fixture.ecdsaSigner,
        harness.fixture.p256Verifier,
      ])
        await harness.deployCreate2(prerequisite.deploymentInput);
      for (const component of components(143))
        if (
          (component.required || component.passkeySession) &&
          component.deploymentInput &&
          component.id !== "validityPolicy" &&
          !(await harness.client.getCode({ address: component.address }))
        )
          await harness.deployCreate2(component.deploymentInput);
      let sends = 0,
        signatures = 0;
      const network = new Rpc(chain.url, { maxRequests: 128 });
      const account = {
        ...harness.submitter,
        signTransaction: async (...args: Parameters<typeof harness.submitter.signTransaction>) => {
          signatures++;
          return harness.submitter.signTransaction(...args);
        },
      };
      const rpc: RpcReader = {
        request: async (method, params) => {
          if (method === "eth_sendRawTransaction") {
            sends++;
            expect(journal.pending(143)?.state).toBe("attempted");
            await network.request(method, params);
            throw new Error("lost reply");
          }
          return network.request(method, params);
        },
      };
      const uncertain = await deployRuntime({
        chainId: 143,
        rpc,
        journal,
        account: () => account,
        observationAttempts: 1,
      });
      expect(uncertain.status).toBe("pending");
      expect(signatures).toBe(1);
      expect(sends).toBe(1);
      journal.close();
      journal = new DeploymentJournal(path);
      const stillPending = await deployRuntime({
        chainId: 143,
        rpc: {
          request: (method, params) =>
            method === "eth_getTransactionReceipt"
              ? Promise.resolve(null)
              : rpc.request(method, params),
        },
        journal,
        account: () => {
          throw new Error("must not load a key for recovery");
        },
        observationAttempts: 1,
      });
      expect(stillPending.transactionHash).toBe(uncertain.transactionHash);
      expect(stillPending.status).toBe("pending");
      await network.request("anvil_mine", ["0x40"]);
      await expect(
        deployRuntime({
          chainId: 143,
          rpc: {
            request: async (method, params) => {
              const response = await network.request(method, params);
              return method === "eth_getTransactionByHash"
                ? { ...(response as object), input: "0x" }
                : response;
            },
          },
          journal,
          account: () => {
            throw new Error("must not sign after invalid evidence");
          },
          observationAttempts: 1,
        }),
      ).rejects.toThrow("deployment_evidence_invalid");
      expect(journal.pending(143)?.transactionHash).toBe(uncertain.transactionHash);
      const recovered = await deployRuntime({
        chainId: 143,
        rpc: new Rpc(chain.url, { maxRequests: 256 }),
        journal,
        account: () => {
          throw new Error("must not sign again");
        },
        observationAttempts: 1,
      });
      expect(recovered.status).toBe("ready");
      expect(signatures).toBe(1);
      expect(sends).toBe(1);
      expect(journal.get(143, "validityPolicy")?.state).toBe("confirmed");
    } finally {
      journal.close();
      chain.stop();
      await rm(directory, { recursive: true, force: true });
    }
  }, 30_000);
});
