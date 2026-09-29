import { describe, expect, it } from "vitest";
import type { Erc7677PaymasterServiceRequest, OaathChainCapability } from "../src/advanced.js";
import { prepareSponsoredKernelOperation } from "../src/advanced.js";
import {
  createKernelRuntime,
  kernelDeployment,
  ownerOperator,
  prepareUserOperation,
  sessionOperator,
} from "../src/kernel.js";
import { oaathProvider } from "../src/viem.js";
import {
  CALL_DATA,
  CHAIN_ID,
  type ChainFixture,
  createChainFixture,
  createRealm,
  permissionInput,
  signingProfiles,
  TARGET,
} from "./support/browser.js";

function configured(chainId: number, floor?: bigint): ChainFixture {
  const base = createChainFixture({ chainId });
  return {
    ...base,
    capability: {
      ...base.capability,
      ...(floor === undefined ? {} : { gas: { enableVerificationGasFloor: floor } }),
    },
    get quotes() {
      return base.quotes;
    },
  };
}

function realmFor(chain: ChainFixture) {
  return createRealm({
    chains: chain.capability.chainId === CHAIN_ID ? [chain] : [createChainFixture(), chain],
  });
}

describe("per-chain session-enable verification gas", () => {
  it.each([
    { chainId: 143, floor: undefined, expected: "2000000" },
    { chainId: CHAIN_ID, floor: 3_000_000n, expected: "3000000" },
  ])(
    "applies and reviews the enable floor on $chainId only until installation",
    async ({ chainId, floor, expected }) => {
      const chain = configured(chainId, floor);
      const realm = realmFor(chain);
      try {
        const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
        const request = {
          chain: chainId,
          calls: [{ target: TARGET, value: "0", data: CALL_DATA }],
        };
        expect(await grant.reviewCalls(request)).toMatchObject({
          enableVerificationGasFloor: expected,
        });
        expect(chain.quotes).toBe(0);
        const first = await grant.sendCalls(request);
        expect((await first.wait()).status).toBe("finalized");
        expect(chain.sends[0]?.userOperation.verificationGasLimit).toBe(expected);
        expect(await grant.reviewCalls(request)).toMatchObject({
          enableVerificationGasFloor: null,
        });
        const second = await grant.sendCalls(request);
        expect((await second.wait()).status).toBe("finalized");
        expect(chain.sends[1]?.userOperation.verificationGasLimit).toBe("200000");
      } finally {
        await realm.oaath.close();
      }
    },
  );

  it("keeps a higher quote and leaves other chains unchanged", async () => {
    for (const [chainId, quoted] of [
      [143, "4000000"],
      [CHAIN_ID, "200000"],
    ] as const) {
      const base = configured(chainId);
      const chain = {
        ...base,
        capability: {
          ...base.capability,
          async quote(request: Parameters<OaathChainCapability["quote"]>[0]) {
            const value = (await base.capability.quote(request)) as {
              nonceKey: string;
              sequence: string;
              gas: Record<string, string>;
            };
            return { ...value, gas: { ...value.gas, verificationGasLimit: quoted } };
          },
        },
      };
      const realm = realmFor(chain);
      try {
        const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
        await grant.sendCalls({
          chain: chainId,
          calls: [{ target: TARGET, value: "0", data: CALL_DATA }],
        });
        expect(chain.sends[0]?.userOperation.verificationGasLimit).toBe(quoted);
      } finally {
        await realm.oaath.close();
      }
    }
  });

  it("rejects invalid policies before any chain activity", () => {
    for (const floor of [-1n, 1n << 120n, "2000000", 2_000_000]) {
      const chain = configured(143, floor as bigint);
      expect(() => realmFor(chain)).toThrow();
      expect(chain.quotes).toBe(0);
      expect(chain.sends).toHaveLength(0);
    }
  });

  it("keeps owner gas unchanged and refuses to sign an externally prepared enable below the floor", async () => {
    const chain = configured(143);
    const keys = signingProfiles();
    const deployment = kernelDeployment({ chainId: 143 });
    const owner = createKernelRuntime({
      deployment,
      operator: ownerOperator({ key: keys.owner }),
      reads: chain.capability.reads,
    });
    const session = createKernelRuntime({
      deployment,
      operator: sessionOperator({
        key: keys.session,
        policies: [
          {
            kind: "call",
            permissions: [{ target: TARGET, selector: "0xa9059cbb", valueLimit: "0" }],
          },
        ],
      }),
      reads: chain.capability.reads,
    });
    const account = await session.bindAccount({
      accountIndex: "0",
      initialPackages: owner.packages,
    });
    const input = {
      account,
      kind: "execution" as const,
      grantId: "gas-floor",
      nonceKey: "0",
      sequence: "0",
      calls: [{ target: TARGET, value: "0", data: CALL_DATA }],
      gas: {
        callGasLimit: "100000",
        verificationGasLimit: "200000",
        preVerificationGas: "50000",
        maxFeePerGas: "1000000000",
        maxPriorityFeePerGas: "100000000",
      },
    };
    expect(owner.prepareOperation(input).userOperation.verificationGasLimit).toBe("200000");
    const prepared = session.prepareOperation({ ...input, mode: "enable-replayable" });
    const underfunded = prepareUserOperation({
      kind: prepared.kind,
      grantId: prepared.grantId,
      chainId: prepared.chainId,
      entryPoint: prepared.entryPoint,
      userOperation: { ...prepared.userOperation, verificationGasLimit: "200000" },
    });
    const refusal = await session.signOperation(underfunded).then(
      () => null,
      (error: unknown) => (error as { code: string }).code,
    );
    expect(refusal).toBe("kernel_runtime_binding_mismatch");
    await expect(
      prepareSponsoredKernelOperation({
        runtime: session,
        operation: { ...input, mode: "enable-replayable" },
        simulationSignature: session.dummySignature,
        sponsorship: {
          async sponsor(request) {
            expect(request.verificationGasFloor).toBe("2000000");
            return {
              gas: input.gas,
              paymaster: {
                address: TARGET,
                verificationGasLimit: "50000",
                postOpGasLimit: "50000",
                data: "0x",
              },
            };
          },
        },
      }),
    ).rejects.toMatchObject({ code: "routing_sponsorship_invalid" });
  });

  it("captures an override before asynchronous work", async () => {
    const base = configured(CHAIN_ID);
    const gas = { enableVerificationGasFloor: 3_000_000n };
    const chain = { ...base, capability: { ...base.capability, gas } };
    const realm = realmFor(chain);
    gas.enableVerificationGasFloor = 1n;
    try {
      const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
      await grant.sendCalls({
        chain: CHAIN_ID,
        calls: [{ target: TARGET, value: "0", data: CALL_DATA }],
      });
      expect(chain.sends[0]?.userOperation.verificationGasLimit).toBe("3000000");
    } finally {
      await realm.oaath.close();
    }
  });

  it("uses the same floored gas in ERC-7677 final authorization and the submitted operation", async () => {
    const requests: Readonly<Erc7677PaymasterServiceRequest>[] = [];
    const url = "https://issuer.example/chains/143/paymaster";
    const paymaster = "0x3333333333333333333333333333333333333333" as const;
    const base = configured(143);
    const chain = {
      ...base,
      capability: {
        ...base.capability,
        paymasterService: {
          url,
          async request(request: Readonly<Erc7677PaymasterServiceRequest>) {
            requests.push(request);
            return request.method === "pm_getPaymasterStubData"
              ? { paymaster, paymasterData: "0x01", paymasterPostOpGasLimit: "0x3c" }
              : { paymaster, paymasterData: "0x02" };
          },
          async estimate() {
            return {
              callGasLimit: "100000",
              verificationGasLimit: "100000",
              preVerificationGas: "50000",
              paymasterVerificationGasLimit: "50000",
            };
          },
        },
      },
    };
    const realm = realmFor(chain);
    try {
      const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
      const provider = oaathProvider({ grant, chain: 143 });
      await provider.request({
        method: "wallet_sendCalls",
        params: [
          {
            version: "2.0.0",
            id: "enable-gas-floor",
            from: await grant.account(143),
            chainId: "0x8f",
            atomicRequired: true,
            calls: [{ to: TARGET, data: CALL_DATA }],
            capabilities: { paymasterService: { url, context: {} } },
          },
        ],
      });
      const final = requests.find((request) => request.method === "pm_getPaymasterData");
      expect(final?.params[0].verificationGasLimit).toBe("0x1e8480");
      expect(chain.sends[0]?.userOperation.verificationGasLimit).toBe("2000000");
      expect(chain.sends).toHaveLength(1);
    } finally {
      await realm.oaath.close();
    }
  });
});
