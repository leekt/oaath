import { describe, expect, it } from "vitest";
import {
  createErc7677SponsorshipCapability,
  type Erc7677GasEstimationRequest,
  type Erc7677PaymasterServiceRequest,
  type OaathKernelSponsorshipRuntime,
  type OaathRoutingError,
  prepareSponsoredKernelOperation,
} from "../src/advanced.js";
import type { KernelRuntimePrepareInput } from "../src/kernel.js";
import {
  KERNEL_V4_ENTRY_POINT_V07,
  KERNEL_V4_FACTORY_V07,
  KERNEL_V4_UUPS_IMPLEMENTATION_V07,
  prepareUserOperation,
} from "../src/kernel.js";
import { readCompletedErc7677ResultCapabilities } from "../src/provider/erc7677.js";

const SERVICE_URL = "https://service.example/chains/421614/paymaster";
const OTHER_URL = "https://attacker.example/paymaster";
const ACCOUNT = `0x${"11".repeat(20)}` as const;
const TARGET = `0x${"22".repeat(20)}` as const;
const PAYMASTER = `0x${"33".repeat(20)}` as const;
const OTHER_PAYMASTER = `0x${"44".repeat(20)}` as const;
const SIMULATION_SIGNATURE = "0x1234" as const;

function operation(): KernelRuntimePrepareInput {
  return {
    kind: "execution",
    grantId: "erc7677-operation",
    account: {
      profile: "kernel-v4-uups-entrypoint-v0.7",
      state: "counterfactual",
      chainId: 421_614,
      entryPoint: KERNEL_V4_ENTRY_POINT_V07,
      implementation: KERNEL_V4_UUPS_IMPLEMENTATION_V07,
      factory: KERNEL_V4_FACTORY_V07,
      account: ACCOUNT,
      accountIndex: "0",
      initialPackages: [],
      factoryAddressCalldata: "0x",
      factoryDeployCalldata: "0x1234",
    },
    nonceKey: "0",
    sequence: "7",
    calls: [{ target: TARGET, value: "0", data: "0xabcdef" }],
    gas: {
      callGasLimit: "1",
      verificationGasLimit: "2",
      preVerificationGas: "3",
      maxFeePerGas: "40",
      maxPriorityFeePerGas: "10",
    },
    mode: "enable-replayable",
  };
}

function runtime(preparations: KernelRuntimePrepareInput[]): OaathKernelSponsorshipRuntime {
  return Object.freeze({
    dummySignature: SIMULATION_SIGNATURE,
    prepareOperation(input: KernelRuntimePrepareInput) {
      preparations.push(input);
      return prepareUserOperation({
        kind: input.kind,
        grantId: input.grantId,
        chainId: input.account.chainId,
        entryPoint: { version: "0.7", address: input.account.entryPoint },
        userOperation: {
          sender: input.account.account,
          nonce: input.sequence,
          callData: input.calls[0]?.data ?? "0x",
          callGasLimit: input.gas.callGasLimit,
          verificationGasLimit: input.gas.verificationGasLimit,
          preVerificationGas: input.gas.preVerificationGas,
          maxFeePerGas: input.gas.maxFeePerGas,
          maxPriorityFeePerGas: input.gas.maxPriorityFeePerGas,
          factory: { address: input.account.factory, data: input.account.factoryDeployCalldata },
          paymaster: input.paymaster ?? null,
        },
      });
    },
  });
}

function stub(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    paymaster: PAYMASTER,
    paymasterData: "0x01020304",
    paymasterPostOpGasLimit: "0x3c",
    ...overrides,
  };
}

function estimate(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    callGasLimit: "100",
    verificationGasLimit: "200",
    preVerificationGas: "30",
    paymasterVerificationGasLimit: "50",
    ...overrides,
  };
}

describe("ERC-7677 sponsorship adapter", () => {
  it("translates stub, estimation, and final data into the existing exact sponsorship owner", async () => {
    const preparations: KernelRuntimePrepareInput[] = [];
    const stages: string[] = [];
    const serviceRequests: Readonly<Erc7677PaymasterServiceRequest>[] = [];
    const estimatorRequests: Readonly<Erc7677GasEstimationRequest>[] = [];
    const requestedContext = { policyId: "policy-a", nested: { tier: 1 } };
    const sponsorship = createErc7677SponsorshipCapability({
      requested: { url: SERVICE_URL, context: requestedContext },
      service: {
        url: SERVICE_URL,
        async request(request) {
          serviceRequests.push(request);
          stages.push(request.method === "pm_getPaymasterStubData" ? "stub" : "final");
          if (request.method === "pm_getPaymasterStubData") {
            expect(request.params[0]).toEqual({
              sender: ACCOUNT,
              nonce: "0x7",
              factory: KERNEL_V4_FACTORY_V07,
              factoryData: "0x1234",
              callData: "0xabcdef",
              callGasLimit: "0x1",
              verificationGasLimit: "0x2",
              preVerificationGas: "0x3",
              maxFeePerGas: "0x28",
              maxPriorityFeePerGas: "0xa",
            });
            expect(Object.hasOwn(request.params[0], "signature")).toBe(false);
            return stub({
              sponsor: { name: "Example Sponsor", icon: "data:image/png;base64,AQ==" },
            });
          }
          expect(request.params[0]).toEqual({
            sender: ACCOUNT,
            nonce: "0x7",
            factory: KERNEL_V4_FACTORY_V07,
            factoryData: "0x1234",
            callData: "0xabcdef",
            callGasLimit: "0x64",
            verificationGasLimit: "0xc8",
            preVerificationGas: "0x1e",
            maxFeePerGas: "0x28",
            maxPriorityFeePerGas: "0xa",
            paymaster: PAYMASTER,
            paymasterVerificationGasLimit: "0x32",
            paymasterPostOpGasLimit: "0x3c",
            paymasterData: "0x01020304",
          });
          expect(Object.hasOwn(request.params[0], "signature")).toBe(false);
          return { paymaster: PAYMASTER, paymasterData: "0x01020305" };
        },
      },
      estimator: {
        async estimate(request) {
          estimatorRequests.push(request);
          stages.push("estimate");
          expect(request.userOperation).toEqual({
            sender: ACCOUNT,
            nonce: "0x7",
            factory: KERNEL_V4_FACTORY_V07,
            factoryData: "0x1234",
            callData: "0xabcdef",
            callGasLimit: "0x1",
            verificationGasLimit: "0x2",
            preVerificationGas: "0x3",
            maxFeePerGas: "0x28",
            maxPriorityFeePerGas: "0xa",
            paymaster: PAYMASTER,
            paymasterPostOpGasLimit: "0x3c",
            paymasterData: "0x01020304",
            signature: SIMULATION_SIGNATURE,
          });
          return estimate();
        },
      },
    });
    requestedContext.policyId = "mutated";
    requestedContext.nested.tier = 9;

    expect(() => readCompletedErc7677ResultCapabilities(sponsorship)).toThrowError(
      expect.objectContaining({ code: "routing_capability_invalid" }),
    );

    const final = await prepareSponsoredKernelOperation({
      runtime: runtime(preparations),
      operation: operation(),
      simulationSignature: SIMULATION_SIGNATURE,
      sponsorship,
    });

    expect(stages).toEqual(["stub", "estimate", "final"]);
    expect(serviceRequests).toHaveLength(2);
    expect(estimatorRequests).toHaveLength(1);
    for (const request of serviceRequests) {
      expect(request.params[1]).toBe(KERNEL_V4_ENTRY_POINT_V07);
      expect(request.params[2]).toBe("0x66eee");
      expect(request.params[3]).toEqual({ policyId: "policy-a", nested: { tier: 1 } });
      expect(Object.isFrozen(request.params[3])).toBe(true);
    }
    expect(preparations).toHaveLength(2);
    const resultCapabilities = readCompletedErc7677ResultCapabilities(sponsorship);
    expect(resultCapabilities).toEqual({
      paymasterService: {
        sponsor: { name: "Example Sponsor", icon: "data:image/png;base64,AQ==" },
      },
    });
    expect(Object.isFrozen(resultCapabilities)).toBe(true);
    expect(Object.isFrozen(resultCapabilities?.paymasterService)).toBe(true);
    expect(Object.isFrozen(resultCapabilities?.paymasterService.sponsor)).toBe(true);
    expect(preparations[1]?.mode).toBe("enable-replayable");
    expect(final).toMatchObject({
      kind: "execution",
      grantId: "erc7677-operation",
      chainId: 421_614,
      entryPoint: { version: "0.7", address: KERNEL_V4_ENTRY_POINT_V07 },
      userOperation: {
        sender: ACCOUNT,
        nonce: "7",
        factory: { address: KERNEL_V4_FACTORY_V07, data: "0x1234" },
        callData: "0xabcdef",
        callGasLimit: "100",
        verificationGasLimit: "200",
        preVerificationGas: "30",
        maxFeePerGas: "40",
        maxPriorityFeePerGas: "10",
        paymaster: {
          address: PAYMASTER,
          verificationGasLimit: "50",
          postOpGasLimit: "60",
          data: "0x01020305",
        },
      },
    });
    await expect(
      prepareSponsoredKernelOperation({
        runtime: runtime(preparations),
        operation: operation(),
        simulationSignature: SIMULATION_SIGNATURE,
        sponsorship,
      }),
    ).rejects.toMatchObject({ code: "routing_sponsorship_invalid" });
    expect(stages).toEqual(["stub", "estimate", "final"]);
    expect(readCompletedErc7677ResultCapabilities(sponsorship)).toBe(resultCapabilities);
  });

  it("uses final stub data but still estimates when the service marks the stub final", async () => {
    const preparations: KernelRuntimePrepareInput[] = [];
    let serviceCalls = 0;
    let estimateCalls = 0;
    const sponsorship = createErc7677SponsorshipCapability({
      requested: { url: SERVICE_URL, context: {} },
      service: {
        url: SERVICE_URL,
        async request(request) {
          serviceCalls += 1;
          expect(request.method).toBe("pm_getPaymasterStubData");
          return stub({
            sponsor: { name: "One Padding Sponsor", icon: "data:image/png;base64,AQI=" },
            paymasterVerificationGasLimit: "0x32",
            isFinal: true,
          });
        },
      },
      estimator: {
        async estimate() {
          estimateCalls += 1;
          return {
            callGasLimit: "100",
            verificationGasLimit: "200",
            preVerificationGas: "30",
          };
        },
      },
    });

    const final = await prepareSponsoredKernelOperation({
      runtime: runtime(preparations),
      operation: operation(),
      simulationSignature: SIMULATION_SIGNATURE,
      sponsorship,
    });
    expect(serviceCalls).toBe(1);
    expect(estimateCalls).toBe(1);
    expect(final.userOperation.paymaster).toEqual({
      address: PAYMASTER,
      verificationGasLimit: "50",
      postOpGasLimit: "60",
      data: "0x01020304",
    });
    expect(readCompletedErc7677ResultCapabilities(sponsorship)).toEqual({
      paymasterService: {
        sponsor: { name: "One Padding Sponsor", icon: "data:image/png;base64,AQI=" },
      },
    });
  });

  it("refuses an unregistered URL before preparation or either external capability", () => {
    let serviceCalls = 0;
    let estimateCalls = 0;
    const preparations: KernelRuntimePrepareInput[] = [];
    expect(() =>
      createErc7677SponsorshipCapability({
        requested: { url: OTHER_URL, context: {} },
        service: {
          url: SERVICE_URL,
          async request() {
            serviceCalls += 1;
            return stub();
          },
        },
        estimator: {
          async estimate() {
            estimateCalls += 1;
            return estimate();
          },
        },
      }),
    ).toThrowError(
      expect.objectContaining({
        code: "routing_capability_invalid",
      } satisfies Partial<OaathRoutingError>),
    );
    expect(preparations).toHaveLength(0);
    expect(serviceCalls).toBe(0);
    expect(estimateCalls).toBe(0);
  });

  it("rejects replacement fields before estimation or final preparation", async () => {
    const preparations: KernelRuntimePrepareInput[] = [];
    let estimateCalls = 0;
    const sponsorship = createErc7677SponsorshipCapability({
      requested: { url: SERVICE_URL, context: {} },
      service: {
        url: SERVICE_URL,
        async request() {
          return stub({ sender: OTHER_PAYMASTER });
        },
      },
      estimator: {
        async estimate() {
          estimateCalls += 1;
          return estimate();
        },
      },
    });
    await expect(
      prepareSponsoredKernelOperation({
        runtime: runtime(preparations),
        operation: operation(),
        simulationSignature: SIMULATION_SIGNATURE,
        sponsorship,
      }),
    ).rejects.toMatchObject({
      code: "routing_sponsorship_invalid",
    } satisfies Partial<OaathRoutingError>);
    expect(preparations).toHaveLength(1);
    expect(estimateCalls).toBe(0);
  });

  it.each([
    ["a remote URL", "https://service.example/icon.png"],
    ["SVG", "data:image/svg+xml;base64,PHN2Zz4="],
    ["noncanonical base64", "data:image/png;base64,AQ"],
    ["noncanonical two-padding bits AR", "data:image/png;base64,AR=="],
    ["noncanonical two-padding bits AZ", "data:image/png;base64,AZ=="],
    ["noncanonical two-padding bits Af", "data:image/png;base64,Af=="],
    ["noncanonical one-padding bits", "data:image/png;base64,AQJ="],
    ["a fragment", "data:image/png;base64,AQ==#fragment"],
    ["an oversized payload", `data:image/png;base64,${"AAAA".repeat(8_193)}`],
  ])("rejects %s sponsor icon before estimation", async (_label, icon) => {
    let estimateCalls = 0;
    const sponsorship = createErc7677SponsorshipCapability({
      requested: { url: SERVICE_URL, context: {} },
      service: {
        url: SERVICE_URL,
        async request() {
          return stub({ sponsor: { name: "Example Sponsor", icon } });
        },
      },
      estimator: {
        async estimate() {
          estimateCalls += 1;
          return estimate();
        },
      },
    });
    await expect(
      prepareSponsoredKernelOperation({
        runtime: runtime([]),
        operation: operation(),
        simulationSignature: SIMULATION_SIGNATURE,
        sponsorship,
      }),
    ).rejects.toMatchObject({ code: "routing_sponsorship_invalid" });
    expect(estimateCalls).toBe(0);
    expect(() => readCompletedErc7677ResultCapabilities(sponsorship)).toThrow();
  });

  it.each([
    ["a different paymaster", { paymaster: OTHER_PAYMASTER, paymasterData: "0x01020305" }],
    ["a different data length", { paymaster: PAYMASTER, paymasterData: "0x010203" }],
    ["a stub with too many zero bytes", { paymaster: PAYMASTER, paymasterData: "0x01020305" }],
  ])("rejects %s in final data before final preparation", async (_label, finalData) => {
    const preparations: KernelRuntimePrepareInput[] = [];
    const sponsorship = createErc7677SponsorshipCapability({
      requested: { url: SERVICE_URL, context: {} },
      service: {
        url: SERVICE_URL,
        async request(request) {
          return request.method === "pm_getPaymasterStubData"
            ? stub({ paymasterData: "0x00020304" })
            : finalData;
        },
      },
      estimator: {
        async estimate() {
          return estimate();
        },
      },
    });
    await expect(
      prepareSponsoredKernelOperation({
        runtime: runtime(preparations),
        operation: operation(),
        simulationSignature: SIMULATION_SIGNATURE,
        sponsorship,
      }),
    ).rejects.toMatchObject({ code: "routing_sponsorship_invalid" });
    expect(preparations).toHaveLength(1);
    expect(() => readCompletedErc7677ResultCapabilities(sponsorship)).toThrow();
  });
});
