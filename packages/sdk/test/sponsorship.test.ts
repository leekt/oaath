import { describe, expect, it } from "vitest";
import type {
  KernelRuntimePrepareInput,
  OaathKernelSponsorshipRuntime,
  PreparedPaymaster,
} from "../src/index.js";
import {
  KERNEL_V4_ENTRY_POINT_V07,
  KERNEL_V4_FACTORY_V07,
  KERNEL_V4_UUPS_IMPLEMENTATION_V07,
  type OaathRoutingError,
  prepareSponsoredKernelOperation,
  prepareUserOperation,
} from "../src/index.js";

const ACCOUNT = `0x${"11".repeat(20)}` as const;
const TARGET = `0x${"22".repeat(20)}` as const;
const PAYMASTER = `0x${"33".repeat(20)}` as const;
const DUMMY_SIGNATURE = "0x1234" as const;

function operation(): KernelRuntimePrepareInput {
  return {
    kind: "execution",
    grantId: "sponsored-operation",
    account: {
      profile: "kernel-v4-uups-entrypoint-v0.7",
      state: "deployed",
      chainId: 421_614,
      entryPoint: KERNEL_V4_ENTRY_POINT_V07,
      implementation: KERNEL_V4_UUPS_IMPLEMENTATION_V07,
      factory: KERNEL_V4_FACTORY_V07,
      account: ACCOUNT,
      accountIndex: "0",
      initialPackages: [],
      factoryAddressCalldata: "0x",
      factoryDeployCalldata: "0x",
    },
    nonceKey: "0",
    sequence: "7",
    calls: [{ target: TARGET, value: "0", data: "0xabcdef" }],
    gas: {
      callGasLimit: "1",
      verificationGasLimit: "2",
      preVerificationGas: "3",
      maxFeePerGas: "4",
      maxPriorityFeePerGas: "4",
    },
    mode: "standard",
  };
}

function runtime(): OaathKernelSponsorshipRuntime {
  return Object.freeze({
    dummySignature: DUMMY_SIGNATURE,
    prepareOperation(input: KernelRuntimePrepareInput) {
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
          factory: null,
          paymaster: input.paymaster ?? null,
        },
      });
    },
  });
}

function sponsorshipResult(): {
  gas: KernelRuntimePrepareInput["gas"];
  paymaster: PreparedPaymaster;
} {
  return {
    gas: {
      callGasLimit: "100",
      verificationGasLimit: "200",
      preVerificationGas: "30",
      maxFeePerGas: "40",
      maxPriorityFeePerGas: "10",
    },
    paymaster: {
      address: PAYMASTER,
      verificationGasLimit: "50",
      postOpGasLimit: "60",
      data: "0xdeadbeef",
    },
  };
}

describe("pre-sign Kernel sponsorship", () => {
  it("exposes only a dummy candidate and returns one final hash-bound operation", async () => {
    const requests: unknown[] = [];
    const final = await prepareSponsoredKernelOperation({
      runtime: runtime(),
      operation: operation(),
      simulationSignature: DUMMY_SIGNATURE,
      sponsorship: {
        async sponsor(request) {
          requests.push(request);
          expect(request.simulationSignature).toBe(DUMMY_SIGNATURE);
          expect(request.prepared.userOperation.paymaster).toBeNull();
          return sponsorshipResult();
        },
      },
    });

    expect(requests).toHaveLength(1);
    expect(final.userOperation.sender).toBe(ACCOUNT);
    expect(final.userOperation.nonce).toBe("7");
    expect(final.userOperation.callData).toBe("0xabcdef");
    expect(final.userOperation.callGasLimit).toBe("100");
    expect(final.userOperation.paymaster).toEqual(sponsorshipResult().paymaster);
    expect(final.userOperationHash).not.toBe(
      runtime().prepareOperation(operation()).userOperationHash,
    );
  });

  it("rejects provider replacement fields before final preparation", async () => {
    let preparations = 0;
    const base = runtime();
    const countingRuntime: OaathKernelSponsorshipRuntime = {
      ...base,
      prepareOperation(input) {
        preparations += 1;
        return base.prepareOperation(input);
      },
    };

    await expect(
      prepareSponsoredKernelOperation({
        runtime: countingRuntime,
        operation: operation(),
        simulationSignature: DUMMY_SIGNATURE,
        sponsorship: {
          async sponsor() {
            return { ...sponsorshipResult(), calls: [] };
          },
        },
      }),
    ).rejects.toMatchObject({
      code: "routing_sponsorship_invalid",
    } satisfies Partial<OaathRoutingError>);
    expect(preparations).toBe(1);
  });

  it("preserves enable mode while using the caller-owned complete simulation envelope", async () => {
    const enableSignature = "0xabcd" as const;
    const final = await prepareSponsoredKernelOperation({
      runtime: runtime(),
      operation: { ...operation(), mode: "enable-replayable" },
      simulationSignature: enableSignature,
      sponsorship: {
        async sponsor(request) {
          expect(request.simulationSignature).toBe(enableSignature);
          return sponsorshipResult();
        },
      },
    });
    expect(final.userOperation.paymaster).toEqual(sponsorshipResult().paymaster);
  });
});
