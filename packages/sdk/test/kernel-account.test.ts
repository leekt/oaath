/**
 * The version-agnostic Kernel account entry points: default deployment
 * selection, onchain detection of an existing account's deployment, and the one
 * structured code for an explicit deployment that disagrees with the account.
 */
import { describe, expect, it, vi } from "vitest";
import {
  bindKernelAccount,
  createKernelReads,
  kernelAccountDeployment,
  kernelDeployment,
  prepareKernelUserOperation,
} from "../src/kernel.js";
import {
  KERNEL_V4_ENTRY_POINT_V07,
  KERNEL_V4_ENTRY_POINT_V07_CODE_HASH,
  KERNEL_V4_FACTORY_V07,
  KERNEL_V4_FACTORY_V07_CODE_HASH,
  KERNEL_V4_UUPS_IMPLEMENTATION_V07,
} from "../src/kernel-v4.js";

const chainId = 143;
const account = "0xc3a56de6dfc1dcef5113927ec09513918e8c44aa";
const validator = "0x845adb2c711129d4f3966735ed98a9f09fc4ce57";
const root = `0x01${validator.slice(2)}`;
const v33Implementation = "0xd6cedde84be40893d153be9d467cd6ad37875b28";

/** Canned evidence for one existing account running `implementation`. */
function reads(implementation: string) {
  const read = vi.fn(
    async (request: { type: string; address?: string; factory?: string }): Promise<unknown> => {
      switch (request.type) {
        case "chain_id":
          return chainId;
        case "code":
          return "0x6000";
        case "runtime_code_hash":
          return request.address === KERNEL_V4_FACTORY_V07
            ? KERNEL_V4_FACTORY_V07_CODE_HASH
            : KERNEL_V4_ENTRY_POINT_V07_CODE_HASH;
        case "kernel_factory_implementation":
          return KERNEL_V4_UUPS_IMPLEMENTATION_V07;
        case "kernel_account_implementation":
          return implementation;
        case "kernel_account_version":
          return "kernel.advanced.v0.3.3";
        case "kernel_account_entrypoint":
          return KERNEL_V4_ENTRY_POINT_V07;
        case "kernel_account_root_validator":
        case "kernel_v4_account_root":
          return root;
        default:
          throw new Error("unexpected read");
      }
    },
  );
  return { read, reads: { read } };
}

describe("version-agnostic Kernel deployment selection", () => {
  it("defaults every omitted setting and checks every given one", () => {
    const current = kernelDeployment({ chainId });
    expect(current).toMatchObject({ kernelVersion: "0.4.0", entryPoint: { version: "0.7" } });
    expect(kernelDeployment({ chainId, kernelVersion: "0.4.0", entryPoint: "0.7" })).toBe(current);
    expect(kernelDeployment({ chainId, kernelVersion: "0.3.3" }).kernelVersion).toBe("0.3.3");
    for (const input of [
      { chainId, kernelVersion: "0.3.2" },
      { chainId, entryPoint: "0.8" },
      { chainId: 0 },
      { chainId, version: "0.4.0" },
    ]) {
      expect(() => kernelDeployment(input as never)).toThrow(
        expect.objectContaining({ code: "kernel_runtime_input_invalid" }),
      );
    }
  });
});

describe("version-agnostic Kernel account binding", () => {
  it.each([
    [v33Implementation, "0.3.3", "kernel-v3.3-entrypoint-v0.7"],
    [KERNEL_V4_UUPS_IMPLEMENTATION_V07, "0.4.0", "kernel-v4-uups-entrypoint-v0.7"],
  ] as const)(
    "detects the deployment of an account running %s",
    async (implementation, version, profile) => {
      const evidence = reads(implementation);
      const bound = await bindKernelAccount({ chainId, address: account, reads: evidence.reads });
      expect(bound).toMatchObject({ profile, state: "deployed", account, rootValidator: root });
      expect(kernelAccountDeployment(bound).kernelVersion).toBe(version);
      // An explicit matching deployment is accepted as-is.
      const explicit = kernelDeployment({ chainId, kernelVersion: version });
      await expect(
        bindKernelAccount({
          chainId,
          address: account,
          reads: evidence.reads,
          deployment: explicit,
        }),
      ).resolves.toMatchObject({ profile });
    },
  );

  it.each([
    [v33Implementation, "0.4.0"],
    [KERNEL_V4_UUPS_IMPLEMENTATION_V07, "0.3.3"],
  ] as const)(
    "refuses an account running %s under an explicit %s deployment",
    async (implementation, other) => {
      const evidence = reads(implementation);
      await expect(
        bindKernelAccount({
          chainId,
          address: account,
          reads: evidence.reads,
          deployment: kernelDeployment({ chainId, kernelVersion: other }),
        }),
      ).rejects.toMatchObject({ code: "kernel_runtime_deployment_mismatch" });
      // Detection is the only evidence read; the mismatch never reaches a binder.
      expect(evidence.read).toHaveBeenCalledTimes(1);
    },
  );

  it("refuses a derived account or another chain under a mismatching deployment", async () => {
    const evidence = reads(KERNEL_V4_UUPS_IMPLEMENTATION_V07);
    const mismatch = { code: "kernel_runtime_deployment_mismatch" };
    await expect(
      bindKernelAccount({
        chainId,
        initialPackages: [],
        accountIndex: "0",
        reads: evidence.reads,
        deployment: kernelDeployment({ chainId, kernelVersion: "0.3.3" }),
      }),
    ).rejects.toMatchObject(mismatch);
    await expect(
      bindKernelAccount({
        chainId,
        address: account,
        reads: evidence.reads,
        deployment: kernelDeployment({ chainId: 1 }),
      }),
    ).rejects.toMatchObject(mismatch);
    expect(evidence.read).not.toHaveBeenCalled();
  });

  it("never guesses an unsupported or unreadable implementation", async () => {
    await expect(
      bindKernelAccount({ chainId, address: account, reads: reads(validator).reads }),
    ).rejects.toMatchObject({ code: "kernel_runtime_binding_mismatch" });
    const unavailable = reads(v33Implementation);
    unavailable.read.mockRejectedValueOnce(new Error("provider diagnostic"));
    await expect(
      bindKernelAccount({ chainId, address: account, reads: unavailable.reads }),
    ).rejects.toMatchObject({ code: "kernel_runtime_read_unavailable" });
    expect(unavailable.read).toHaveBeenCalledTimes(1);
  });

  it("refuses an existing Kernel v4 account whose root validation is absent", async () => {
    const evidence = reads(KERNEL_V4_UUPS_IMPLEMENTATION_V07);
    const original = evidence.read.getMockImplementation()!;
    evidence.read.mockImplementation(async (request) =>
      request.type === "kernel_v4_account_root" ? `0x01${"00".repeat(20)}` : original(request),
    );
    await expect(
      bindKernelAccount({ chainId, address: account, reads: evidence.reads }),
    ).rejects.toMatchObject({ code: "kernel_v4_evidence_invalid" });
  });

  it("routes union reads to the owning version adapter", async () => {
    const call = vi.fn(async () => ({ data: `0x${root.slice(2).padEnd(64, "0")}` as const }));
    const client = {
      getChainId: async () => chainId,
      getCode: async () => "0x6000" as const,
      getStorageAt: async () => `0x${"00".repeat(12)}${account.slice(2)}` as const,
      call,
    };
    const union = createKernelReads(client);
    await expect(union.read({ type: "kernel_v4_account_root", chainId, account })).resolves.toBe(
      root,
    );
    await expect(
      union.read({ type: "kernel_account_root_validator", chainId, account }),
    ).resolves.toBe(root);
    expect(call).toHaveBeenCalledTimes(2);
  });
});

describe("version-agnostic Kernel UserOperation preparation", () => {
  const operation = {
    kind: "execution" as const,
    grantId: "owner-context",
    nonce: {
      mode: "standard" as const,
      validation: { kind: "root" as const },
      nonceKey: "0",
      sequence: "0",
    },
    calls: [{ target: `0x${"44".repeat(20)}` as const, value: "0", data: "0x" as const }],
    gas: {
      callGasLimit: "1",
      verificationGasLimit: "1",
      preVerificationGas: "1",
      maxFeePerGas: "1",
      maxPriorityFeePerGas: "1",
    },
  };

  it.each([v33Implementation, KERNEL_V4_UUPS_IMPLEMENTATION_V07])(
    "prepares an existing %s account with no factory",
    async (implementation) => {
      const bound = await bindKernelAccount({
        chainId,
        address: account,
        reads: reads(implementation).reads,
      });
      const prepared = prepareKernelUserOperation({ ...operation, account: bound });
      expect(prepared).toMatchObject({
        chainId,
        entryPoint: { version: "0.7", address: KERNEL_V4_ENTRY_POINT_V07 },
        userOperation: { sender: account, factory: null },
      });
    },
  );

  it("refuses a validity range on a Kernel v3.3 account", async () => {
    const bound = await bindKernelAccount({
      chainId,
      address: account,
      reads: reads(v33Implementation).reads,
    });
    expect(() =>
      prepareKernelUserOperation({
        ...operation,
        account: bound,
        validityTimeRange: { validAfter: "0", validUntil: "1" },
      }),
    ).toThrow(expect.objectContaining({ code: "kernel_runtime_unsupported" }));
  });
});
