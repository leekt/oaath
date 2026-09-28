import { encodeAbiParameters, encodeFunctionData, pad, parseAbi, recoverAddress } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { describe, expect, it, vi } from "vitest";
import { createKernelRuntime } from "../src/kernel/create-kernel-runtime.js";
import {
  bindKernelAccount,
  createKernelV33Reads,
  kernelV33Deployment,
} from "../src/kernel/deployment/v33.js";
import { ecdsaKey } from "../src/kernel/key/ecdsa.js";
import { ownerOperator } from "../src/kernel/operator/owner.js";
import {
  KERNEL_V4_ENTRY_POINT_V07,
  KERNEL_V4_ENTRY_POINT_V07_CODE_HASH,
  KERNEL_V4_IMPLEMENTATION_SLOT,
} from "../src/kernel-v4.js";
import { prepareUserOperation } from "../src/prepared-user-operation.js";

const account = "0xc3a56de6dfc1dcef5113927ec09513918e8c44aa";
const implementation = "0xd6cedde84be40893d153be9d467cd6ad37875b28";
const validator = "0x845adb2c711129d4f3966735ed98a9f09fc4ce57";
const root = `0x01${validator.slice(2)}` as const;
const abi = parseAbi([
  "function accountId() view returns (string)",
  "function entrypoint() view returns (address)",
  "function rootValidator() view returns (bytes21)",
]);

function fixture() {
  const replies = new Map([
    [
      encodeFunctionData({ abi, functionName: "accountId" }),
      encodeAbiParameters([{ type: "string" }], ["kernel.advanced.v0.3.3"]),
    ],
    [
      encodeFunctionData({ abi, functionName: "entrypoint" }),
      encodeAbiParameters([{ type: "address" }], [KERNEL_V4_ENTRY_POINT_V07]),
    ],
    [
      encodeFunctionData({ abi, functionName: "rootValidator" }),
      encodeAbiParameters([{ type: "bytes21" }], [root]),
    ],
  ]);
  const read = vi.fn(async (request: { type: string; address?: string }): Promise<unknown> => {
    switch (request.type) {
      case "chain_id":
        return 143;
      case "code":
        return "0x6000";
      case "runtime_code_hash":
        return KERNEL_V4_ENTRY_POINT_V07_CODE_HASH;
      case "kernel_account_implementation":
        return implementation;
      case "kernel_account_version":
        return "kernel.advanced.v0.3.3";
      case "kernel_account_entrypoint":
        return KERNEL_V4_ENTRY_POINT_V07;
      case "kernel_account_root_validator":
        return root;
      default:
        throw new Error("unexpected read");
    }
  });
  return {
    replies,
    read,
    input: {
      version: "0.3.3" as const,
      chainId: 143,
      address: account as `0x${string}`,
      reads: { read },
    },
  };
}

describe("existing Kernel v3.3 account binding", () => {
  it("preserves the deployed address without deriving or deploying a v4 account", async () => {
    const { read, input } = fixture();
    const bound = await bindKernelAccount(input);
    expect(bound).toEqual({
      profile: "kernel-v3.3-entrypoint-v0.7",
      version: "0.3.3",
      state: "deployed",
      chainId: 143,
      account,
      entryPoint: KERNEL_V4_ENTRY_POINT_V07,
      implementation,
      rootValidator: root,
    });
    expect(Object.isFrozen(bound)).toBe(true);
    expect(read.mock.calls.every(([request]) => !request.type.includes("factory"))).toBe(true);
    expect(kernelV33Deployment(143)).toBe(kernelV33Deployment(143));
  });

  it.each([
    ["chain_id", 480],
    ["runtime_code_hash", `0x${"00".repeat(32)}`],
    ["code", "0x"],
    ["code", undefined],
    ["kernel_account_implementation", "0x3c504000d05c1e28687f70fca40a76f7ddda9952"],
    ["kernel_account_version", "kernel.advanced.v0.3.2"],
    ["kernel_account_entrypoint", validator],
    ["kernel_account_root_validator", `0x00${"00".repeat(20)}`],
    ["kernel_account_root_validator", `0x02${"11".repeat(20)}`],
  ])("refuses contradictory or absent %s evidence", async (type, result) => {
    const { read, input } = fixture();
    const original = read.getMockImplementation()!;
    read.mockImplementation(async (request) =>
      request.type === type ? result : original(request),
    );
    await expect(bindKernelAccount(input)).rejects.toMatchObject({
      code: "kernel_runtime_binding_mismatch",
    });
  });

  it("keeps unavailable reads distinct from absent accounts and never retries them itself", async () => {
    const { read, input } = fixture();
    read.mockRejectedValueOnce(new Error("private provider diagnostic"));
    await expect(bindKernelAccount(input)).rejects.toMatchObject({
      code: "kernel_runtime_read_unavailable",
      message: "Kernel v3.3 account evidence could not be read",
    });
    expect(read).toHaveBeenCalledTimes(1);
  });

  it("refuses a different requested version before reading", async () => {
    const { read, input } = fixture();
    await expect(bindKernelAccount({ ...input, version: "0.3.2" } as never)).rejects.toMatchObject({
      code: "kernel_runtime_input_invalid",
    });
    expect(read).not.toHaveBeenCalled();
  });

  it("adapts public-client reads to the exact deployed-account checks", async () => {
    const { replies } = fixture();
    const client = {
      getChainId: vi.fn(async () => 143),
      getCode: vi.fn(async () => "0x6000" as const),
      getStorageAt: vi.fn(async () => pad(implementation, { size: 32 })),
      call: vi.fn(async ({ to, data }: { to: string; data: `0x${string}` }) => {
        expect(to).toBe(account);
        return { data: replies.get(data) };
      }),
    };
    const reads = createKernelV33Reads(client);
    expect(await reads.read({ type: "chain_id", chainId: 143 })).toBe(143);
    expect(await reads.read({ type: "kernel_account_implementation", chainId: 143, account })).toBe(
      implementation,
    );
    expect(await reads.read({ type: "kernel_account_version", chainId: 143, account })).toBe(
      "kernel.advanced.v0.3.3",
    );
    expect(await reads.read({ type: "kernel_account_entrypoint", chainId: 143, account })).toBe(
      KERNEL_V4_ENTRY_POINT_V07,
    );
    expect(await reads.read({ type: "kernel_account_root_validator", chainId: 143, account })).toBe(
      root,
    );
    expect(client.getStorageAt).toHaveBeenCalledWith({
      address: account,
      slot: KERNEL_V4_IMPLEMENTATION_SLOT,
    });
  });
});

describe("existing Kernel v3.3 owner composition", () => {
  function ownerFixture() {
    const fixtureValue = fixture();
    const owner = privateKeyToAccount(generatePrivateKey());
    const sign = vi.fn(owner.sign);
    const original = fixtureValue.read.getMockImplementation()!;
    fixtureValue.read.mockImplementation(async (request) =>
      request.type === "kernel_ecdsa_owner" ? owner.address.toLowerCase() : original(request),
    );
    const runtime = createKernelRuntime({
      deployment: kernelV33Deployment(143),
      operator: ownerOperator({
        key: ecdsaKey({ account: { address: owner.address, sign }, validator }),
      }),
      reads: { read: fixtureValue.read },
    });
    return { ...fixtureValue, owner, sign, runtime };
  }
  const gas = {
    callGasLimit: "100000",
    verificationGasLimit: "200000",
    preVerificationGas: "50000",
    maxFeePerGas: "1000000000",
    maxPriorityFeePerGas: "100000000",
  };
  const calls = [
    {
      target: "0x1111111111111111111111111111111111111111" as const,
      value: "0",
      data: "0x12345678" as const,
    },
  ];

  it("binds, prepares and signs an owner operation at the existing address through the composition entry", async () => {
    const { runtime, owner, sign } = ownerFixture();
    const bound = await runtime.bindAccount({ address: account });
    const operation = runtime.prepareOperation({
      account: bound,
      kind: "execution",
      grantId: "owner-operation",
      nonceKey: "0",
      sequence: "3",
      calls,
      gas,
    });
    expect(operation.userOperation).toMatchObject({
      sender: account,
      nonce: "3",
      factory: null,
      paymaster: null,
    });
    expect(operation.userOperation.callData.startsWith("0xe9ae5c53")).toBe(true);
    const signature = await runtime.signOperation(operation);
    expect(await recoverAddress({ hash: operation.userOperationHash, signature })).toBe(
      owner.address,
    );
    expect(sign).toHaveBeenCalledTimes(1);
    expect(runtime.packages).toEqual([]);
  });

  it("refuses a connected key that does not own the deployed account", async () => {
    const { runtime, read, sign } = ownerFixture();
    const original = read.getMockImplementation()!;
    read.mockImplementation(async (request) =>
      request.type === "kernel_ecdsa_owner" ? account : original(request),
    );
    await expect(runtime.bindAccount({ address: account })).rejects.toMatchObject({
      code: "kernel_runtime_binding_mismatch",
    });
    expect(sign).not.toHaveBeenCalled();
  });

  it("never signs for an unbound account or an enable-mode operation", async () => {
    const { runtime, sign } = ownerFixture();
    const bound = await runtime.bindAccount({ address: account });
    const input = {
      account: bound,
      kind: "execution" as const,
      grantId: "owner-operation",
      nonceKey: "0",
      sequence: "0",
      calls,
      gas,
    };
    expect(() =>
      runtime.prepareOperation({ ...input, mode: "enable-replayable" } as never),
    ).toThrow();
    expect(() => runtime.prepareOperation({ ...input, account: { ...bound } })).toThrow();
    const operation = runtime.prepareOperation(input);
    const changed = prepareUserOperation({
      kind: operation.kind,
      grantId: operation.grantId,
      chainId: operation.chainId,
      entryPoint: operation.entryPoint,
      userOperation: { ...operation.userOperation, sender: calls[0]!.target },
    });
    await expect(runtime.signOperation(changed)).rejects.toMatchObject({
      code: "kernel_runtime_binding_mismatch",
    });
    expect(sign).not.toHaveBeenCalled();
  });
});
