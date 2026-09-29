import {
  encodeAbiParameters,
  encodeFunctionData,
  hashTypedData,
  pad,
  parseAbi,
  recoverAddress,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { describe, expect, it, vi } from "vitest";
import { kernelOperationSigningHash } from "../src/advanced.js";
import { createKernelRuntime } from "../src/kernel/create-kernel-runtime.js";
import {
  bindKernelV33Account,
  createKernelV33Reads,
  kernelV33Deployment,
} from "../src/kernel/deployment/v33.js";
import { kernelV33OperationSigningHash } from "../src/kernel/deployment/v33-operation.js";
import { ecdsaKey } from "../src/kernel/key/ecdsa.js";
import {
  OAATH_KERNEL_RATE_LIMIT_POLICY,
  OAATH_KERNEL_RATE_LIMIT_POLICY_RUNTIME_CODE_HASH,
} from "../src/kernel/modules.js";
import { ownerOperator } from "../src/kernel/operator/owner.js";
import { sessionOperator } from "../src/kernel/operator/session.js";
import {
  kernelGrantCapabilityHash,
  parseKernelGrantApproval,
  verifyKernelPermissionApproval,
} from "../src/kernel/permission/approval.js";
import {
  approveKernelV33Permission,
  bindKernelV33PermissionApproval,
  type KernelV33ExpectedPermission,
  kernelV33PermissionEnableTypedData,
  kernelV33PermissionInstallNonce,
  materializeKernelV33Permission,
  parseKernelV33PermissionApproval,
} from "../src/kernel/permission/v33.js";
import {
  KERNEL_V4_ENTRY_POINT_V07,
  KERNEL_V4_ENTRY_POINT_V07_CODE_HASH,
  KERNEL_V4_IMPLEMENTATION_SLOT,
} from "../src/kernel-v4.js";
import { deriveOperationId, prepareUserOperation } from "../src/prepared-user-operation.js";

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
      chainId: 143,
      address: account as `0x${string}`,
      reads: { read },
    },
  };
}

describe("existing Kernel v3.3 account binding", () => {
  it("preserves the deployed address without deriving or deploying a v4 account", async () => {
    const { read, input } = fixture();
    const bound = await bindKernelV33Account(input);
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
    await expect(bindKernelV33Account(input)).rejects.toMatchObject({
      code: "kernel_runtime_binding_mismatch",
    });
  });

  it("keeps unavailable reads distinct from absent accounts and never retries them itself", async () => {
    const { read, input } = fixture();
    read.mockRejectedValueOnce(new Error("private provider diagnostic"));
    await expect(bindKernelV33Account(input)).rejects.toMatchObject({
      code: "kernel_runtime_read_unavailable",
      message: "Kernel v3.3 account evidence could not be read",
    });
    expect(read).toHaveBeenCalledTimes(1);
  });

  it("refuses an unexpected binding field before reading", async () => {
    const { read, input } = fixture();
    await expect(
      bindKernelV33Account({ ...input, version: "0.3.3" } as never),
    ).rejects.toMatchObject({
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

describe("Kernel v3.3 session composition", () => {
  async function sessionFixture() {
    const owner = privateKeyToAccount(generatePrivateKey());
    const session = privateKeyToAccount(generatePrivateKey());
    const sign = vi.fn(session.sign.bind(session));
    const { read } = fixture();
    const runtime = createKernelRuntime({
      deployment: kernelV33Deployment(143),
      operator: sessionOperator({
        key: ecdsaKey({ account: { address: session.address, sign }, validator }),
        policies: [
          {
            kind: "call",
            permissions: [{ target: account, selector: "0x00000000", valueLimit: "5" }],
          },
        ],
      }),
      reads: { read },
    });
    const bound = await runtime.bindAccount({ address: account });
    const input = {
      account: bound,
      kind: "execution" as const,
      grantId: "v33-session",
      nonceKey: "0",
      sequence: "0",
      calls: [{ target: account as `0x${string}`, value: "1", data: "0x" as const }],
      gas: {
        callGasLimit: "100000",
        verificationGasLimit: "300000",
        preVerificationGas: "50000",
        maxFeePerGas: "1000000000",
        maxPriorityFeePerGas: "100000000",
      },
    };
    const approval = await approveKernelV33Permission({
      owner: ecdsaKey({ account: owner, validator }),
      runtime,
      account: bound,
      nonce: "1",
    });
    return { runtime, input, approval, sign, session };
  }

  it("prepares enable without signing and refuses standard operations at the approval boundary", async () => {
    const { runtime, input, approval, sign } = await sessionFixture();
    const bound = bindKernelV33PermissionApproval({
      runtime,
      approval,
      account: input.account.account,
    });
    const prepared = bound.prepareOperation(input);
    expect(sign).not.toHaveBeenCalled();
    expect(bound.dummySignature.length > runtime.dummySignature.length).toBe(true);
    await expect(bound.signOperation(runtime.prepareOperation(input))).rejects.toMatchObject({
      code: "kernel_runtime_binding_mismatch",
    });
    expect(sign).not.toHaveBeenCalled();
    const signature = await bound.signOperation(prepared);
    expect(sign).toHaveBeenCalledTimes(1);
    const { kind: _kind, ...oneShot } = input;
    const materialized = await materializeKernelV33Permission({ ...oneShot, runtime, approval });
    expect(signature === materialized.signature).toBe(true);
    expect(prepared.userOperationHash).toBe(materialized.prepared.userOperationHash);
  });

  it("binds a Grant approval to the account version and existing address", async () => {
    const { approval } = await sessionFixture();
    const profile = {
      version: "oaath.kernel-existing-account-profile/v3",
      kind: "kernel",
      kernelVersion: "0.3.3",
      address: account,
      entryPoint: { version: "0.7" },
      ownerCredential: {
        version: "oaath.owner-credential-profile/v1",
        kind: "ecdsa",
        address: account,
      },
    } as const;
    const captured = parseKernelGrantApproval(JSON.parse(JSON.stringify(approval)), profile);
    expect(kernelGrantCapabilityHash(captured) === kernelGrantCapabilityHash(approval)).toBe(true);
    expect(() => parseKernelGrantApproval(approval, { ...profile, address: validator })).toThrow();
    expect(() =>
      parseKernelGrantApproval(approval, {
        ...profile,
        version: "oaath.kernel-account-profile/v1",
        kernelVersion: "0.4.0",
        accountIndex: "0",
        factoryRoute: "kernel_factory",
      }),
    ).toThrow();
    expect(
      kernelGrantCapabilityHash({ ...approval, enableSignature: "0x01" }) ===
        kernelGrantCapabilityHash(approval),
    ).toBe(false);
  });

  it("enables with an all-chain approval while preserving the actual operation identity", async () => {
    const { runtime, input, approval, sign } = await sessionFixture();
    const { kind: _kind, ...materializationInput } = input;
    const enabled = await materializeKernelV33Permission({
      ...materializationInput,
      runtime,
      approval,
    });
    expect(BigInt(enabled.prepared.userOperation.nonce) >> 248n).toBe(1n);
    expect(enabled.prepared.userOperation.verificationGasLimit).toBe("2000000");
    expect(approval).toMatchObject({
      version: "oaath.kernel.v33-permission-approval/v2",
      chainScope: "all",
    });
    expect(Object.hasOwn(approval, "chainId")).toBe(false);
    const signingHash = kernelOperationSigningHash({
      deployment: kernelV33Deployment(143),
      operation: enabled.prepared,
    });
    expect(signingHash).not.toBe(enabled.prepared.userOperationHash);
    expect(sign).toHaveBeenNthCalledWith(1, { hash: signingHash });
    const anotherChain = prepareUserOperation({
      kind: enabled.prepared.kind,
      grantId: enabled.prepared.grantId,
      chainId: 480,
      entryPoint: enabled.prepared.entryPoint,
      userOperation: enabled.prepared.userOperation,
    });
    expect(anotherChain.userOperationHash).not.toBe(enabled.prepared.userOperationHash);
    expect(deriveOperationId(anotherChain, null)).not.toEqual(
      deriveOperationId(enabled.prepared, null),
    );
    expect(
      kernelOperationSigningHash({ deployment: kernelV33Deployment(143), operation: anotherChain }),
    ).toBe(signingHash);
    const standard = runtime.prepareOperation(input);
    expect(BigInt(standard.userOperation.nonce) >> 248n).toBe(0n);
    expect(standard.userOperation.verificationGasLimit).toBe("300000");
    const signature = await runtime.signOperation(standard);
    expect(signature.startsWith("0xff")).toBe(true);
    expect(signature.length).toBe(134);
    expect(
      kernelOperationSigningHash({ deployment: kernelV33Deployment(143), operation: standard }),
    ).toBe(standard.userOperationHash);
    expect(sign).toHaveBeenCalledTimes(2);
    expect(parseKernelV33PermissionApproval(JSON.parse(JSON.stringify(approval)))).toEqual(
      approval,
    );
  });

  it("rejects approval reassociation and v4 enable mode before session signing", async () => {
    const { runtime, input, approval, sign } = await sessionFixture();
    const { kind: _kind, ...materializationInput } = input;
    for (const altered of [
      { ...approval, chainId: 480 },
      { ...approval, nonce: "2" },
      { ...approval, permissionId: "0x12345678" as const },
    ]) {
      await expect(
        materializeKernelV33Permission({ ...materializationInput, runtime, approval: altered }),
      ).rejects.toThrow();
    }
    const { version: _version, digest: _digest, enableSignature: _signature, ...scope } = approval;
    const otherAccount = { ...scope, account: validator as `0x${string}` };
    await expect(
      materializeKernelV33Permission({
        ...materializationInput,
        runtime,
        approval: {
          ...approval,
          account: validator,
          digest: hashTypedData(kernelV33PermissionEnableTypedData(otherAccount)),
        },
      }),
    ).rejects.toMatchObject({ code: "kernel_runtime_binding_mismatch" });
    expect(() =>
      runtime.prepareOperation({ ...input, mode: "enable-replayable" } as never),
    ).toThrow();
    const enabled = runtime.prepareOperation({ ...input, mode: "enable" });
    const lowGas = prepareUserOperation({
      kind: enabled.kind,
      grantId: enabled.grantId,
      chainId: enabled.chainId,
      entryPoint: enabled.entryPoint,
      userOperation: { ...enabled.userOperation, verificationGasLimit: "1" },
    });
    await expect(runtime.signOperation(lowGas)).rejects.toThrow();
    expect(sign).not.toHaveBeenCalled();
  });

  it("verifies external enable signatures against the replayable digest only", async () => {
    const { runtime, input, session, sign, approval } = await sessionFixture();
    const prepared = runtime.prepareOperation({ ...input, mode: "enable" });
    await expect(
      runtime.encodeVerifiedSignature(
        prepared,
        await session.sign({ hash: prepared.userOperationHash }),
      ),
    ).rejects.toMatchObject({ code: "kernel_runtime_signature_invalid" });
    expect(
      await runtime.encodeVerifiedSignature(
        prepared,
        await session.sign({ hash: kernelV33OperationSigningHash(prepared) }),
      ),
    ).toMatch(/^0xff/u);
    expect(sign).not.toHaveBeenCalled();
    expect(() =>
      parseKernelV33PermissionApproval({
        ...approval,
        version: "oaath.kernel.v33-permission-approval/v1",
      }),
    ).toThrow();
  });

  it("verifies an approval offline against the reviewed scope and types each mismatch", async () => {
    const owner = privateKeyToAccount(generatePrivateKey());
    const session = privateKeyToAccount(generatePrivateKey());
    const { read } = fixture();
    const runtime = createKernelRuntime({
      deployment: kernelV33Deployment(143),
      operator: sessionOperator({
        key: ecdsaKey({ account: session, validator }),
        policies: [
          {
            kind: "call",
            permissions: [{ target: account, selector: "0x00000000", valueLimit: "5" }],
          },
          { kind: "rate-limit", intervalSeconds: "86400", maximumOperations: "25" },
        ],
      }),
      reads: { read },
    });
    const original = read.getMockImplementation()!;
    read.mockImplementation(async (request) =>
      request.type === "runtime_code_hash" && request.address === OAATH_KERNEL_RATE_LIMIT_POLICY
        ? OAATH_KERNEL_RATE_LIMIT_POLICY_RUNTIME_CODE_HASH
        : original(request),
    );
    const bound = await runtime.bindAccount({ address: account });
    const approval = await approveKernelV33Permission({
      owner: ecdsaKey({ account: owner, validator }),
      runtime,
      account: bound,
      nonce: "1",
    });
    read.mockClear();
    const signer = runtime.packages.at(-1)!;
    const policies = runtime.packages.slice(0, -1);
    expect(policies).toHaveLength(2);
    const expected: KernelV33ExpectedPermission = {
      owner: owner.address,
      account,
      permissionId: approval.permissionId,
      sessionKey: {
        module: signer.module,
        publicMaterial: session.address.toLowerCase() as `0x${string}`,
      },
      packages: runtime.packages,
    };
    const wire = JSON.parse(JSON.stringify(approval));
    expect(await verifyKernelPermissionApproval({ approval: wire, expected })).toEqual({
      status: "verified",
      binding: { approval, owner: owner.address.toLowerCase() },
    });

    const other = privateKeyToAccount(generatePrivateKey());
    const cases: [Record<string, unknown>, string, string][] = [
      [{ owner: other.address }, "enableSignature", "wrong_signer"],
      [{ account: validator }, "account", "different"],
      [{ permissionId: "0x12345678" }, "permissionId", "different"],
      [
        { sessionKey: { module: signer.module, publicMaterial: other.address.toLowerCase() } },
        "sessionKey",
        "different",
      ],
      [
        { sessionKey: { module: validator, publicMaterial: session.address.toLowerCase() } },
        "sessionKey",
        "different",
      ],
      [{ packages: [...policies].reverse().concat(signer) }, "packages", "reordered"],
      [{ packages: [policies[0], signer] }, "packages", "different"],
    ];
    for (const [change, field, reason] of cases) {
      expect(
        await verifyKernelPermissionApproval({
          approval: wire,
          expected: { ...expected, ...change } as never,
        }),
      ).toEqual({ status: "mismatch", field, reason });
    }

    // Re-hashed scope keeps the old signature: well-formed, but not the owner's.
    const { version: _v, digest: _d, enableSignature, ...scope } = approval;
    const nonce2 = { ...scope, nonce: "2" };
    const rehashed = {
      ...approval,
      nonce: "2",
      digest: hashTypedData(kernelV33PermissionEnableTypedData(nonce2)),
    };
    expect(await verifyKernelPermissionApproval({ approval: rehashed, expected })).toEqual({
      status: "mismatch",
      field: "enableSignature",
      reason: "wrong_signer",
    });
    const flipped = `${enableSignature.slice(0, -2)}${enableSignature.endsWith("1b") ? "1c" : "1b"}`;
    expect(
      await verifyKernelPermissionApproval({
        approval: { ...approval, enableSignature: flipped },
        expected,
      }),
    ).toMatchObject({ status: "mismatch", field: "enableSignature" });
    expect(
      await verifyKernelPermissionApproval({
        approval: { ...approval, enableSignature: `0x${"11".repeat(64)}` },
        expected,
      }),
    ).toEqual({ status: "mismatch", field: "enableSignature", reason: "unrecoverable" });

    expect(
      await verifyKernelPermissionApproval({
        approval: { version: "oaath.kernel.all-chain-approval/v1" },
        expected,
      }),
    ).toEqual({ status: "mismatch", field: "version", reason: "unsupported" });
    await expect(
      verifyKernelPermissionApproval({ approval: { ...approval, nonce: "2" }, expected }),
    ).rejects.toMatchObject({ code: "kernel_runtime_input_invalid" });
    await expect(
      verifyKernelPermissionApproval({
        approval: wire,
        expected: { ...expected, accountIndex: "0" } as never,
      }),
    ).rejects.toMatchObject({ code: "kernel_runtime_input_invalid" });
    expect(read).not.toHaveBeenCalled();
  });

  it("does not invent a nonce from unavailable or malformed chain evidence", async () => {
    const { runtime, input } = await sessionFixture();
    for (const result of [undefined, null, "0", "4294967296", "01"]) {
      await expect(
        kernelV33PermissionInstallNonce({
          runtime,
          account: input.account,
          reads: { read: async () => result },
        }),
      ).rejects.toThrow();
    }
    await expect(
      kernelV33PermissionInstallNonce({
        runtime,
        account: input.account,
        reads: {
          read: async () => {
            throw new Error("private provider diagnostic");
          },
        },
      }),
    ).rejects.toMatchObject({
      code: "kernel_runtime_read_unavailable",
      message: "Kernel v3.3 validation nonce could not be read",
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
