import {
  type Address,
  concatHex,
  encodeFunctionData,
  getAddress,
  getContractAddress,
  type Hex,
  keccak256,
  parseAbi,
  recoverAddress,
  toHex,
  zeroAddress,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { describe, expect, it, vi } from "vitest";
import { createKernelRuntime } from "../src/kernel/create-kernel-runtime.js";
import { kernelV33Deployment } from "../src/kernel/deployment/v33.js";
import { ecdsaKey } from "../src/kernel/key/ecdsa.js";
import { ownerOperator } from "../src/kernel/operator/owner.js";
import { sessionOperator } from "../src/kernel/operator/session.js";
import { bindKernelAccount, deriveKernelAccount, kernelDeployment } from "../src/kernel.js";
import {
  KERNEL_V4_ENTRY_POINT_V07,
  KERNEL_V4_ENTRY_POINT_V07_CODE_HASH,
} from "../src/kernel-v4.js";
import { prepareUserOperation } from "../src/prepared-user-operation.js";

/**
 * ZeroDev SDK cd7c05b53b6ae6bede7dfefe9e59fbddfadf0c0a, transcribed:
 * `KernelVersionToAddressesMap["0.3.3"]` (packages/core/constants.ts), the ECDSA
 * validator for ">=0.3.1" (plugins/ecdsa/constants.ts), `initCodeHashV0_7` and
 * `generateSaltForV07` (plugins/ecdsa/getAddress.ts), and the MetaFactory
 * `deployWithFactory` init code (createKernelAccount.ts `getAccountInitCode`).
 */
const zeroDev = {
  accountImplementationAddress: "0xd6CEDDe84be40893d153Be9d467CD6aD37875b28",
  factoryAddress: "0x2577507b78c2008Ff367261CB6285d44ba5eF2E9",
  metaFactoryAddress: "0xd703aaE79538628d27099B8c4f621bE4CCd142d5",
  initCodeHash: "0xc452397f1e7518f8cea0566ac057e243bb1643f6298aba8eec8cdee78ee3b3dd",
  ecdsaValidator: "0x845ADb2C711129d4f3966735eD98a9F09fC4cE57",
} as const;
const zeroDevAbi = parseAbi([
  "function initialize(bytes21 _rootValidator, address hook, bytes validatorData, bytes hookData, bytes[] initConfig)",
  "function deployWithFactory(address factory, bytes createData, bytes32 salt) payable returns (address)",
]);

function zeroDevInitCodeHash(implementation: Address): Hex {
  return keccak256(
    concatHex([
      "0x603d3d8160223d3973",
      implementation,
      "0x6009",
      "0x5155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076",
      "0xcc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3",
    ]),
  );
}

function zeroDevAccount(eoaAddress: Address, index: bigint) {
  const initData = encodeFunctionData({
    abi: zeroDevAbi,
    functionName: "initialize",
    args: [concatHex(["0x01", zeroDev.ecdsaValidator]), zeroAddress, eoaAddress, "0x", []],
  });
  return {
    address: getContractAddress({
      bytecodeHash: zeroDev.initCodeHash,
      opcode: "CREATE2",
      from: zeroDev.factoryAddress,
      salt: keccak256(concatHex([initData, toHex(index, { size: 32 })])),
    }),
    factory: zeroDev.metaFactoryAddress,
    factoryData: encodeFunctionData({
      abi: zeroDevAbi,
      functionName: "deployWithFactory",
      args: [zeroDev.factoryAddress, initData, toHex(index, { size: 32 })],
    }),
  };
}

const deployment = kernelV33Deployment(143);

describe("counterfactual Kernel 0.3.3 derivation", () => {
  it("pins ZeroDev's 0.3.3 addresses and proxy init code hash", () => {
    expect(zeroDevInitCodeHash(zeroDev.accountImplementationAddress)).toBe(zeroDev.initCodeHash);
    expect(deployment).toMatchObject({
      implementation: zeroDev.accountImplementationAddress.toLowerCase(),
      factory: zeroDev.factoryAddress.toLowerCase(),
      metaFactory: zeroDev.metaFactoryAddress.toLowerCase(),
      ecdsaValidator: zeroDev.ecdsaValidator.toLowerCase(),
    });
  });

  it.each([
    ["0x1111111111111111111111111111111111111111", 0n],
    ["0x70997970C51812dc3A010C7d01b50e0d17dc79C8", 1n],
    ["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", 7n],
    [privateKeyToAccount(generatePrivateKey()).address, (1n << 256n) - 1n],
  ] as const)("matches ZeroDev's address and factory data for %s at index %s", (owner, index) => {
    const expected = zeroDevAccount(owner, index);
    const derived = deriveKernelAccount({ deployment, owner, accountIndex: index.toString(10) });
    expect(derived).toEqual({
      address: expected.address.toLowerCase(),
      factory: expected.factory.toLowerCase(),
      factoryData: expected.factoryData.toLowerCase(),
    });
    expect(Object.isFrozen(derived)).toBe(true);
    // One address on every chain; the index is the account's identity.
    expect(
      deriveKernelAccount({
        deployment: kernelV33Deployment(8453),
        owner: owner.toLowerCase() as Hex,
        accountIndex: index.toString(10),
      }),
    ).toEqual(derived);
  });

  it("refuses malformed input and Kernel 0.4.0 offline derivation", () => {
    const owner = "0x1111111111111111111111111111111111111111";
    for (const input of [
      { deployment, owner, accountIndex: "01" },
      { deployment, owner, accountIndex: (1n << 256n).toString(10) },
      { deployment, owner: zeroAddress, accountIndex: "0" },
      { deployment, owner, accountIndex: "0", index: "0" },
    ])
      expect(() => deriveKernelAccount(input as never)).toThrowError(
        expect.objectContaining({ code: "kernel_runtime_input_invalid" }),
      );
    expect(() =>
      deriveKernelAccount({
        deployment: kernelDeployment({ chainId: 143 }),
        owner,
        accountIndex: "0",
      }),
    ).toThrowError(expect.objectContaining({ code: "kernel_runtime_unsupported" }));
  });
});

function routeReads(owner: Hex, accountIndex = "0") {
  const derived = deriveKernelAccount({ deployment, owner, accountIndex });
  const read = vi.fn(async (request: Record<string, unknown>): Promise<unknown> => {
    switch (request.type) {
      case "chain_id":
        return 143;
      case "code":
        return request.address === derived.address ? "0x" : "0x6000";
      case "runtime_code_hash":
        if (request.address === deployment.entryPoint.address)
          return KERNEL_V4_ENTRY_POINT_V07_CODE_HASH;
        if (request.address === deployment.factory) return deployment.factoryRuntimeCodeHash;
        if (request.address === deployment.metaFactory)
          return deployment.metaFactoryRuntimeCodeHash;
        return undefined;
      case "kernel_v33_factory_approval":
        expect(request).toMatchObject({
          metaFactory: deployment.metaFactory,
          factory: deployment.factory,
        });
        return true;
      default:
        throw new Error("unexpected read");
    }
  });
  return { derived, read };
}

describe("counterfactual Kernel 0.3.3 binding", () => {
  const owner = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8" as const;

  it("binds the derived address after proving the MetaFactory route", async () => {
    const { derived, read } = routeReads(owner, "3");
    const bound = await bindKernelAccount({
      chainId: 143,
      owner,
      accountIndex: "3",
      deployment,
      reads: { read },
    });
    expect(bound).toEqual({
      profile: "kernel-v3.3-entrypoint-v0.7",
      version: "0.3.3",
      state: "counterfactual",
      chainId: 143,
      account: derived.address,
      entryPoint: KERNEL_V4_ENTRY_POINT_V07,
      implementation: deployment.implementation,
      rootValidator: `0x01${deployment.ecdsaValidator.slice(2)}`,
      owner,
      accountIndex: "3",
      factory: deployment.metaFactory,
      factoryData: derived.factoryData,
    });
    expect(Object.isFrozen(bound)).toBe(true);
  });

  it.each([
    ["chain", "chain_id", null, 1],
    ["implementation code", "code", deployment.implementation, "0x"],
    ["validator code", "code", deployment.ecdsaValidator, "0x"],
    ["factory code", "runtime_code_hash", deployment.factory, `0x${"00".repeat(32)}`],
    ["MetaFactory code", "runtime_code_hash", deployment.metaFactory, undefined],
    ["EntryPoint code", "runtime_code_hash", deployment.entryPoint.address, undefined],
    ["factory approval", "kernel_v33_factory_approval", null, false],
  ] as const)("fails closed on %s drift", async (_label, type, address, value) => {
    const { read } = routeReads(owner);
    const original = read.getMockImplementation()!;
    read.mockImplementation(async (request) =>
      request.type === type && (address === null || request.address === address)
        ? value
        : original(request),
    );
    await expect(
      bindKernelAccount({ chainId: 143, owner, accountIndex: "0", deployment, reads: { read } }),
    ).rejects.toMatchObject({ code: "kernel_runtime_binding_mismatch" });
  });

  it("binds a deployed derived address as an existing account and refuses another implementation", async () => {
    const { derived, read } = routeReads(owner);
    const original = read.getMockImplementation()!;
    read.mockImplementation(async (request) =>
      request.type === "code"
        ? "0x6000"
        : request.type === "kernel_account_implementation"
          ? "0x3c504000d05c1e28687f70fca40a76f7ddda9952"
          : original(request),
    );
    await expect(
      bindKernelAccount({ chainId: 143, owner, accountIndex: "0", deployment, reads: { read } }),
    ).rejects.toMatchObject({ code: "kernel_runtime_binding_mismatch" });
    expect(read).toHaveBeenCalledWith(
      expect.objectContaining({ type: "kernel_account_implementation", account: derived.address }),
    );
    expect(
      read.mock.calls.some(([request]) => request.type === "kernel_v33_factory_approval"),
    ).toBe(false);
  });

  it("requires the explicit 0.3.3 deployment", async () => {
    const { read } = routeReads(owner);
    const input = { chainId: 143, owner, accountIndex: "0", reads: { read } };
    await expect(bindKernelAccount(input as never)).rejects.toMatchObject({
      code: "kernel_runtime_input_invalid",
    });
    await expect(
      bindKernelAccount({ ...input, deployment: kernelDeployment({ chainId: 143 }) }),
    ).rejects.toMatchObject({ code: "kernel_runtime_unsupported" });
    expect(read).not.toHaveBeenCalled();
  });
});

describe("counterfactual Kernel 0.3.3 activation through the runtime", () => {
  const gas = {
    callGasLimit: "100000",
    verificationGasLimit: "1000000",
    preVerificationGas: "50000",
    maxFeePerGas: "1000000000",
    maxPriorityFeePerGas: "100000000",
  };
  const calls = [
    {
      target: "0x1111111111111111111111111111111111111111" as const,
      value: "0",
      data: "0x" as const,
    },
  ];

  it("prepares the deploying operation for the owner's own account and signs it", async () => {
    const owner = privateKeyToAccount(generatePrivateKey());
    const { derived, read } = routeReads(owner.address.toLowerCase() as Hex, "2");
    const sign = vi.fn(owner.sign);
    const runtime = createKernelRuntime({
      deployment,
      operator: ownerOperator({
        key: ecdsaKey({
          account: { address: owner.address, sign },
          validator: deployment.ecdsaValidator,
        }),
      }),
      reads: { read },
    });
    const account = await runtime.bindAccount({ accountIndex: "2" });
    expect(account).toMatchObject({ state: "counterfactual", account: derived.address });
    const input = {
      account,
      kind: "execution" as const,
      grantId: "activation",
      nonceKey: "0",
      sequence: "0",
      calls,
      gas,
    };
    const operation = runtime.prepareOperation(input);
    expect(operation.entryPoint).toEqual({ version: "0.7", address: KERNEL_V4_ENTRY_POINT_V07 });
    expect(operation.userOperation).toMatchObject({
      sender: derived.address,
      factory: { address: deployment.metaFactory, data: derived.factoryData },
    });
    const signature = await runtime.signOperation(operation);
    expect(await recoverAddress({ hash: operation.userOperationHash, signature })).toBe(
      getAddress(owner.address),
    );
    // Another factory route or no deployment is never signed for this sender.
    for (const factory of [
      null,
      { address: deployment.factory, data: derived.factoryData },
      { address: deployment.metaFactory, data: `${derived.factoryData}00` as Hex },
    ]) {
      const changed = prepareUserOperation({
        kind: operation.kind,
        grantId: operation.grantId,
        chainId: operation.chainId,
        entryPoint: operation.entryPoint,
        userOperation: { ...operation.userOperation, factory },
      });
      await expect(runtime.signOperation(changed)).rejects.toMatchObject({
        code: "kernel_runtime_binding_mismatch",
      });
    }
    expect(sign).toHaveBeenCalledTimes(1);
  });

  it("refuses to derive a session account", async () => {
    const owner = privateKeyToAccount(generatePrivateKey());
    const { read } = routeReads(owner.address.toLowerCase() as Hex);
    const runtime = createKernelRuntime({
      deployment,
      operator: sessionOperator({
        key: ecdsaKey({
          account: privateKeyToAccount(generatePrivateKey()),
          validator: deployment.ecdsaValidator,
        }),
        policies: [
          {
            kind: "call",
            permissions: [
              {
                target: "0x1111111111111111111111111111111111111111",
                selector: "0x00000000",
                valueLimit: "0",
              },
            ],
          },
        ],
      }),
      reads: { read },
    });
    await expect(runtime.bindAccount({ accountIndex: "0" })).rejects.toMatchObject({
      code: "kernel_runtime_unsupported",
    });
    expect(read).not.toHaveBeenCalled();
  });
});
