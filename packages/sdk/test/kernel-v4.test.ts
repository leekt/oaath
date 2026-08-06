import {
  concat,
  decodeAbiParameters,
  decodeFunctionData,
  encodeAbiParameters,
  getAddress,
  keccak256,
  pad,
  toHex,
} from "viem";
import { describe, expect, it } from "vitest";
import {
  bindKernelV4Account,
  createKernelV4Reads,
  encodeKernelV4EnableSignature,
  encodeKernelV4Execution,
  encodeKernelV4FactoryAddressRead,
  encodeKernelV4FactoryDeploy,
  encodeKernelV4FactoryImplementationRead,
  encodeKernelV4Initialize,
  encodeKernelV4InstallModules,
  encodeKernelV4Nonce,
  encodeKernelV4NonceKey,
  encodeKernelV4NonceRead,
  encodeKernelV4PermissionSignature,
  encodeKernelV4PermissionUninstallCalls,
  encodeKernelV4PolicyData,
  encodeKernelV4SignerData,
  encodeKernelV4ValidatorData,
  KERNEL_V4_CREATE2_DEPLOYER,
  KERNEL_V4_ENTRY_POINT_V07,
  KERNEL_V4_ENTRY_POINT_V07_CODE_HASH,
  KERNEL_V4_EXECUTE_SELECTOR,
  KERNEL_V4_FACTORY_V07,
  KERNEL_V4_FACTORY_V07_CODE_HASH,
  KERNEL_V4_IMPLEMENTATION_SLOT,
  KERNEL_V4_UUPS_IMPLEMENTATION_V07,
  type KernelV4AccountReadRequest,
  type KernelV4Install,
  kernelV4Deployment,
  prepareKernelV4UserOperation,
} from "../src/kernel-v4.js";
import { parsePreparedUserOperation } from "../src/prepared-user-operation.js";

const validator = `0x${"22".repeat(20)}` as const;
const hook = `0x${"33".repeat(20)}` as const;
const target = `0x${"44".repeat(20)}` as const;
const factory = KERNEL_V4_FACTORY_V07;
const account = `0x${"66".repeat(20)}` as const;
const permissionId = "0xaabbccdd" as const;
const selector = "0x12345678" as const;

function runtimeCodeHash(address: `0x${string}`): `0x${string}` {
  if (address === KERNEL_V4_ENTRY_POINT_V07) return KERNEL_V4_ENTRY_POINT_V07_CODE_HASH;
  if (address === KERNEL_V4_UUPS_IMPLEMENTATION_V07) {
    return kernelV4Deployment(421_614).implementationDeployment.runtimeCodeHash;
  }
  return KERNEL_V4_FACTORY_V07_CODE_HASH;
}

const baseInstall: KernelV4Install = Object.freeze({
  moduleType: 1,
  module: validator,
  moduleData: "0x1234",
  internalData: encodeKernelV4ValidatorData({ hook: "none", selectors: [] }),
});
const installs = Object.freeze([baseInstall]) satisfies readonly KernelV4Install[];

const installComponents = [
  { name: "moduleType", type: "uint256" },
  { name: "module", type: "address" },
  { name: "moduleData", type: "bytes" },
  { name: "internalData", type: "bytes" },
] as const;

const factoryAbi = [
  {
    type: "function",
    name: "UUPS",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "address" }],
  },
  {
    type: "function",
    name: "getAddress",
    stateMutability: "view",
    inputs: [
      { name: "packages", type: "tuple[]", components: installComponents },
      { name: "nonce", type: "uint256" },
    ],
    outputs: [{ type: "address" }],
  },
  {
    type: "function",
    name: "deploy",
    stateMutability: "payable",
    inputs: [
      { name: "packages", type: "tuple[]", components: installComponents },
      { name: "nonce", type: "uint256" },
    ],
    outputs: [{ type: "address" }],
  },
] as const;

const kernelAbi = [
  {
    type: "function",
    name: "initialize",
    stateMutability: "payable",
    inputs: [{ name: "packages", type: "tuple[]", components: installComponents }],
    outputs: [],
  },
  {
    type: "function",
    name: "installModule",
    stateMutability: "payable",
    inputs: [{ name: "packages", type: "tuple[]", components: installComponents }],
    outputs: [],
  },
  {
    type: "function",
    name: "execute",
    stateMutability: "payable",
    inputs: [
      { name: "mode", type: "bytes32" },
      { name: "executionData", type: "bytes" },
    ],
    outputs: [],
  },
] as const;

const uninstallAbi = [
  {
    type: "function",
    name: "uninstallModule",
    stateMutability: "payable",
    inputs: [
      { name: "moduleType", type: "uint256" },
      { name: "module", type: "address" },
      { name: "initData", type: "bytes" },
    ],
    outputs: [],
  },
] as const;

// Hostile-input probes bypass the typed public surface on purpose: they prove
// the runtime capture layer, which must not trust compile-time types.
const asHostile = <R>(fn: (value: never) => R) => fn as (value: unknown) => R;

describe("Kernel v4 deployment profile", () => {
  it.each([
    [
      421_614,
      "arbitrum-sepolia",
      "0xa63c36c76b536b1c11d75c68ac5ca15d4ce2c09a40e90ab29ff6601b4bdb0d33",
      "0xd0c42b1ed1738560c1b243fd9e5fc04b2eb5aa1be9962ac7f1f61696f9e6902b",
    ],
    [
      11_155_111,
      "ethereum-sepolia",
      "0x54528619ceafbcc656a7d0f7b637213f38d2fbe013a0e2909cfa3fef6dca7cc0",
      "0xb1f85627093213ec87a1484b6af7192651f4dbd6c5f9e9c0aff22e332c5ddb01",
    ],
    [
      46_630,
      "robinhood-sepolia",
      "0xf662be20e4e8d3b0fcfb7bd08845ea89b45977d82aa315cb78530f013f4f2782",
      "0xaef18d8059fa2474272125891050e2e755f45db00c2668b45b7062b2a9579be0",
    ],
  ] as const)(
    "binds chain %i to the sole UUPS / EntryPoint 0.7 profile",
    (chainId, chain, transactionHash, runtimeCodeHash) => {
      const deployment = kernelV4Deployment(chainId);
      expect(deployment).toEqual({
        profile: "kernel-v4-uups-entrypoint-v0.7",
        kernelVersion: "0.4.0",
        accountType: "uups",
        chainId,
        chain,
        entryPoint: { version: "0.7", address: KERNEL_V4_ENTRY_POINT_V07 },
        implementation: KERNEL_V4_UUPS_IMPLEMENTATION_V07,
        factory: KERNEL_V4_FACTORY_V07,
        implementationDeployment: {
          deployer: KERNEL_V4_CREATE2_DEPLOYER,
          transactionHash,
          runtimeCodeHash,
        },
      });
      expect(Object.isFrozen(deployment)).toBe(true);
      expect(Object.isFrozen(deployment.entryPoint)).toBe(true);
      expect(Object.isFrozen(deployment.implementationDeployment)).toBe(true);
    },
  );

  it.each([1, 11_155_110, 46_631, "421614", Number.NaN])(
    "rejects unsupported or non-canonical chain %s",
    (chainId) => {
      expect(() => kernelV4Deployment(chainId)).toThrowError(
        expect.objectContaining({
          name: "OaathKernelV4Error",
          code: "kernel_v4_chain_unsupported",
        }),
      );
    },
  );
});

describe("Kernel v4 module and account codecs", () => {
  it("encodes native validator, policy, and signer internal data", () => {
    expect(encodeKernelV4ValidatorData({ hook: "none", selectors: [selector] })).toBe(
      `0x${"00".repeat(19)}01${selector.slice(2)}`,
    );
    expect(encodeKernelV4ValidatorData({ hook, selectors: [] })).toBe(hook);
    expect(encodeKernelV4PolicyData(permissionId)).toBe(permissionId);
    expect(encodeKernelV4SignerData({ permissionId, hook: "none", selectors: [selector] })).toBe(
      `${permissionId}${"00".repeat(19)}01${selector.slice(2)}`,
    );
  });

  it("encodes the exact UUPS factory reads, counterfactual address, and deploy call", () => {
    expect(
      decodeFunctionData({ abi: factoryAbi, data: encodeKernelV4FactoryImplementationRead() }),
    ).toEqual({ functionName: "UUPS" });

    const input = { initialPackages: installs, accountIndex: "7" };
    const addressRead = decodeFunctionData({
      abi: factoryAbi,
      data: encodeKernelV4FactoryAddressRead(input),
    });
    const deploy = decodeFunctionData({
      abi: factoryAbi,
      data: encodeKernelV4FactoryDeploy(input),
    });
    expect(addressRead.functionName).toBe("getAddress");
    expect(addressRead.args?.[1]).toBe(7n);
    expect(deploy.functionName).toBe("deploy");
    expect(deploy.args?.[0]).toEqual([
      {
        moduleType: 1n,
        module: validator,
        moduleData: "0x1234",
        internalData: `0x${"00".repeat(19)}01`,
      },
    ]);
  });

  it("encodes initialize and post-deployment batch install without translating v3 permissions", () => {
    expect(
      decodeFunctionData({ abi: kernelAbi, data: encodeKernelV4Initialize(installs) }).functionName,
    ).toBe("initialize");
    expect(
      decodeFunctionData({ abi: kernelAbi, data: encodeKernelV4InstallModules(installs) })
        .functionName,
    ).toBe("installModule");
  });

  it.each([
    [{ ...installs[0], legacyValidationId: `0x${"00".repeat(21)}` }],
    [{ ...installs[0], moduleType: 7 }],
    [{ ...installs[0], moduleType: 2 }],
    [{ ...installs[0], module: validator.toUpperCase() }],
    [{ ...installs[0], internalData: "0x0" }],
  ])("rejects malformed, legacy, or ambiguous install packages", (packages) => {
    expect(() => asHostile(encodeKernelV4Initialize)(packages)).toThrowError(
      expect.objectContaining({ code: "kernel_v4_input_invalid" }),
    );
  });

  it("captures data properties once and rejects accessors before encoding", () => {
    const hostile = { moduleType: 1, module: validator, moduleData: "0x", internalData: "0x" };
    Object.defineProperty(hostile, "moduleData", {
      enumerable: true,
      get: () => "0x",
    });
    expect(() => asHostile(encodeKernelV4Initialize)([hostile])).toThrowError(
      expect.objectContaining({ code: "kernel_v4_input_invalid" }),
    );
    const reflectionFailure = new Proxy([], {
      getPrototypeOf() {
        throw new Error("credential-bearing reflection detail");
      },
    });
    expect(() => encodeKernelV4Initialize(reflectionFailure)).toThrowError(
      expect.objectContaining({
        code: "kernel_v4_input_invalid",
        message: "Kernel initial packages is invalid",
      }),
    );
  });

  it("accepts checksummed addresses and captures them in canonical lowercase", () => {
    const checksummed = getAddress("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd");
    expect(encodeKernelV4Initialize([{ ...baseInstall, module: checksummed }])).toBe(
      encodeKernelV4Initialize([
        { ...baseInstall, module: checksummed.toLowerCase() as `0x${string}` },
      ]),
    );
  });

  it.each([
    [[{ ...installs[0], moduleType: 5, internalData: permissionId }]],
    [[{ ...installs[0], moduleType: 6, internalData: "0x01" }]],
    [
      [
        { ...installs[0], moduleType: 5, internalData: permissionId },
        { ...installs[0], moduleType: 6, internalData: "0x11223344" },
      ],
    ],
    [
      [
        {
          ...installs[0],
          moduleType: 6,
          internalData: encodeKernelV4SignerData({ permissionId, hook: "none", selectors: [] }),
        },
      ],
    ],
    [
      [
        {
          ...installs[0],
          moduleType: 6,
          internalData: encodeKernelV4SignerData({ permissionId, hook: "none", selectors: [] }),
        },
        {
          ...installs[0],
          moduleType: 6,
          internalData: encodeKernelV4SignerData({ permissionId, hook: "none", selectors: [] }),
        },
      ],
    ],
  ])("rejects incomplete or contradictory permission package sequences", (packages) => {
    expect(() => asHostile(encodeKernelV4InstallModules)(packages)).toThrowError(
      expect.objectContaining({ code: "kernel_v4_input_invalid" }),
    );
    expect(() => asHostile(encodeKernelV4Initialize)(packages)).toThrowError(
      expect.objectContaining({ code: "kernel_v4_input_invalid" }),
    );
  });

  it("requires every permission signer to follow its policy packages", () => {
    const policy: KernelV4Install = {
      ...baseInstall,
      moduleType: 5,
      internalData: encodeKernelV4PolicyData(permissionId),
    };
    const signer: KernelV4Install = {
      ...baseInstall,
      moduleType: 6,
      internalData: encodeKernelV4SignerData({ permissionId, hook: "none", selectors: [selector] }),
    };
    expect(encodeKernelV4InstallModules([policy, signer])).toMatch(/^0x/u);
  });

  it("derives reverse-ordered permission uninstall self-calls from the install packages", () => {
    const permissionPrefix = pad(permissionId, { size: 32, dir: "right" });
    const policyPackage = (module: `0x${string}`, policyData: `0x${string}`): KernelV4Install => ({
      moduleType: 5,
      module,
      moduleData: concat([permissionPrefix, policyData]),
      internalData: encodeKernelV4PolicyData(permissionId),
    });
    const policyA = policyPackage(`0x${"55".repeat(20)}`, "0x01");
    const policyB = policyPackage(`0x${"77".repeat(20)}`, "0x02");
    const signer: KernelV4Install = {
      moduleType: 6,
      module: `0x${"88".repeat(20)}`,
      moduleData: concat([permissionPrefix, "0x99"]),
      internalData: encodeKernelV4SignerData({ permissionId, hook: "none", selectors: [selector] }),
    };
    const calls = encodeKernelV4PermissionUninstallCalls({
      account,
      packages: [policyA, policyB, signer],
    });

    // Policies leave in reverse install order, the signer last — the order
    // Kernel's pop-last policy check and empty-policies signer check enforce.
    expect(calls.map((call) => call.target)).toEqual([account, account, account]);
    expect(calls.map((call) => call.value)).toEqual(["0", "0", "0"]);
    const decoded = calls.map((call) => decodeFunctionData({ abi: uninstallAbi, data: call.data }));
    expect(decoded.map((entry) => entry.args[1])).toEqual([
      getAddress(policyB.module),
      getAddress(policyA.module),
      getAddress(signer.module),
    ]);
    expect(decoded.map((entry) => entry.args[0])).toEqual([5n, 5n, 6n]);
    // initData is InstallModuleDataFormat(installData, internalData): the
    // permission-scoped 32-byte prefix of the install data, and the exact
    // internalData the install carried (permission ID in its first 4 bytes).
    for (const [index, source] of [policyB, policyA, signer].entries()) {
      const [installData, internalData] = decodeAbiParameters(
        [{ type: "bytes" }, { type: "bytes" }],
        decoded[index]?.args[2] as `0x${string}`,
      );
      expect(installData).toBe(permissionPrefix);
      expect(internalData).toBe(source.internalData);
      expect(internalData.slice(0, 10)).toBe(permissionId);
    }
  });

  it.each([
    [[baseInstall], "requires policy packages and exactly one signer"],
    [
      [
        {
          moduleType: 5,
          module: validator,
          moduleData: "0x1234",
          internalData: encodeKernelV4PolicyData(permissionId),
        },
        {
          moduleType: 6,
          module: validator,
          moduleData: concat([pad(permissionId, { size: 32, dir: "right" }), "0x99"]),
          internalData: encodeKernelV4SignerData({ permissionId, hook: "none", selectors: [] }),
        },
      ],
      "must carry the permission prefix",
    ],
  ])("rejects uninstall inputs that cannot express a complete permission", (packages, reason) => {
    expect(() =>
      asHostile((value: never) =>
        encodeKernelV4PermissionUninstallCalls({ account, packages: value }),
      )(packages),
    ).toThrowError(expect.objectContaining({ code: "kernel_v4_input_invalid" }));
    expect(() =>
      asHostile((value: never) =>
        encodeKernelV4PermissionUninstallCalls({ account, packages: value }),
      )(packages),
    ).toThrowError(new RegExp(reason, "u"));
  });
});

describe("Kernel v4 account binding", () => {
  function binding(overrides: Partial<Record<KernelV4AccountReadRequest["type"], unknown>> = {}) {
    const requests: KernelV4AccountReadRequest[] = [];
    const reads = {
      async read(request: KernelV4AccountReadRequest): Promise<unknown> {
        requests.push(request);
        if (request.type in overrides) return overrides[request.type];
        if (request.type === "chain_id") return request.chainId;
        if (request.type === "runtime_code_hash") return runtimeCodeHash(request.address);
        if (request.type === "code") return request.address === account ? "0x" : "0x01";
        if (request.type === "kernel_factory_implementation") {
          return KERNEL_V4_UUPS_IMPLEMENTATION_V07;
        }
        if (request.type === "kernel_factory_account") return account;
        return KERNEL_V4_UUPS_IMPLEMENTATION_V07;
      },
    };
    return {
      requests,
      input: { chainId: 421_614, initialPackages: installs, accountIndex: "7", reads },
    } as const;
  }

  it("binds a counterfactual account only after proving the exact factory implementation", async () => {
    const { input, requests } = binding();
    const descriptor = await bindKernelV4Account(input);
    expect(descriptor).toEqual({
      profile: "kernel-v4-uups-entrypoint-v0.7",
      state: "counterfactual",
      chainId: 421_614,
      entryPoint: KERNEL_V4_ENTRY_POINT_V07,
      implementation: KERNEL_V4_UUPS_IMPLEMENTATION_V07,
      factory,
      account,
      accountIndex: "7",
      initialPackages: installs,
      factoryAddressCalldata: encodeKernelV4FactoryAddressRead({
        initialPackages: installs,
        accountIndex: "7",
      }),
      factoryDeployCalldata: encodeKernelV4FactoryDeploy({
        initialPackages: installs,
        accountIndex: "7",
      }),
    });
    expect(Object.isFrozen(descriptor)).toBe(true);
    expect(requests.map((request) => request.type)).toEqual([
      "chain_id",
      "runtime_code_hash",
      "runtime_code_hash",
      "runtime_code_hash",
      "code",
      "kernel_factory_implementation",
      "kernel_factory_account",
      "code",
    ]);
  });

  it("accepts deployed state only after proving the account proxy implementation", async () => {
    const { input, requests } = binding({
      code: "0x01",
      kernel_account_implementation: KERNEL_V4_UUPS_IMPLEMENTATION_V07,
    });
    await expect(bindKernelV4Account(input)).resolves.toMatchObject({ state: "deployed" });
    expect(requests.at(-1)?.type).toBe("kernel_account_implementation");
  });

  it("rejects caller-selected factories instead of widening the deployment registry", async () => {
    const { input } = binding();
    await expect(
      asHostile(bindKernelV4Account)({ ...input, factory: target }),
    ).rejects.toMatchObject({
      code: "kernel_v4_input_invalid",
    });
  });

  it.each([
    ["wrong chain", { chain_id: 1 }],
    ["wrong runtime code", { runtime_code_hash: `0x${"ff".repeat(32)}` }],
    ["missing required module code", { code: "0x" }],
    ["wrong factory implementation", { kernel_factory_implementation: target }],
    ["wrong deployed implementation", { code: "0x01", kernel_account_implementation: target }],
  ] as const)("fails closed on %s evidence", async (_label, overrides) => {
    const { input } = binding(overrides);
    await expect(bindKernelV4Account(input)).rejects.toMatchObject({
      code: "kernel_v4_evidence_invalid",
    });
  });

  it("maps provider failure to a stable read-unavailable code without inspecting prose", async () => {
    const { input } = binding();
    const unavailable = {
      ...input,
      reads: {
        async read(): Promise<never> {
          throw new Error("credential-bearing provider detail");
        },
      },
    };
    await expect(bindKernelV4Account(unavailable)).rejects.toMatchObject({
      code: "kernel_v4_read_unavailable",
      message: "Kernel v4 account evidence is unavailable",
    });
  });
});

describe("Kernel v4 prepared UserOperation", () => {
  const gas = Object.freeze({
    callGasLimit: "100000",
    verificationGasLimit: "200000",
    preVerificationGas: "30000",
    maxFeePerGas: "4",
    maxPriorityFeePerGas: "2",
  });

  async function descriptor(state: "counterfactual" | "deployed") {
    const reads = {
      async read(request: KernelV4AccountReadRequest): Promise<unknown> {
        if (request.type === "chain_id") return request.chainId;
        if (request.type === "runtime_code_hash") return runtimeCodeHash(request.address);
        if (request.type === "code") {
          return request.address === account && state === "counterfactual" ? "0x" : "0x01";
        }
        if (request.type === "kernel_factory_implementation") {
          return KERNEL_V4_UUPS_IMPLEMENTATION_V07;
        }
        if (request.type === "kernel_factory_account") return account;
        return KERNEL_V4_UUPS_IMPLEMENTATION_V07;
      },
    };
    return bindKernelV4Account({
      chainId: 421_614,
      initialPackages: installs,
      accountIndex: "7",
      reads,
    });
  }

  it("binds a counterfactual factory deployment into the exact operation identity", async () => {
    const accountDescriptor = await descriptor("counterfactual");
    const prepared = prepareKernelV4UserOperation({
      kind: "execution",
      grantId: "kernel-v4-grant",
      account: accountDescriptor,
      nonce: { mode: "standard", validation: { kind: "root" }, nonceKey: "0", sequence: "0" },
      calls: [{ target, value: "5", data: "0xaabb" }],
      gas,
    });
    expect(prepared).toMatchObject({
      kind: "execution",
      grantId: "kernel-v4-grant",
      chainId: 421_614,
      entryPoint: { version: "0.7", address: KERNEL_V4_ENTRY_POINT_V07 },
      userOperation: {
        sender: account,
        nonce: "0",
        factory: { address: factory, data: accountDescriptor.factoryDeployCalldata },
        paymaster: null,
      },
    });
    expect(prepared.userOperationHash).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(prepared.userOperation.callData).toBe(
      encodeKernelV4Execution({ calls: [{ target, value: "5", data: "0xaabb" }] }),
    );
  });

  it("omits initCode only for a descriptor proven deployed", async () => {
    const prepared = prepareKernelV4UserOperation({
      kind: "revocation",
      grantId: "kernel-v4-grant",
      account: await descriptor("deployed"),
      nonce: {
        mode: "replayable",
        validation: { kind: "permission", permissionId },
        nonceKey: "9",
        sequence: "3",
      },
      calls: [{ target, value: "0", data: "0x1234" }],
      gas,
    });
    const key = BigInt(
      encodeKernelV4NonceKey({
        mode: "replayable",
        validation: { kind: "permission", permissionId },
        nonceKey: "9",
      }),
    );
    const execution = encodeKernelV4Execution({ calls: [{ target, value: "0", data: "0x1234" }] });
    expect(prepared.userOperation.factory).toBeNull();
    expect(prepared.userOperation.nonce).toBe(((key << 64n) | 3n).toString(10));
    // A permission installed with no hook allow-lists execute(bytes32,bytes) and
    // takes Kernel's fast path, which enforces the same allow-list on the outer
    // selector; its policy modules decode exactly this calldata.
    expect(prepared.userOperation.callData).toBe(execution);

    // A validator validation has no such fast path and routes through
    // executeUserOp, where Kernel checks the inner selector instead.
    expect(
      prepareKernelV4UserOperation({
        kind: "revocation",
        grantId: "kernel-v4-grant",
        account: await descriptor("deployed"),
        nonce: {
          mode: "replayable",
          validation: { kind: "validator", validator },
          nonceKey: "9",
          sequence: "3",
        },
        calls: [{ target, value: "0", data: "0x1234" }],
        gas,
      }).userOperation.callData,
    ).toBe(concat(["0x8dd7712f", execution]));
  });

  it("threads an optional paymaster into the exact operation identity", async () => {
    const accountDescriptor = await descriptor("deployed");
    const base = {
      kind: "execution" as const,
      grantId: "kernel-v4-grant",
      account: accountDescriptor,
      nonce: {
        mode: "standard" as const,
        validation: { kind: "root" as const },
        nonceKey: "0",
        sequence: "0",
      },
      calls: [{ target, value: "0", data: "0x" as const }],
      gas,
    };
    const paymaster = Object.freeze({
      address: `0x${"77".repeat(20)}` as const,
      verificationGasLimit: "60000",
      postOpGasLimit: "25000",
      data: "0xdeadbeef" as const,
    });

    const sponsored = prepareKernelV4UserOperation({ ...base, paymaster });
    // Round-trip: the exact fields survive preparation and re-parsing.
    expect(sponsored.userOperation.paymaster).toEqual(paymaster);
    expect(parsePreparedUserOperation(sponsored).userOperation.paymaster).toEqual(paymaster);

    // The hash covers the paymaster fields (viem packs paymasterAndData), so
    // sponsorship can never be attached or swapped after preparation.
    const unsponsored = prepareKernelV4UserOperation(base);
    const explicitNull = prepareKernelV4UserOperation({ ...base, paymaster: null });
    expect(unsponsored.userOperation.paymaster).toBeNull();
    expect(explicitNull.userOperationHash).toBe(unsponsored.userOperationHash);
    expect(sponsored.userOperationHash).not.toBe(unsponsored.userOperationHash);
    const differentData = prepareKernelV4UserOperation({
      ...base,
      paymaster: { ...paymaster, data: "0xdeadbee0" },
    });
    expect(differentData.userOperationHash).not.toBe(sponsored.userOperationHash);
    // Checksummed sponsorship addresses are captured in canonical lowercase.
    expect(
      prepareKernelV4UserOperation({
        ...base,
        paymaster: { ...paymaster, address: getAddress(paymaster.address) },
      }).userOperationHash,
    ).toBe(sponsored.userOperationHash);
  });

  it("rejects hostile paymaster inputs instead of preparing a distorted identity", async () => {
    const accountDescriptor = await descriptor("deployed");
    const base = {
      kind: "execution" as const,
      grantId: "kernel-v4-grant",
      account: accountDescriptor,
      nonce: {
        mode: "standard" as const,
        validation: { kind: "root" as const },
        nonceKey: "0",
        sequence: "0",
      },
      calls: [{ target, value: "0", data: "0x" as const }],
      gas,
    };
    const paymaster = {
      address: `0x${"77".repeat(20)}`,
      verificationGasLimit: "60000",
      postOpGasLimit: "25000",
      data: "0xdeadbeef",
    };
    for (const hostile of [
      "sponsor-me",
      { ...paymaster, address: `0x${"00".repeat(20)}` },
      { ...paymaster, address: "0x1234" },
      { ...paymaster, verificationGasLimit: "-1" },
      { ...paymaster, verificationGasLimit: "0x60000" },
      { ...paymaster, postOpGasLimit: (1n << 120n).toString(10) },
      { ...paymaster, data: "0xzz" },
      { ...paymaster, extra: true },
      { address: paymaster.address, data: "0x" },
      {
        ...paymaster,
        get data() {
          return "0x";
        },
      },
    ]) {
      expect(() =>
        asHostile(prepareKernelV4UserOperation)({ ...base, paymaster: hostile }),
      ).toThrowError(
        expect.objectContaining({ code: "kernel_v4_input_invalid" }) as unknown as Error,
      );
    }
    // An unknown sibling key stays refused even while paymaster is optional.
    expect(() => asHostile(prepareKernelV4UserOperation)({ ...base, sponsor: paymaster })).toThrow(
      expect.objectContaining({ code: "kernel_v4_input_invalid" }) as unknown as Error,
    );
  });

  it("rejects a contradictory account descriptor instead of trusting cached factory calldata", async () => {
    const accountDescriptor = await descriptor("counterfactual");
    expect(() =>
      prepareKernelV4UserOperation({
        kind: "execution",
        grantId: "kernel-v4-grant",
        account: { ...accountDescriptor, factoryDeployCalldata: "0x1234" },
        nonce: { mode: "standard", validation: { kind: "root" }, nonceKey: "0", sequence: "0" },
        calls: [{ target, value: "0", data: "0x" }],
        gas,
      }),
    ).toThrowError(expect.objectContaining({ code: "kernel_v4_input_invalid" }));
  });

  it("rejects a fabricated descriptor even when every public field is self-consistent", async () => {
    const accountDescriptor = await descriptor("counterfactual");
    expect(() =>
      prepareKernelV4UserOperation({
        kind: "execution",
        grantId: "kernel-v4-grant",
        account: { ...accountDescriptor },
        nonce: { mode: "standard", validation: { kind: "root" }, nonceKey: "0", sequence: "0" },
        calls: [{ target, value: "0", data: "0x" }],
        gas,
      }),
    ).toThrowError(
      expect.objectContaining({
        code: "kernel_v4_input_invalid",
        message: "Kernel account descriptor has not been proven by this SDK instance",
      }),
    );
  });
});

describe("Kernel v4 nonce and signature codecs", () => {
  it("encodes root, validator, permission, replayable, and local nonce namespaces", () => {
    expect(
      encodeKernelV4NonceKey({ mode: "standard", validation: { kind: "root" }, nonceKey: "0" }),
    ).toBe("0");

    const validatorKeyHex = concat(["0x00", "0x01", validator, "0x0007"]);
    expect(
      encodeKernelV4NonceKey({
        mode: "standard",
        validation: { kind: "validator", validator },
        nonceKey: "7",
      }),
    ).toBe(BigInt(validatorKeyHex).toString(10));

    const permissionKeyHex = concat([
      "0x40",
      "0x02",
      pad(permissionId, { size: 20, dir: "right" }),
      "0xffff",
    ]);
    expect(
      encodeKernelV4NonceKey({
        mode: "replayable",
        validation: { kind: "permission", permissionId },
        nonceKey: "65535",
      }),
    ).toBe(BigInt(permissionKeyHex).toString(10));

    expect(encodeKernelV4Nonce({ key: "7", sequence: "9" })).toBe(((7n << 64n) | 9n).toString(10));
  });

  it("forbids invalid validation modes and the root enable transition", () => {
    expect(() =>
      encodeKernelV4NonceKey({
        mode: "enable",
        validation: { kind: "root" },
        nonceKey: "0",
      }),
    ).toThrowError(expect.objectContaining({ code: "kernel_v4_input_invalid" }));
    expect(() =>
      asHostile(encodeKernelV4NonceKey)({
        mode: "toString",
        validation: { kind: "root" },
        nonceKey: "0",
      }),
    ).toThrowError(expect.objectContaining({ code: "kernel_v4_input_invalid" }));
  });

  it("encodes permission and enable envelopes in the contract-native order", () => {
    const permission = encodeKernelV4PermissionSignature(["0x11", "0x2233"]);
    expect(decodeAbiParameters([{ type: "bytes[]" }], permission)[0]).toEqual(["0x11", "0x2233"]);

    const enable = encodeKernelV4EnableSignature({
      nonce: "3",
      packages: installs,
      enableSignature: "0x1122",
      userOperationSignature: permission,
    });
    const decoded = decodeAbiParameters(
      [
        { name: "nonce", type: "uint256" },
        { name: "packages", type: "tuple[]", components: installComponents },
        { name: "enableSignature", type: "bytes" },
        { name: "userOpSignature", type: "bytes" },
      ],
      enable,
    );
    expect(decoded[0]).toBe(3n);
    expect(decoded[1][0]?.module).toBe(validator);
    expect(decoded[2]).toBe("0x1122");
    expect(decoded[3]).toBe(permission);
  });
});

describe("Kernel v4 ERC-7579 execution codec", () => {
  it("encodes a single reverting-by-default call as packed execution data", () => {
    const calldata = encodeKernelV4Execution({
      calls: [{ target, value: "5", data: "0xaabb" }],
    });
    const decoded = decodeFunctionData({ abi: kernelAbi, data: calldata });
    expect(decoded.functionName).toBe("execute");
    expect(decoded.args?.[0]).toBe(`0x${"00".repeat(32)}`);
    expect(decoded.args?.[1]).toBe(concat([target, toHex(5n, { size: 32 }), "0xaabb"]));
  });

  it("encodes multiple reverting-by-default calls using the ERC-7579 batch mode", () => {
    const calls = [
      { target, value: "0", data: "0x1234" },
      { target: validator, value: "9", data: "0xabcd" },
    ] as const;
    const decoded = decodeFunctionData({
      abi: kernelAbi,
      data: encodeKernelV4Execution({ calls }),
    });
    expect(decoded.args?.[0]).toBe(`0x0100${"00".repeat(30)}`);
    expect(decoded.args?.[1]).toBe(
      encodeAbiParameters(
        [
          {
            type: "tuple[]",
            components: [
              { name: "to", type: "address" },
              { name: "value", type: "uint256" },
              { name: "data", type: "bytes" },
            ],
          },
        ],
        [
          [
            { to: target, value: 0n, data: "0x1234" },
            { to: validator, value: 9n, data: "0xabcd" },
          ],
        ],
      ),
    );
  });

  it.each([
    [[]],
    [[{ target: `0x${"00".repeat(20)}`, value: "0", data: "0x" }]],
    [[{ target, value: "01", data: "0x" }]],
  ])("rejects empty or non-canonical call input", (calls) => {
    expect(() => asHostile(encodeKernelV4Execution)({ calls })).toThrowError(
      expect.objectContaining({ code: "kernel_v4_input_invalid" }),
    );
  });
});

describe("Kernel v4 read and submission adapters", () => {
  const word = (address: `0x${string}`) => pad(address, { size: 32 });

  it("adapts one viem-style client into all six read request types", async () => {
    const chainId = 421_614 as const;
    const code = "0xdeadbeef" as const;
    const implementation = KERNEL_V4_UUPS_IMPLEMENTATION_V07;
    const slots: string[] = [];
    const reads = createKernelV4Reads({
      getChainId: async () => chainId,
      getCode: async ({ address }) => (address === account ? undefined : code),
      getStorageAt: async ({ slot }) => {
        slots.push(slot);
        return word(implementation);
      },
      call: async () => ({ data: word(implementation) }),
    });
    await expect(reads.read({ type: "chain_id", chainId })).resolves.toBe(chainId);
    await expect(reads.read({ type: "code", chainId, address: account })).resolves.toBe("0x");
    await expect(reads.read({ type: "code", chainId, address: target })).resolves.toBe(code);
    await expect(reads.read({ type: "runtime_code_hash", chainId, address: target })).resolves.toBe(
      keccak256(code),
    );
    await expect(
      reads.read({ type: "kernel_factory_implementation", chainId, factory, calldata: "0x" }),
    ).resolves.toBe(implementation);
    await expect(
      reads.read({ type: "kernel_factory_account", chainId, factory, calldata: "0x" }),
    ).resolves.toBe(implementation);
    await expect(
      reads.read({ type: "kernel_account_implementation", chainId, account }),
    ).resolves.toBe(implementation);
    expect(slots).toEqual([KERNEL_V4_IMPLEMENTATION_SLOT]);
  });

  it("returns undefined evidence instead of guessing when the chain has no answer", async () => {
    const chainId = 421_614 as const;
    const reads = createKernelV4Reads({
      getChainId: async () => chainId,
      getCode: async () => "0x",
      getStorageAt: async () => null,
      call: async () => ({}),
    });
    await expect(
      reads.read({ type: "runtime_code_hash", chainId, address: target }),
    ).resolves.toBeUndefined();
    await expect(
      reads.read({ type: "kernel_factory_account", chainId, factory, calldata: "0x" }),
    ).resolves.toBeUndefined();
    await expect(
      reads.read({ type: "kernel_account_implementation", chainId, account }),
    ).resolves.toBeUndefined();
  });

  it("encodes the exact EntryPoint getNonce read for a canonical key", () => {
    const key = encodeKernelV4NonceKey({
      mode: "standard",
      validation: { kind: "validator", validator },
      nonceKey: "7",
    });
    const decoded = decodeFunctionData({
      abi: [
        {
          type: "function",
          name: "getNonce",
          stateMutability: "view",
          inputs: [
            { name: "sender", type: "address" },
            { name: "key", type: "uint192" },
          ],
          outputs: [{ name: "nonce", type: "uint256" }],
        },
      ] as const,
      data: encodeKernelV4NonceRead({ account, key }),
    });
    expect(decoded.functionName).toBe("getNonce");
    expect(decoded.args).toEqual([getAddress(account), BigInt(key)]);
    expect(() => asHostile(encodeKernelV4NonceRead)({ account, key: "-1" })).toThrowError(
      expect.objectContaining({ code: "kernel_v4_input_invalid" }),
    );
  });

  it("names the execute selector every non-root validation must allow-list", () => {
    expect(KERNEL_V4_EXECUTE_SELECTOR).toBe("0xe9ae5c53");
  });
});
