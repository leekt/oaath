import {
  concat,
  decodeFunctionData,
  encodeAbiParameters,
  hashTypedData,
  keccak256,
  parseAbi,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";
import { readWeightedConfiguration } from "../src/kernel/deployment/weighted.js";
import { pinnedValidatorModule } from "../src/kernel/modules.js";
import {
  createKernelRuntime,
  kernelDeployment,
  kernelKey,
  ownerOperator,
  sessionOperator,
} from "../src/kernel.js";

const accounts = Array.from({ length: 3 }, () => privateKeyToAccount(generatePrivateKey())).sort(
  (a, b) => a.address.toLowerCase().localeCompare(b.address.toLowerCase()),
);
const guardians = accounts.map((account) => ({
  address: account.address.toLowerCase() as `0x${string}`,
  weight: 1,
}));
const input = {
  kind: "weighted-ecdsa" as const,
  guardians,
  threshold: 2,
  signers: accounts.slice(0, 2),
};
const digest = keccak256("0x0123");

describe("weighted Kernel key", () => {
  it("collects a distinct sorted quorum and refuses duplicate or insufficient participants before signing", async () => {
    const key = kernelKey(input);
    const signature = await key.sign(digest);
    expect(await key.verify(digest, signature)).toBe(true);
    expect(await key.verify(keccak256("0x0124"), signature)).toBe(false);
    expect(
      await key.verify(
        digest,
        concat([
          signature.slice(0, 132) as `0x${string}`,
          signature.slice(0, 132) as `0x${string}`,
        ]),
      ),
    ).toBe(false);
    expect(() => kernelKey({ ...input, signers: [accounts[0]!, accounts[0]!] })).toThrow();
    expect(() => kernelKey({ ...input, signers: [accounts[0]!] })).toThrow();
    expect(() => kernelKey({ ...input, guardians: [guardians[0]!, guardians[0]!] })).toThrow();
  });

  it("rejects a claimed guardian that returns another guardian's signature", async () => {
    const signers = [{ address: accounts[0]!.address, sign: accounts[2]!.sign }, accounts[1]!];
    await expect(kernelKey({ ...input, signers }).sign(digest)).rejects.toMatchObject({
      code: "kernel_runtime_signature_invalid",
    });
  });

  it.each(["owner", "session"] as const)(
    "composes %s authority with one weighted profile",
    (authority) => {
      const key = kernelKey(input);
      const deployment = kernelDeployment({ chainId: 143 });
      const operator =
        authority === "owner"
          ? ownerOperator({ key })
          : sessionOperator({
              key,
              policies: [
                {
                  kind: "call",
                  permissions: [
                    { target: guardians[0]!.address, selector: "0x00000000", valueLimit: "1" },
                  ],
                },
              ],
            });
      const runtime = createKernelRuntime({
        deployment,
        operator,
        reads: { read: async () => undefined },
      });
      expect(runtime.keyKind).toBe("weighted-ecdsa");
      expect(runtime.authority).toBe(authority);
      expect(
        runtime.packages.some((pkg) => pkg.moduleData.endsWith(key.publicMaterial.slice(2))),
      ).toBe(true);
      if (authority === "owner")
        expect(runtime.authorityModule).toBe(pinnedValidatorModule("weighted-ecdsa"));
    },
  );
});

const deployment = kernelDeployment({ chainId: 143 });
const address = `0x${"67".repeat(20)}` as const;
const gas = {
  callGasLimit: "900000",
  verificationGasLimit: "3000000",
  preVerificationGas: "150000",
  maxFeePerGas: "2000000000",
  maxPriorityFeePerGas: "1000000000",
};
const calls = [{ target: guardians[2]!.address, value: "1", data: "0x" as const }];
function boundFixture() {
  let signatures = 0;
  let epoch = 1n;
  let unavailable = false;
  const key = kernelKey({
    ...input,
    signers: accounts.slice(0, 2).map((account) => ({
      address: account.address,
      sign: (request: { hash: `0x${string}` }) => {
        signatures++;
        return account.sign(request);
      },
    })),
  });
  const runtime = createKernelRuntime({
    deployment,
    operator: ownerOperator({ key }),
    reads: {
      read: async (request) => {
        if (request.type === "chain_id") return 143;
        if (request.type === "code") return "0x01";
        if (request.type === "kernel_account_implementation") return deployment.implementation;
        if (request.type === "kernel_v4_account_root")
          return `0x01${key.resolveValidator(deployment).slice(2)}`;
        if (request.type === "kernel_weighted_configuration") {
          if (unavailable) throw new Error("unavailable");
          return encodeAbiParameters(
            [{ type: "bytes" }, { type: "uint256" }],
            [key.publicMaterial, epoch],
          );
        }
        return undefined;
      },
    },
  });
  return {
    key,
    runtime,
    count: () => signatures,
    changeEpoch: () => {
      epoch++;
    },
    unavailable: () => {
      unavailable = true;
    },
  };
}

it.each(["epoch", "unreadable"] as const)(
  "refuses weighted signing after %s evidence changes without contacting a guardian",
  async (failure) => {
    const fixture = boundFixture();
    const account = await fixture.runtime.bindAccount({ address });
    const prepared = fixture.runtime.prepareOperation({
      kind: "execution",
      grantId: "weighted-unit",
      account,
      nonceKey: "0",
      sequence: "0",
      calls,
      gas,
    });
    if (failure === "epoch") fixture.changeEpoch();
    else fixture.unavailable();
    await expect(fixture.runtime.signOperation(prepared)).rejects.toMatchObject({
      code:
        failure === "epoch" ? "kernel_runtime_binding_mismatch" : "kernel_runtime_read_unavailable",
    });
    expect(fixture.count()).toBe(0);
  },
);

it("uses distinct proposal/final digests and binds epoch, calldata, nonce and full operation fees", async () => {
  const fixture = boundFixture();
  const account = await fixture.runtime.bindAccount({ address });
  const prepared = fixture.runtime.prepareOperation({
    kind: "execution",
    grantId: "weighted-unit",
    account,
    nonceKey: "0",
    sequence: "0",
    calls,
    gas,
  });
  const signature = await fixture.runtime.signOperation(prepared);
  const domain = {
    name: "WeightedECDSAValidator",
    version: "0.0.5",
    chainId: 143,
    verifyingContract: fixture.runtime.authorityModule,
  };
  const proposal = hashTypedData({
    domain,
    primaryType: "Proposal",
    types: {
      Proposal: [
        { name: "account", type: "address" },
        { name: "id", type: "bytes32" },
        { name: "callData", type: "bytes" },
        { name: "nonce", type: "uint256" },
        { name: "configurationEpoch", type: "uint256" },
      ],
    },
    message: {
      account: address,
      id: `0x${"00".repeat(32)}`,
      callData: prepared.userOperation.callData,
      nonce: BigInt(prepared.userOperation.nonce),
      configurationEpoch: 1n,
    },
  });
  const final = hashTypedData({
    domain,
    primaryType: "WeightedUserOperation",
    types: {
      WeightedUserOperation: [
        { name: "userOpHash", type: "bytes32" },
        { name: "configurationEpoch", type: "uint256" },
      ],
    },
    message: { userOpHash: prepared.userOperationHash, configurationEpoch: 1n },
  });
  const expected = concat([
    await accounts[0]!.sign({ hash: proposal }),
    await accounts[1]!.sign({ hash: final }),
  ]);
  expect(signature === expected).toBe(true);
  const context = {
    operation: prepared,
    module: fixture.runtime.authorityModule,
    permissionId: null,
    configurationEpoch: "1",
  };
  expect(await fixture.key.verify(prepared.userOperationHash, signature, context)).toBe(true);
  expect(
    await fixture.key.verify(prepared.userOperationHash, signature, {
      ...context,
      configurationEpoch: "2",
    }),
  ).toBe(false);
  for (const change of [
    { sequence: "1" },
    { calls: [{ ...calls[0]!, value: "2" }] },
    { gas: { ...gas, maxFeePerGas: "3000000000" } },
  ]) {
    const other = fixture.runtime.prepareOperation({
      kind: "execution",
      grantId: "weighted-unit",
      account,
      nonceKey: "0",
      sequence: "0",
      calls,
      gas,
      ...change,
    });
    await expect(fixture.runtime.encodeVerifiedSignature(other, signature)).rejects.toMatchObject({
      code: "kernel_runtime_signature_invalid",
    });
  }
  expect(fixture.count()).toBe(2);
});

it.each(["cycle", "changed-epoch", "wrong-total", "unreadable"] as const)(
  "does not turn %s configuration evidence into authority",
  async (failure) => {
    const abi = parseAbi([
      "function weightedStorage(address) view returns (uint24,uint24,address)",
      "function guardian(address,address) view returns (uint24,address)",
      "function configurationEpoch(address) view returns (uint256)",
    ]);
    let epochs = 0;
    let requests = 0;
    const client = {
      getChainId: async () => 143,
      getCode: async () => "0x01" as const,
      getStorageAt: async () => undefined,
      call: async ({ data }: { data: `0x${string}` }) => {
        requests++;
        if (failure === "unreadable") return {};
        const decoded = decodeFunctionData({ abi, data });
        if (decoded.functionName === "configurationEpoch")
          return {
            data: encodeAbiParameters(
              [{ type: "uint256" }],
              [failure === "changed-epoch" ? BigInt(++epochs) : 1n],
            ),
          };
        if (decoded.functionName === "weightedStorage")
          return {
            data: encodeAbiParameters(
              [{ type: "uint24" }, { type: "uint24" }, { type: "address" }],
              [failure === "wrong-total" ? 2 : 1, 1, guardians[0]!.address],
            ),
          };
        return {
          data: encodeAbiParameters(
            [{ type: "uint24" }, { type: "address" }],
            [1, failure === "cycle" ? guardians[0]!.address : address],
          ),
        };
      },
    };
    await expect(
      readWeightedConfiguration(client, {
        type: "kernel_weighted_configuration",
        chainId: 143,
        module: pinnedValidatorModule("weighted-ecdsa")!,
        account: address,
        permissionId: null,
      }),
    ).rejects.toThrow();
    expect(requests <= 4).toBe(true);
  },
);
