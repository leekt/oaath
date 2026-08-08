import { concat, encodeAbiParameters, hashTypedData, keccak256, recoverAddress, toHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";
// Internal on purpose: requested-range authorization depends on the exact
// deterministic policy runtime, while the public surface exposes its meaning.
import {
  OAATH_KERNEL_V4_VALIDITY_POLICY,
  OAATH_KERNEL_V4_VALIDITY_POLICY_RUNTIME_CODE_HASH,
} from "../src/kernel/modules.js";
import {
  approveKernelPermissionAllChain,
  createKernelRuntime,
  ecdsaKey,
  encodeKernelV4NonceKey,
  KERNEL_V4_ENTRY_POINT_V07,
  KERNEL_V4_ENTRY_POINT_V07_CODE_HASH,
  KERNEL_V4_FACTORY_V07_CODE_HASH,
  KERNEL_V4_UUPS_IMPLEMENTATION_V07,
  type KernelAllChainApproval,
  type KernelV4AccountReadRequest,
  type KernelV4Install,
  kernelV4Deployment,
  kernelV4ReplayableInstallDigest,
  materializeKernelPermission,
  OAATH_KERNEL_ALL_CHAIN_APPROVAL_VERSION,
  ownerOperator,
  sessionOperator,
} from "../src/kernel.js";

const chainId = 421_614;
const otherChainId = 11_155_111;
const validator = `0x${"22".repeat(20)}` as const;
const account = `0x${"66".repeat(20)}` as const;
const target = `0x${"44".repeat(20)}` as const;
const gas = Object.freeze({
  callGasLimit: "100000",
  verificationGasLimit: "200000",
  preVerificationGas: "30000",
  maxFeePerGas: "4",
  maxPriorityFeePerGas: "2",
});

const ownerAccount = privateKeyToAccount(`0x${"11".repeat(32)}`);
const sessionAccount = privateKeyToAccount(`0x${"33".repeat(32)}`);

/** Forces a hostile value past the compiler without weakening the source types. */
function asHostile<T>(value: T): (input: never) => unknown {
  return value as unknown as (input: never) => unknown;
}

function runtimeCodeHash(
  address: `0x${string}`,
  chain: typeof chainId | typeof otherChainId,
): `0x${string}` {
  if (address === KERNEL_V4_ENTRY_POINT_V07) return KERNEL_V4_ENTRY_POINT_V07_CODE_HASH;
  if (address === OAATH_KERNEL_V4_VALIDITY_POLICY) {
    return OAATH_KERNEL_V4_VALIDITY_POLICY_RUNTIME_CODE_HASH;
  }
  if (address === KERNEL_V4_UUPS_IMPLEMENTATION_V07) {
    return kernelV4Deployment(chain).implementationDeployment.runtimeCodeHash;
  }
  return KERNEL_V4_FACTORY_V07_CODE_HASH;
}

function reads(state: "counterfactual" | "deployed" = "counterfactual") {
  return {
    async read(request: KernelV4AccountReadRequest): Promise<unknown> {
      if (request.type === "chain_id") return request.chainId;
      if (request.type === "runtime_code_hash") {
        return runtimeCodeHash(
          request.address,
          request.chainId === chainId ? chainId : otherChainId,
        );
      }
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
}

const ownerKey = ecdsaKey({ account: ownerAccount, validator });

function runtimes(chain: typeof chainId | typeof otherChainId) {
  const profile = kernelV4Deployment(chain);
  return {
    owner: createKernelRuntime({
      deployment: profile,
      operator: ownerOperator({ key: ownerKey }),
      reads: reads(),
    }),
    session: createKernelRuntime({
      deployment: profile,
      operator: sessionOperator({
        key: ecdsaKey({ account: sessionAccount, validator }),
        policies: [
          { kind: "call", permissions: [{ target, selector: "0x00000000", valueLimit: "500" }] },
        ],
      }),
      reads: reads(),
    }),
  };
}

const local = runtimes(chainId);
const remote = runtimes(otherChainId);

async function approve(
  packages: readonly KernelV4Install[] = local.session.packages,
): Promise<Readonly<KernelAllChainApproval>> {
  return approveKernelPermissionAllChain({
    owner: ownerKey,
    account,
    installNonce: "0",
    packages,
  });
}

describe("Kernel v4 replayable install digest", () => {
  it("reproduces Kernel's chain-agnostic EIP-712 digest from the pinned struct hashes", () => {
    const packages = local.session.packages;
    const nonce = "7";
    // The independent construction: Kernel's own INSTALL_PACKAGES_STRUCT_HASH and
    // INSTALL_STRUCT_HASH constants, its EfficientHashLib array hashing, and
    // Solady's chain-omitting domain separator, assembled by hand from
    // src/types/Constants.sol and dependencies/solady/src/utils/EIP712.sol.
    const installPackagesStructHash =
      "0x633d6810f7f4053622dad4c187707d9c3cd7f57b8b68943473d3437060aefc6d" as const;
    const installStructHash =
      "0x50c63c739a5f8d2e99954b3d4c7008fcdcef795a1b755ab9287372b01d6ac239" as const;
    const domainTypeHashSansChainId =
      "0x91ab3d17e3a50a9d89e63fd30b92be7f5336b03b287bb946787a83a9d62a2766" as const;
    const installHash = keccak256(
      concat(
        packages.map((install) =>
          keccak256(
            encodeAbiParameters(
              [
                { type: "bytes32" },
                { type: "uint256" },
                { type: "uint256" },
                { type: "bytes32" },
                { type: "bytes32" },
              ],
              [
                installStructHash,
                BigInt(install.moduleType),
                BigInt(install.module),
                keccak256(install.moduleData),
                keccak256(install.internalData),
              ],
            ),
          ),
        ),
      ),
    );
    const structHash = keccak256(
      encodeAbiParameters(
        [{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }],
        [installPackagesStructHash, toHex(BigInt(nonce), { size: 32 }), installHash],
      ),
    );
    const domainSeparator = keccak256(
      encodeAbiParameters(
        [{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "address" }],
        [domainTypeHashSansChainId, keccak256(toHex("Kernel")), keccak256(toHex("0.4.0")), account],
      ),
    );

    expect(kernelV4ReplayableInstallDigest({ account, nonce, packages })).toBe(
      keccak256(concat(["0x1901", domainSeparator, structHash])),
    );
  });

  it("omits the chain id from the domain, so the same install digests identically everywhere", () => {
    const packages = local.session.packages;
    // The session on the other supported chain resolves the same permission and
    // the same packages, because every address involved is chain-independent.
    expect(remote.session.packages).toEqual(packages);
    expect(remote.session.validation).toEqual(local.session.validation);

    const digest = kernelV4ReplayableInstallDigest({ account, nonce: "0", packages });
    // The chain-bound variant Kernel would use without the replayable flag is a
    // different digest on every chain; the replayable one is not.
    for (const chain of [chainId, otherChainId]) {
      expect(
        hashTypedData({
          domain: { name: "Kernel", version: "0.4.0", chainId: chain, verifyingContract: account },
          types: {
            InstallPackages: [
              { name: "nonce", type: "uint256" },
              { name: "packages", type: "Install[]" },
            ],
            Install: [
              { name: "moduleType", type: "uint256" },
              { name: "module", type: "address" },
              { name: "moduleData", type: "bytes" },
              { name: "internalData", type: "bytes" },
            ],
          },
          primaryType: "InstallPackages",
          message: {
            nonce: 0n,
            packages: packages.map((install) => ({
              moduleType: BigInt(install.moduleType),
              module: install.module,
              moduleData: install.moduleData,
              internalData: install.internalData,
            })),
          },
        }),
      ).not.toBe(digest);
    }
  });

  it("binds the account, the install nonce, and every package byte", () => {
    const packages = local.session.packages;
    const base = kernelV4ReplayableInstallDigest({ account, nonce: "0", packages });
    expect(
      kernelV4ReplayableInstallDigest({ account: `0x${"67".repeat(20)}`, nonce: "0", packages }),
    ).not.toBe(base);
    expect(kernelV4ReplayableInstallDigest({ account, nonce: "1", packages })).not.toBe(base);
    const widened = packages.map((install, index) =>
      index === 0 ? { ...install, moduleData: concat([install.moduleData, "0xff"]) } : install,
    );
    expect(kernelV4ReplayableInstallDigest({ account, nonce: "0", packages: widened })).not.toBe(
      base,
    );
  });

  it("fails closed on a hostile account, nonce, package set, or field set", () => {
    const packages = local.session.packages;
    for (const input of [
      { account: "0xdead", nonce: "0", packages },
      { account, nonce: "-1", packages },
      { account, nonce: "0", packages: [] },
      { account, nonce: "0", packages: [{ ...packages[0], moduleType: 0 }] },
    ]) {
      expect(() => asHostile(kernelV4ReplayableInstallDigest)(input as never)).toThrowError(
        expect.objectContaining({ code: "kernel_v4_input_invalid" }),
      );
    }
    expect(() =>
      asHostile(kernelV4ReplayableInstallDigest)({
        account,
        nonce: "0",
        packages,
        extra: 1,
      } as never),
    ).toThrowError(expect.objectContaining({ code: "kernel_v4_input_invalid" }));
  });
});

describe("all-chain permission approval", () => {
  it("takes one chain-agnostic owner signature over the install digest", async () => {
    let signatures = 0;
    const countingKey = ecdsaKey({
      account: {
        address: ownerAccount.address,
        sign: async (request: { readonly hash: `0x${string}` }) => {
          signatures += 1;
          return ownerAccount.sign(request);
        },
      },
      validator,
    });
    const approval = await approveKernelPermissionAllChain({
      owner: countingKey,
      account,
      installNonce: "0",
      packages: local.session.packages,
    });
    expect(signatures).toBe(1);
    expect(approval.version).toBe(OAATH_KERNEL_ALL_CHAIN_APPROVAL_VERSION);
    expect(approval.digest).toBe(
      kernelV4ReplayableInstallDigest({
        account,
        nonce: "0",
        packages: local.session.packages,
      }),
    );
    // Kernel's root validation recovers the owner from the digest directly: a
    // replayable enable signature carries no envelope of its own.
    expect(
      (await recoverAddress({ hash: approval.digest, signature: approval.enableSignature })) ===
        ownerAccount.address,
    ).toBe(true);
    expect(Object.isFrozen(approval)).toBe(true);
  });

  it("fails closed on a hostile approval request", async () => {
    await expect(
      asHostile(approveKernelPermissionAllChain)({
        owner: ownerKey,
        account,
        installNonce: "0",
      } as never),
    ).rejects.toMatchObject({ code: "kernel_runtime_input_invalid" });
    await expect(
      approveKernelPermissionAllChain({
        owner: ownerKey,
        account: `0x${"00".repeat(20)}`,
        installNonce: "0",
        packages: local.session.packages,
      }),
    ).rejects.toMatchObject({ code: "kernel_runtime_input_invalid" });
  });
});

describe("all-chain permission materialization", () => {
  it("prepares one enable-mode operation and wraps it in Kernel's enable envelope", async () => {
    const approval = await approve();
    const bound = await local.session.bindAccount({
      accountIndex: "0",
      initialPackages: local.owner.packages,
    });
    const materialized = await materializeKernelPermission({
      approval,
      runtime: local.session,
      grantId: "all-chain-unit",
      account: bound,
      nonceKey: "0",
      sequence: "0",
      calls: [{ target, value: "500", data: "0x" }],
      gas,
    });
    // The nonce carries Kernel's enable-replayable mode byte, which the standard
    // mode key never produces.
    expect(BigInt(materialized.prepared.userOperation.nonce) >> 64n).toBe(
      BigInt(
        encodeKernelV4NonceKey({
          mode: "enable-replayable",
          validation: local.session.validation,
          nonceKey: "0",
        }),
      ),
    );
    expect(BigInt(materialized.prepared.userOperation.nonce) >> 64n).not.toBe(
      BigInt(
        encodeKernelV4NonceKey({
          mode: "standard",
          validation: local.session.validation,
          nonceKey: "0",
        }),
      ),
    );
    // The envelope carries the owner approval verbatim beside the session
    // signature; the session signature alone is what the runtime produced.
    expect(materialized.signature.includes(approval.enableSignature.slice(2))).toBe(true);
    expect(
      materialized.signature.includes(
        (await local.session.signOperation(materialized.prepared)).slice(2),
      ),
    ).toBe(true);

    // The same approval on the other chain: same account, same packages, a
    // different operation identity.
    const remoteBound = await remote.session.bindAccount({
      accountIndex: "0",
      initialPackages: remote.owner.packages,
    });
    const remoteMaterialized = await materializeKernelPermission({
      approval,
      runtime: remote.session,
      grantId: "all-chain-unit",
      account: remoteBound,
      nonceKey: "0",
      sequence: "0",
      calls: [{ target, value: "500", data: "0x" }],
      gas,
    });
    expect(remoteMaterialized.prepared.chainId).toBe(otherChainId);
    expect(remoteMaterialized.prepared.userOperationHash).not.toBe(
      materialized.prepared.userOperationHash,
    );
  });

  it("forwards a requested validity range without changing the approved package ceiling", async () => {
    const runtime = createKernelRuntime({
      deployment: kernelV4Deployment(chainId),
      operator: sessionOperator({
        key: ecdsaKey({ account: sessionAccount, validator }),
        policies: [
          { kind: "call", permissions: [{ target, selector: "0x00000000", valueLimit: "500" }] },
          { kind: "expiry", validAfter: "0", validUntil: "2000" },
        ],
      }),
      reads: reads(),
    });
    const approval = await approve(runtime.packages);
    const bound = await runtime.bindAccount({
      accountIndex: "0",
      initialPackages: local.owner.packages,
    });
    const request = {
      approval,
      runtime,
      grantId: "all-chain-validity-range",
      account: bound,
      nonceKey: "0",
      sequence: "0",
      calls: [{ target, value: "1", data: "0x" as const }],
      gas,
    };
    const first = await materializeKernelPermission({
      ...request,
      validityTimeRange: { validAfter: "100", validUntil: "1000" },
    });
    const second = await materializeKernelPermission({
      ...request,
      validityTimeRange: { validAfter: "100", validUntil: "999" },
    });

    expect(first.prepared.userOperation.callData).toContain("1ba8f415");
    expect(first.prepared.userOperationHash).not.toBe(second.prepared.userOperationHash);
    expect(approval.packages).toEqual(runtime.packages);
    expect(approval.digest).toBe(
      kernelV4ReplayableInstallDigest({ account, nonce: "0", packages: runtime.packages }),
    );
  });

  it("refuses an approval whose version, digest, signature, or packages do not hold", async () => {
    const approval = await approve();
    const bound = await local.session.bindAccount({
      accountIndex: "0",
      initialPackages: local.owner.packages,
    });
    const request = Object.freeze({
      runtime: local.session,
      grantId: "all-chain-unit",
      account: bound,
      nonceKey: "0",
      sequence: "0",
      calls: [{ target, value: "500", data: "0x" as const }],
      gas,
    });

    await expect(
      materializeKernelPermission({
        ...request,
        approval: { ...approval, version: "oaath.kernel.all-chain-approval/v0" as never },
      }),
    ).rejects.toMatchObject({ code: "kernel_runtime_input_invalid" });
    await expect(
      materializeKernelPermission({
        ...request,
        approval: { ...approval, enableSignature: "0x" },
      }),
    ).rejects.toMatchObject({ code: "kernel_runtime_input_invalid" });
    // A digest that no longer matches its own account, nonce and packages is
    // contradictory: the owner signature beside it covers something else.
    await expect(
      materializeKernelPermission({
        ...request,
        approval: { ...approval, installNonce: "1" },
      }),
    ).rejects.toMatchObject({ code: "kernel_runtime_input_invalid" });
    await expect(
      materializeKernelPermission({
        ...request,
        approval: { ...approval, digest: `0x${"00".repeat(32)}` },
      }),
    ).rejects.toMatchObject({ code: "kernel_runtime_input_invalid" });
    await expect(
      asHostile(materializeKernelPermission)({
        ...request,
        approval: { ...approval, extra: 1 },
      } as never),
    ).rejects.toMatchObject({ code: "kernel_runtime_input_invalid" });

    // An approval covering a different permission may not install through this
    // runtime, even though the owner really did sign it.
    const foreign = await approveKernelPermissionAllChain({
      owner: ownerKey,
      account,
      installNonce: "0",
      packages: local.owner.packages,
    });
    await expect(
      materializeKernelPermission({ ...request, approval: foreign }),
    ).rejects.toMatchObject({ code: "kernel_runtime_binding_mismatch" });

    // An approval covering a different account may not install into this one.
    const otherAccount = await approveKernelPermissionAllChain({
      owner: ownerKey,
      account: `0x${"67".repeat(20)}`,
      installNonce: "0",
      packages: local.session.packages,
    });
    await expect(
      materializeKernelPermission({ ...request, approval: otherAccount }),
    ).rejects.toMatchObject({ code: "kernel_runtime_binding_mismatch" });
  });
});

describe("Kernel runtime validation modes", () => {
  it("reaches standard and enable-replayable only, and refuses every other mode", async () => {
    const bound = await local.session.bindAccount({
      accountIndex: "0",
      initialPackages: local.owner.packages,
    });
    const prepare = (mode: unknown) =>
      asHostile(local.session.prepareOperation)({
        kind: "execution",
        mode,
        grantId: "all-chain-unit",
        account: bound,
        nonceKey: "0",
        sequence: "0",
        calls: [{ target, value: "500", data: "0x" }],
        gas,
      } as never);

    // Every mode Kernel's codec knows but a composed runtime must never reach.
    for (const mode of [
      "enable",
      "replayable",
      "enable-user-operation-replayable",
      "enable-all-replayable",
      "toString",
    ]) {
      expect(() => prepare(mode)).toThrowError(
        expect.objectContaining({ code: "kernel_runtime_input_invalid" }),
      );
    }

    // Kernel forbids enable mode on root validation, so an owner runtime cannot
    // prepare one at all.
    const ownerBound = await local.owner.bindAccount({
      accountIndex: "0",
      initialPackages: local.owner.packages,
    });
    expect(() =>
      local.owner.prepareOperation({
        kind: "execution",
        mode: "enable-replayable",
        grantId: "all-chain-unit",
        account: ownerBound,
        nonceKey: "0",
        sequence: "0",
        calls: [{ target, value: "0", data: "0x" }],
        gas,
      }),
    ).toThrowError(expect.objectContaining({ code: "kernel_v4_input_invalid" }));

    // And an owner runtime refuses to sign an enable-mode operation prepared by
    // the session, mode byte and all.
    const enabled = local.session.prepareOperation({
      kind: "execution",
      mode: "enable-replayable",
      grantId: "all-chain-unit",
      account: bound,
      nonceKey: "0",
      sequence: "0",
      calls: [{ target, value: "500", data: "0x" }],
      gas,
    });
    await expect(local.owner.signOperation(enabled)).rejects.toMatchObject({
      code: "kernel_runtime_binding_mismatch",
    });
    // The session signs both of its own reachable modes.
    expect(await local.session.signOperation(enabled)).toMatch(/^0x[0-9a-f]+$/u);
    expect(
      await local.session.signOperation(
        local.session.prepareOperation({
          kind: "execution",
          grantId: "all-chain-unit",
          account: bound,
          nonceKey: "0",
          sequence: "0",
          calls: [{ target, value: "500", data: "0x" }],
          gas,
        }),
      ),
    ).toMatch(/^0x[0-9a-f]+$/u);
  });
});
