import { parseAbi, parseEther, toFunctionSelector } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { afterAll, describe, expect, it } from "vitest";
import { kernelPermissionInstallNonce } from "../src/kernel/permission/install-nonce.js";
import {
  approveKernelPermissionAllChain,
  type KernelAllChainApproval,
} from "../src/kernel/permission/materialize.js";
import { observeKernelPermissionRevocation } from "../src/kernel/permission/observe-revocation.js";
import {
  createKernelReads,
  createKernelRuntime,
  type EcdsaSignRequest,
  type KernelRuntime,
  type KeyProfile,
  kernelDeployment,
  kernelKey,
  materializeKernelPermission,
  ownerOperator,
  prepareKernelPermissionRevocation,
  readKernelPermissionStatus,
  sessionOperator,
  verifyKernelPermissionRevocation,
} from "../src/kernel.js";
import type { KernelV4AccountDescriptor } from "../src/kernel-v4.js";
import {
  encodeKernelInstallNonceInvalidationCall,
  encodeKernelPermissionUninstallCalls,
  encodeKernelV4InstallNonceRead,
  kernelV4ReplayableInstallDigest,
} from "../src/kernel-v4.js";
import type { OperationObserverCapabilities } from "../src/operation-observer.js";
import {
  type AnvilChain,
  createHarness,
  deployKernelStack,
  type KernelHarness,
  lower,
  startAnvil,
} from "./support/anvil.js";

const requireAnvil = process.env.OAATH_REQUIRE_ANVIL === "1";
/**
 * Chain A carries pinned per-chain deployment evidence; chain B is Base — an
 * open production chain with no pin, introduced after approval — so this proof
 * covers both verification paths of issue #117.
 */
const CHAIN_A = 421_614;
const CHAIN_B = 8_453;
/** Kernel's own install nonce for the one approval; per-chain state, same value. */
const INSTALL_NONCE = "0";
const REVERTING_CONTRACT_DEPLOYMENT = "0x6005600c60003960056000f360006000fd" as const;
const KERNEL_MODULE_VIEW_ABI = [
  {
    type: "function",
    name: "isModuleInstalled",
    stateMutability: "view",
    inputs: [
      { name: "moduleTypeId", type: "uint256" },
      { name: "module", type: "address" },
      { name: "additionalContext", type: "bytes" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
] as const;

const gas = Object.freeze({
  callGasLimit: "900000",
  verificationGasLimit: "3000000",
  preVerificationGas: "150000",
  maxFeePerGas: "2000000000",
  maxPriorityFeePerGas: "1000000000",
});

const chains: AnvilChain[] = [];

afterAll(() => {
  for (const chain of chains) chain.stop();
});

/**
 * One owner credential that counts its own signing invocations. The count is the
 * evidence: an implementation that quietly re-approved per chain would show two.
 */
function countingOwner() {
  const account = privateKeyToAccount(generatePrivateKey());
  let signatures = 0;
  return {
    signatures: () => signatures,
    account: Object.freeze({
      address: account.address,
      sign: async (request: EcdsaSignRequest) => {
        signatures += 1;
        return account.sign(request);
      },
    }),
  };
}

interface ChainStack {
  readonly chain: AnvilChain;
  readonly harness: KernelHarness;
  readonly ownerKey: Readonly<KeyProfile>;
  readonly ownerRuntime: Readonly<KernelRuntime>;
  readonly sessionRuntime: Readonly<KernelRuntime>;
  readonly account: Readonly<KernelV4AccountDescriptor>;
}

/**
 * Brings up one chain with the identical stack: EntryPoint, both Kernel
 * implementations, the factory, the pinned CallPolicy and ECDSA signer, and the
 * ECDSA validator. Every one of those addresses is CREATE2-derived, including the
 * validator, which is the only module the registry leaves caller-bound — so the
 * owner's initial packages, and therefore the account address, are identical on
 * both chains. The proof asserts that rather than assuming it.
 */
async function bringUp(
  chainId: number,
  owner: ReturnType<typeof countingOwner>,
  sessionKeyAccount: ReturnType<typeof privateKeyToAccount>,
  sessionTarget: `0x${string}`,
): Promise<ChainStack> {
  const chain = await startAnvil(chainId);
  chains.push(chain);
  const harness = await createHarness(chain);
  await deployKernelStack(harness);
  await harness.deployModule(harness.fixture.callPolicy);
  await harness.deployModule(harness.fixture.ecdsaSigner);
  const validator = await harness.deployValidatorCreate2();

  const deployment = kernelDeployment({ chainId });
  const ownerKey = kernelKey({ account: owner.account, validator });
  const ownerRuntime = createKernelRuntime({
    deployment,
    operator: ownerOperator({ key: ownerKey }),
    reads: harness.reads,
  });
  const sessionRuntime = createKernelRuntime({
    deployment,
    operator: sessionOperator({
      key: kernelKey({ account: sessionKeyAccount, validator }),
      policies: [
        {
          kind: "call",
          permissions: [{ target: sessionTarget, selector: "0x00000000", valueLimit: "500" }],
        },
      ],
    }),
    reads: harness.reads,
  });
  // The session binds the account the owner's root packages define, so the
  // address depends on the owner authority, never on the session.
  const account = await sessionRuntime.bindAccount({
    accountIndex: "0",
    initialPackages: ownerRuntime.packages,
  });
  await harness.fund(account.account, parseEther("1"));
  return { chain, harness, ownerKey, ownerRuntime, sessionRuntime, account };
}

(requireAnvil ? describe : describe.skip)("all-chain materialization local proof", () => {
  it("applies the Monad enable gas floor before signing an actual first operation", async () => {
    const target = lower(privateKeyToAccount(generatePrivateKey()).address);
    const stack = await bringUp(
      143,
      countingOwner(),
      privateKeyToAccount(generatePrivateKey()),
      target,
    );
    const approval = await approveKernelPermissionAllChain({
      owner: stack.ownerKey,
      account: stack.account.account,
      installNonce: "0",
      packages: stack.sessionRuntime.packages,
    });
    const quoted = { ...gas, verificationGasLimit: "200000" };
    const first = await materializeKernelPermission({
      approval,
      runtime: stack.sessionRuntime,
      grantId: "enable-floor",
      account: stack.account,
      nonceKey: "0",
      sequence: "0",
      calls: [{ target, value: "1", data: "0x" }],
      gas: quoted,
    });
    expect(first.prepared.userOperation.verificationGasLimit).toBe("2000000");
    expect(await stack.harness.sendSigned(first.prepared, first.signature)).toBe("success");
    const account = await stack.sessionRuntime.bindAccount({
      accountIndex: "0",
      initialPackages: stack.ownerRuntime.packages,
    });
    const second = stack.sessionRuntime.prepareOperation({
      kind: "execution",
      grantId: "installed-no-floor",
      account,
      nonceKey: "0",
      sequence: "0",
      calls: [{ target, value: "1", data: "0x" }],
      gas: quoted,
    });
    expect(second.userOperation.verificationGasLimit).toBe("200000");
    expect(await stack.harness.send(stack.sessionRuntime, second)).toBe("success");
    expect(await stack.harness.client.getBalance({ address: target })).toBe(2n);
  }, 30_000);

  it("invalidates an unused chain approval without invalidating another grant", async () => {
    const owner = countingOwner();
    const sessionKey = privateKeyToAccount(generatePrivateKey());
    const target = lower(privateKeyToAccount(generatePrivateKey()).address);
    const installNonce = kernelPermissionInstallNonce(`0x${"33".repeat(32)}`);
    const a = await bringUp(CHAIN_A, owner, sessionKey, target);
    const approval = await approveKernelPermissionAllChain({
      owner: a.ownerKey,
      account: a.account.account,
      installNonce,
      packages: a.sessionRuntime.packages,
    });
    const first = await materializeKernelPermission({
      approval,
      runtime: a.sessionRuntime,
      grantId: "installed-on-a",
      account: a.account,
      nonceKey: "0",
      sequence: "0",
      calls: [{ target, value: "500", data: "0x" }],
      gas,
    });
    expect(await a.harness.sendSigned(first.prepared, first.signature)).toBe("success");

    // B has never deployed the account or installed this permission. The
    // owner operation deploys the account and invalidates only the approval key.
    const b = await bringUp(CHAIN_B, owner, sessionKey, target);
    expect(b.account.account).toBe(a.account.account);
    expect(b.account.state).toBe("counterfactual");
    if (b.sessionRuntime.validation.kind !== "permission") throw new Error("expected permission");
    const observation: OperationObserverCapabilities = {
      close: async () => {},
      async read(request) {
        if (request.type === "chain_id") return b.harness.client.getChainId();
        if (request.type === "finalized_block" || request.type === "canonical_block") {
          const block = await b.harness.client.getBlock(
            request.type === "finalized_block"
              ? { blockTag: "finalized" }
              : { blockNumber: BigInt(request.blockNumber) },
          );
          return { number: `0x${block.number.toString(16)}`, hash: block.hash };
        }
        if (request.type === "kernel_permission_installed")
          return b.harness.client.readContract({
            address: request.account,
            abi: KERNEL_MODULE_VIEW_ABI,
            functionName: "isModuleInstalled",
            args: [6n, request.signer, request.permissionId],
            blockNumber: BigInt(request.blockNumber),
          });
        if (request.type === "kernel_install_nonce")
          return (
            await b.harness.client.call({
              to: request.account,
              data: encodeKernelV4InstallNonceRead({
                key: (BigInt(request.nonce) >> 64n).toString(10),
              }),
              blockNumber: BigInt(request.blockNumber),
            })
          ).data;
        throw new Error("unexpected revocation effect read");
      },
    };
    const observeRevocation = () =>
      observeKernelPermissionRevocation({
        binding: {
          chainId: CHAIN_B,
          account: b.account.account,
          permissionId:
            b.sessionRuntime.validation.kind === "permission"
              ? b.sessionRuntime.validation.permissionId
              : "0x00000000",
        },
        approval,
        observation,
        now: () => 100,
      });
    // The account is not deployed on B yet: missing code is unreadable, not absent.
    expect(await observeRevocation()).toEqual({ status: "unreadable" });
    const invalidation = b.ownerRuntime.prepareOperation({
      kind: "revocation",
      grantId: "invalidate-unused-on-b",
      account: b.account,
      nonceKey: "0",
      sequence: "0",
      calls: [
        encodeKernelInstallNonceInvalidationCall({ account: b.account.account, installNonce }),
      ],
      gas,
    });
    expect(await b.harness.send(b.ownerRuntime, invalidation)).toBe("success");
    const readNonce = async (nonce: string) => {
      const result = await b.harness.client.call({
        to: b.account.account,
        data: encodeKernelV4InstallNonceRead({ key: (BigInt(nonce) >> 64n).toString(10) }),
      });
      if (result.data === undefined || result.data.length !== 66) throw new Error("missing nonce");
      return BigInt(result.data);
    };
    expect(await readNonce(installNonce)).toBe(BigInt(installNonce) + 1n);
    await b.harness.client.request({
      method: "anvil_mine" as "eth_chainId",
      params: ["0x40"] as never,
    });
    const verified = await observeRevocation();
    // The public verifier derives the same binding from the approval alone.
    expect(
      await verifyKernelPermissionRevocation({
        approval,
        chainId: CHAIN_B,
        reads: observation,
        now: () => 100,
      }),
    ).toEqual(verified);
    expect(
      await readKernelPermissionStatus({
        approval,
        chainId: CHAIN_B,
        blockTag: "finalized",
        reads: createKernelReads(b.harness.client),
      }),
    ).toEqual({ status: "revoked", installNonce: (BigInt(installNonce) + 1n).toString() });
    expect(
      await readKernelPermissionStatus({
        approval,
        chainId: CHAIN_A,
        blockTag: "latest",
        reads: createKernelReads(a.harness.client),
      }),
    ).toEqual({ status: "installed" });
    const effectProof = verified.status === "revoked" ? verified.evidence : null;
    expect(effectProof?.installNonce).toBe((BigInt(installNonce) + 1n).toString(10));
    expect(effectProof?.permission).toMatchObject({
      chainId: CHAIN_B,
      account: b.account.account,
      kind: "permission_absent",
    });
    expect(
      await b.harness.client.readContract({
        address: b.account.account,
        abi: parseAbi(["function validNonceFrom() view returns (uint64)"]),
        functionName: "validNonceFrom",
      }),
    ).toBe(0n);
    const deployed = await b.sessionRuntime.bindAccount({
      accountIndex: "0",
      initialPackages: b.ownerRuntime.packages,
    });
    const refused = await materializeKernelPermission({
      approval,
      runtime: b.sessionRuntime,
      grantId: "old-approval-on-b",
      account: deployed,
      nonceKey: "0",
      sequence: "0",
      calls: [{ target, value: "500", data: "0x" }],
      gas,
    });
    expect(await b.harness.rejectionOf(refused.prepared, refused.signature)).toMatchObject({
      errorName: "FailedOpWithRevert",
      args: [0n, "AA23 reverted", toFunctionSelector("InvalidNonce()")],
    });
    expect(await b.harness.client.getBalance({ address: target })).toBe(0n);

    const otherNonce = kernelPermissionInstallNonce(`0x${"44".repeat(32)}`);
    expect(await readNonce(otherNonce)).toBe(BigInt(otherNonce));
    const otherTarget = lower(privateKeyToAccount(generatePrivateKey()).address);
    const otherRuntime = createKernelRuntime({
      deployment: kernelDeployment({ chainId: CHAIN_B }),
      operator: sessionOperator({
        key: kernelKey({
          account: privateKeyToAccount(generatePrivateKey()),
          validator: await b.harness.deployValidatorCreate2(),
        }),
        policies: [
          {
            kind: "call",
            permissions: [{ target: otherTarget, selector: "0x00000000", valueLimit: "500" }],
          },
        ],
      }),
      reads: b.harness.reads,
    });
    const otherApproval = await approveKernelPermissionAllChain({
      owner: b.ownerKey,
      account: b.account.account,
      installNonce: otherNonce,
      packages: otherRuntime.packages,
    });
    expect(
      await readKernelPermissionStatus({
        approval: otherApproval,
        chainId: CHAIN_B,
        blockTag: "latest",
        reads: createKernelReads(b.harness.client),
      }),
    ).toEqual({ status: "approval-replayable" });
    const other = await materializeKernelPermission({
      approval: otherApproval,
      runtime: otherRuntime,
      grantId: "other-grant-on-b",
      account: await otherRuntime.bindAccount({
        accountIndex: "0",
        initialPackages: b.ownerRuntime.packages,
      }),
      nonceKey: "0",
      sequence: "0",
      calls: [{ target: otherTarget, value: "500", data: "0x" }],
      gas,
    });
    expect(await b.harness.sendSigned(other.prepared, other.signature)).toBe("success");
    expect(await b.harness.client.getBalance({ address: otherTarget })).toBe(500n);
    expect(await readNonce(installNonce)).toBe(BigInt(installNonce) + 1n);
    expect(await a.harness.client.getBalance({ address: target })).toBe(500n);
    expect(owner.signatures()).toBe(3); // two approvals and one owner invalidation operation
  }, 180_000);

  it("installs two grants in opposite chain orders without sharing install counters", async () => {
    const owner = countingOwner();
    const firstKey = privateKeyToAccount(generatePrivateKey());
    const firstTarget = lower(privateKeyToAccount(generatePrivateKey()).address);
    const secondKey = privateKeyToAccount(generatePrivateKey());
    const secondTarget = lower(privateKeyToAccount(generatePrivateKey()).address);
    const firstNonce = kernelPermissionInstallNonce(`0x${"11".repeat(32)}`);
    const secondNonce = kernelPermissionInstallNonce(`0x${"22".repeat(32)}`);
    const a = await bringUp(CHAIN_A, owner, firstKey, firstTarget);
    const secondRuntime = async (stack: ChainStack) =>
      createKernelRuntime({
        deployment: kernelDeployment({ chainId: stack.chain.chainId }),
        operator: sessionOperator({
          key: kernelKey({
            account: secondKey,
            validator: await stack.harness.deployValidatorCreate2(),
          }),
          policies: [
            {
              kind: "call",
              permissions: [{ target: secondTarget, selector: "0x00000000", valueLimit: "500" }],
            },
          ],
        }),
        reads: stack.harness.reads,
      });
    const firstApproval = await approveKernelPermissionAllChain({
      owner: a.ownerKey,
      account: a.account.account,
      installNonce: firstNonce,
      packages: a.sessionRuntime.packages,
    });
    const prepare = async (
      stack: ChainStack,
      runtime: Readonly<KernelRuntime>,
      approval: Readonly<KernelAllChainApproval>,
      target: `0x${string}`,
      sequence = "0",
    ) =>
      materializeKernelPermission({
        approval,
        runtime,
        grantId: approval.installNonce,
        account: await runtime.bindAccount({
          accountIndex: "0",
          initialPackages: stack.ownerRuntime.packages,
        }),
        nonceKey: "0",
        sequence,
        calls: [{ target, value: "500", data: "0x" }],
        gas,
      });
    const install = async (
      stack: ChainStack,
      runtime: Readonly<KernelRuntime>,
      approval: Readonly<KernelAllChainApproval>,
      target: `0x${string}`,
    ) => {
      const operation = await prepare(stack, runtime, approval, target);
      expect(await stack.harness.sendSigned(operation.prepared, operation.signature)).toBe(
        "success",
      );
      expect(await stack.harness.client.getBalance({ address: target })).toBe(500n);
    };

    // Grant one is installed on A before grant two even exists. Chain B has no
    // account or install history yet when both owner approvals are produced.
    await install(a, a.sessionRuntime, firstApproval, firstTarget);
    const secondA = await secondRuntime(a);
    const secondApproval = await approveKernelPermissionAllChain({
      owner: a.ownerKey,
      account: a.account.account,
      installNonce: secondNonce,
      packages: secondA.packages,
    });
    expect(owner.signatures()).toBe(2);
    const b = await bringUp(CHAIN_B, owner, firstKey, firstTarget);
    const secondB = await secondRuntime(b);
    expect(b.account.account).toBe(a.account.account);
    expect(secondB.packages).toEqual(secondA.packages);
    expect(secondA.validation).not.toEqual(a.sessionRuntime.validation);
    await install(b, secondB, secondApproval, secondTarget);
    await install(a, secondA, secondApproval, secondTarget);
    await install(b, b.sessionRuntime, firstApproval, firstTarget);

    // A fresh EntryPoint sequence does not revive a consumed install approval.
    // Assert Kernel's own refusal, excluding EntryPoint nonce reuse as a cause.
    const reused = await prepare(a, a.sessionRuntime, firstApproval, firstTarget, "1");
    expect(await a.harness.rejectionOf(reused.prepared, reused.signature)).toMatchObject({
      errorName: "FailedOpWithRevert",
      args: [0n, "AA23 reverted", toFunctionSelector("InvalidNonce()")],
    });
    expect(await a.harness.client.getBalance({ address: firstTarget })).toBe(500n);
    expect(owner.signatures()).toBe(2);
  }, 180_000);

  it("retains validation-installed permission when enable-mode execution reverts", async () => {
    const owner = countingOwner();
    const sessionKeyAccount = privateKeyToAccount(generatePrivateKey());
    const placeholderTarget = lower(privateKeyToAccount(generatePrivateKey()).address);
    const stack = await bringUp(CHAIN_A, owner, sessionKeyAccount, placeholderTarget);
    const deploymentHash = await stack.harness.wallet.deployContract({
      account: stack.harness.submitter,
      chain: null,
      abi: [],
      bytecode: REVERTING_CONTRACT_DEPLOYMENT,
      gas: 500_000n,
    });
    const deploymentReceipt = await stack.harness.client.waitForTransactionReceipt({
      hash: deploymentHash,
    });
    if (
      deploymentReceipt.status !== "success" ||
      deploymentReceipt.contractAddress === null ||
      deploymentReceipt.contractAddress === undefined
    ) {
      throw new Error("reverting target deployment failed");
    }
    const revertingTarget = lower(deploymentReceipt.contractAddress);
    const sessionRuntime = createKernelRuntime({
      deployment: kernelDeployment({ chainId: CHAIN_A }),
      operator: sessionOperator({
        key: kernelKey({
          account: sessionKeyAccount,
          validator: await stack.harness.deployValidatorCreate2(),
        }),
        policies: [
          {
            kind: "call",
            permissions: [{ target: revertingTarget, selector: "0x00000000", valueLimit: "0" }],
          },
        ],
      }),
      reads: stack.harness.reads,
    });
    const account = await sessionRuntime.bindAccount({
      accountIndex: "0",
      initialPackages: stack.ownerRuntime.packages,
    });
    const approval = await approveKernelPermissionAllChain({
      owner: stack.ownerKey,
      account: account.account,
      installNonce: INSTALL_NONCE,
      packages: sessionRuntime.packages,
    });
    const materialized = await materializeKernelPermission({
      approval,
      runtime: sessionRuntime,
      grantId: "enable-revert-installation",
      account,
      nonceKey: "0",
      sequence: "0",
      calls: [{ target: revertingTarget, value: "0", data: "0x" }],
      gas,
    });

    expect(await stack.harness.sendSigned(materialized.prepared, materialized.signature)).toBe(
      "reverted",
    );
    if (sessionRuntime.validation.kind !== "permission") {
      throw new Error("session runtime carries no permission validation");
    }
    const signer = sessionRuntime.packages.find((entry) => entry.moduleType === 6)?.module;
    if (signer === undefined) throw new Error("session runtime carries no signer module");
    expect(
      await stack.harness.client.readContract({
        address: account.account,
        abi: KERNEL_MODULE_VIEW_ABI,
        functionName: "isModuleInstalled",
        args: [6n, signer, sessionRuntime.validation.permissionId],
      }),
    ).toBe(true);

    const deployed = await stack.ownerRuntime.bindAccount({
      accountIndex: "0",
      initialPackages: stack.ownerRuntime.packages,
    });
    expect(
      await stack.harness.send(
        stack.ownerRuntime,
        stack.ownerRuntime.prepareOperation({
          kind: "revocation",
          grantId: "enable-revert-uninstall",
          account: deployed,
          nonceKey: "0",
          sequence: "0",
          calls: encodeKernelPermissionUninstallCalls({
            account: account.account,
            packages: sessionRuntime.packages,
          }),
          gas,
        }),
      ),
    ).toBe("success");
    expect(
      await stack.harness.client.readContract({
        address: account.account,
        abi: KERNEL_MODULE_VIEW_ABI,
        functionName: "isModuleInstalled",
        args: [6n, signer, sessionRuntime.validation.permissionId],
      }),
    ).toBe(false);
    expect(owner.signatures()).toBe(2);
  }, 90_000);

  it("materializes one replayable owner approval on two chains with different chain ids", async () => {
    const owner = countingOwner();
    // One session credential and one scope, shared by both chains: the canonical
    // policy and operator credential an all-chain grant approves once.
    const sessionKeyAccount = privateKeyToAccount(generatePrivateKey());
    const sessionTarget = lower(privateKeyToAccount(generatePrivateKey()).address);

    // Chain A only. Chain B does not exist yet, and the approval below is taken
    // before it does, so nothing about it can depend on chain B.
    const a = await bringUp(CHAIN_A, owner, sessionKeyAccount, sessionTarget);
    expect(a.account.state).toBe("counterfactual");
    expect(a.account.chainId).toBe(CHAIN_A);

    // The one owner approval. It reads no chain and no deployment profile.
    const approval: Readonly<KernelAllChainApproval> = await approveKernelPermissionAllChain({
      owner: a.ownerKey,
      account: a.account.account,
      installNonce: INSTALL_NONCE,
      packages: a.sessionRuntime.packages,
    });
    expect(owner.signatures()).toBe(1);
    // A Kernel 0.4.0 Grant revokes through its grant handle, not staged revocation.
    await expect(
      prepareKernelPermissionRevocation({
        approval,
        chainId: CHAIN_A,
        reads: a.harness.reads,
        nonceKey: "0",
        sequence: "0",
        gas,
      }),
    ).rejects.toMatchObject({ code: "kernel_runtime_unsupported" });
    // The digest is reproducible from the approval's own chain-independent fields.
    expect(approval.digest).toBe(
      kernelV4ReplayableInstallDigest({
        account: a.account.account,
        nonce: INSTALL_NONCE,
        packages: a.sessionRuntime.packages,
      }),
    );

    // Chain A: the session's first operation carries the enable envelope, so one
    // submission deploys the account, installs the permission, and executes the
    // covered call. The owner signs no UserOperation at all.
    const materializedA = await materializeKernelPermission({
      approval,
      runtime: a.sessionRuntime,
      grantId: "all-chain-a",
      account: a.account,
      nonceKey: "0",
      sequence: "0",
      calls: [{ target: sessionTarget, value: "500", data: "0x" }],
      gas,
    });
    expect(materializedA.prepared.chainId).toBe(CHAIN_A);
    expect(materializedA.prepared.userOperation.factory?.address).toBe(a.account.factory);
    expect(await a.harness.sendSigned(materializedA.prepared, materializedA.signature)).toBe(
      "success",
    );
    expect(await a.harness.client.getBalance({ address: sessionTarget })).toBe(500n);
    expect(owner.signatures()).toBe(1);

    // Chain B, introduced now: the same stack at the same addresses, and the same
    // account address, because every address is CREATE2-derived.
    const b = await bringUp(CHAIN_B, owner, sessionKeyAccount, sessionTarget);
    expect(b.chain.chainId).not.toBe(a.chain.chainId);
    expect(b.account.chainId).toBe(CHAIN_B);
    expect(b.account.account).toBe(a.account.account);
    expect(b.account.state).toBe("counterfactual");
    expect(b.ownerRuntime.authorityModule).toBe(a.ownerRuntime.authorityModule);
    // One scope, one permission ID, on both chains.
    expect(b.sessionRuntime.validation).toEqual(a.sessionRuntime.validation);
    expect(b.sessionRuntime.packages).toEqual(a.sessionRuntime.packages);

    // The same approval — the same digest and the same owner signature bytes —
    // materializes the same permission on chain B. No new owner signature.
    const materializedB = await materializeKernelPermission({
      approval,
      runtime: b.sessionRuntime,
      grantId: "all-chain-b",
      account: b.account,
      nonceKey: "0",
      sequence: "0",
      calls: [{ target: sessionTarget, value: "500", data: "0x" }],
      gas,
    });
    expect(materializedB.prepared.chainId).toBe(CHAIN_B);
    // The operation identity is chain-local even though the approval is not.
    expect(materializedB.prepared.userOperationHash).not.toBe(
      materializedA.prepared.userOperationHash,
    );
    expect(await b.harness.sendSigned(materializedB.prepared, materializedB.signature)).toBe(
      "success",
    );
    expect(await b.harness.client.getBalance({ address: sessionTarget })).toBe(500n);

    // The whole point, asserted on the credential: exactly one owner signature
    // covered an account deployment, a permission install and a session execution
    // on two chains with different chain ids.
    expect(owner.signatures()).toBe(1);

    // Chain B's permission is installed, so the session's next operation there is
    // an ordinary standard-mode one and needs no envelope. Kernel encodes the
    // validation mode into the EntryPoint nonce key, so standard mode is a
    // different key than the enable-mode materialization and its own sequence
    // starts at zero — the materialization did not consume this lane.
    const deployedB = await b.sessionRuntime.bindAccount({
      accountIndex: "0",
      initialPackages: b.ownerRuntime.packages,
    });
    expect(deployedB.state).toBe("deployed");
    expect(
      await b.harness.send(
        b.sessionRuntime,
        b.sessionRuntime.prepareOperation({
          kind: "execution",
          grantId: "all-chain-b-standard",
          account: deployedB,
          nonceKey: "0",
          sequence: "0",
          calls: [{ target: sessionTarget, value: "500", data: "0x" }],
          gas,
        }),
      ),
    ).toBe("success");
    expect(await b.harness.client.getBalance({ address: sessionTarget })).toBe(1_000n);

    // The materialized scope is the approved scope, not whole-account authority:
    // on chain B a target the policy never named is refused before any key
    // signs, with the structured call-policy code.
    const uncoveredTarget = lower(privateKeyToAccount(generatePrivateKey()).address);
    expect(() =>
      b.sessionRuntime.prepareOperation({
        kind: "execution",
        grantId: "all-chain-b-uncovered",
        account: deployedB,
        nonceKey: "0",
        sequence: "1",
        calls: [{ target: uncoveredTarget, value: "1", data: "0x" }],
        gas,
      }),
    ).toThrowError(expect.objectContaining({ code: "kernel_runtime_call_forbidden" }));
    expect(await b.harness.client.getBalance({ address: uncoveredTarget })).toBe(0n);
    expect(owner.signatures()).toBe(1);
  }, 180_000);
});
