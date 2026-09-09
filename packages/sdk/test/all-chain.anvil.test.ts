/**
 * One owner approval, two chains, one owner signature.
 *
 * Both chains run the identical pinned stack at identical addresses. The owner
 * approves once — one `sign()` invocation, counted on the credential itself —
 * and that single chain-agnostic enable signature deploys the account, installs
 * the permission and authorizes the session's first call on chain A, then does
 * the same on chain B, which is introduced only after the approval exists.
 *
 * @author taek <leekt216@gmail.com>
 */
import { p256 } from "@noble/curves/nist.js";
import {
  hashKernelV4RevocationSigningRequest,
  hashOwnerSigningRequest,
  parsePermissionRequest,
} from "@oaath/protocol";
import { bytesToHex, hexToBytes, parseAbi, parseEther, toFunctionSelector } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { afterAll, describe, expect, it } from "vitest";
import { deriveSessionPolicyProfiles } from "../src/kernel/permission/profiles.js";
import {
  approveKernelPermissionAllChain,
  createKernelRuntime,
  type EcdsaSignRequest,
  ecdsaKey,
  encodeKernelV4InstallNonceInvalidationCall,
  encodeKernelV4InstallNonceRead,
  encodeKernelV4PermissionUninstallCalls,
  type KernelAllChainApproval,
  type KernelRuntime,
  type KernelV4AccountDescriptor,
  type KeyProfile,
  kernelPermissionInstallNonce,
  kernelV4Deployment,
  kernelV4ReplayableInstallDigest,
  materializeKernelPermission,
  ownerOperator,
  p256Key,
  prepareKernelPhonePermissionApproval,
  prepareKernelPhoneRevocation,
  sessionOperator,
} from "../src/kernel.js";
import {
  type AnvilChain,
  createHarness,
  deployKernelStack,
  type KernelHarness,
  lower,
  startAnvil,
} from "./support/anvil.js";
import { accountProfile, workspaceContext } from "./support/browser.js";

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
/**
 * ZeroDev CallPolicy's `InvalidCallData()`: the operation named a
 * (target, selector) pair the installed permission holds no entry for. Naming the
 * class from its signature keeps the assertion machine-checked rather than prose.
 */
const CALL_POLICY_INVALID_CALL_DATA = toFunctionSelector("InvalidCallData()");
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

  const deployment = kernelV4Deployment(chainId);
  const ownerKey = ecdsaKey({ account: owner.account, validator });
  const ownerRuntime = createKernelRuntime({
    deployment,
    operator: ownerOperator({ key: ownerKey }),
    reads: harness.reads,
  });
  const sessionRuntime = createKernelRuntime({
    deployment,
    operator: sessionOperator({
      key: ecdsaKey({ account: sessionKeyAccount, validator }),
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
  it.each(["invalidate-install", "uninstall-permission"] as const)(
    "accepts the phone's exact P-256 %s operation on Kernel",
    async (effect) => {
      const chain = await startAnvil(CHAIN_A, "osaka");
      chains.push(chain);
      const harness = await createHarness(chain);
      await deployKernelStack(harness);
      for (const module of [
        harness.fixture.p256Validator,
        harness.fixture.ecdsaSigner,
        harness.fixture.callPolicy,
        harness.fixture.validityPolicy,
        harness.fixture.rateLimitPolicy,
      ])
        await harness.deployModule(module);
      const secret = p256.utils.randomPrivateKey();
      const sessionAccount = privateKeyToAccount(generatePrivateKey());
      const target = lower(privateKeyToAccount(generatePrivateKey()).address);
      const now = Number((await harness.client.getBlock()).timestamp);
      const request = parsePermissionRequest({
        version: "oaath.permission-request/v2",
        requestId: `phone-${effect}`,
        context: workspaceContext,
        application: {
          applicationId: "app-1",
          clientId: "client-1",
          origin: "https://app.example",
          deviceId: "device-1",
        },
        chainScope: "all",
        logicalAccount: {
          ...accountProfile,
          ownerCredential: {
            version: "oaath.owner-credential-profile/v1",
            kind: "p256",
            publicKey: bytesToHex(p256.getPublicKey(secret, false)),
          },
        },
        operatorCredential: {
          version: "oaath.operator-credential-profile/v1",
          kind: "ecdsa",
          address: lower(sessionAccount.address),
        },
        sessionSigner: null,
        policy: {
          version: "oaath.grant-policy/v1",
          calls: [{ target, selector: "0x12345678", valueLimit: "500", argumentEquals: [] }],
          validAfter: 0,
          validUntil: now + 600,
          perChainOperationLimit: 3,
        },
        requestedAt: now,
        expiresAt: now + 601,
      });
      let signatures = 0;
      const sign = (digest: `0x${string}`, requestHash: `0x${string}`) => {
        signatures += 1;
        return {
          version: "oaath.owner-signing-artifact/v1" as const,
          kind: "p256" as const,
          requestHash,
          signature: bytesToHex(
            p256
              .sign(hexToBytes(digest), secret, { prehash: false, lowS: true })
              .toCompactRawBytes(),
          ),
        };
      };
      const permission = await prepareKernelPhonePermissionApproval({
        request,
        chainId: CHAIN_A,
        reads: harness.reads,
      });
      const { installApproval } = await permission.complete(
        sign(
          permission.signingRequest.expectedDigest,
          hashOwnerSigningRequest(permission.signingRequest),
        ),
        now,
      );
      await harness.fund(installApproval.account, parseEther("1"));
      const deployment = kernelV4Deployment(CHAIN_A);
      const owner = createKernelRuntime({
        deployment,
        operator: ownerOperator({
          key: p256Key({
            credential: request.logicalAccount.ownerCredential,
            sign: async () => {
              throw new Error("owner secret stays with phone fixture");
            },
          }),
        }),
        reads: harness.reads,
      });
      const session = createKernelRuntime({
        deployment,
        operator: sessionOperator({
          key: ecdsaKey({
            account: sessionAccount,
            validator: await harness.deployValidatorCreate2(),
          }),
          policies: deriveSessionPolicyProfiles(request.policy),
        }),
        reads: harness.reads,
      });
      const materialize = async () =>
        materializeKernelPermission({
          approval: installApproval,
          runtime: session,
          grantId: request.requestId,
          account: await session.bindAccount({
            accountIndex: "0",
            initialPackages: owner.packages,
          }),
          nonceKey: "0",
          sequence: effect === "uninstall-permission" ? "1" : "0",
          calls: [{ target, value: "500", data: "0x12345678" }],
          gas,
        });
      if (effect === "uninstall-permission") {
        const installed = await materializeKernelPermission({
          approval: installApproval,
          runtime: session,
          grantId: request.requestId,
          account: await session.bindAccount({
            accountIndex: "0",
            initialPackages: owner.packages,
          }),
          nonceKey: "0",
          sequence: "0",
          calls: [{ target, value: "500", data: "0x12345678" }],
          gas,
        });
        expect(await harness.sendSigned(installed.prepared, installed.signature)).toBe("success");
      }
      const revocation = await prepareKernelPhoneRevocation({
        request,
        approval: installApproval,
        chainId: CHAIN_A,
        reads: harness.reads,
        effect,
        nonceKey: "0",
        sequence: "0",
        gas,
      });
      expect(revocation.prepared.userOperation.factory !== null).toBe(
        effect === "invalidate-install",
      );
      const signature = await revocation.complete(
        sign(
          revocation.signingRequest.expectedDigest,
          hashKernelV4RevocationSigningRequest(revocation.signingRequest),
        ),
      );
      expect(await harness.sendSigned(revocation.prepared, signature)).toBe("success");
      if (session.validation.kind !== "permission") throw new Error("permission validation absent");
      const signer = session.packages.find((entry) => entry.moduleType === 6)?.module;
      if (!signer) throw new Error("permission signer absent");
      expect(
        await harness.client.readContract({
          address: installApproval.account,
          abi: KERNEL_MODULE_VIEW_ABI,
          functionName: "isModuleInstalled",
          args: [6n, signer, session.validation.permissionId],
        }),
      ).toBe(false);
      const refused = await materialize();
      expect(await harness.rejectionOf(refused.prepared, refused.signature)).toMatchObject({
        errorName: "FailedOpWithRevert",
        args: [0n, "AA23 reverted", toFunctionSelector("InvalidNonce()")],
      });
      expect(signatures).toBe(2);
    },
    120_000,
  );

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
    const invalidation = b.ownerRuntime.prepareOperation({
      kind: "revocation",
      grantId: "invalidate-unused-on-b",
      account: b.account,
      nonceKey: "0",
      sequence: "0",
      calls: [
        encodeKernelV4InstallNonceInvalidationCall({ account: b.account.account, installNonce }),
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
      deployment: kernelV4Deployment(CHAIN_B),
      operator: sessionOperator({
        key: ecdsaKey({
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
        deployment: kernelV4Deployment(stack.chain.chainId),
        operator: sessionOperator({
          key: ecdsaKey({
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
      deployment: kernelV4Deployment(CHAIN_A),
      operator: sessionOperator({
        key: ecdsaKey({
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
          calls: encodeKernelV4PermissionUninstallCalls({
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
    // on chain B a target the policy never named is refused inside Kernel's
    // validation phase by CallPolicy itself, and the refusal is decoded to its
    // class rather than observed as a bare revert.
    const uncoveredTarget = lower(privateKeyToAccount(generatePrivateKey()).address);
    expect(
      await b.harness.rejection(
        b.sessionRuntime,
        b.sessionRuntime.prepareOperation({
          kind: "execution",
          grantId: "all-chain-b-uncovered",
          account: deployedB,
          nonceKey: "0",
          sequence: "1",
          calls: [{ target: uncoveredTarget, value: "1", data: "0x" }],
          gas,
        }),
      ),
    ).toMatchObject({
      errorName: "FailedOpWithRevert",
      args: [0n, "AA23 reverted", CALL_POLICY_INVALID_CALL_DATA],
    });
    expect(await b.harness.client.getBalance({ address: uncoveredTarget })).toBe(0n);
    expect(owner.signatures()).toBe(1);
  }, 180_000);
});
