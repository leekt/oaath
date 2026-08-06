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
import { parseEther, toFunctionSelector } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { afterAll, describe, expect, it } from "vitest";
import {
  approveKernelPermissionAllChain,
  createKernelRuntime,
  type EcdsaSignRequest,
  ecdsaKey,
  type KernelAllChainApproval,
  type KernelRuntime,
  type KernelV4AccountDescriptor,
  type KernelV4SupportedChainId,
  type KeyProfile,
  kernelV4Deployment,
  kernelV4ReplayableInstallDigest,
  materializeKernelPermission,
  ownerOperator,
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

const requireAnvil = process.env.OAATH_REQUIRE_ANVIL === "1";
/** Chain A, and chain B, which this proof treats as introduced after approval. */
const CHAIN_A = 421_614 satisfies KernelV4SupportedChainId;
const CHAIN_B = 11_155_111 satisfies KernelV4SupportedChainId;
/** Kernel's own install nonce for the one approval; per-chain state, same value. */
const INSTALL_NONCE = "0";
/**
 * ZeroDev CallPolicy's `InvalidCallData()`: the operation named a
 * (target, selector) pair the installed permission holds no entry for. Naming the
 * class from its signature keeps the assertion machine-checked rather than prose.
 */
const CALL_POLICY_INVALID_CALL_DATA = toFunctionSelector("InvalidCallData()");

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
  chainId: KernelV4SupportedChainId,
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
