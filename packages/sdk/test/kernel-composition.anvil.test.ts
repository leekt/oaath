import { p256 } from "@noble/curves/nist.js";
import { OAATH_OWNER_CREDENTIAL_PROFILE_VERSION } from "@oaath/protocol";
import { bytesToHex, hexToBytes, keccak256, parseEther, toFunctionSelector } from "viem";
import { generatePrivateKey, type PrivateKeyAccount, privateKeyToAccount } from "viem/accounts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  captureRoutingCapabilities,
  classifyBundlerAcceptance,
  createKernelRuntime,
  decideExecution,
  deriveHandleOpsRequirement,
  ecdsaKey,
  encodeHandleOps,
  encodeKernelV4InstallModules,
  KERNEL_V4_CREATE2_DEPLOYER,
  KERNEL_V4_ENTRY_POINT_V07,
  KERNEL_V4_EXECUTE_USER_OP_SELECTOR,
  type KeyProfile,
  kernelV4Deployment,
  OAATH_HANDLE_OPS_OVERHEAD_GAS,
  ownerOperator,
  p256Key,
  pinnedPolicyModule,
  pinnedSignerModule,
  sessionOperator,
} from "../src/index.js";
// Internal on purpose: a consumer reads this fact through
// diagnoseKernelCapability, so the pinned validator stays off the public surface.
import { pinnedValidatorModule } from "../src/kernel/modules.js";
import {
  type AnvilChain,
  createHarness as createChainHarness,
  deployKernelStack,
  lower,
  startAnvil,
} from "./support/anvil.js";

const requireAnvil = process.env.OAATH_REQUIRE_ANVIL === "1";
/**
 * The two refusals ZeroDev's pinned CallPolicy raises for the two scope axes it
 * enforces, named from their Solidity signatures so each assertion is
 * machine-checked against a distinct class instead of a shared bare revert:
 *
 * - `InvalidCallData()` — the operation named a (target, selector) pair the
 *   installed permission holds no entry for at all.
 * - `CallViolatesValueRule()` — the pair is permitted, but the call carries more
 *   native value than the entry's ceiling.
 *
 * Both reach EntryPoint as `FailedOpWithRevert(0, "AA23 reverted", selector)`,
 * because CallPolicy reverts inside Kernel's validation phase rather than
 * returning Kernel's signature-failure sentinel.
 */
const CALL_POLICY_INVALID_CALL_DATA = toFunctionSelector("InvalidCallData()");
const CALL_POLICY_VIOLATES_VALUE_RULE = toFunctionSelector("CallViolatesValueRule()");
const chainId = 421_614;
const deployment = kernelV4Deployment(chainId);
const gas = Object.freeze({
  callGasLimit: "900000",
  verificationGasLimit: "3000000",
  preVerificationGas: "150000",
  maxFeePerGas: "2000000000",
  maxPriorityFeePerGas: "1000000000",
});

let anvil: AnvilChain | undefined;

/** One consumer-authored credential kind, which this SDK pins nothing for. */
const customKind = "custom:demo" as const;

/**
 * A consumer-authored KeyProfile wrapping the reviewed ECDSA machinery under a
 * kind this SDK never authored: the same secp256k1 signing and public material,
 * but every module resolved through the caller-bound path rather than a pin.
 */
function customKey(
  input: Readonly<{
    account: PrivateKeyAccount;
    validator: `0x${string}`;
    signerModule: `0x${string}` | null;
  }>,
): Readonly<KeyProfile> {
  const inner = ecdsaKey({ account: input.account, validator: input.validator });
  return Object.freeze({
    kind: customKind,
    publicMaterial: inner.publicMaterial,
    resolveValidator: inner.resolveValidator,
    signerModule: input.signerModule,
    dummySignature: inner.dummySignature,
    sign: inner.sign,
    verify: inner.verify,
  });
}

/**
 * One raw P-256 credential and the caller-owned signing capability behind it: the
 * exact shape the phone's Secure Enclave key takes, with the private scalar living
 * outside the SDK and only compact low-s (r ‖ s) crossing the boundary.
 */
function p256Owner(secret: `0x${string}`) {
  const secretKey = hexToBytes(secret);
  return p256Key({
    credential: Object.freeze({
      version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
      kind: "p256" as const,
      publicKey: bytesToHex(p256.getPublicKey(secretKey, false)),
    }),
    sign: ({ hash }) =>
      Promise.resolve(
        `0x${p256.sign(hexToBytes(hash), secretKey, { lowS: true, prehash: false }).toCompactHex()}`,
      ),
  });
}

beforeAll(async () => {
  if (!requireAnvil) return;
  anvil = await startAnvil(chainId);
});

afterAll(() => {
  anvil?.stop();
});

async function createHarness() {
  if (!anvil) throw new Error("Anvil is unavailable");
  return createChainHarness(anvil);
}

(requireAnvil ? describe : describe.skip)("Kernel composition local proof", () => {
  it("deploys every pinned module at its chain-independent address", async () => {
    const { fixture, client, wallet, submitter, deployCreate2 } = await createHarness();

    // A CREATE2 address is derived from deployer, salt and init code alone, so
    // code landing on the pinned address proves the registry names exactly this
    // reviewed module and that nothing about the address depends on the chain.
    // The runtime code hash is compared too, so a module whose deployed code ever
    // stopped matching the pinned artifact fails here rather than at validation.
    for (const [pinned, module] of [
      [pinnedSignerModule("ecdsa"), fixture.ecdsaSigner],
      [pinnedSignerModule("webauthn"), fixture.webAuthnSigner],
      [pinnedPolicyModule("call"), fixture.callPolicy],
      [pinnedPolicyModule("value"), fixture.callPolicy],
      [pinnedPolicyModule("expiry"), fixture.timestampPolicy],
      [pinnedPolicyModule("operation-limit"), fixture.rateLimitPolicy],
    ] as const) {
      expect(pinned).toBe(module.expectedAddress);
      if (pinned === null) throw new Error("registry pins no module for a bound axis");
      if (!(await client.getCode({ address: pinned }))) {
        await deployCreate2(module.deploymentInput);
      }
      const code = await client.getCode({ address: pinned });
      if (!code) throw new Error("pinned module carries no code");
      expect(keccak256(code)).toBe(module.runtimeCodeHash);
    }

    // The reviewed module sets ship no raw P-256 signer, so that axis stays
    // unbound instead of borrowing the WebAuthn module.
    expect(pinnedSignerModule("p256")).toBeNull();

    // The pinned raw P-256 validator is the one module whose dependency is a chain
    // feature rather than another deployment: it verifies through the RIP-7212 /
    // EIP-7951 precompile at 0x100 and its constructor reverts when that is
    // absent. This chain is Prague, which does not carry it, so the module cannot
    // exist here at all — the deployment is refused and the pinned address stays
    // codeless, which is exactly what makes bindAccount fail closed on such a
    // chain rather than deriving an account nothing can validate for.
    expect(pinnedValidatorModule("p256")).toBe(fixture.p256Validator.expectedAddress);
    const refused = await wallet.sendTransaction({
      account: submitter,
      chain: null,
      to: KERNEL_V4_CREATE2_DEPLOYER,
      data: fixture.p256Validator.deploymentInput,
      gas: 2_000_000n,
    });
    expect((await client.waitForTransactionReceipt({ hash: refused })).status).toBe("reverted");
    expect(
      await client.getCode({ address: fixture.p256Validator.expectedAddress }),
    ).toBeUndefined();
  }, 60_000);

  it("executes a P-256 owner and an ECDSA session installed under it", async () => {
    // Its own chain, at the hardfork that carries the P-256 precompile the pinned
    // validator verifies through. The proof above shows the same module refusing to
    // deploy on Prague, so this chain is not a convenience: it is the condition
    // under which a raw P-256 owner exists at all.
    const chain = await startAnvil(chainId, "osaka");
    try {
      const harness = await createChainHarness(chain);
      const { fixture, client, reads, deployModule, deployValidator, fund, send } = harness;
      await deployKernelStack(harness);

      // The pinned address holds the reviewed artifact, and the deployment itself is
      // the precompile evidence: this module's constructor probes 0x100 with a
      // known-valid vector and reverts P256PrecompileNotAvailable otherwise.
      const p256Validator = fixture.p256Validator;
      expect(pinnedValidatorModule("p256")).toBe(p256Validator.expectedAddress);
      await deployModule(p256Validator);
      const validatorCode = await client.getCode({ address: p256Validator.expectedAddress });
      if (!validatorCode) throw new Error("pinned P-256 validator carries no code");
      expect(keccak256(validatorCode)).toBe(p256Validator.runtimeCodeHash);

      // Root authority is the phone's key: the validator module the registry pins,
      // installed with the account's own initial packages.
      const ownerKey = p256Owner(`0x${"31".repeat(32)}`);
      const ownerRuntime = createKernelRuntime({
        deployment,
        operator: ownerOperator({ key: ownerKey }),
        reads,
      });
      expect(ownerRuntime.keyKind).toBe("p256");
      expect(ownerRuntime.authorityModule).toBe(p256Validator.expectedAddress);

      const counterfactual = await ownerRuntime.bindAccount({
        accountIndex: "0",
        initialPackages: ownerRuntime.packages,
      });
      expect(counterfactual).toMatchObject({ state: "counterfactual", chainId });
      const account = counterfactual.account;
      await fund(account, parseEther("1"));

      // One covered call, deploying the account in the same operation: the P-256
      // signature validates on-chain and the value moves.
      const ownerTarget = lower(privateKeyToAccount(generatePrivateKey()).address);
      const deployAndExecute = ownerRuntime.prepareOperation({
        kind: "execution",
        grantId: "kernel-composition-p256-owner",
        account: counterfactual,
        nonceKey: "0",
        sequence: "0",
        calls: [{ target: ownerTarget, value: "12345", data: "0x" }],
        gas,
      });
      expect(deployAndExecute.userOperation.factory?.address).toBe(deployment.factory);
      expect(await send(ownerRuntime, deployAndExecute)).toBe("success");
      expect(await client.getBalance({ address: ownerTarget })).toBe(12_345n);
      const deployed = await ownerRuntime.bindAccount({
        accountIndex: "0",
        initialPackages: ownerRuntime.packages,
      });
      expect(deployed).toMatchObject({ state: "deployed", account });

      // A signature from another P-256 key is refused by the installed validator,
      // not by this client: the SDK's own self-verification rejects it locally
      // first, so the on-chain refusal is proven with a signature produced outside
      // the runtime and handed straight to EntryPoint.
      const wrongKeyOperation = ownerRuntime.prepareOperation({
        kind: "execution",
        grantId: "kernel-composition-p256-wrong-key",
        account: deployed,
        nonceKey: "0",
        sequence: "1",
        calls: [{ target: ownerTarget, value: "1", data: "0x" }],
        gas,
      });
      const foreignSecret = hexToBytes(`0x${"32".repeat(32)}`);
      const signWithForeignKey = (hash: `0x${string}`) =>
        Promise.resolve(
          `0x${p256.sign(hexToBytes(hash), foreignSecret, { lowS: true, prehash: false }).toCompactHex()}` as const,
        );
      expect(
        await harness.rejectionOf(
          wrongKeyOperation,
          await signWithForeignKey(wrongKeyOperation.userOperationHash),
        ),
      ).toMatchObject({ errorName: "FailedOp", args: [0n, "AA24 signature error"] });
      // The same signature never leaves this SDK: a profile bound to the owner's
      // public key whose capability returns another key's signature fails its own
      // verification before any submission exists.
      await expect(
        createKernelRuntime({
          deployment,
          operator: ownerOperator({
            key: Object.freeze({ ...ownerKey, sign: signWithForeignKey }),
          }),
          reads,
        }).signOperation(wrongKeyOperation),
      ).rejects.toMatchObject({ code: "kernel_runtime_signature_invalid" });
      expect(await client.getBalance({ address: ownerTarget })).toBe(12_345n);

      // The session under that owner: the reviewed plugin set ships no raw P-256
      // permission signer, so the session key is ECDSA and its scope is policy
      // bound. This is the shape the phone flow installs — a P-256 root owner
      // approving an ECDSA session — and the owner signs the install.
      expect(pinnedSignerModule("p256")).toBeNull();
      await deployModule(fixture.callPolicy);
      await deployModule(fixture.ecdsaSigner);
      const sessionTarget = lower(privateKeyToAccount(generatePrivateKey()).address);
      const sessionRuntime = createKernelRuntime({
        deployment,
        operator: sessionOperator({
          key: ecdsaKey({
            account: privateKeyToAccount(generatePrivateKey()),
            validator: await deployValidator(),
          }),
          policies: [
            { kind: "call", calls: [{ target: sessionTarget, selectors: ["0x00000000"] }] },
            { kind: "value", maximumValue: "777" },
          ],
        }),
        reads,
      });
      expect(sessionRuntime.authorityModule).toBe(fixture.ecdsaSigner.expectedAddress);
      await expect(
        sessionRuntime.bindAccount({ accountIndex: "0", initialPackages: ownerRuntime.packages }),
      ).resolves.toMatchObject({ state: "deployed", account });
      expect(
        await send(
          ownerRuntime,
          ownerRuntime.prepareOperation({
            kind: "execution",
            grantId: "kernel-composition-p256-install",
            account: deployed,
            nonceKey: "0",
            sequence: "1",
            calls: [
              {
                target: account,
                value: "0",
                data: encodeKernelV4InstallModules(sessionRuntime.packages),
              },
            ],
            gas,
          }),
        ),
      ).toBe("success");

      expect(
        await send(
          sessionRuntime,
          sessionRuntime.prepareOperation({
            kind: "execution",
            grantId: "kernel-composition-p256-session",
            account: deployed,
            nonceKey: "0",
            sequence: "0",
            calls: [{ target: sessionTarget, value: "777", data: "0x" }],
            gas,
          }),
        ),
      ).toBe("success");
      expect(await client.getBalance({ address: sessionTarget })).toBe(777n);

      // The scope still bounds the session installed by a P-256 owner: CallPolicy
      // refuses a value above the installed ceiling inside Kernel's validation
      // phase, so nothing moves.
      expect(
        await harness.rejection(
          sessionRuntime,
          sessionRuntime.prepareOperation({
            kind: "execution",
            grantId: "kernel-composition-p256-session-excessive",
            account: deployed,
            nonceKey: "0",
            sequence: "1",
            calls: [{ target: sessionTarget, value: "778", data: "0x" }],
            gas,
          }),
        ),
      ).toMatchObject({
        errorName: "FailedOpWithRevert",
        args: [0n, "AA23 reverted", CALL_POLICY_VIOLATES_VALUE_RULE],
      });
      expect(await client.getBalance({ address: sessionTarget })).toBe(777n);
    } finally {
      chain.stop();
    }
  }, 90_000);

  it("executes owner and session authorities and falls back to handleOps without changing identity", async () => {
    const harness = await createHarness();
    const { fixture, client, wallet, submitter, reads, deployModule, deployValidator, send } =
      harness;
    await deployKernelStack(harness);

    const ownerAccount = privateKeyToAccount(generatePrivateKey());
    const ownerRuntime = createKernelRuntime({
      deployment,
      operator: ownerOperator({
        key: ecdsaKey({ account: ownerAccount, validator: await deployValidator() }),
      }),
      reads,
    });
    // The session's scope: exactly one target, exactly one selector (empty
    // calldata, which CallPolicy keys as selector zero) and one value ceiling.
    await deployModule(fixture.callPolicy);
    await deployModule(fixture.ecdsaSigner);
    const sessionTarget = lower(privateKeyToAccount(generatePrivateKey()).address);
    const sessionAccount = privateKeyToAccount(generatePrivateKey());
    const sessionRuntime = createKernelRuntime({
      deployment,
      operator: sessionOperator({
        key: ecdsaKey({ account: sessionAccount, validator: await deployValidator() }),
        policies: [
          { kind: "call", calls: [{ target: sessionTarget, selectors: ["0x00000000"] }] },
          { kind: "value", maximumValue: "777" },
        ],
      }),
      reads,
    });

    // Root authority: the composed owner runtime derives, deploys, and executes.
    const counterfactual = await ownerRuntime.bindAccount({
      accountIndex: "0",
      initialPackages: ownerRuntime.packages,
    });
    expect(counterfactual).toMatchObject({ state: "counterfactual", chainId });
    const account = counterfactual.account;
    const fundHash = await wallet.sendTransaction({
      account: submitter,
      chain: null,
      to: account,
      value: parseEther("1"),
    });
    await client.waitForTransactionReceipt({ hash: fundHash });

    const ownerTarget = lower(privateKeyToAccount(generatePrivateKey()).address);
    const deployAndExecute = ownerRuntime.prepareOperation({
      kind: "execution",
      grantId: "kernel-composition-owner",
      account: counterfactual,
      nonceKey: "0",
      sequence: "0",
      calls: [{ target: ownerTarget, value: "12345", data: "0x" }],
      gas,
    });
    expect(deployAndExecute.userOperation.factory?.address).toBe(deployment.factory);
    expect(
      deployAndExecute.userOperation.callData.startsWith(KERNEL_V4_EXECUTE_USER_OP_SELECTOR),
    ).toBe(false);
    expect(await send(ownerRuntime, deployAndExecute)).toBe("success");
    expect(await client.getBalance({ address: ownerTarget })).toBe(12_345n);

    // Session authority: the owner installs the permission — the policy that
    // bounds the session, then the signer that carries its key — and the session
    // runtime signs inside Kernel's permission envelope.
    const deployed = await sessionRuntime.bindAccount({
      accountIndex: "0",
      initialPackages: ownerRuntime.packages,
    });
    expect(deployed).toMatchObject({ state: "deployed", account });

    const install = ownerRuntime.prepareOperation({
      kind: "execution",
      grantId: "kernel-composition-install",
      account: deployed,
      nonceKey: "0",
      sequence: "1",
      calls: [
        {
          target: account,
          value: "0",
          data: encodeKernelV4InstallModules(sessionRuntime.packages),
        },
      ],
      gas,
    });
    expect(await send(ownerRuntime, install)).toBe("success");

    // One policy package per bounded axis, then the signer, all under one
    // permission ID.
    expect(sessionRuntime.packages.map((entry) => entry.moduleType)).toEqual([5, 6]);
    expect(sessionRuntime.validation.kind).toBe("permission");
    const sessionOperation = sessionRuntime.prepareOperation({
      kind: "execution",
      grantId: "kernel-composition-session",
      account: deployed,
      nonceKey: "0",
      sequence: "0",
      calls: [{ target: sessionTarget, value: "777", data: "0x" }],
      gas,
    });
    // A hookless permission takes Kernel's fast path, so the policy module sees
    // the plain execute calldata it decodes.
    expect(
      sessionOperation.userOperation.callData.startsWith(KERNEL_V4_EXECUTE_USER_OP_SELECTOR),
    ).toBe(false);
    expect(await send(sessionRuntime, sessionOperation)).toBe("success");
    expect(await client.getBalance({ address: sessionTarget })).toBe(777n);

    // Scope tightening, proven on-chain by the same installed session: a target
    // the policy never named and a value above the ceiling are both rejected in
    // Kernel's validation phase, so neither moves anything. Each refusal is
    // decoded to its own class rather than observed as a bare revert, and the two
    // classes differ: an unnamed target has no permission entry at all, while an
    // excessive value violates the entry it does match. "The transaction failed"
    // for any other reason would not satisfy either assertion.
    const uncoveredTarget = lower(privateKeyToAccount(generatePrivateKey()).address);
    const uncovered = sessionRuntime.prepareOperation({
      kind: "execution",
      grantId: "kernel-composition-session-uncovered",
      account: deployed,
      nonceKey: "0",
      sequence: "1",
      calls: [{ target: uncoveredTarget, value: "1", data: "0x" }],
      gas,
    });
    expect(await harness.rejection(sessionRuntime, uncovered)).toMatchObject({
      errorName: "FailedOpWithRevert",
      args: [0n, "AA23 reverted", CALL_POLICY_INVALID_CALL_DATA],
    });
    expect(await client.getBalance({ address: uncoveredTarget })).toBe(0n);

    const excessive = sessionRuntime.prepareOperation({
      kind: "execution",
      grantId: "kernel-composition-session-excessive",
      account: deployed,
      nonceKey: "0",
      sequence: "1",
      calls: [{ target: sessionTarget, value: "778", data: "0x" }],
      gas,
    });
    expect(await harness.rejection(sessionRuntime, excessive)).toMatchObject({
      errorName: "FailedOpWithRevert",
      args: [0n, "AA23 reverted", CALL_POLICY_VIOLATES_VALUE_RULE],
    });
    expect(await client.getBalance({ address: sessionTarget })).toBe(777n);

    // Authorities never borrow one another's operations: the owner runtime refuses
    // to sign an operation bound to the session's permission before any
    // submission exists.
    const foreign = sessionRuntime.prepareOperation({
      kind: "execution",
      grantId: "kernel-composition-foreign",
      account: deployed,
      nonceKey: "0",
      sequence: "1",
      calls: [{ target: sessionTarget, value: "1", data: "0x" }],
      gas,
    });
    await expect(send(ownerRuntime, foreign)).rejects.toMatchObject({
      code: "kernel_runtime_binding_mismatch",
    });
    expect(await client.getBalance({ address: sessionTarget })).toBe(777n);

    // Routing fallback: a conclusive pre-acceptance rejection is the only
    // bundler evidence that authorizes EntryPoint.handleOps, and the fallback
    // submits the same signed operation identity the bundler would have taken.
    const capabilities = captureRoutingCapabilities({
      chainId,
      bundler: classifyBundlerAcceptance({ outcome: "rejected", code: -32505 }),
      sessionCoverage: "uncovered",
      feePayer: {
        address: lower(submitter.address),
        balance: (await client.getBalance({ address: submitter.address })).toString(10),
      },
    });
    expect(capabilities.bundler).toBe("unsupported");
    const decision = decideExecution({
      operationKind: "execution",
      sessionCoverage: capabilities.sessionCoverage,
      bundler: capabilities.bundler,
      feePayer: capabilities.feePayer,
    });
    expect(decision).toMatchObject({
      signer: "owner",
      route: "entrypoint-handleops",
      reasons: ["session_calls_uncovered", "bundler_unsupported", "fee_payer_configured"],
    });
    const decidedFeePayer = decision.feePayer;
    if (decidedFeePayer === null) throw new Error("handleOps decision carries no fee payer");

    const fallbackTarget = lower(privateKeyToAccount(generatePrivateKey()).address);
    const fallback = ownerRuntime.prepareOperation({
      kind: "execution",
      grantId: "kernel-composition-fallback",
      account: deployed,
      nonceKey: "0",
      sequence: "2",
      calls: [{ target: fallbackTarget, value: "4321", data: "0x" }],
      gas,
    });
    const requirement = deriveHandleOpsRequirement({
      prepared: fallback,
      feePayer: decidedFeePayer,
      overheadGas: OAATH_HANDLE_OPS_OVERHEAD_GAS,
    });
    expect(requirement).toMatchObject({
      status: "funded",
      chainId,
      account,
      userOperationHash: fallback.userOperationHash,
    });

    // The signature is produced once, before the route is exercised.
    const fallbackSignature = await ownerRuntime.signOperation(fallback);
    const encoded = encodeHandleOps({
      prepared: fallback,
      signature: fallbackSignature,
      beneficiary: decidedFeePayer.address,
    });
    expect(encoded.userOperationHash).toBe(fallback.userOperationHash);
    const fallbackHash = await wallet.sendTransaction({
      account: submitter,
      chain: null,
      to: encoded.entryPoint,
      data: encoded.data,
      gas: 8_000_000n,
    });
    const fallbackReceipt = await client.waitForTransactionReceipt({ hash: fallbackHash });
    expect(fallbackReceipt.status).toBe("success");
    // UserOperationEvent's first indexed topic is the userOpHash: the chain
    // itself confirms the fallback preserved the prepared identity.
    expect(
      fallbackReceipt.logs.some(
        (log) =>
          lower(log.address) === KERNEL_V4_ENTRY_POINT_V07 &&
          log.topics[1] === fallback.userOperationHash,
      ),
    ).toBe(true);
    expect(await client.getBalance({ address: fallbackTarget })).toBe(4_321n);
  }, 60_000);

  it("composes a consumer-authored key profile through both authorities", async () => {
    const harness = await createHarness();
    const { fixture, client, reads, deployModule, deployValidator, fund, send } = harness;
    await deployKernelStack(harness);
    await deployModule(fixture.callPolicy);
    await deployModule(fixture.ecdsaSigner);

    // The pinned registry is not consulted for this kind at all: it binds the
    // ECDSAValidator this test deploys and the ECDSASigner module by address, so
    // every module resolution below runs through the caller-bound path.
    expect(pinnedSignerModule(customKind)).toBeNull();
    const ownerKey = customKey({
      account: privateKeyToAccount(generatePrivateKey()),
      validator: await deployValidator(),
      signerModule: fixture.ecdsaSigner.expectedAddress,
    });
    const ownerRuntime = createKernelRuntime({
      deployment,
      operator: ownerOperator({ key: ownerKey }),
      reads,
    });
    expect(ownerRuntime.keyKind).toBe(customKind);

    // Root authority: the consumer-authored owner derives, deploys and executes.
    const counterfactual = await ownerRuntime.bindAccount({
      accountIndex: "0",
      initialPackages: ownerRuntime.packages,
    });
    const account = counterfactual.account;
    await fund(account, parseEther("1"));
    const ownerTarget = lower(privateKeyToAccount(generatePrivateKey()).address);
    expect(
      await send(
        ownerRuntime,
        ownerRuntime.prepareOperation({
          kind: "execution",
          grantId: "kernel-composition-custom-owner",
          account: counterfactual,
          nonceKey: "0",
          sequence: "0",
          calls: [{ target: ownerTarget, value: "2468", data: "0x" }],
          gas,
        }),
      ),
    ).toBe("success");
    expect(await client.getBalance({ address: ownerTarget })).toBe(2_468n);
    const deployed = await ownerRuntime.bindAccount({
      accountIndex: "0",
      initialPackages: ownerRuntime.packages,
    });
    expect(deployed).toMatchObject({ state: "deployed", account });

    // Permission authority for the same kind: one bounded scope, one caller-bound
    // signer module, installed by the owner and exercised by the session.
    const sessionTarget = lower(privateKeyToAccount(generatePrivateKey()).address);
    const sessionKey = customKey({
      account: privateKeyToAccount(generatePrivateKey()),
      validator: await deployValidator(),
      signerModule: fixture.ecdsaSigner.expectedAddress,
    });
    const sessionRuntime = createKernelRuntime({
      deployment,
      operator: sessionOperator({
        key: sessionKey,
        policies: [
          { kind: "call", calls: [{ target: sessionTarget, selectors: ["0x00000000"] }] },
          { kind: "value", maximumValue: "777" },
        ],
      }),
      reads,
    });
    expect(sessionRuntime.authorityModule).toBe(fixture.ecdsaSigner.expectedAddress);
    expect(sessionRuntime.packages.map((entry) => entry.moduleType)).toEqual([5, 6]);
    await expect(
      sessionRuntime.bindAccount({ accountIndex: "0", initialPackages: ownerRuntime.packages }),
    ).resolves.toMatchObject({ state: "deployed", account });
    expect(
      await send(
        ownerRuntime,
        ownerRuntime.prepareOperation({
          kind: "execution",
          grantId: "kernel-composition-custom-install",
          account: deployed,
          nonceKey: "0",
          sequence: "1",
          calls: [
            {
              target: account,
              value: "0",
              data: encodeKernelV4InstallModules(sessionRuntime.packages),
            },
          ],
          gas,
        }),
      ),
    ).toBe("success");
    expect(
      await send(
        sessionRuntime,
        sessionRuntime.prepareOperation({
          kind: "execution",
          grantId: "kernel-composition-custom-session",
          account: deployed,
          nonceKey: "0",
          sequence: "0",
          calls: [{ target: sessionTarget, value: "777", data: "0x" }],
          gas,
        }),
      ),
    ).toBe("success");
    expect(await client.getBalance({ address: sessionTarget })).toBe(777n);

    // The scope still bounds this kind on-chain: CallPolicy itself refuses a value
    // above the installed ceiling inside Kernel's validation phase.
    expect(
      await harness.rejection(
        sessionRuntime,
        sessionRuntime.prepareOperation({
          kind: "execution",
          grantId: "kernel-composition-custom-excessive",
          account: deployed,
          nonceKey: "0",
          sequence: "1",
          calls: [{ target: sessionTarget, value: "778", data: "0x" }],
          gas,
        }),
      ),
    ).toMatchObject({
      errorName: "FailedOpWithRevert",
      args: [0n, "AA23 reverted", CALL_POLICY_VIOLATES_VALUE_RULE],
    });
    expect(await client.getBalance({ address: sessionTarget })).toBe(777n);

    // Fail-closed negatives on the same live chain. Self-verification is
    // mandatory, so a profile whose signature does not verify against its own
    // bound public material never reaches EntryPoint.
    const foreign = privateKeyToAccount(generatePrivateKey());
    const foreignRuntime = createKernelRuntime({
      deployment,
      operator: ownerOperator({
        key: Object.freeze({ ...ownerKey, sign: (hash: `0x${string}`) => foreign.sign({ hash }) }),
      }),
      reads,
    });
    await expect(
      foreignRuntime.signOperation(
        foreignRuntime.prepareOperation({
          kind: "execution",
          grantId: "kernel-composition-custom-unverified",
          account: deployed,
          nonceKey: "0",
          sequence: "2",
          calls: [{ target: ownerTarget, value: "1", data: "0x" }],
          gas,
        }),
      ),
    ).rejects.toMatchObject({ code: "kernel_runtime_signature_invalid" });
    expect(await client.getBalance({ address: ownerTarget })).toBe(2_468n);

    // A consumer-authored kind that binds no signer module has no session
    // authority at all, and a session with no policy is not expressible.
    expect(() =>
      sessionOperator({
        key: customKey({
          account: privateKeyToAccount(generatePrivateKey()),
          validator: ownerKey.resolveValidator(deployment),
          signerModule: null,
        }),
        policies: [{ kind: "call", calls: [{ target: sessionTarget, selectors: ["0x00000000"] }] }],
      }),
    ).toThrowError(expect.objectContaining({ code: "kernel_runtime_signer_unavailable" }));
    expect(() => sessionOperator({ key: sessionKey, policies: [] })).toThrowError(
      expect.objectContaining({ code: "kernel_runtime_input_invalid" }),
    );

    // A caller-bound module carries no pinned review, so an address that holds no
    // code on this chain fails closed at bind, before any account or permission
    // identity depends on it.
    const undeployedRuntime = createKernelRuntime({
      deployment,
      operator: sessionOperator({
        key: customKey({
          account: privateKeyToAccount(generatePrivateKey()),
          validator: ownerKey.resolveValidator(deployment),
          signerModule: lower(privateKeyToAccount(generatePrivateKey()).address),
        }),
        policies: [{ kind: "call", calls: [{ target: sessionTarget, selectors: ["0x00000000"] }] }],
      }),
      reads,
    });
    await expect(
      undeployedRuntime.bindAccount({
        accountIndex: "0",
        initialPackages: ownerRuntime.packages,
      }),
    ).rejects.toMatchObject({
      code: "kernel_runtime_signer_unavailable",
      message: "Kernel authority module carries no code on this chain",
    });
  }, 90_000);

  it("enforces a multi-package session, its validity window, and its operation count", async () => {
    const harness = await createHarness();
    const { fixture, client, wallet, submitter, reads, deployModule, deployValidator, send } =
      harness;
    await deployKernelStack(harness);
    for (const module of [
      fixture.callPolicy,
      fixture.timestampPolicy,
      fixture.rateLimitPolicy,
      fixture.ecdsaSigner,
    ]) {
      await deployModule(module);
    }

    const ownerAccount = privateKeyToAccount(generatePrivateKey());
    const ownerRuntime = createKernelRuntime({
      deployment,
      operator: ownerOperator({
        key: ecdsaKey({ account: ownerAccount, validator: await deployValidator() }),
      }),
      reads,
    });
    const counterfactual = await ownerRuntime.bindAccount({
      accountIndex: "0",
      initialPackages: ownerRuntime.packages,
    });
    const account = counterfactual.account;
    const fundHash = await wallet.sendTransaction({
      account: submitter,
      chain: null,
      to: account,
      value: parseEther("1"),
    });
    await client.waitForTransactionReceipt({ hash: fundHash });
    const deployOwner = ownerRuntime.prepareOperation({
      kind: "execution",
      grantId: "kernel-composition-expiry-owner",
      account: counterfactual,
      nonceKey: "0",
      sequence: "0",
      calls: [{ target: account, value: "0", data: "0x" }],
      gas,
    });
    expect(await send(ownerRuntime, deployOwner)).toBe("success");
    const deployed = await ownerRuntime.bindAccount({
      accountIndex: "0",
      initialPackages: ownerRuntime.packages,
    });
    expect(deployed).toMatchObject({ state: "deployed", account });

    const latest = await client.getBlock({ blockTag: "latest" });
    const validUntil = Number(latest.timestamp) + 3_600;
    const expiryTarget = lower(privateKeyToAccount(generatePrivateKey()).address);
    // Two policy packages under one permission: CallPolicy for the call and value
    // axes, TimestampPolicy for the window. This is the exact shape Kernel refused
    // with FailedOpWithRevert(0, "AA23 reverted", InvalidSignature()) while the
    // permission envelope carried a fixed two-slice signature.
    const expiryRuntime = createKernelRuntime({
      deployment,
      operator: sessionOperator({
        key: ecdsaKey({
          account: privateKeyToAccount(generatePrivateKey()),
          validator: await deployValidator(),
        }),
        policies: [
          { kind: "call", calls: [{ target: expiryTarget, selectors: ["0x00000000"] }] },
          { kind: "value", maximumValue: "500" },
          { kind: "expiry", validAfter: "0", validUntil: validUntil.toString(10) },
        ],
      }),
      reads,
    });
    expect(expiryRuntime.packages.map((entry) => entry.moduleType)).toEqual([5, 5, 6]);
    expect(expiryRuntime.packages.map((entry) => entry.module)).toEqual([
      fixture.callPolicy.expectedAddress,
      fixture.timestampPolicy.expectedAddress,
      fixture.ecdsaSigner.expectedAddress,
    ]);
    expect(
      await send(
        ownerRuntime,
        ownerRuntime.prepareOperation({
          kind: "execution",
          grantId: "kernel-composition-expiry-install",
          account: deployed,
          nonceKey: "0",
          sequence: "1",
          calls: [
            {
              target: account,
              value: "0",
              data: encodeKernelV4InstallModules(expiryRuntime.packages),
            },
          ],
          gas,
        }),
      ),
    ).toBe("success");

    // The regression itself: a two-package session executes its covered call.
    expect(
      await send(
        expiryRuntime,
        expiryRuntime.prepareOperation({
          kind: "execution",
          grantId: "kernel-composition-expiry-covered",
          account: deployed,
          nonceKey: "0",
          sequence: "0",
          calls: [{ target: expiryTarget, value: "500", data: "0x" }],
          gas,
        }),
      ),
    ).toBe("success");
    expect(await client.getBalance({ address: expiryTarget })).toBe(500n);

    // Past the installed validUntil, EntryPoint itself refuses the same session:
    // TimestampPolicy returns the packed range and EntryPoint enforces it, so the
    // window is a chain fact, not a client-side refusal.
    const expired = expiryRuntime.prepareOperation({
      kind: "execution",
      grantId: "kernel-composition-expiry-expired",
      account: deployed,
      nonceKey: "0",
      sequence: "1",
      calls: [{ target: expiryTarget, value: "1", data: "0x" }],
      gas,
    });
    await client.request({
      method: "evm_increaseTime" as "eth_chainId",
      params: [3_601] as never,
    });
    await client.request({ method: "evm_mine" as "eth_chainId", params: [] as never });
    expect(await harness.rejection(expiryRuntime, expired)).toMatchObject({
      errorName: "FailedOp",
      args: [0n, "AA22 expired or not due"],
    });
    expect(await client.getBalance({ address: expiryTarget })).toBe(500n);

    // One session limited to two operations: the second still executes, the third
    // is refused because RateLimitPolicy's count is exhausted.
    const limitTarget = lower(privateKeyToAccount(generatePrivateKey()).address);
    const limitRuntime = createKernelRuntime({
      deployment,
      operator: sessionOperator({
        key: ecdsaKey({
          account: privateKeyToAccount(generatePrivateKey()),
          validator: await deployValidator(),
        }),
        policies: [
          { kind: "call", calls: [{ target: limitTarget, selectors: ["0x00000000"] }] },
          { kind: "value", maximumValue: "10" },
          { kind: "operation-limit", maximumOperations: "2" },
        ],
      }),
      reads,
    });
    expect(limitRuntime.packages.map((entry) => entry.module)).toEqual([
      fixture.callPolicy.expectedAddress,
      fixture.rateLimitPolicy.expectedAddress,
      fixture.ecdsaSigner.expectedAddress,
    ]);
    expect(
      await send(
        ownerRuntime,
        ownerRuntime.prepareOperation({
          kind: "execution",
          grantId: "kernel-composition-limit-install",
          account: deployed,
          nonceKey: "0",
          sequence: "2",
          calls: [
            {
              target: account,
              value: "0",
              data: encodeKernelV4InstallModules(limitRuntime.packages),
            },
          ],
          gas,
        }),
      ),
    ).toBe("success");

    const limited = (sequence: string) =>
      limitRuntime.prepareOperation({
        kind: "execution",
        grantId: `kernel-composition-limit-${sequence}`,
        account: deployed,
        nonceKey: "0",
        sequence,
        calls: [{ target: limitTarget, value: "10", data: "0x" }],
        gas,
      });
    expect(await send(limitRuntime, limited("0"))).toBe("success");
    expect(await send(limitRuntime, limited("1"))).toBe("success");
    expect(await client.getBalance({ address: limitTarget })).toBe(20n);
    // RateLimitPolicy returns 1 once the count is spent, which is Kernel's
    // signature-failure sentinel, so EntryPoint refuses the operation as AA24.
    expect(await harness.rejection(limitRuntime, limited("2"))).toMatchObject({
      errorName: "FailedOp",
      args: [0n, "AA24 signature error"],
    });
    expect(await client.getBalance({ address: limitTarget })).toBe(20n);
  }, 90_000);
});
