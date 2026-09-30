/**
 * The only Kernel composition entry. Deployment profile, key kind, operator
 * authority, and policy hooks are orthogonal inputs; adding a key or a policy
 * never adds a runtime here.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type CaptureContext, captureRecord, exactCapturedRecord } from "@oaath/protocol";
import {
  bindKernelV4Account,
  decodeKernelV4Execution,
  encodeKernelV4NonceKey,
  type KernelInstall,
  type KernelV4AccountDescriptor,
  type KernelV4AccountReadCapability,
  type KernelV4Deployment,
  type KernelValidation,
  prepareKernelV4UserOperation,
} from "../kernel-v4.js";
import {
  type PreparedFactory,
  type PreparedUserOperation,
  parsePreparedUserOperation,
} from "../prepared-user-operation.js";
import {
  bindKernelAccount,
  type KernelAccountDescriptor,
  type KernelReads,
} from "./deployment/account.js";
import { ECDSA_VALIDATOR } from "./deployment/v33.js";
import {
  encodeKernelV33NonceKey,
  kernelV33OperationSigningHash,
  prepareKernelV33Operation,
} from "./deployment/v33-operation.js";
import {
  applyKernelGasPolicy,
  captureKernelGasPolicy,
  enableVerificationFloorForNonce,
  type KernelGasPolicy,
} from "./gas-policy.js";
import {
  captureKeyProfile,
  exactInput,
  inputCapability,
  inputInvalid,
  isBytes,
  runtimeFail,
  sameInstall,
} from "./internal.js";
import {
  exactKernelDeployment,
  KERNEL_P256_VERIFIER,
  KERNEL_P256_VERIFIER_RUNTIME_CODE_HASH,
  OAATH_KERNEL_RATE_LIMIT_POLICY,
  OAATH_KERNEL_RATE_LIMIT_POLICY_RUNTIME_CODE_HASH,
  OAATH_KERNEL_V4_VALIDITY_POLICY,
  OAATH_KERNEL_V4_VALIDITY_POLICY_RUNTIME_CODE_HASH,
  pinnedSignerModule,
  pinnedValidatorModule,
  resolvePolicyModule,
} from "./modules.js";
import { kernelCallPolicyCheck } from "./permission/compile.js";
import { observeRuntimeModule } from "./runtime-modules.js";
import type {
  CreateKernelRuntimeInput,
  CreateKernelV4RuntimeInput,
  CreateKernelV33RuntimeInput,
  KernelRuntime,
  KernelRuntimeBindAccountInput,
  KernelRuntimeExistingAccountInput,
  KernelRuntimePrepareInput,
  KernelRuntimeValidationMode,
  KernelV4Runtime,
  KernelV33Runtime,
  KernelV33RuntimePrepareInput,
  KeyProfile,
  OperatorProfile,
} from "./types.js";

/**
 * The only validation modes a composed runtime prepares or signs. Kernel accepts
 * six; the four omitted here are unreachable by construction rather than
 * unsupported by accident, and kernel-v4.ts records why for each.
 */
const RUNTIME_MODES: readonly KernelRuntimeValidationMode[] = Object.freeze([
  "standard",
  "enable-replayable",
]);
const MAX_EXTERNAL_SIGNATURE_BYTES = 4_096;

function runtimeMode(value: unknown): KernelRuntimeValidationMode {
  if (value === undefined) return "standard";
  const mode = RUNTIME_MODES.find((candidate) => candidate === value);
  return mode ?? inputInvalid("Kernel runtime validation mode is unsupported");
}

interface CapturedOperator {
  readonly authority: "owner" | "session";
  readonly key: Readonly<KeyProfile>;
  readonly resolveAuthorityModule: OperatorProfile["resolveAuthorityModule"];
  readonly encodeSignature: OperatorProfile["encodeSignature"];
  readonly resolveValidation: OperatorProfile["resolveValidation"];
  readonly resolvePackages: OperatorProfile["resolvePackages"];
}

function captureOperator(value: unknown, context: CaptureContext): CapturedOperator {
  const record = exactInput(
    value,
    [
      "authority",
      "key",
      "policy",
      "resolveAuthorityModule",
      "encodeSignature",
      "resolveValidation",
      "resolvePackages",
    ],
    "Kernel operator profile",
    context,
  );
  if (record.authority !== "owner" && record.authority !== "session") {
    return inputInvalid("Kernel operator authority is unsupported");
  }
  if (record.policy !== null && (!record.policy || typeof record.policy !== "object")) {
    return inputInvalid("Kernel operator policy is invalid");
  }
  return Object.freeze({
    authority: record.authority,
    key: captureKeyProfile(record.key),
    resolveAuthorityModule: inputCapability<OperatorProfile["resolveAuthorityModule"]>(
      record.resolveAuthorityModule,
      "Kernel operator authority module resolution",
    ),
    encodeSignature: inputCapability<OperatorProfile["encodeSignature"]>(
      record.encodeSignature,
      "Kernel operator signature envelope",
    ),
    resolveValidation: inputCapability<OperatorProfile["resolveValidation"]>(
      record.resolveValidation,
      "Kernel operator validation resolution",
    ),
    resolvePackages: inputCapability<OperatorProfile["resolvePackages"]>(
      record.resolvePackages,
      "Kernel operator package resolution",
    ),
  });
}

/**
 * Composes one deployment profile, one operator authority, and one key into a
 * runtime that binds accounts, prepares exact operations, and signs them.
 * Validator and policy resolution happen once, here, so an unavailable module
 * fails closed before any account address or operation identity exists.
 */
export function createKernelRuntime(value: CreateKernelV33RuntimeInput): Readonly<KernelV33Runtime>;
export function createKernelRuntime(value: CreateKernelV4RuntimeInput): Readonly<KernelV4Runtime>;
export function createKernelRuntime(value: CreateKernelRuntimeInput): Readonly<KernelRuntime>;
export function createKernelRuntime(
  value: unknown,
): Readonly<KernelRuntime> | Readonly<KernelV33Runtime> {
  const context: CaptureContext = new WeakSet();
  const captured = captureRecord(value, "Kernel runtime", context, inputInvalid);
  const record = exactCapturedRecord(
    captured,
    ["deployment", "operator", "reads", ...(Object.hasOwn(captured, "gas") ? ["gas"] : [])],
    "Kernel runtime",
    inputInvalid,
  );
  const deployment = exactKernelDeployment(record.deployment);
  const gasPolicy = captureKernelGasPolicy(deployment.chainId, record.gas);
  const operator = captureOperator(record.operator, context);
  const isV33 = deployment.kernelVersion === "0.3.3";
  // Existing-account root binding below proves the ECDSA validator's owner.
  // A session instead resolves its own signer module and public material; its
  // key kind is independent of the account's root validator.
  if (isV33 && operator.authority === "owner" && operator.key.kind !== "ecdsa") {
    return inputInvalid("Kernel v3.3 root composition currently requires an ECDSA key");
  }
  const read = inputCapability<KernelV4AccountReadCapability["read"]>(
    exactInput(record.reads, ["read"], "Kernel runtime reads", context).read,
    "Kernel runtime read capability",
  );
  const authorityModule = operator.resolveAuthorityModule(deployment);
  const validation: Readonly<KernelValidation> = operator.resolveValidation(deployment);
  const packages =
    isV33 && operator.authority === "owner"
      ? Object.freeze([])
      : operator.resolvePackages(deployment);
  const rootPackage: Readonly<KernelInstall> | undefined = packages[0];
  if (!isV33 && !rootPackage) return inputInvalid("Kernel operator resolved no install packages");
  // Kernel's ValidationManager forbids enable mode on root validation — a root
  // authority is the account's own last-resort access path and has nothing to
  // enable — so a root runtime's only reachable mode is standard. kernel-v4.ts
  // owns that rule and fails closed on it; this set only keeps prepare and sign
  // asking the same question.
  const reachableModes: readonly KernelRuntimeValidationMode[] =
    validation.kind === "root" ? Object.freeze(["standard" as const]) : RUNTIME_MODES;
  // A session checks every call against the exact CallPolicy payload it
  // installs, so a call the chain would refuse fails before any key signs.
  const callPolicy =
    operator.authority === "session"
      ? packages.find(
          (install) => install.moduleType === 5 && install.module === resolvePolicyModule("call"),
        )
      : undefined;
  const checkCalls = callPolicy
    ? kernelCallPolicyCheck(`0x${callPolicy.moduleData.slice(66)}`)
    : null;
  const hasValidityPolicy =
    operator.authority === "session" &&
    packages.some(
      (install) => install.moduleType === 5 && install.module === OAATH_KERNEL_V4_VALIDITY_POLICY,
    );
  const validityPolicyProvenDescriptors = new WeakSet<object>();
  // The only factory deployment each bound v3.3 sender's operations may carry.
  const boundV33Accounts = new Map<string, Readonly<PreparedFactory> | null>();

  /**
   * Proves this authority's module carries code on the action chain. An owner's
   * validator is covered by bindKernelV4Account, which proves every module the
   * account's initial packages install, but a session binds the account's root
   * packages, not its own permission packages, so its signer module is proven
   * here. A caller-bound module carries no pinned review at all, which is why
   * code presence is proven before this runtime's bindAccount returns.
   *
   * Boundary, stated exactly: this proof runs only in bindAccount. A session
   * descriptor bound by a different runtime therefore cannot prove this
   * runtime's signer or policy deployment. Requested validity ranges below are
   * accepted only for descriptors returned by this runtime after the exact
   * policy hash was observed.
   */
  async function proveAuthorityModule(): Promise<void> {
    const unavailable =
      operator.authority === "owner"
        ? "kernel_runtime_validator_unavailable"
        : "kernel_runtime_signer_unavailable";
    let code: unknown;
    try {
      code = await read({
        type: "code",
        chainId: deployment.chainId,
        address: authorityModule,
      });
    } catch {
      return runtimeFail(unavailable, "Kernel authority module code could not be read");
    }
    if (!isBytes(code) || code === "0x") {
      return runtimeFail(unavailable, "Kernel authority module carries no code on this chain");
    }
    // The pinned WebAuthn signer verifies through the software P-256 verifier
    // (kernel/key/webauthn.ts never selects the RIP-7212 precompile), so a
    // passkey session is unusable on a chain without that exact verifier.
    if (operator.authority !== "session" || authorityModule !== pinnedSignerModule("webauthn"))
      return;
    const verifier = await observeRuntimeModule(
      read as KernelReads["read"],
      deployment.chainId,
      KERNEL_P256_VERIFIER,
      KERNEL_P256_VERIFIER_RUNTIME_CODE_HASH,
    );
    if (verifier !== "present") {
      return runtimeFail(unavailable, "P-256 verifier is not deployed on this chain");
    }
  }

  async function provePinnedPolicies(): Promise<void> {
    if (operator.authority !== "session") return;
    for (const [address, expected] of [
      [OAATH_KERNEL_V4_VALIDITY_POLICY, OAATH_KERNEL_V4_VALIDITY_POLICY_RUNTIME_CODE_HASH],
      [OAATH_KERNEL_RATE_LIMIT_POLICY, OAATH_KERNEL_RATE_LIMIT_POLICY_RUNTIME_CODE_HASH],
    ] as const) {
      if (!packages.some((install) => install.moduleType === 5 && install.module === address))
        continue;
      const observed = await observeRuntimeModule(
        read as KernelReads["read"],
        deployment.chainId,
        address,
        expected,
      );
      if (observed !== "present") {
        return runtimeFail(
          "kernel_runtime_policy_unavailable",
          "Kernel policy runtime code does not match the pinned artifact",
        );
      }
    }
  }

  async function bindAccount(
    input: KernelRuntimeBindAccountInput | KernelRuntimeExistingAccountInput,
  ): Promise<Readonly<KernelAccountDescriptor>> {
    const existing = exactInput(
      input,
      Object.hasOwn(input ?? {}, "address")
        ? ["address"]
        : isV33
          ? ["accountIndex"]
          : ["accountIndex", "initialPackages"],
      "Kernel runtime account",
      new WeakSet(),
    );
    if (Object.hasOwn(existing, "address")) return bindExistingAccount(existing.address);
    if (isV33) return bindDerivedV33Account(existing.accountIndex);
    await proveAuthorityModule();
    await provePinnedPolicies();
    // bindKernelV4Account owns exact capture and on-chain evidence for every
    // field below; each caller field is read exactly once into its argument.
    const descriptor = await bindKernelV4Account({
      chainId: deployment.chainId,
      initialPackages: existing.initialPackages as KernelRuntimeBindAccountInput["initialPackages"],
      accountIndex: existing.accountIndex as string,
      reads: Object.freeze({ read }),
    });
    // An owner runtime holds root authority only over an account whose initial
    // packages install this owner's validator and public material.
    if (
      operator.authority === "owner" &&
      !descriptor.initialPackages.some(
        (install) => rootPackage && sameInstall(install, rootPackage),
      )
    ) {
      return runtimeFail(
        "kernel_runtime_binding_mismatch",
        "Kernel account root packages do not install this owner authority",
      );
    }
    if (hasValidityPolicy) validityPolicyProvenDescriptors.add(descriptor);
    return descriptor;
  }

  /**
   * Binds an existing account at its address. The account's own deployment is
   * detected and must be this runtime's, so a mismatch fails before any key is
   * asked to sign. Root authority is proven from the account's current root
   * validation; only the reviewed ECDSA validator and the pinned raw P-256
   * validator expose their owner onchain.
   */
  async function bindExistingAccount(address: unknown): Promise<Readonly<KernelAccountDescriptor>> {
    return proveBoundAccount(
      await bindKernelAccount({
        chainId: deployment.chainId,
        address: address as `0x${string}`,
        reads: Object.freeze({ read: read as KernelReads["read"] }),
        deployment,
      }),
    );
  }

  /**
   * Derives this owner's own Kernel 0.3.3 account: the ECDSA key's address is
   * the root owner, so the account can only be the one this runtime signs for.
   * A deployed account is then proven exactly like an existing one.
   */
  async function bindDerivedV33Account(
    accountIndex: unknown,
  ): Promise<Readonly<KernelAccountDescriptor>> {
    if (operator.authority !== "owner")
      return runtimeFail(
        "kernel_runtime_unsupported",
        "Kernel 0.3.3 derives only an owner's account; sessions bind an existing address",
      );
    if (authorityModule !== ECDSA_VALIDATOR)
      return runtimeFail(
        "kernel_runtime_binding_mismatch",
        "Kernel account does not use this root validator",
      );
    const descriptor = await bindKernelAccount({
      chainId: deployment.chainId,
      owner: operator.key.publicMaterial as `0x${string}`,
      accountIndex: accountIndex as string,
      reads: Object.freeze({ read: read as KernelReads["read"] }),
      deployment,
    });
    if (descriptor.state !== "counterfactual" || !("owner" in descriptor))
      return proveBoundAccount(descriptor);
    if (descriptor.owner !== operator.key.publicMaterial)
      return runtimeFail(
        "kernel_runtime_binding_mismatch",
        "Kernel account does not belong to this owner key",
      );
    boundV33Accounts.set(
      descriptor.account,
      Object.freeze({ address: descriptor.factory, data: descriptor.factoryData }),
    );
    return descriptor;
  }

  async function proveBoundAccount(
    descriptor: Readonly<KernelAccountDescriptor>,
  ): Promise<Readonly<KernelAccountDescriptor>> {
    if (operator.authority === "session") {
      await proveAuthorityModule();
      await provePinnedPolicies();
      for (const install of packages) {
        if (install.moduleType !== 5) continue;
        let code: unknown;
        try {
          code = await read({
            type: "code",
            chainId: deployment.chainId,
            address: install.module,
          });
        } catch {
          return runtimeFail(
            "kernel_runtime_policy_unavailable",
            "Kernel policy code could not be read",
          );
        }
        if (!isBytes(code) || code === "0x")
          return runtimeFail(
            "kernel_runtime_policy_unavailable",
            "Kernel policy carries no code on this chain",
          );
      }
    } else {
      const rootValidator = (descriptor as { readonly rootValidator: `0x${string}` }).rootValidator;
      // Only validators whose owner is readable onchain can prove root
      // authority: the reviewed ECDSA validator and, on Kernel 0.4.0, the pinned
      // raw P-256 validator. Any other root validator fails closed.
      const p256 = !isV33 && authorityModule === pinnedValidatorModule("p256");
      if (
        (authorityModule !== ECDSA_VALIDATOR && !p256) ||
        rootValidator !== `0x01${authorityModule.slice(2)}`
      ) {
        return runtimeFail(
          "kernel_runtime_binding_mismatch",
          "Kernel account does not use this root validator",
        );
      }
      let owner: unknown;
      try {
        owner = await (read as KernelReads["read"])(
          p256
            ? {
                type: "kernel_p256_owner",
                chainId: deployment.chainId,
                validator: authorityModule,
                account: descriptor.account,
              }
            : {
                type: "kernel_ecdsa_owner",
                chainId: deployment.chainId,
                account: descriptor.account,
              },
        );
      } catch {
        return runtimeFail(
          "kernel_runtime_read_unavailable",
          "Kernel root owner could not be read",
        );
      }
      if (owner !== operator.key.publicMaterial) {
        return runtimeFail(
          "kernel_runtime_binding_mismatch",
          "Kernel account does not belong to this owner key",
        );
      }
    }
    if (isV33) boundV33Accounts.set(descriptor.account, null);
    else if (hasValidityPolicy) validityPolicyProvenDescriptors.add(descriptor);
    return descriptor;
  }

  function prepareOperation(
    input: KernelRuntimePrepareInput | KernelV33RuntimePrepareInput,
  ): PreparedUserOperation {
    if (isV33) {
      const operation = prepareKernelV33Operation(
        input as KernelV33RuntimePrepareInput,
        validation,
        gasPolicy,
      );
      return boundOperation(operation);
    }
    const requestsValidityRange = Object.hasOwn(input, "validityTimeRange");
    const account = input.account;
    if (
      requestsValidityRange &&
      (!hasValidityPolicy || !account || !validityPolicyProvenDescriptors.has(account))
    ) {
      return runtimeFail(
        "kernel_runtime_policy_unavailable",
        "Kernel requested validity range has no proven OAAth validity policy binding",
      );
    }
    // prepareKernelV4UserOperation owns exact capture of the account descriptor,
    // calls, gas, and nonce; this axis only binds the authority's validation.
    const mode = runtimeMode(input.mode);
    return permittedCalls(
      prepareKernelV4UserOperation({
        kind: input.kind,
        grantId: input.grantId,
        account: account as KernelV4AccountDescriptor,
        nonce: {
          mode,
          validation,
          nonceKey: input.nonceKey,
          sequence: input.sequence,
        },
        calls: input.calls,
        gas: applyKernelGasPolicy(input.gas, mode, gasPolicy),
        ...(requestsValidityRange
          ? { validityTimeRange: (input as KernelRuntimePrepareInput).validityTimeRange }
          : {}),
        paymaster: input.paymaster ?? null,
      }),
    );
  }

  /**
   * Decodes the exact execute calldata the key would sign and refuses it when
   * the session's call policy forbids any call, so prepare, sign, and external
   * signature encoding all refuse before a key is asked.
   */
  function permittedCalls(operation: PreparedUserOperation): PreparedUserOperation {
    if (checkCalls) checkCalls(decodeKernelV4Execution(operation.userOperation.callData));
    return operation;
  }

  function boundOperation(prepared: unknown): PreparedUserOperation {
    let operation: PreparedUserOperation;
    try {
      operation = parsePreparedUserOperation(prepared);
    } catch {
      return runtimeFail(
        "kernel_runtime_binding_mismatch",
        "Prepared UserOperation could not be captured",
      );
    }
    if (
      operation.chainId !== deployment.chainId ||
      operation.entryPoint.version !== deployment.entryPoint.version ||
      operation.entryPoint.address !== deployment.entryPoint.address
    ) {
      return runtimeFail(
        "kernel_runtime_binding_mismatch",
        "Prepared UserOperation does not match this Kernel runtime",
      );
    }
    const factory = operation.userOperation.factory;
    const boundFactory = boundV33Accounts.get(operation.userOperation.sender);
    if (
      isV33 &&
      (boundFactory === undefined ||
        (boundFactory === null
          ? factory !== null
          : factory?.address !== boundFactory.address || factory.data !== boundFactory.data))
    ) {
      return runtimeFail(
        "kernel_runtime_binding_mismatch",
        "Kernel v3.3 operation does not use an account bound to this runtime",
      );
    }
    // The nonce carries Kernel's validation mode, type and identifier, so
    // recomputing the key for this runtime's own validation is an exact authority
    // check: a root runtime can never sign a permission operation, and a session
    // can never sign another permission's. The namespace is read back from the
    // prepared nonce so only the validation binding is compared. The mode is
    // compared against exactly the modes prepareOperation can emit, so an
    // operation carrying any of Kernel's four unreachable modes is refused here
    // rather than signed.
    const nonce = BigInt(operation.userOperation.nonce);
    if (
      BigInt(operation.userOperation.verificationGasLimit) <
      enableVerificationFloorForNonce(operation.userOperation.nonce, gasPolicy)
    ) {
      return runtimeFail(
        "kernel_runtime_binding_mismatch",
        "Prepared enable operation is below the configured verification gas floor",
      );
    }
    const namespace = ((nonce >> 64n) & 0xffffn).toString(10);
    const key = (nonce >> 64n).toString(10);
    if (
      !(isV33
        ? (validation.kind === "root"
            ? (["standard"] as const)
            : (["standard", "enable"] as const)
          ).some(
            (mode) => encodeKernelV33NonceKey({ mode, validation, nonceKey: namespace }) === key,
          )
        : reachableModes.some(
            (mode) => encodeKernelV4NonceKey({ mode, validation, nonceKey: namespace }) === key,
          ))
    ) {
      return runtimeFail(
        "kernel_runtime_binding_mismatch",
        "Prepared UserOperation validation does not match this authority",
      );
    }
    return permittedCalls(operation);
  }

  async function signOperation(prepared: unknown): Promise<`0x${string}`> {
    const operation = boundOperation(prepared);
    return operator.encodeSignature(
      await operator.key.sign(
        isV33 ? kernelV33OperationSigningHash(operation) : operation.userOperationHash,
      ),
      deployment,
    );
  }

  async function encodeVerifiedSignature(
    prepared: unknown,
    signatureValue: unknown,
  ): Promise<`0x${string}`> {
    const operation = boundOperation(prepared);
    if (typeof signatureValue !== "string") {
      return inputInvalid("Kernel external key signature is invalid");
    }
    const signature = signatureValue.toLowerCase();
    if (
      signature === "0x" ||
      !isBytes(signature) ||
      (signature.length - 2) / 2 > MAX_EXTERNAL_SIGNATURE_BYTES
    ) {
      return inputInvalid("Kernel external key signature is invalid");
    }
    if (
      !(await operator.key.verify(
        isV33 ? kernelV33OperationSigningHash(operation) : operation.userOperationHash,
        signature,
      ))
    ) {
      return runtimeFail(
        "kernel_runtime_signature_invalid",
        "Kernel external key signature does not verify against the bound public material",
      );
    }
    return operator.encodeSignature(signature, deployment);
  }

  return Object.freeze({
    deployment,
    gasPolicy,
    authority: operator.authority,
    keyKind: operator.key.kind,
    authorityModule,
    validation,
    packages,
    // Simulation must receive the same authority envelope shape as a real
    // signature. Owner encoding is raw; session encoding adds policy/signer slices.
    dummySignature: operator.encodeSignature(operator.key.dummySignature, deployment),
    bindAccount,
    prepareOperation,
    signOperation,
    encodeVerifiedSignature,
  }) as Readonly<KernelRuntime> | Readonly<KernelV33Runtime>;
}
