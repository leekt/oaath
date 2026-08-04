/**
 * The only Kernel composition entry. Deployment profile, key kind, operator
 * authority, and policy hooks are orthogonal inputs; adding a key or a policy
 * never adds a runtime here.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { CaptureContext } from "@oaath/protocol";
import {
  bindKernelV4Account,
  encodeKernelV4NonceKey,
  type KernelV4AccountDescriptor,
  type KernelV4AccountReadCapability,
  type KernelV4Install,
  type KernelV4Validation,
  prepareKernelV4UserOperation,
} from "../kernel-v4.js";
import {
  type PreparedUserOperation,
  parsePreparedUserOperation,
} from "../prepared-user-operation.js";
import {
  captureKeyProfile,
  exactInput,
  inputCapability,
  inputInvalid,
  runtimeFail,
  sameInstall,
} from "./internal.js";
import { exactKernelDeployment } from "./modules.js";
import type {
  CreateKernelRuntimeInput,
  KernelRuntime,
  KernelRuntimeBindAccountInput,
  KernelRuntimePrepareInput,
  KernelRuntimeValidationMode,
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
export function createKernelRuntime(value: CreateKernelRuntimeInput): Readonly<KernelRuntime> {
  const context: CaptureContext = new WeakSet();
  const record = exactInput(value, ["deployment", "operator", "reads"], "Kernel runtime", context);
  const deployment = exactKernelDeployment(record.deployment);
  const operator = captureOperator(record.operator, context);
  const read = inputCapability<KernelV4AccountReadCapability["read"]>(
    exactInput(record.reads, ["read"], "Kernel runtime reads", context).read,
    "Kernel runtime read capability",
  );
  const authorityModule = operator.resolveAuthorityModule(deployment);
  const validation: Readonly<KernelV4Validation> = operator.resolveValidation(deployment);
  const packages = operator.resolvePackages(deployment);
  const rootPackage: Readonly<KernelV4Install> =
    packages[0] ?? inputInvalid("Kernel operator resolved no install packages");
  // Kernel's ValidationManager forbids enable mode on root validation — a root
  // authority is the account's own last-resort access path and has nothing to
  // enable — so a root runtime's only reachable mode is standard. kernel-v4.ts
  // owns that rule and fails closed on it; this set only keeps prepare and sign
  // asking the same question.
  const reachableModes: readonly KernelRuntimeValidationMode[] =
    validation.kind === "root" ? Object.freeze(["standard" as const]) : RUNTIME_MODES;

  async function bindAccount(
    input: KernelRuntimeBindAccountInput,
  ): Promise<Readonly<KernelV4AccountDescriptor>> {
    // bindKernelV4Account owns exact capture and on-chain evidence for every
    // field below; each caller field is read exactly once into its argument.
    const descriptor = await bindKernelV4Account({
      chainId: deployment.chainId,
      initialPackages: input.initialPackages,
      accountIndex: input.accountIndex,
      reads: Object.freeze({ read }),
    });
    // An owner runtime holds root authority only over an account whose initial
    // packages install this owner's validator and public material.
    if (
      operator.authority === "owner" &&
      !descriptor.initialPackages.some((install) => sameInstall(install, rootPackage))
    ) {
      return runtimeFail(
        "kernel_runtime_binding_mismatch",
        "Kernel account root packages do not install this owner authority",
      );
    }
    return descriptor;
  }

  function prepareOperation(input: KernelRuntimePrepareInput): PreparedUserOperation {
    // prepareKernelV4UserOperation owns exact capture of the account descriptor,
    // calls, gas, and nonce; this axis only binds the authority's validation.
    return prepareKernelV4UserOperation({
      kind: input.kind,
      grantId: input.grantId,
      account: input.account,
      nonce: {
        mode: runtimeMode(input.mode),
        validation,
        nonceKey: input.nonceKey,
        sequence: input.sequence,
      },
      calls: input.calls,
      gas: input.gas,
    });
  }

  async function signOperation(prepared: unknown): Promise<`0x${string}`> {
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
    // The nonce carries Kernel's validation mode, type and identifier, so
    // recomputing the key for this runtime's own validation is an exact authority
    // check: a root runtime can never sign a permission operation, and a session
    // can never sign another permission's. The namespace is read back from the
    // prepared nonce so only the validation binding is compared. The mode is
    // compared against exactly the modes prepareOperation can emit, so an
    // operation carrying any of Kernel's four unreachable modes is refused here
    // rather than signed.
    const nonce = BigInt(operation.userOperation.nonce);
    const namespace = ((nonce >> 64n) & 0xffffn).toString(10);
    const key = (nonce >> 64n).toString(10);
    if (
      !reachableModes.some(
        (mode) => encodeKernelV4NonceKey({ mode, validation, nonceKey: namespace }) === key,
      )
    ) {
      return runtimeFail(
        "kernel_runtime_binding_mismatch",
        "Prepared UserOperation validation does not match this authority",
      );
    }
    return operator.encodeSignature(await operator.key.sign(operation.userOperationHash));
  }

  return Object.freeze({
    deployment,
    authority: operator.authority,
    keyKind: operator.key.kind,
    authorityModule,
    validation,
    packages,
    dummySignature: operator.key.dummySignature,
    bindAccount,
    prepareOperation,
    signOperation,
  });
}
