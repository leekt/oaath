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
  KERNEL_V4_EXECUTE_USER_OP_SELECTOR,
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
} from "./internal.js";
import { exactKernelDeployment } from "./modules.js";
import type {
  CreateKernelRuntimeInput,
  KernelRuntime,
  KernelRuntimeBindAccountInput,
  KernelRuntimePrepareInput,
  KeyProfile,
  OperatorProfile,
} from "./types.js";

interface CapturedOperator {
  readonly authority: "owner" | "session";
  readonly key: Readonly<KeyProfile>;
  readonly resolveValidation: OperatorProfile["resolveValidation"];
  readonly resolvePackages: OperatorProfile["resolvePackages"];
}

function captureOperator(value: unknown, context: CaptureContext): CapturedOperator {
  const record = exactInput(
    value,
    ["authority", "key", "policy", "resolveValidation", "resolvePackages"],
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

function sameInstall(left: Readonly<KernelV4Install>, right: Readonly<KernelV4Install>): boolean {
  return (
    left.moduleType === right.moduleType &&
    left.module === right.module &&
    left.moduleData === right.moduleData &&
    left.internalData === right.internalData
  );
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
  const validator = operator.key.resolveValidator(deployment);
  const validation: Readonly<KernelV4Validation> = operator.resolveValidation(deployment);
  const packages = operator.resolvePackages(deployment);
  const rootPackage: Readonly<KernelV4Install> =
    packages[0] ?? inputInvalid("Kernel operator resolved no install packages");

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
        mode: "standard",
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
    const wrapped = operation.userOperation.callData.startsWith(KERNEL_V4_EXECUTE_USER_OP_SELECTOR);
    if (wrapped !== (operator.authority === "session")) {
      return runtimeFail(
        "kernel_runtime_binding_mismatch",
        "Prepared UserOperation validation shape does not match this authority",
      );
    }
    return operator.key.sign(operation.userOperationHash);
  }

  return Object.freeze({
    deployment,
    authority: operator.authority,
    keyKind: operator.key.kind,
    validator,
    validation,
    packages,
    dummySignature: operator.key.dummySignature,
    bindAccount,
    prepareOperation,
    signOperation,
  });
}
