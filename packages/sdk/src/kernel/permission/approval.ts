/**
 * Versioned Grant capability dispatch, and the version-agnostic permission
 * approval entry points. Each approval artifact keeps its own wire owner
 * (`materialize.ts` for Kernel 0.4.0, `v33.ts` for Kernel 0.3.3); this module
 * only selects one from the runtime's deployment or the artifact's version.
 */
import type { CanonicalEip712TypedData, KernelAccountProfile } from "@oaath/protocol";
import { kernelV4ReplayableInstallTypedData } from "../../kernel-v4.js";
import type { KernelAccountDescriptor, KernelReads } from "../deployment/account.js";
import type { KernelV33AccountDescriptor } from "../deployment/v33.js";
import { captureInput, exactInput, inputAddress, inputInvalid } from "../internal.js";
import type {
  KernelRuntime,
  KernelRuntimePrepareInput,
  KernelV33Runtime,
  KeyProfile,
} from "../types.js";
import { kernelPermissionInstallNonce } from "./install-nonce.js";
import {
  approveKernelPermissionAllChain,
  type KernelAllChainApproval,
  type KernelPermissionMaterialization,
  kernelAllChainCapabilityHash,
  materializeKernelV4Permission,
  OAATH_KERNEL_ALL_CHAIN_APPROVAL_VERSION,
  parseKernelAllChainApproval,
} from "./materialize.js";
import {
  approveKernelV33Permission,
  checkKernelV33PermissionApproval,
  type KernelV33ApprovalMismatchField,
  type KernelV33ApprovalMismatchReason,
  type KernelV33ExpectedPermission,
  type KernelV33PermissionApproval,
  kernelV33CapabilityHash,
  kernelV33PermissionEnableTypedData,
  kernelV33PermissionInstallNonce,
  kernelV33RuntimeScope,
  materializeKernelV33Permission,
  OAATH_KERNEL_V33_APPROVAL_VERSION,
  parseKernelV33PermissionApproval,
} from "./v33.js";

export type KernelGrantApproval = KernelAllChainApproval | KernelV33PermissionApproval;

export function parseKernelGrantApproval(
  value: unknown,
  account: Readonly<KernelAccountProfile>,
): Readonly<KernelGrantApproval> {
  if (account.kernelVersion === "0.4.0") return parseKernelAllChainApproval(value);
  const approval = parseKernelV33PermissionApproval(value);
  if (approval.account !== account.address)
    return inputInvalid("Kernel v3.3 approval names another account");
  return approval;
}

/** Captures an approval by its own version discriminant, with no account profile. */
export function parseVersionedKernelGrantApproval(value: unknown): Readonly<KernelGrantApproval> {
  const version = captureInput(value, "Kernel approval", new WeakSet()).version;
  if (version === OAATH_KERNEL_V33_APPROVAL_VERSION) return parseKernelV33PermissionApproval(value);
  if (version === OAATH_KERNEL_ALL_CHAIN_APPROVAL_VERSION)
    return parseKernelAllChainApproval(value);
  return inputInvalid("Kernel approval version is unsupported");
}

export function kernelGrantCapabilityHash(approval: Readonly<KernelGrantApproval>): `0x${string}` {
  return approval.version === OAATH_KERNEL_V33_APPROVAL_VERSION
    ? kernelV33CapabilityHash(approval)
    : kernelAllChainCapabilityHash(approval);
}

export type KernelPermissionApprovalVerification =
  | {
      readonly status: "verified";
      /** The parsed approval whose scope and owner signature were proven. */
      readonly binding: Readonly<{ approval: Readonly<KernelGrantApproval>; owner: `0x${string}` }>;
    }
  | {
      readonly status: "mismatch";
      readonly field: "version" | KernelV33ApprovalMismatchField;
      readonly reason: "unsupported" | KernelV33ApprovalMismatchReason;
    };

/**
 * Pure offline check of a permission approval against the reviewed scope. It
 * makes no RPC, signer or submission call and implies nothing about chain
 * readiness, installation or inclusion. Dispatches on `approval.version`; an
 * approval kind without offline verification is an `unsupported` mismatch.
 * Only an EOA root owner can verify: ERC-1271 owners need chain state. v3.3
 * approvals carry no account index; the account address is the binding.
 * Malformed approval or expected input throws kernel_runtime_input_invalid.
 */
export async function verifyKernelPermissionApproval(value: {
  readonly approval: unknown;
  readonly expected: Readonly<KernelV33ExpectedPermission>;
}): Promise<KernelPermissionApprovalVerification> {
  const context = new WeakSet();
  const record = exactInput(value, ["approval", "expected"], "Kernel approval check", context);
  const captured = captureInput(record.approval, "Kernel permission approval", context);
  if (captured.version !== OAATH_KERNEL_V33_APPROVAL_VERSION)
    return Object.freeze({ status: "mismatch", field: "version", reason: "unsupported" });
  const approval = parseKernelV33PermissionApproval(captured);
  const checked = await checkKernelV33PermissionApproval(approval, record.expected);
  if ("field" in checked) return Object.freeze({ status: "mismatch", ...checked });
  return Object.freeze({
    status: "verified",
    binding: Object.freeze({ approval, owner: checked.owner }),
  });
}

export function kernelGrantApprovalNonce(approval: Readonly<KernelGrantApproval>): string {
  return approval.version === OAATH_KERNEL_V33_APPROVAL_VERSION
    ? approval.nonce
    : approval.installNonce;
}

function isV33(runtime: Readonly<KernelRuntime>): boolean {
  let version: unknown;
  try {
    version = runtime.deployment.kernelVersion;
  } catch {
    return inputInvalid("Kernel permission runtime is invalid");
  }
  return version === "0.3.3";
}

/** A Kernel 0.4.0 approval covers the permission a session runtime installs. */
function sessionPackages(runtime: Readonly<KernelRuntime>) {
  if (runtime.authority !== "session" || runtime.validation.kind !== "permission")
    return inputInvalid("Kernel permission approval requires a session runtime");
  return runtime.packages;
}

function accountAddress(account: unknown): `0x${string}` {
  return typeof account === "string"
    ? inputAddress(account, "Kernel permission account")
    : inputAddress(
        (account as { readonly account?: unknown } | null)?.account,
        "Kernel permission account",
      );
}

export interface KernelPermissionNonceInput {
  /** The session runtime whose permission will be approved. */
  readonly runtime: Readonly<KernelRuntime>;
  readonly account: Readonly<KernelAccountDescriptor>;
  readonly reads: KernelReads;
  /**
   * A unique 32-byte hash for this approval, such as the permission request
   * hash. It seeds a fresh Kernel `0.4.0` install key; a Kernel `0.3.3`
   * account's effective validation nonce is read onchain instead.
   */
  readonly requestHash: `0x${string}`;
}

/** The enable nonce one approval binds, chosen the way the runtime's deployment requires. */
export async function kernelPermissionNonce(value: KernelPermissionNonceInput): Promise<string> {
  const record = exactInput(
    value,
    ["runtime", "account", "reads", "requestHash"],
    "Kernel permission nonce request",
    new WeakSet(),
  );
  const runtime = record.runtime as Readonly<KernelRuntime>;
  const nonce = kernelPermissionInstallNonce(record.requestHash as `0x${string}`);
  if (!isV33(runtime)) return nonce;
  return kernelV33PermissionInstallNonce({
    runtime: runtime as unknown as Readonly<KernelV33Runtime>,
    account: record.account as Readonly<KernelV33AccountDescriptor>,
    reads: record.reads as KernelReads,
  });
}

export interface ApproveKernelPermissionInput {
  /** The account's root owner credential; it signs exactly once. */
  readonly owner: Readonly<KeyProfile>;
  /** The session runtime whose permission packages the owner approves. */
  readonly runtime: Readonly<KernelRuntime>;
  /**
   * The bound account. A derived Kernel `0.4.0` account may be given by its
   * CREATE2 address, since its approval never depends on a chain.
   */
  readonly account: Readonly<KernelAccountDescriptor> | `0x${string}`;
  /** From `kernelPermissionNonce`. */
  readonly nonce: string;
}

/** Takes the one owner signature that enables a session's permission on every chain. */
export async function approveKernelPermission(
  value: ApproveKernelPermissionInput,
): Promise<Readonly<KernelGrantApproval>> {
  const record = exactInput(
    value,
    ["owner", "runtime", "account", "nonce"],
    "Kernel permission approval",
    new WeakSet(),
  );
  const runtime = record.runtime as Readonly<KernelRuntime>;
  if (isV33(runtime))
    return approveKernelV33Permission({
      owner: record.owner as Readonly<KeyProfile>,
      runtime: runtime as unknown as Readonly<KernelV33Runtime>,
      account: record.account as Readonly<KernelV33AccountDescriptor>,
      nonce: record.nonce as string,
    });
  return approveKernelPermissionAllChain({
    owner: record.owner as Readonly<KeyProfile>,
    account: accountAddress(record.account),
    installNonce: record.nonce as string,
    packages: sessionPackages(runtime),
  });
}

/** The EIP-712 value a wallet signs for one approval; the digest `approveKernelPermission` signs. */
export type KernelPermissionEnableTypedData =
  | ReturnType<typeof kernelV33PermissionEnableTypedData>
  | Readonly<CanonicalEip712TypedData>;

/** The exact typed data for a wallet's `signTypedData` prompt, from the runtime's deployment. */
export function kernelPermissionEnableTypedData(
  value: Omit<ApproveKernelPermissionInput, "owner">,
): KernelPermissionEnableTypedData {
  const record = exactInput(
    value,
    ["runtime", "account", "nonce"],
    "Kernel permission typed data",
    new WeakSet(),
  );
  const runtime = record.runtime as Readonly<KernelRuntime>;
  if (isV33(runtime))
    return kernelV33PermissionEnableTypedData(
      kernelV33RuntimeScope(
        runtime as unknown as Readonly<KernelV33Runtime>,
        record.account as Readonly<KernelV33AccountDescriptor>,
        record.nonce as string,
      ),
    );
  return kernelV4ReplayableInstallTypedData({
    account: accountAddress(record.account),
    nonce: record.nonce as string,
    packages: sessionPackages(runtime),
  });
}

export interface MaterializeKernelPermissionInput
  extends Omit<KernelRuntimePrepareInput<KernelAccountDescriptor>, "kind" | "mode"> {
  readonly approval: Readonly<KernelGrantApproval>;
  /** The session runtime for the target chain, composed over that chain's deployment. */
  readonly runtime: Readonly<KernelRuntime>;
}

/**
 * Prepares and signs a session's first execution on one chain together with the
 * owner approval that installs its permission there.
 */
export async function materializeKernelPermission(
  value: MaterializeKernelPermissionInput,
): Promise<Readonly<KernelPermissionMaterialization>> {
  const record = captureInput(value, "Kernel permission materialization", new WeakSet());
  if (isV33(record.runtime as Readonly<KernelRuntime>))
    return materializeKernelV33Permission(record as never);
  return materializeKernelV4Permission(record as never);
}
