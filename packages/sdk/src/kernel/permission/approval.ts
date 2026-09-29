/** Versioned Grant capability dispatch. Each artifact retains its own wire owner. */
import type { KernelAccountProfile } from "@oaath/protocol";
import { captureInput, exactInput, inputInvalid } from "../internal.js";
import {
  type KernelAllChainApproval,
  kernelAllChainCapabilityHash,
  OAATH_KERNEL_ALL_CHAIN_APPROVAL_VERSION,
  parseKernelAllChainApproval,
} from "./materialize.js";
import {
  checkKernelV33PermissionApproval,
  type KernelV33ApprovalMismatchField,
  type KernelV33ApprovalMismatchReason,
  type KernelV33ExpectedPermission,
  type KernelV33PermissionApproval,
  kernelV33CapabilityHash,
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
