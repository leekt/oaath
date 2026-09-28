/** Versioned Grant capability dispatch. Each artifact retains its own wire owner. */
import type { KernelAccountProfile } from "@oaath/protocol";
import { inputInvalid } from "../internal.js";
import {
  type KernelAllChainApproval,
  kernelAllChainCapabilityHash,
  parseKernelAllChainApproval,
} from "./materialize.js";
import {
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

export function kernelGrantCapabilityHash(approval: Readonly<KernelGrantApproval>): `0x${string}` {
  return approval.version === OAATH_KERNEL_V33_APPROVAL_VERSION
    ? kernelV33CapabilityHash(approval)
    : kernelAllChainCapabilityHash(approval);
}

export function kernelGrantApprovalNonce(approval: Readonly<KernelGrantApproval>): string {
  return approval.version === OAATH_KERNEL_V33_APPROVAL_VERSION
    ? approval.nonce
    : approval.installNonce;
}
