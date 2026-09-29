import { type ChainBinding, type ChainRevocationEvidence, captureRecord } from "@oaath/protocol";
import type { OperationObserverCapabilities } from "../../operation-observer.js";
import { captureInput, inputInvalid } from "../internal.js";
import { type KernelGrantApproval, kernelGrantApprovalNonce } from "./approval.js";
import {
  OAATH_KERNEL_ALL_CHAIN_APPROVAL_VERSION,
  parseKernelAllChainApproval,
} from "./materialize.js";
import { OAATH_KERNEL_V33_APPROVAL_VERSION, parseKernelV33PermissionApproval } from "./v33.js";
import {
  kernelV33EffectivePermissionNonce,
  kernelV33PermissionStatus,
  parseKernelV33PermissionState,
} from "./v33-revocation.js";

/**
 * One finalized answer for one approval on one chain.
 *
 * - `revoked`: the permission is absent and its enable nonce is consumed.
 * - `active`: the permission is installed.
 * - `approval-replayable`: absent, but the retained enable signature can still install it.
 * - `unreadable`: transport, finality, chain or state evidence was missing or contradictory.
 */
export type KernelPermissionRevocationVerification =
  | Readonly<{ status: "revoked"; evidence: Readonly<ChainRevocationEvidence> }>
  | Readonly<{ status: "active" | "approval-replayable" | "unreadable" }>;

export interface VerifyKernelPermissionRevocationInput {
  /** The exact issued Grant approval; its `version` selects the Kernel semantics. */
  readonly approval: Readonly<KernelGrantApproval>;
  readonly chainId: number;
  /** Caller-owned finalized chain reads, for example a chain port's `observation`. */
  readonly reads: Readonly<Pick<OperationObserverCapabilities, "read">>;
  /** Unix seconds recorded as `observedAt`; defaults to the local clock. */
  readonly now?: () => number;
}

const UNREADABLE = Object.freeze({ status: "unreadable" as const });
const ACTIVE = Object.freeze({ status: "active" as const });
const REPLAYABLE = Object.freeze({ status: "approval-replayable" as const });

function blockFields(value: unknown) {
  return captureRecord(value, "revocation block", new WeakSet(), () => {
    throw new Error("revocation block is unreadable");
  });
}

/**
 * The one revocation-evidence owner. Reads are pinned to one finalized block
 * that is rebound by height before any answer. Borrows the chain capability;
 * never signs, submits, retries or closes it. Only the enable/install nonce
 * decides replayability: EntryPoint nonce keys, including custom uint16 lanes
 * in the owner validator namespace, are not read and cannot change authority.
 */
export async function observeKernelPermissionRevocation(input: {
  readonly binding: Readonly<ChainBinding>;
  readonly approval: Readonly<KernelGrantApproval>;
  readonly observation: Readonly<Pick<OperationObserverCapabilities, "read">>;
  readonly now: () => number;
}): Promise<KernelPermissionRevocationVerification> {
  const { binding, approval, observation } = input;
  const signer = approval.packages.find((entry) => entry.moduleType === 6)?.module;
  if (signer === undefined || binding.account !== approval.account) return UNREADABLE;
  try {
    if (
      (await observation.read({ type: "chain_id", chainId: binding.chainId })) !== binding.chainId
    )
      return UNREADABLE;
    const block = blockFields(
      await observation.read({
        type: "finalized_block",
        chainId: binding.chainId,
      }),
    );
    if (
      !block ||
      typeof block.number !== "string" ||
      !/^0x(?:0|[1-9a-f][0-9a-f]*)$/u.test(block.number) ||
      typeof block.hash !== "string" ||
      !/^0x[0-9a-f]{64}$/u.test(block.hash)
    )
      return UNREADABLE;
    const blockNumber = BigInt(block.number).toString(10);
    const expected = BigInt(kernelGrantApprovalNonce(approval));
    let observed: bigint | null = null;
    if (approval.version === OAATH_KERNEL_V33_APPROVAL_VERSION) {
      if (binding.permissionId !== approval.permissionId) return UNREADABLE;
      const state = parseKernelV33PermissionState(
        await observation.read({ type: "kernel_v33_permission_state", ...binding, blockNumber }),
      );
      // Both are Kernel's uint32 validation nonce; there is no key namespace.
      if (kernelV33PermissionStatus(state, approval) === "absent")
        observed = BigInt(kernelV33EffectivePermissionNonce(state));
    } else {
      const installed = await observation.read({
        type: "kernel_permission_installed",
        ...binding,
        signer,
        blockNumber,
      });
      if (installed !== true && installed !== false) return UNREADABLE;
      if (!installed) {
        const nonce = await observation.read({
          type: "kernel_install_nonce",
          chainId: binding.chainId,
          account: binding.account,
          nonce: approval.installNonce,
          blockNumber,
        });
        // Empty account code / empty result is not zero.
        if (typeof nonce !== "string" || !/^0x[0-9a-f]{1,64}$/u.test(nonce)) return UNREADABLE;
        observed = BigInt(nonce);
        // The uint192 install key is the approval's own namespace; another key is contradictory.
        if (observed >> 64n !== expected >> 64n) return UNREADABLE;
      }
    }
    const rebound = blockFields(
      await observation.read({
        type: "canonical_block",
        chainId: binding.chainId,
        blockNumber,
      }),
    );
    if (rebound?.number !== block.number || rebound.hash !== block.hash) return UNREADABLE;
    if (observed === null) return ACTIVE;
    if (observed <= expected) return REPLAYABLE;
    return Object.freeze({
      status: "revoked" as const,
      evidence: Object.freeze({
        permission: Object.freeze({
          ...binding,
          kind: "permission_absent" as const,
          blockNumber,
          blockHash: block.hash as `0x${string}`,
          observedAt: input.now(),
        }),
        installNonce: observed.toString(10),
      }),
    });
  } catch {
    return UNREADABLE;
  }
}

/** The v4 signer package's module data starts with its right-padded bytes4 permission ID. */
function v4PermissionId(approval: Readonly<KernelGrantApproval>): `0x${string}` {
  const data = approval.packages.find((entry) => entry.moduleType === 6)?.moduleData ?? "";
  if (!/^0x[0-9a-f]{8}0{56}/u.test(data))
    return inputInvalid("Kernel approval signer has no permission ID");
  return data.slice(0, 10) as `0x${string}`;
}

/**
 * Stateless, read-only check of one issued Grant approval on one chain, for
 * servers that keep their own authority records. It dispatches on the
 * approval's version, returns the same evidence the SDK records, and never
 * signs, submits or retries. Any transport or finality failure is `unreadable`.
 */
export async function verifyKernelPermissionRevocation(
  value: Readonly<VerifyKernelPermissionRevocationInput>,
): Promise<KernelPermissionRevocationVerification> {
  const input = captureInput(value, "Kernel revocation verification", new WeakSet());
  if (Object.keys(input).some((key) => !["approval", "chainId", "reads", "now"].includes(key)))
    return inputInvalid("Kernel revocation verification contains unknown fields");
  const version = captureInput(input.approval, "Kernel approval", new WeakSet()).version;
  const approval =
    version === OAATH_KERNEL_V33_APPROVAL_VERSION
      ? parseKernelV33PermissionApproval(input.approval)
      : version === OAATH_KERNEL_ALL_CHAIN_APPROVAL_VERSION
        ? parseKernelAllChainApproval(input.approval)
        : inputInvalid("Kernel approval version is unsupported");
  const reads = input.reads as VerifyKernelPermissionRevocationInput["reads"];
  if (
    typeof input.chainId !== "number" ||
    !Number.isSafeInteger(input.chainId) ||
    input.chainId < 1 ||
    typeof reads?.read !== "function" ||
    (input.now !== undefined && typeof input.now !== "function")
  )
    return inputInvalid("Kernel revocation verification input is invalid");
  const now = (input.now as (() => number) | undefined) ?? (() => Math.floor(Date.now() / 1000));
  return observeKernelPermissionRevocation({
    binding: {
      chainId: input.chainId,
      account: approval.account,
      permissionId:
        approval.version === OAATH_KERNEL_V33_APPROVAL_VERSION
          ? approval.permissionId
          : v4PermissionId(approval),
    },
    approval,
    observation: { read: (request) => reads.read(request) },
    now,
  });
}
