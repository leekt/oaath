import { type ChainBinding, type ChainRevocationEvidence, captureRecord } from "@oaath/protocol";
import type { OperationObserverCapabilities } from "../../operation-observer.js";
import type { KernelReads } from "../deployment/account.js";
import { captureInput, inputInvalid } from "../internal.js";
import {
  type KernelGrantApproval,
  kernelGrantApprovalNonce,
  parseVersionedKernelGrantApproval,
} from "./approval.js";
import { type KernelV33PermissionApproval, OAATH_KERNEL_V33_APPROVAL_VERSION } from "./v33.js";
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

type KernelPermissionClass =
  | Readonly<{ status: "installed" }>
  | Readonly<{ status: "approval-replayable" }>
  | Readonly<{ status: "revoked"; installNonce: string }>;

/**
 * The one status owner: `null` means installed; otherwise the observed enable/install
 * nonce decides whether the approval can still install or its nonce is consumed.
 */
function classifyKernelPermission(
  observed: bigint | null,
  approval: Readonly<KernelGrantApproval>,
): KernelPermissionClass {
  if (observed === null) return { status: "installed" };
  if (observed <= BigInt(kernelGrantApprovalNonce(approval)))
    return { status: "approval-replayable" };
  return { status: "revoked", installNonce: observed.toString(10) };
}

/** v3.3: the effective enable nonce when the configuration is removed; throws on contradiction. */
function kernelV33ObservedNonce(
  state: unknown,
  approval: Readonly<KernelV33PermissionApproval>,
): bigint | null {
  const parsed = parseKernelV33PermissionState(state);
  // Both are Kernel's uint32 validation nonce; there is no key namespace.
  return kernelV33PermissionStatus(parsed, approval) === "absent"
    ? BigInt(kernelV33EffectivePermissionNonce(parsed))
    : null;
}

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
      observed = kernelV33ObservedNonce(
        await observation.read({ type: "kernel_v33_permission_state", ...binding, blockNumber }),
        approval,
      );
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
    const classified = classifyKernelPermission(observed, approval);
    if (classified.status === "installed") return ACTIVE;
    if (classified.status === "approval-replayable") return REPLAYABLE;
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
        installNonce: classified.installNonce,
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
  const approval = parseVersionedKernelGrantApproval(input.approval);
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

/**
 * One permission's status from plain account reads at a named block.
 *
 * - `installed`: the permission is live.
 * - `approval-replayable`: absent, but the retained enable signature can still install it.
 * - `revoked`: absent and its enable nonce is consumed.
 * - `unreadable`: a read failed, or chain or state evidence was malformed or contradictory.
 */
export type KernelPermissionStatus =
  | Readonly<{ status: "installed" | "approval-replayable" | "unreadable" }>
  | Readonly<{ status: "revoked"; installNonce: string }>;

export interface ReadKernelPermissionStatusInput {
  /** The exact issued approval; its `version` selects the Kernel semantics. */
  readonly approval: Readonly<KernelGrantApproval>;
  readonly chainId: number;
  /** Plain account reads, for example `createKernelReads(publicClient)`. */
  readonly reads: Readonly<Pick<KernelReads, "read">>;
  /** The named block every state read is answered at. */
  readonly blockTag: "latest" | "finalized";
}

/**
 * Reads one approval's permission status without an observation port. It
 * classifies with the same owner as `verifyKernelPermissionRevocation`, but the
 * answer is not retained revocation evidence: use that verifier to record it.
 * Kernel `0.4.0` presence and install nonce are read at one resolved block and
 * rebound by hash; a changing tag cannot combine evidence from different blocks.
 */
export async function readKernelPermissionStatus(
  value: Readonly<ReadKernelPermissionStatusInput>,
): Promise<KernelPermissionStatus> {
  const input = captureInput(value, "Kernel permission status", new WeakSet());
  if (Object.keys(input).some((key) => !["approval", "chainId", "reads", "blockTag"].includes(key)))
    return inputInvalid("Kernel permission status contains unknown fields");
  const approval = parseVersionedKernelGrantApproval(input.approval);
  const reads = input.reads as ReadKernelPermissionStatusInput["reads"];
  const chainId = input.chainId;
  const blockTag = input.blockTag;
  if (
    typeof chainId !== "number" ||
    !Number.isSafeInteger(chainId) ||
    chainId < 1 ||
    typeof reads?.read !== "function" ||
    (blockTag !== "latest" && blockTag !== "finalized")
  )
    return inputInvalid("Kernel permission status input is invalid");
  try {
    if ((await reads.read({ type: "chain_id", chainId })) !== chainId) return UNREADABLE;
    if (approval.version !== OAATH_KERNEL_V33_APPROVAL_VERSION) {
      const signer = approval.packages.find((entry) => entry.moduleType === 6)?.module;
      if (!signer) return UNREADABLE;
      const state = blockFields(
        await reads.read({
          type: "kernel_v4_permission_state",
          chainId,
          account: approval.account,
          signer,
          permissionId: v4PermissionId(approval),
          nonce: approval.installNonce,
          blockTag,
        }),
      );
      if (Object.keys(state).length !== 2 || typeof state.installed !== "boolean")
        return UNREADABLE;
      if (state.installed)
        return state.installNonce === null
          ? Object.freeze({ status: "installed" as const })
          : UNREADABLE;
      if (
        typeof state.installNonce !== "string" ||
        !/^(?:0|[1-9][0-9]{0,77})$/u.test(state.installNonce)
      )
        return UNREADABLE;
      const nonce = BigInt(state.installNonce);
      if (nonce >> 256n !== 0n || nonce >> 64n !== BigInt(approval.installNonce) >> 64n)
        return UNREADABLE;
      return Object.freeze(classifyKernelPermission(nonce, approval));
    }
    return Object.freeze(
      classifyKernelPermission(
        kernelV33ObservedNonce(
          await reads.read({
            type: "kernel_v33_permission_state",
            chainId,
            account: approval.account,
            permissionId: approval.permissionId,
            blockTag,
          }),
          approval,
        ),
        approval,
      ),
    );
  } catch {
    return UNREADABLE;
  }
}
