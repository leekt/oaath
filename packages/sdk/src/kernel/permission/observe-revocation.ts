import { type ChainBinding, type ChainRevocationEvidence, captureRecord } from "@oaath/protocol";
import type { OperationObserverCapabilities } from "../../operation-observer.js";
import type { KernelAllChainApproval } from "./materialize.js";

function blockFields(value: unknown) {
  return captureRecord(value, "revocation block", new WeakSet(), () => {
    throw new Error("revocation block is unreadable");
  });
}

/**
 * One finalized effect read, including an unused approval's nonce namespace.
 * Borrows the chain capability; never signs, submits, retries or closes it.
 * Permission absence alone does not invalidate a replayable enable signature.
 */
export async function observeKernelPermissionRevocation(input: {
  readonly binding: Readonly<ChainBinding>;
  readonly approval: Readonly<KernelAllChainApproval>;
  readonly observation: Readonly<OperationObserverCapabilities>;
  readonly now: () => number;
}): Promise<Readonly<ChainRevocationEvidence> | null> {
  const { binding, approval, observation } = input;
  const signer = approval.packages.find((entry) => entry.moduleType === 6)?.module;
  if (signer === undefined || binding.account !== approval.account) return null;
  try {
    if (
      (await observation.read({ type: "chain_id", chainId: binding.chainId })) !== binding.chainId
    )
      return null;
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
      return null;
    const blockNumber = BigInt(block.number).toString(10);
    const installed = await observation.read({
      type: "kernel_permission_installed",
      ...binding,
      signer,
      blockNumber,
    });
    if (installed !== false) return null;
    const nonce = await observation.read({
      type: "kernel_install_nonce",
      chainId: binding.chainId,
      account: binding.account,
      nonce: approval.installNonce,
      blockNumber,
    });
    // eth_call may return a padded ABI word. Empty account code / empty result is not zero.
    if (typeof nonce !== "string" || !/^0x[0-9a-f]{1,64}$/u.test(nonce)) return null;
    const observed = BigInt(nonce);
    const expected = BigInt(approval.installNonce);
    if (observed >> 64n !== expected >> 64n || observed <= expected) return null;
    const rebound = blockFields(
      await observation.read({
        type: "canonical_block",
        chainId: binding.chainId,
        blockNumber,
      }),
    );
    if (rebound?.number !== block.number || rebound.hash !== block.hash) return null;
    return Object.freeze({
      permission: Object.freeze({
        ...binding,
        kind: "permission_absent" as const,
        blockNumber,
        blockHash: block.hash as `0x${string}`,
        observedAt: input.now(),
      }),
      installNonce: observed.toString(10),
    });
  } catch {
    return null;
  }
}
