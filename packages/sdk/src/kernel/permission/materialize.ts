/**
 * All-chain permission materialization: one owner approval, every supported
 * chain, including a chain introduced after the approval was made.
 *
 * The authority is Kernel v4's replayable enable mode, not a collection of
 * per-chain approvals. `approveKernelPermissionAllChain` takes exactly one owner
 * signature, over a digest that binds the account, Kernel's install nonce and the
 * exact install packages — and no chain ID, because Kernel hashes a replayable
 * enable under a domain separator that omits it. Every module and account address
 * in this SDK is CREATE2-derived, so one set of initial packages yields one
 * account address everywhere, so that one signature authorizes the same install
 * on a chain nobody had configured when the owner approved.
 * `kernelV4ReplayableInstallDigest` in kernel-v4.ts owns the derivation and cites
 * the vendored Kernel source it was read from.
 *
 * `materializeKernelPermission` spends that approval on one chain: the session's
 * first operation there carries the enable envelope, which installs the
 * permission during Kernel's validation phase and then validates that same
 * operation against it. Nothing else on that chain needs the owner. Later
 * operations use `standard` mode against the now-installed permission, so the
 * approval is spent once per chain and the owner is never asked again.
 *
 * What stays chain-local is unchanged: account state, Kernel's install nonce, the
 * EntryPoint nonce, the operation identity, the submission route, and inclusion,
 * finality and revocation evidence. This module claims no global atomic install —
 * it authorizes one install per chain from one approval.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  captureKernelV4Installs,
  encodeKernelV4EnableSignature,
  type KernelV4Install,
  kernelV4ReplayableInstallDigest,
} from "../../kernel-v4.js";
import type { PreparedUserOperation } from "../../prepared-user-operation.js";
import {
  captureKeyProfile,
  exactInput,
  inputAddress,
  inputInvalid,
  inputUint,
  isBytes,
  runtimeFail,
  sameInstall,
} from "../internal.js";
import type { KernelRuntime, KernelRuntimePrepareInput, KeyProfile } from "../types.js";

const MAX_UINT256 = (1n << 256n) - 1n;

/** The version of this approval artifact. An older one is rejected, never read. */
export const OAATH_KERNEL_ALL_CHAIN_APPROVAL_VERSION =
  "oaath.kernel.all-chain-approval/v1" as const;

/**
 * One owner approval covering one permission on every supported chain. Every
 * field is chain-independent, which is the point: there is no chain ID to bind
 * and no per-chain variant to collect.
 */
export interface KernelAllChainApproval {
  readonly version: typeof OAATH_KERNEL_ALL_CHAIN_APPROVAL_VERSION;
  /** The Kernel account this approval installs into, on every chain. */
  readonly account: `0x${string}`;
  /** Kernel's own install nonce, `key << 64 | sequence`, as a decimal uint256. */
  readonly installNonce: string;
  /** The exact ERC-7579 packages the enable envelope installs, in install order. */
  readonly packages: readonly Readonly<KernelV4Install>[];
  /** The chain-agnostic digest the owner signed. */
  readonly digest: `0x${string}`;
  /** The one owner signature. Kernel's root validation verifies it as-is. */
  readonly enableSignature: `0x${string}`;
}

export interface ApproveKernelPermissionAllChainInput {
  /**
   * The account's owner credential. Kernel verifies a replayable enable signature
   * through the account's *root* validation, with the account itself as the
   * requester, so the normalized key signature is what it expects: root
   * validation carries no signature envelope of its own.
   */
  readonly owner: Readonly<KeyProfile>;
  /**
   * The Kernel account address, CREATE2-derived from the owner's initial packages
   * and therefore the same on every chain. A wrong address yields a digest the
   * account's root validation will not accept, so materialization fails closed
   * on-chain rather than installing anything.
   */
  readonly account: `0x${string}`;
  /** Kernel's install nonce for this approval, as a decimal uint256. */
  readonly installNonce: string;
  /** The permission's install packages, exactly as the session runtime resolves them. */
  readonly packages: readonly KernelV4Install[];
}

/**
 * One materialization request. The operation axis is the runtime's own prepare
 * contract minus the two fields this module owns: the kind is always an
 * execution, and the mode is always Kernel's replayable enable mode.
 */
export interface MaterializeKernelPermissionInput
  extends Omit<KernelRuntimePrepareInput, "kind" | "mode"> {
  readonly approval: Readonly<KernelAllChainApproval>;
  /** The session runtime for the target chain, composed over that chain's deployment. */
  readonly runtime: Readonly<KernelRuntime>;
}

/**
 * One chain-local materialization: the exact operation identity and the signature
 * that installs the permission and authorizes that operation together.
 */
export interface KernelPermissionMaterialization {
  readonly prepared: PreparedUserOperation;
  /** Kernel's EnableModeSignature envelope: the owner approval plus the session signature. */
  readonly signature: `0x${string}`;
}

/** The account, nonce and packages one approval binds, captured exactly once. */
function capturedApprovalScope(
  account: unknown,
  installNonce: unknown,
  packages: unknown,
): Readonly<{
  account: `0x${string}`;
  installNonce: string;
  packages: readonly Readonly<KernelV4Install>[];
}> {
  return Object.freeze({
    account: inputAddress(account, "Kernel all-chain approval account"),
    installNonce: inputUint(
      installNonce,
      MAX_UINT256,
      "Kernel all-chain approval install nonce",
    ).toString(10),
    packages: captureKernelV4Installs(packages),
  });
}

/**
 * Takes the one owner signature that covers this permission on every supported
 * chain, now and later. Nothing here reads a chain or a deployment profile,
 * because nothing about the approval depends on one.
 */
export async function approveKernelPermissionAllChain(
  value: ApproveKernelPermissionAllChainInput,
): Promise<Readonly<KernelAllChainApproval>> {
  const record = exactInput(
    value,
    ["owner", "account", "installNonce", "packages"],
    "Kernel all-chain approval request",
    new WeakSet(),
  );
  const owner = captureKeyProfile(record.owner);
  const scope = capturedApprovalScope(record.account, record.installNonce, record.packages);
  const digest = kernelV4ReplayableInstallDigest({
    account: scope.account,
    nonce: scope.installNonce,
    packages: scope.packages,
  });
  // The key profile normalizes and locally verifies its own signature, so an
  // approval never carries bytes the owner's public material does not recover to.
  return Object.freeze({
    version: OAATH_KERNEL_ALL_CHAIN_APPROVAL_VERSION,
    ...scope,
    digest,
    enableSignature: await owner.sign(digest),
  });
}

/**
 * Spends one all-chain approval on one chain: prepares the session's first
 * operation there in `enable-replayable` mode and wraps the session signature in
 * Kernel's EnableModeSignature envelope beside the owner approval.
 *
 * The envelope lives in the signature, which no operation hash covers, so it
 * changes nothing about the prepared identity the runtime derived. Two bindings
 * are checked before any signature exists: the approval installs exactly the
 * packages this runtime validates through, and it covers exactly this account.
 */
export async function materializeKernelPermission(
  value: MaterializeKernelPermissionInput,
): Promise<Readonly<KernelPermissionMaterialization>> {
  const approval = exactInput(
    value.approval,
    ["version", "account", "installNonce", "packages", "digest", "enableSignature"],
    "Kernel all-chain approval",
    new WeakSet(),
  );
  if (approval.version !== OAATH_KERNEL_ALL_CHAIN_APPROVAL_VERSION) {
    return inputInvalid("Kernel all-chain approval version is unsupported");
  }
  const scope = capturedApprovalScope(approval.account, approval.installNonce, approval.packages);
  if (!isBytes(approval.enableSignature) || approval.enableSignature === "0x") {
    return inputInvalid("Kernel all-chain approval enable signature is invalid");
  }
  // The digest is recomputed rather than trusted: a stored approval whose digest
  // no longer matches its own account, nonce and packages is contradictory
  // evidence, and the owner signature beside it covers something else.
  if (
    approval.digest !==
    kernelV4ReplayableInstallDigest({
      account: scope.account,
      nonce: scope.installNonce,
      packages: scope.packages,
    })
  ) {
    return inputInvalid("Kernel all-chain approval digest is contradictory");
  }

  const runtimePackages = captureKernelV4Installs(value.runtime.packages);
  if (
    runtimePackages.length !== scope.packages.length ||
    !runtimePackages.every((install, index) => {
      const approved = scope.packages[index];
      return approved !== undefined && sameInstall(install, approved);
    })
  ) {
    return runtimeFail(
      "kernel_runtime_binding_mismatch",
      "Kernel all-chain approval does not install this runtime's permission",
    );
  }

  // prepareOperation owns exact capture of the descriptor, calls, gas and nonce;
  // this axis only binds the enable mode and the envelope.
  const prepared = value.runtime.prepareOperation({
    kind: "execution",
    mode: "enable-replayable",
    grantId: value.grantId,
    account: value.account,
    nonceKey: value.nonceKey,
    sequence: value.sequence,
    calls: value.calls,
    gas: value.gas,
    paymaster: value.paymaster ?? null,
  });
  if (prepared.userOperation.sender !== scope.account) {
    return runtimeFail(
      "kernel_runtime_binding_mismatch",
      "Kernel all-chain approval does not cover this account",
    );
  }
  return Object.freeze({
    prepared,
    signature: encodeKernelV4EnableSignature({
      nonce: scope.installNonce,
      packages: scope.packages,
      enableSignature: approval.enableSignature,
      userOperationSignature: await value.runtime.signOperation(prepared),
    }),
  });
}
