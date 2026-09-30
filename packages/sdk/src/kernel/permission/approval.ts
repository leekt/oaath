/**
 * Versioned Grant capability dispatch, and the version-agnostic permission
 * approval entry points. Each approval artifact keeps its own wire owner
 * (`materialize.ts` for Kernel 0.4.0, `v33.ts` for Kernel 0.3.3); this module
 * only selects one from the runtime's deployment or the artifact's version.
 */
import {
  type CanonicalEip712TypedData,
  isKernelExistingAccountProfile,
  type KernelAccountProfile,
} from "@oaath/protocol";
import { hashTypedData, recoverAddress } from "viem";
import type { KernelCall } from "../../kernel-v4.js";
import { kernelV4ReplayableInstallTypedData } from "../../kernel-v4.js";
import type { PreparedUserOperation } from "../../prepared-user-operation.js";
import type { KernelAccountDescriptor, KernelReads } from "../deployment/account.js";
import type { KernelV33AccountDescriptor } from "../deployment/v33.js";
import {
  captureInput,
  exactInput,
  inputAddress,
  inputCapability,
  inputInvalid,
  isBytesOfLength,
  runtimeFail,
} from "../internal.js";
import { resolvePinnedSigner } from "../modules.js";
import type {
  KernelRuntime,
  KernelRuntimePrepareInput,
  KernelV33Runtime,
  KeyProfile,
} from "../types.js";
import { kernelPermissionInstallNonce } from "./install-nonce.js";
import {
  approveKernelPermissionAllChain,
  bindKernelPermissionApproval,
  type KernelAllChainApproval,
  type KernelPermissionMaterialization,
  kernelAllChainCapabilityHash,
  materializeKernelV4Permission,
  OAATH_KERNEL_ALL_CHAIN_APPROVAL_VERSION,
  parseKernelAllChainApproval,
} from "./materialize.js";
import {
  approveKernelV33Permission,
  bindKernelV33PermissionApproval,
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
import {
  kernelV33PermissionNonceAlignmentCalls,
  NONCE_ALIGNMENT_PERMISSION_ID,
} from "./v33-revocation.js";

export type KernelGrantApproval = KernelAllChainApproval | KernelV33PermissionApproval;

export function parseKernelGrantApproval(
  value: unknown,
  account: Readonly<KernelAccountProfile>,
): Readonly<KernelGrantApproval> {
  const approval =
    account.kernelVersion === "0.4.0"
      ? parseKernelAllChainApproval(value)
      : parseKernelV33PermissionApproval(value);
  if (isKernelExistingAccountProfile(account) && approval.account !== account.address)
    return inputInvalid("Kernel approval names another account");
  return approval;
}

export interface SignedKernelPermissionApprovalInput
  extends Omit<ApproveKernelPermissionInput, "owner"> {
  /**
   * The account's ECDSA root owner address, already proven onchain, for
   * example by binding the account through `ownerOperator`.
   */
  readonly owner: `0x${string}`;
  /** The typed data the wallet signed; it must hash as `kernelPermissionEnableTypedData`. */
  readonly typedData: unknown;
  /** The wallet's 65-byte `eth_signTypedData_v4` signature. */
  readonly signature: unknown;
}

/**
 * Assembles the approval `approveKernelPermission` would produce from an owner
 * signature taken elsewhere, such as a browser wallet's `eth_signTypedData_v4`.
 * The typed data must hash to the runtime, account and nonce's enable digest
 * (`kernel_runtime_binding_mismatch`), and the signature must recover to the
 * owner (`kernel_runtime_signature_invalid`) before anything is returned.
 */
export async function signedKernelPermissionApproval(
  value: SignedKernelPermissionApprovalInput,
): Promise<Readonly<KernelGrantApproval>> {
  const record = exactInput(
    value,
    ["runtime", "account", "nonce", "owner", "typedData", "signature"],
    "Kernel signed permission approval",
    new WeakSet(),
  );
  const owner = inputAddress(record.owner, "Kernel permission owner");
  const runtime = record.runtime as Readonly<KernelRuntime>;
  const account = record.account as ApproveKernelPermissionInput["account"];
  const nonce = record.nonce as string;
  const digest = hashTypedData(
    kernelPermissionEnableTypedData({ runtime, account, nonce }) as Parameters<
      typeof hashTypedData
    >[0],
  );
  let signed: `0x${string}` | undefined;
  try {
    signed = hashTypedData(record.typedData as Parameters<typeof hashTypedData>[0]);
  } catch {
    signed = undefined;
  }
  if (signed !== digest)
    return runtimeFail(
      "kernel_runtime_binding_mismatch",
      "signed typed data is not this permission's enable approval",
    );
  if (typeof record.signature !== "string" || !isBytesOfLength(record.signature.toLowerCase(), 65))
    return runtimeFail("kernel_runtime_signature_invalid", "enable signature is invalid");
  const enableSignature = record.signature.toLowerCase() as `0x${string}`;
  let recovered: `0x${string}` | undefined;
  try {
    recovered = (
      await recoverAddress({ hash: digest, signature: enableSignature })
    ).toLowerCase() as `0x${string}`;
  } catch {
    recovered = undefined;
  }
  if (recovered !== owner)
    return runtimeFail("kernel_runtime_signature_invalid", "enable signature is not the owner's");
  if (isV33(runtime)) {
    const scope = kernelV33RuntimeScope(
      runtime as unknown as Readonly<KernelV33Runtime>,
      account as Readonly<KernelV33AccountDescriptor>,
      nonce,
    );
    return parseKernelV33PermissionApproval({
      version: OAATH_KERNEL_V33_APPROVAL_VERSION,
      ...scope,
      digest,
      enableSignature,
    });
  }
  return parseKernelAllChainApproval({
    version: OAATH_KERNEL_ALL_CHAIN_APPROVAL_VERSION,
    account: accountAddress(account),
    installNonce: nonce,
    packages: sessionPackages(runtime),
    digest,
    enableSignature,
  });
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
  readonly runtime: Readonly<KernelRuntime> | Readonly<KernelV33Runtime>;
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
  readonly runtime: Readonly<KernelRuntime> | Readonly<KernelV33Runtime>;
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
  readonly runtime: Readonly<KernelRuntime> | Readonly<KernelV33Runtime>;
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

export interface BindKernelPermissionEnableInput {
  /** The session runtime for the target chain, composed over that chain's deployment. */
  readonly runtime: Readonly<KernelRuntime> | Readonly<KernelV33Runtime>;
  /** The account bound by that runtime on the target chain. */
  readonly account: Readonly<KernelAccountDescriptor>;
  readonly approval: Readonly<KernelGrantApproval>;
}

/** One chain's enable-mode first execution, before its session signature exists. */
export interface KernelPermissionEnable {
  /**
   * The exact enable envelope around the session key's placeholder signature:
   * the real owner approval, so validation reaches the session signer. For
   * `eth_estimateUserOperationGas` only; it never validates onchain.
   */
  readonly simulationSignature: `0x${string}`;
  /** Prepares the enable-mode execution; it signs nothing. */
  prepareOperation(
    input: Omit<MaterializeKernelPermissionInput, "approval" | "runtime" | "account">,
  ): PreparedUserOperation;
  /** The session key's one signature, wrapped in the enable envelope. */
  signOperation(prepared: Readonly<PreparedUserOperation>): Promise<`0x${string}`>;
}

/**
 * Binds an owner approval to one chain's session runtime so an enable-mode
 * execution can be prepared and estimated before the session key is asked to
 * sign: prepare with placeholder gas, estimate with `simulationSignature`,
 * prepare again with the estimate, then `signOperation` once.
 */
export function bindKernelPermissionEnable(
  value: BindKernelPermissionEnableInput,
): Readonly<KernelPermissionEnable> {
  const record = exactInput(
    value,
    ["runtime", "account", "approval"],
    "Kernel permission enable",
    new WeakSet(),
  );
  const runtime = record.runtime as Readonly<KernelRuntime>;
  const account = record.account as Readonly<KernelAccountDescriptor>;
  const address = accountAddress(account);
  const approval = parseVersionedKernelGrantApproval(record.approval);
  if (isV33(runtime) !== (approval.version === OAATH_KERNEL_V33_APPROVAL_VERSION))
    return runtimeFail(
      "kernel_runtime_binding_mismatch",
      "Kernel approval belongs to another Kernel version",
    );
  const bound =
    approval.version === OAATH_KERNEL_V33_APPROVAL_VERSION
      ? bindKernelV33PermissionApproval({
          runtime: runtime as unknown as Readonly<KernelV33Runtime>,
          approval,
          account: address,
        })
      : bindKernelPermissionApproval({ runtime, approval, account: address });
  return Object.freeze({
    simulationSignature: bound.dummySignature,
    prepareOperation(
      input: Omit<MaterializeKernelPermissionInput, "approval" | "runtime" | "account">,
    ) {
      const captured = captureInput(input, "Kernel permission enable operation", new WeakSet());
      return bound.prepareOperation({
        ...(captured as unknown as KernelRuntimePrepareInput),
        kind: "execution",
        account,
      } as never);
    },
    signOperation: (prepared: Readonly<PreparedUserOperation>) => bound.signOperation(prepared),
  });
}

export interface KernelPermissionNonceAlignmentInput {
  /** The session runtime for the chain being aligned. */
  readonly runtime: Readonly<KernelRuntime> | Readonly<KernelV33Runtime>;
  /** The account bound by that runtime. */
  readonly account: Readonly<KernelAccountDescriptor>;
  readonly reads: KernelReads;
  /** The target enable nonce: the highest `kernelPermissionNonce` among the chains. */
  readonly nonce: string;
}

/**
 * The owner calls that align one chain's enable nonce for a session's
 * not-yet-installed permission with `nonce`, so one approval can cover every
 * chain. Execute them as one owner operation on that chain, then prepare the
 * approval again. An aligned chain needs no calls. Kernel `0.4.0` approvals use
 * a request-derived nonce that is equal on every chain, so they fail with
 * `kernel_runtime_unsupported`. See `kernelV33PermissionNonceAlignmentCalls`
 * for the effects on the account.
 */
export async function kernelPermissionNonceAlignmentCalls(
  value: KernelPermissionNonceAlignmentInput,
): Promise<readonly Readonly<KernelCall>[]> {
  const context = new WeakSet();
  const record = exactInput(
    value,
    ["runtime", "account", "reads", "nonce"],
    "Kernel permission nonce alignment",
    context,
  );
  const runtime = record.runtime as Readonly<KernelRuntime>;
  if (!isV33(runtime))
    return runtimeFail(
      "kernel_runtime_unsupported",
      "Kernel 0.4.0 approvals use one request-derived nonce on every chain",
    );
  const v33 = runtime as unknown as Readonly<KernelV33Runtime>;
  const scope = kernelV33RuntimeScope(
    v33,
    record.account as Readonly<KernelV33AccountDescriptor>,
    "1",
  );
  const read = inputCapability<KernelReads["read"]>(
    exactInput(record.reads, ["read"], "Kernel permission nonce alignment reads", context).read,
    "Kernel permission nonce alignment read",
  );
  const chainId = v33.deployment.chainId;
  const signerModule = resolvePinnedSigner("ecdsa");
  let state: unknown;
  let alignmentState: unknown;
  let signerCode: unknown;
  try {
    const stateOf = (permissionId: `0x${string}`) =>
      read({ type: "kernel_v33_permission_state", chainId, account: scope.account, permissionId });
    state = await stateOf(scope.permissionId);
    alignmentState = await stateOf(NONCE_ALIGNMENT_PERMISSION_ID);
    signerCode = await read({ type: "code", chainId, address: signerModule });
  } catch {
    return runtimeFail(
      "kernel_runtime_read_unavailable",
      "Kernel permission state could not be read",
    );
  }
  if (typeof signerCode !== "string" || signerCode === "0x")
    return runtimeFail(
      "kernel_runtime_signer_unavailable",
      "the nonce alignment signer module is not deployed on this chain",
    );
  return kernelV33PermissionNonceAlignmentCalls({
    scope,
    state: state as never,
    alignmentState: alignmentState as never,
    signerModule,
    nonce: record.nonce as string,
  });
}
