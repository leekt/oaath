/**
 * Owner revocation of one Grant approval as separate awaited stages: prepare
 * (reads only), sign (one owner signature), and the caller's own submission
 * route. Finality is `verifyKernelPermissionRevocation`. The approval's version
 * selects the Kernel semantics; nothing here chooses a transport or submits.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { KernelCall, KernelUserOperationGas } from "../../kernel-v4.js";
import {
  type PreparedUserOperation,
  parsePreparedUserOperation,
} from "../../prepared-user-operation.js";
import { createKernelRuntime } from "../create-kernel-runtime.js";
import { type KernelV33Reads, kernelV33Deployment } from "../deployment/v33.js";
import {
  captureInput,
  exactCaptured,
  exactInput,
  inputAddress,
  inputInvalid,
  runtimeFail,
} from "../internal.js";
import { ecdsaKey } from "../key/ecdsa.js";
import { ownerOperator } from "../operator/owner.js";
import type { KeyProfile } from "../types.js";
import { type KernelGrantApproval, parseVersionedKernelGrantApproval } from "./approval.js";
import {
  type KernelV33PermissionApproval,
  kernelV33CapabilityHash,
  OAATH_KERNEL_V33_APPROVAL_VERSION,
} from "./v33.js";
import {
  type KernelV33PermissionState,
  kernelV33PermissionRevocationCalls,
  parseKernelV33PermissionState,
} from "./v33-revocation.js";

export const OAATH_KERNEL_PERMISSION_REVOCATION_VERSION =
  "oaath.kernel-permission-revocation/v1" as const;

export interface PrepareKernelPermissionRevocationInput {
  /** The exact issued Grant approval; its `version` selects the Kernel semantics. */
  readonly approval: Readonly<KernelGrantApproval>;
  readonly chainId: number;
  /** Caller-owned account and permission-state reads; no bundler method is used. */
  readonly reads: KernelV33Reads;
  /** Root EntryPoint lane: a caller-reserved uint16 key and its uint64 sequence. */
  readonly nonceKey: string;
  readonly sequence: string;
  readonly gas: Readonly<KernelUserOperationGas>;
  /** Optional expectations, each defaulting from the approval or its deployment. */
  readonly account?: `0x${string}`;
  readonly kernelVersion?: "0.3.3" | "0.4.0";
  readonly entryPoint?: `0x${string}`;
}

/** The JSON-safe identity a consumer records before prompting and again before broadcast. */
export interface KernelPermissionRevocationPreparation {
  readonly version: typeof OAATH_KERNEL_PERMISSION_REVOCATION_VERSION;
  readonly approval: Readonly<KernelV33PermissionApproval>;
  /** The account's root ECDSA owner at preparation; only this key may sign. */
  readonly owner: `0x${string}`;
  /** Permission state the calls were derived from. */
  readonly state: Readonly<KernelV33PermissionState>;
  readonly calls: readonly Readonly<KernelCall>[];
  readonly nonceKey: string;
  readonly sequence: string;
  readonly gas: Readonly<KernelUserOperationGas>;
  /** The exact unsigned operation and its hash. */
  readonly prepared: Readonly<PreparedUserOperation>;
}

export interface PreparedKernelPermissionRevocation extends KernelPermissionRevocationPreparation {
  /**
   * One owner signature over exactly `prepared`, encoded for the account.
   * Rebinds the account through the preparation's reads; never submits.
   */
  sign(owner: Readonly<KeyProfile>): Promise<`0x${string}`>;
}

export interface RestoreKernelPermissionRevocationInput {
  /** A recorded preparation, for example `JSON.parse(JSON.stringify(prepared))`. */
  readonly preparation: Readonly<KernelPermissionRevocationPreparation>;
  readonly reads: KernelV33Reads;
}

const GAS_KEYS = [
  "callGasLimit",
  "verificationGasLimit",
  "preVerificationGas",
  "maxFeePerGas",
  "maxPriorityFeePerGas",
] as const;

function mismatch(message: string): never {
  return runtimeFail("kernel_runtime_binding_mismatch", message);
}

/** v4 owner revocation is `prepareKernelPhoneRevocation`, which needs the permission request. */
function v33Approval(
  approval: Readonly<KernelGrantApproval>,
): Readonly<KernelV33PermissionApproval> {
  if (approval.version !== OAATH_KERNEL_V33_APPROVAL_VERSION)
    return runtimeFail(
      "kernel_runtime_unsupported",
      "Kernel v4 revocation preparation requires its permission request",
    );
  return approval;
}

function captureGas(value: unknown): Readonly<KernelUserOperationGas> {
  const gas = exactInput(value, GAS_KEYS, "Kernel revocation gas", new WeakSet());
  return Object.freeze(
    Object.fromEntries(GAS_KEYS.map((key) => [key, gas[key]])),
  ) as Readonly<KernelUserOperationGas>;
}

function ownerRuntime(chainId: number, owner: Readonly<KeyProfile>, reads: KernelV33Reads) {
  return createKernelRuntime({
    deployment: kernelV33Deployment(chainId),
    reads,
    operator: ownerOperator({ key: owner }),
  });
}

/**
 * The one v3.3 composition: derive calls from the recorded state and prepare
 * the root operation through the owner runtime. A restore compares both with
 * the recording, so a changed approval, state, lane, gas or hash is rejected.
 */
async function compose(
  fields: Omit<KernelPermissionRevocationPreparation, "version" | "calls" | "prepared"> & {
    readonly chainId: number;
  },
  reads: KernelV33Reads,
  recorded: Pick<KernelPermissionRevocationPreparation, "calls" | "prepared"> | null,
): Promise<Readonly<PreparedKernelPermissionRevocation>> {
  const { approval, owner, state, nonceKey, sequence, gas, chainId } = fields;
  const deployment = kernelV33Deployment(chainId);
  const preparer = ownerRuntime(
    chainId,
    ecdsaKey({
      account: {
        address: owner,
        sign: async () =>
          runtimeFail("kernel_runtime_signing_failed", "revocation preparation has no signer"),
      },
      validator: deployment.ecdsaValidator,
    }),
    reads,
  );
  // Proves the account's root validator and ECDSA owner on the caller's transport.
  const account = await preparer.bindAccount({ address: approval.account });
  const calls = kernelV33PermissionRevocationCalls({ approval, state });
  if (calls.length === 0) return inputInvalid("Kernel permission is already revoked");
  const prepared = preparer.prepareOperation({
    kind: "revocation",
    grantId: kernelV33CapabilityHash(approval),
    account,
    nonceKey,
    sequence,
    calls,
    gas,
  });
  if (
    recorded !== null &&
    (JSON.stringify(recorded.calls) !== JSON.stringify(calls) ||
      JSON.stringify(parsePreparedUserOperation(recorded.prepared)) !== JSON.stringify(prepared))
  )
    return mismatch("recorded revocation does not match its approval, state or operation hash");
  const preparation: KernelPermissionRevocationPreparation = Object.freeze({
    version: OAATH_KERNEL_PERMISSION_REVOCATION_VERSION,
    approval,
    owner,
    state,
    calls,
    nonceKey,
    sequence,
    gas,
    prepared,
  });
  return Object.freeze({
    ...preparation,
    async sign(value: Readonly<KeyProfile>) {
      const key = captureInput(value, "Kernel revocation owner", new WeakSet());
      // Refuse another credential before it is prompted.
      if (key.kind !== "ecdsa" || key.publicMaterial !== owner)
        return mismatch("revocation owner key does not match the prepared owner");
      const signer = ownerRuntime(chainId, value, reads);
      await signer.bindAccount({ address: approval.account });
      return signer.signOperation(prepared);
    },
  });
}

/**
 * Side-effect-free preparation of one owner revocation on one chain. Reads the
 * account's root owner and the permission's current state, then derives the
 * canonical teardown (enable-then-uninstall for an unused approval). It never
 * prompts, signs, submits or allocates a nonce: the caller reserves the lane.
 */
export async function prepareKernelPermissionRevocation(
  value: Readonly<PrepareKernelPermissionRevocationInput>,
): Promise<Readonly<PreparedKernelPermissionRevocation>> {
  const input = captureInput(value, "Kernel revocation preparation", new WeakSet());
  const optional = ["account", "kernelVersion", "entryPoint"].filter((key) =>
    Object.hasOwn(input, key),
  );
  exactCaptured(
    input,
    ["approval", "chainId", "reads", "nonceKey", "sequence", "gas", ...optional],
    "Kernel revocation preparation",
  );
  const approval = v33Approval(parseVersionedKernelGrantApproval(input.approval));
  const deployment = kernelV33Deployment(input.chainId);
  if (
    (input.kernelVersion !== undefined && input.kernelVersion !== deployment.kernelVersion) ||
    (input.entryPoint !== undefined &&
      inputAddress(input.entryPoint, "Kernel revocation EntryPoint") !==
        deployment.entryPoint.address)
  )
    return mismatch("revocation deployment contradicts its approval");
  if (
    input.account !== undefined &&
    inputAddress(input.account, "Kernel revocation account") !== approval.account
  )
    return mismatch("revocation account contradicts its approval");
  if (typeof input.nonceKey !== "string" || typeof input.sequence !== "string")
    return inputInvalid("Kernel revocation lane is invalid");
  const reads = input.reads as KernelV33Reads;
  const chainId = deployment.chainId;
  async function read(request: Parameters<KernelV33Reads["read"]>[0]) {
    try {
      return await reads.read(Object.freeze(request));
    } catch {
      return runtimeFail("kernel_runtime_read_unavailable", "Kernel revocation evidence is unread");
    }
  }
  const owner = inputAddress(
    await read({ type: "kernel_ecdsa_owner", chainId, account: approval.account }),
    "Kernel v3.3 root owner",
  );
  const state = parseKernelV33PermissionState(
    await read({
      type: "kernel_v33_permission_state",
      chainId,
      account: approval.account,
      permissionId: approval.permissionId,
    }),
  );
  return compose(
    {
      approval,
      owner,
      state,
      nonceKey: input.nonceKey,
      sequence: input.sequence,
      gas: captureGas(input.gas),
      chainId,
    },
    reads,
    null,
  );
}

/**
 * Recreates a recorded preparation. The recorded calls and operation must be
 * exactly what its approval, state, lane and gas produce on the same account;
 * permission state is not re-read, so the operation is the one first recorded.
 */
export async function restoreKernelPermissionRevocation(
  value: Readonly<RestoreKernelPermissionRevocationInput>,
): Promise<Readonly<PreparedKernelPermissionRevocation>> {
  const input = exactInput(
    value,
    ["preparation", "reads"],
    "Kernel revocation restore",
    new WeakSet(),
  );
  const record = exactInput(
    input.preparation,
    ["version", "approval", "owner", "state", "calls", "nonceKey", "sequence", "gas", "prepared"],
    "Kernel revocation preparation record",
    new WeakSet(),
  );
  if (record.version !== OAATH_KERNEL_PERMISSION_REVOCATION_VERSION)
    return inputInvalid("Kernel revocation preparation version is unsupported");
  const approval = v33Approval(parseVersionedKernelGrantApproval(record.approval));
  const prepared = parsePreparedUserOperation(record.prepared);
  if (typeof record.nonceKey !== "string" || typeof record.sequence !== "string")
    return inputInvalid("Kernel revocation lane is invalid");
  return compose(
    {
      approval,
      owner: inputAddress(record.owner, "Kernel v3.3 root owner"),
      state: parseKernelV33PermissionState(record.state),
      nonceKey: record.nonceKey,
      sequence: record.sequence,
      gas: captureGas(record.gas),
      chainId: prepared.chainId,
    },
    input.reads as KernelV33Reads,
    { calls: record.calls as KernelPermissionRevocationPreparation["calls"], prepared },
  );
}
