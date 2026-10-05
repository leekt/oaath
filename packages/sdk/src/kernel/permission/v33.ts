/**
 * Kernel 0.3.3 all-chain permission enable. Contract reference:
 * zerodevapp/kernel cd697c7e21715d015e0643af22310a99aa17433b,
 * ValidationManager._enableDigest/_enableMode/_installPermission.
 * Replayable enable uses domain chainId zero and the signature marker also
 * selects Kernel's chain-zero UserOperation signing hash. Operation identity
 * and observation still use the actual chain's EntryPoint hash.
 */
import {
  concat,
  encodeAbiParameters,
  hashMessage,
  hashTypedData,
  keccak256,
  pad,
  recoverAddress,
  size,
} from "viem";
import {
  captureKernelV4Installs,
  encodeKernelV4SignerData,
  KERNEL_V4_EXECUTE_SELECTOR,
  type KernelInstall,
} from "../../kernel-v4.js";
import type { PreparedUserOperation } from "../../prepared-user-operation.js";
import {
  type KernelV33AccountDescriptor,
  type KernelV33Reads,
  provenKernelV33Account,
} from "../deployment/v33.js";
import {
  encodeKernelV33NonceKey,
  KERNEL_V33_REPLAYABLE_SIGNATURE_PREFIX,
} from "../deployment/v33-operation.js";
import {
  captureInput,
  captureKeyProfile,
  exactCaptured,
  exactInput,
  inputAddress,
  inputCapability,
  inputInvalid,
  inputUint,
  isBytes,
  runtimeFail,
  sameInstall,
} from "../internal.js";
import type { KernelV33Runtime, KernelV33RuntimePrepareInput, KeyProfile } from "../types.js";
import type { KernelPermissionMaterialization } from "./materialize.js";

const NO_HOOK = "0x0000000000000000000000000000000000000001" as const;
export const OAATH_KERNEL_V33_APPROVAL_VERSION = "oaath.kernel.v33-permission-approval/v2" as const;
const SCOPE_KEYS = ["chainScope", "account", "nonce", "permissionId", "packages"] as const;

export interface KernelV33PermissionScope {
  readonly chainScope: "all";
  readonly account: `0x${string}`;
  /** Effective uint32 validation nonce from Kernel's currentNonce/validationConfig. */
  readonly nonce: string;
  readonly permissionId: `0x${string}`;
  /** Shared module configuration; encoded as v3.3 bytes[] only at the wire boundary. */
  readonly packages: readonly Readonly<KernelInstall>[];
}

export interface KernelV33PermissionApproval extends KernelV33PermissionScope {
  readonly version: typeof OAATH_KERNEL_V33_APPROVAL_VERSION;
  readonly digest: `0x${string}`;
  readonly enableSignature: `0x${string}`;
}

function captureScope(record: Record<string, unknown>): Readonly<KernelV33PermissionScope> {
  if (record.chainScope !== "all")
    return inputInvalid("Kernel v3.3 approval chain scope is unsupported");
  const nonce = inputUint(record.nonce, (1n << 32n) - 1n, "Kernel v3.3 validation nonce");
  if (nonce === 0n) return inputInvalid("Kernel v3.3 validation nonce must be positive");
  if (typeof record.permissionId !== "string" || !/^0x[0-9a-f]{8}$/u.test(record.permissionId))
    return inputInvalid("Kernel v3.3 permission ID is invalid");
  const permissionId = record.permissionId as `0x${string}`;
  const packages = captureKernelV4Installs(record.packages);
  if (packages.length < 2 || packages.length > 254)
    return inputInvalid("Kernel v3.3 permission requires policies and one signer");
  const prefix = pad(permissionId, { size: 32, dir: "right" });
  for (const [index, install] of packages.entries()) {
    const last = index === packages.length - 1;
    if (
      install.moduleType !== (last ? 6 : 5) ||
      !install.moduleData.startsWith(prefix) ||
      install.internalData !==
        (last
          ? encodeKernelV4SignerData({
              permissionId,
              selectors: [KERNEL_V4_EXECUTE_SELECTOR],
            })
          : permissionId)
    )
      return inputInvalid("Kernel v3.3 permission configuration does not match its authority");
  }
  return Object.freeze({
    chainScope: "all",
    account: inputAddress(record.account, "Kernel v3.3 permission account"),
    nonce: nonce.toString(10),
    permissionId,
    packages,
  });
}

function typedData(scope: Readonly<KernelV33PermissionScope>) {
  return {
    domain: {
      name: "Kernel",
      version: "0.3.3",
      chainId: 0,
      verifyingContract: scope.account,
    },
    types: {
      Enable: [
        { name: "validationId", type: "bytes21" },
        { name: "nonce", type: "uint32" },
        { name: "hook", type: "address" },
        { name: "validatorData", type: "bytes" },
        { name: "hookData", type: "bytes" },
        { name: "selectorData", type: "bytes" },
      ],
    },
    primaryType: "Enable",
    message: {
      validationId: concat(["0x02", pad(scope.permissionId, { size: 20, dir: "right" })]),
      nonce: Number(scope.nonce),
      hook: NO_HOOK,
      validatorData: encodeAbiParameters(
        [{ type: "bytes[]" }],
        [
          scope.packages.map((install) =>
            // All policies run for operations; ERC-1271 message signing is disabled.
            concat(["0x0002", install.module, `0x${install.moduleData.slice(66)}`]),
          ),
        ],
      ),
      hookData: "0x",
      selectorData: KERNEL_V4_EXECUTE_SELECTOR,
    },
  } as const;
}

/** The exact EIP-712 value for a wallet's signTypedData prompt. */
export function kernelV33PermissionEnableTypedData(value: KernelV33PermissionScope) {
  return typedData(
    captureScope(exactInput(value, SCOPE_KEYS, "Kernel v3.3 permission scope", new WeakSet())),
  );
}

/** The exact v3.3 approval scope a session runtime and bound account produce. */
export function kernelV33RuntimeScope(
  runtime: Readonly<KernelV33Runtime>,
  accountValue: Readonly<KernelV33AccountDescriptor>,
  nonce: string,
) {
  const account = provenKernelV33Account(accountValue);
  if (
    runtime.deployment.kernelVersion !== "0.3.3" ||
    runtime.authority !== "session" ||
    runtime.validation.kind !== "permission" ||
    runtime.deployment.chainId !== account.chainId
  )
    return inputInvalid("Kernel v3.3 approval requires a session runtime for this account chain");
  return captureScope({
    chainScope: "all",
    account: account.account,
    nonce,
    permissionId: runtime.validation.permissionId,
    packages: runtime.packages,
  });
}

export interface ApproveKernelV33PermissionInput {
  readonly owner: Readonly<KeyProfile>;
  readonly runtime: Readonly<KernelV33Runtime>;
  readonly account: Readonly<KernelV33AccountDescriptor>;
  readonly nonce: string;
}

/** Reads Kernel's effective enable nonce. An unavailable record is never treated as zero. */
export async function kernelV33PermissionInstallNonce(value: {
  readonly runtime: Readonly<KernelV33Runtime>;
  readonly account: Readonly<KernelV33AccountDescriptor>;
  readonly reads: KernelV33Reads;
}): Promise<string> {
  const context = new WeakSet();
  const record = exactInput(
    value,
    ["runtime", "account", "reads"],
    "Kernel v3.3 nonce request",
    context,
  );
  const scope = kernelV33RuntimeScope(
    record.runtime as KernelV33Runtime,
    record.account as KernelV33AccountDescriptor,
    "1",
  );
  const read = inputCapability<KernelV33Reads["read"]>(
    exactInput(record.reads, ["read"], "Kernel v3.3 nonce reads", context).read,
    "Kernel v3.3 nonce read",
  );
  let result: unknown;
  try {
    result = await read({
      type: "kernel_v33_permission_nonce",
      chainId: (record.runtime as KernelV33Runtime).deployment.chainId,
      account: scope.account,
      permissionId: scope.permissionId,
    });
  } catch {
    return runtimeFail(
      "kernel_runtime_read_unavailable",
      "Kernel v3.3 validation nonce could not be read",
    );
  }
  const nonce = inputUint(result, (1n << 32n) - 1n, "Kernel v3.3 validation nonce");
  if (nonce === 0n) return inputInvalid("Kernel v3.3 validation nonce must be positive");
  return nonce.toString(10);
}

/** One owner signature for the same account, permission and validation nonce on all chains. */
export async function approveKernelV33Permission(
  value: ApproveKernelV33PermissionInput,
): Promise<Readonly<KernelV33PermissionApproval>> {
  const record = exactInput(
    value,
    ["owner", "runtime", "account", "nonce"],
    "Kernel v3.3 permission approval",
    new WeakSet(),
  );
  const owner = captureKeyProfile(record.owner);
  const scope = kernelV33RuntimeScope(
    record.runtime as KernelV33Runtime,
    record.account as KernelV33AccountDescriptor,
    record.nonce as string,
  );
  const digest = hashTypedData(typedData(scope));
  return Object.freeze({
    version: OAATH_KERNEL_V33_APPROVAL_VERSION,
    ...scope,
    digest,
    enableSignature: await owner.sign(digest),
  });
}

export function parseKernelV33PermissionApproval(
  value: unknown,
): Readonly<KernelV33PermissionApproval> {
  const record = exactInput(
    value,
    ["version", ...SCOPE_KEYS, "digest", "enableSignature"],
    "Kernel v3.3 permission approval",
    new WeakSet(),
  );
  if (record.version !== OAATH_KERNEL_V33_APPROVAL_VERSION)
    return inputInvalid("Kernel v3.3 approval version is unsupported");
  const scope = captureScope(record);
  const digest = hashTypedData(typedData(scope));
  if (
    record.digest !== digest ||
    !isBytes(record.enableSignature) ||
    record.enableSignature === "0x" ||
    record.enableSignature.length > 8194
  )
    return inputInvalid("Kernel v3.3 permission approval is invalid");
  return Object.freeze({
    version: OAATH_KERNEL_V33_APPROVAL_VERSION,
    ...scope,
    digest,
    enableSignature: record.enableSignature,
  });
}

/** The scope a consumer reviewed for one v3.3 approval. */
export interface KernelV33ExpectedPermission {
  /** Root ECDSA owner EOA that must have signed the enable digest. */
  readonly owner: `0x${string}`;
  readonly account: `0x${string}`;
  readonly permissionId: `0x${string}`;
  /** Session signer: its moduleType 6 module and the key's public material. */
  readonly sessionKey: Readonly<{ module: `0x${string}`; publicMaterial: `0x${string}` }>;
  /**
   * The exact ordered install list (policies, then the signer), as a session
   * runtime's `packages`. Policy order is significant.
   */
  readonly packages: readonly Readonly<KernelInstall>[];
}

export type KernelV33ApprovalMismatchField =
  | "account"
  | "permissionId"
  | "sessionKey"
  | "packages"
  | "enableSignature";
export type KernelV33ApprovalMismatchReason =
  | "different"
  | "reordered"
  | "unrecoverable"
  | "wrong_signer";

/**
 * Offline v3.3 check: no reads, signer or submission. Owner recovery is
 * 65-byte ECDSA over the enable digest or its EIP-191 hash, the two forms the
 * v3.3 ECDSA validator accepts; an ERC-1271 or other contract root cannot be
 * proven offline and never verifies.
 * Returns the recovered owner when every reviewed field matches.
 */
export async function checkKernelV33PermissionApproval(
  approval: Readonly<KernelV33PermissionApproval>,
  value: unknown,
): Promise<
  | { readonly owner: `0x${string}` }
  | {
      readonly field: KernelV33ApprovalMismatchField;
      readonly reason: KernelV33ApprovalMismatchReason;
    }
> {
  const context = new WeakSet();
  const record = exactInput(
    value,
    ["owner", "account", "permissionId", "sessionKey", "packages"],
    "Kernel v3.3 expected permission",
    context,
  );
  const owner = inputAddress(record.owner, "Kernel v3.3 expected owner");
  const account = inputAddress(record.account, "Kernel v3.3 expected account");
  const sessionKey = exactInput(
    record.sessionKey,
    ["module", "publicMaterial"],
    "Kernel v3.3 expected session key",
    context,
  );
  const signerModule = inputAddress(sessionKey.module, "Kernel v3.3 expected session module");
  if (!isBytes(sessionKey.publicMaterial) || sessionKey.publicMaterial === "0x")
    return inputInvalid("Kernel v3.3 expected session material is invalid");
  if (typeof record.permissionId !== "string" || !/^0x[0-9a-f]{8}$/u.test(record.permissionId))
    return inputInvalid("Kernel v3.3 expected permission ID is invalid");
  const packages = captureKernelV4Installs(record.packages);
  const mismatch = (
    field: KernelV33ApprovalMismatchField,
    reason: KernelV33ApprovalMismatchReason = "different",
  ) => Object.freeze({ field, reason });
  if (account !== approval.account) return mismatch("account");
  if (record.permissionId !== approval.permissionId) return mismatch("permissionId");
  const signer = approval.packages.at(-1)!;
  if (
    signer.module !== signerModule ||
    signer.moduleData.slice(66) !== sessionKey.publicMaterial.slice(2)
  )
    return mismatch("sessionKey");
  const approved = approval.packages;
  if (
    approved.length !== packages.length ||
    !approved.every((install, index) => sameInstall(install, packages[index]!))
  )
    return mismatch(
      "packages",
      approved.length === packages.length &&
        approved.every((install) => packages.some((expected) => sameInstall(install, expected)))
        ? "reordered"
        : "different",
    );
  if (size(approval.enableSignature) !== 65) return mismatch("enableSignature", "unrecoverable");
  // Kernel v3.3's ECDSA validator accepts the raw digest (signTypedData) and
  // its EIP-191 hash (a wallet's signMessage over the raw digest).
  let recovered: readonly `0x${string}`[];
  try {
    recovered = await Promise.all(
      [approval.digest, hashMessage({ raw: approval.digest })].map((hash) =>
        recoverAddress({ hash, signature: approval.enableSignature }),
      ),
    );
  } catch {
    return mismatch("enableSignature", "unrecoverable");
  }
  return recovered.some((address) => address.toLowerCase() === owner)
    ? Object.freeze({ owner })
    : mismatch("enableSignature", "wrong_signer");
}

export interface MaterializeKernelV33PermissionInput
  extends Omit<KernelV33RuntimePrepareInput, "kind" | "mode"> {
  readonly runtime: Readonly<KernelV33Runtime>;
  readonly approval: Readonly<KernelV33PermissionApproval>;
}

export async function materializeKernelV33Permission(
  value: MaterializeKernelV33PermissionInput,
): Promise<KernelPermissionMaterialization> {
  const captured = captureInput(value, "Kernel v3.3 materialization", new WeakSet());
  const record = exactCaptured(
    captured,
    [
      "runtime",
      "account",
      "approval",
      "grantId",
      "nonceKey",
      "sequence",
      "calls",
      "gas",
      ...(Object.hasOwn(captured, "paymaster") ? ["paymaster"] : []),
    ],
    "Kernel v3.3 materialization",
  );
  const input = record as unknown as MaterializeKernelV33PermissionInput;
  const bound = bindKernelV33PermissionApproval({
    runtime: input.runtime,
    account: input.account.account,
    approval: parseKernelV33PermissionApproval(input.approval),
  });
  const prepared = bound.prepareOperation({
    kind: "execution",
    grantId: input.grantId,
    account: input.account,
    nonceKey: input.nonceKey,
    sequence: input.sequence,
    calls: input.calls,
    gas: input.gas,
    paymaster: input.paymaster ?? null,
  });
  return Object.freeze({ prepared, signature: await bound.signOperation(prepared) });
}

/** Decision binding for an exact v3.3 all-chain enable artifact. */
export function kernelV33CapabilityHash(
  value: Readonly<KernelV33PermissionApproval>,
): `0x${string}` {
  const approval = parseKernelV33PermissionApproval(value);
  return keccak256(
    encodeAbiParameters(
      [{ type: "string" }, { type: "bytes32" }, { type: "bytes32" }],
      [OAATH_KERNEL_V33_APPROVAL_VERSION, approval.digest, keccak256(approval.enableSignature)],
    ),
  );
}

/** Internal enable composition: preparation never invokes either signing key. */
export function bindKernelV33PermissionApproval(
  value: Readonly<{
    runtime: Readonly<KernelV33Runtime>;
    approval: Readonly<KernelV33PermissionApproval>;
    account: `0x${string}`;
  }>,
) {
  const { runtime, approval } = value;
  if (
    runtime.authority !== "session" ||
    runtime.validation.kind !== "permission" ||
    runtime.validation.permissionId !== approval.permissionId ||
    value.account !== approval.account ||
    runtime.packages.length !== approval.packages.length ||
    !runtime.packages.every((install, index) => sameInstall(install, approval.packages[index]!))
  )
    return runtimeFail(
      "kernel_runtime_binding_mismatch",
      "Kernel v3.3 approval does not match this session",
    );
  const message = typedData(approval).message;
  function envelope(signature: `0x${string}`): `0x${string}` {
    return concat([
      KERNEL_V33_REPLAYABLE_SIGNATURE_PREFIX,
      NO_HOOK,
      encodeAbiParameters(
        [
          { type: "bytes" },
          { type: "bytes" },
          { type: "bytes" },
          { type: "bytes" },
          { type: "bytes" },
        ],
        [
          message.validatorData,
          message.hookData,
          message.selectorData,
          approval.enableSignature,
          signature,
        ],
      ),
    ]);
  }
  function requireMaterialization(prepared: Readonly<PreparedUserOperation>): void {
    const nonce = BigInt(prepared.userOperation.nonce);
    if (
      prepared.kind !== "execution" ||
      prepared.userOperation.sender !== approval.account ||
      (nonce >> 64n).toString() !==
        encodeKernelV33NonceKey({
          mode: "enable",
          validation: runtime.validation,
          nonceKey: ((nonce >> 64n) & 0xffffn).toString(),
        })
    )
      runtimeFail(
        "kernel_runtime_binding_mismatch",
        "Kernel v3.3 approval does not cover this materialization",
      );
  }
  return Object.freeze({
    gasPolicy: runtime.gasPolicy,
    dummySignature: envelope(runtime.dummySignature),
    prepareOperation(input: KernelV33RuntimePrepareInput): PreparedUserOperation {
      if (input.kind !== "execution" || (input.mode !== undefined && input.mode !== "enable"))
        return runtimeFail(
          "kernel_runtime_binding_mismatch",
          "Kernel v3.3 materialization requires an enable execution",
        );
      const prepared = runtime.prepareOperation({ ...input, mode: "enable" });
      requireMaterialization(prepared);
      return prepared;
    },
    async signOperation(prepared: Readonly<PreparedUserOperation>): Promise<`0x${string}`> {
      requireMaterialization(prepared);
      return envelope(await runtime.signOperation(prepared));
    },
    async encodeVerifiedSignature(
      prepared: Readonly<PreparedUserOperation>,
      signature: `0x${string}`,
    ): Promise<`0x${string}`> {
      requireMaterialization(prepared);
      return envelope(await runtime.encodeVerifiedSignature(prepared, signature));
    },
  });
}
