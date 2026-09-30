/** Kernel v3.3 revokes one permission without advancing the global validNonceFrom. */
import { captureDenseArray } from "@oaath/protocol";
import {
  concat,
  decodeFunctionResult,
  encodeAbiParameters,
  encodeFunctionData,
  encodeFunctionResult,
  keccak256,
  pad,
  parseAbi,
  stringToHex,
  zeroAddress,
} from "viem";
import type { KernelCall } from "../../kernel-v4.js";
import {
  exactInput,
  inputAddress,
  inputInvalid,
  inputUint,
  isBytes,
  runtimeFail,
} from "../internal.js";
import { resolvePinnedSigner } from "../modules.js";
import {
  type KernelV33PermissionApproval,
  kernelV33PermissionEnableTypedData,
  parseKernelV33PermissionApproval,
} from "./v33.js";

const ABI = parseAbi([
  "function currentNonce() view returns (uint32)",
  "function validationConfig(bytes21) view returns (uint32 nonce, address hook)",
  "function permissionConfig(bytes4) view returns ((bytes2 permissionFlag, address signer, bytes22[] policyData))",
  "function installValidations(bytes21[] vIds, (uint32 nonce, address hook)[] configs, bytes[] validationData, bytes[] hookData)",
  "function uninstallValidation(bytes21 vId, bytes deinitData, bytes hookDeinitData)",
]);
const NO_HOOK = "0x0000000000000000000000000000000000000001";
const MAX_NONCE = (1n << 32n) - 1n;
const STATE_KEYS = [
  "currentNonce",
  "validationNonce",
  "hook",
  "signer",
  "permissionFlag",
  "policies",
] as const;

export interface KernelV33PermissionState {
  readonly currentNonce: string;
  readonly validationNonce: string;
  readonly hook: `0x${string}`;
  readonly signer: `0x${string}`;
  readonly permissionFlag: `0x${string}`;
  readonly policies: readonly `0x${string}`[];
}

export function parseKernelV33PermissionState(value: unknown): Readonly<KernelV33PermissionState> {
  const context = new WeakSet();
  const record = exactInput(value, STATE_KEYS, "Kernel v3.3 permission state", context);
  const current = inputUint(record.currentNonce, MAX_NONCE, "Kernel v3.3 current nonce");
  const validation = inputUint(record.validationNonce, MAX_NONCE, "Kernel v3.3 validation nonce");
  if (current === 0n || validation > current || (current === MAX_NONCE && validation === current))
    return inputInvalid("Kernel v3.3 permission nonce is unavailable");
  if (
    typeof record.permissionFlag !== "string" ||
    !/^0x[0-9a-f]{4}$/u.test(record.permissionFlag) ||
    !Array.isArray(record.policies) ||
    record.policies.length > 253
  )
    return inputInvalid("Kernel v3.3 permission configuration is invalid");
  const policies = captureDenseArray(
    record.policies,
    "Kernel v3.3 policies",
    context,
    inputInvalid,
  ).map((policy: unknown) => {
    if (typeof policy !== "string" || !/^0x[0-9a-f]{44}$/u.test(policy))
      return inputInvalid("Kernel v3.3 policy binding is invalid");
    return policy as `0x${string}`;
  });
  return Object.freeze({
    currentNonce: current.toString(),
    validationNonce: validation.toString(),
    hook:
      record.hook === zeroAddress
        ? zeroAddress
        : inputAddress(record.hook, "Kernel v3.3 permission hook"),
    signer:
      record.signer === zeroAddress
        ? zeroAddress
        : inputAddress(record.signer, "Kernel v3.3 permission signer"),
    permissionFlag: record.permissionFlag as `0x${string}`,
    policies: Object.freeze(policies),
  });
}

function validationId(permissionId: `0x${string}`): `0x${string}` {
  if (!/^0x[0-9a-f]{8}$/u.test(permissionId))
    return inputInvalid("Kernel v3.3 permission ID is invalid");
  return concat(["0x02", pad(permissionId, { size: 20, dir: "right" })]);
}

/** The caller pins all three reads to the same block when producing finalized evidence. */
export async function readKernelV33PermissionState(
  input: Readonly<{
    permissionId: `0x${string}`;
    call: (data: `0x${string}`) => Promise<unknown>;
  }>,
): Promise<Readonly<KernelV33PermissionState>> {
  async function read(data: `0x${string}`) {
    const result = await input.call(data);
    if (!isBytes(result) || result === "0x")
      return inputInvalid("Kernel v3.3 permission read is unavailable");
    return result;
  }
  const currentData = await read(encodeFunctionData({ abi: ABI, functionName: "currentNonce" }));
  const validationData = await read(
    encodeFunctionData({
      abi: ABI,
      functionName: "validationConfig",
      args: [validationId(input.permissionId)],
    }),
  );
  const permissionData = await read(
    encodeFunctionData({ abi: ABI, functionName: "permissionConfig", args: [input.permissionId] }),
  );
  const current = decodeFunctionResult({
    abi: ABI,
    functionName: "currentNonce",
    data: currentData,
  });
  const validation = decodeFunctionResult({
    abi: ABI,
    functionName: "validationConfig",
    data: validationData,
  });
  const permission = decodeFunctionResult({
    abi: ABI,
    functionName: "permissionConfig",
    data: permissionData,
  });
  if (
    encodeFunctionResult({
      abi: ABI,
      functionName: "currentNonce",
      result: current,
    }).toLowerCase() !== currentData.toLowerCase() ||
    encodeFunctionResult({
      abi: ABI,
      functionName: "validationConfig",
      result: validation,
    }).toLowerCase() !== validationData.toLowerCase() ||
    encodeFunctionResult({
      abi: ABI,
      functionName: "permissionConfig",
      result: permission,
    }).toLowerCase() !== permissionData.toLowerCase()
  )
    return inputInvalid("Kernel v3.3 permission read is noncanonical");
  return parseKernelV33PermissionState({
    currentNonce: current.toString(),
    validationNonce: validation[0].toString(),
    hook: validation[1].toLowerCase(),
    signer: permission.signer.toLowerCase(),
    permissionFlag: permission.permissionFlag,
    policies: permission.policyData.map((policy) => policy.toLowerCase()),
  });
}

/** Absent means removed configuration, not merely a false generic module query. */
export function kernelV33PermissionStatus(
  state: Readonly<KernelV33PermissionState>,
  approval: Readonly<Pick<KernelV33PermissionApproval, "packages">>,
): "installed" | "absent" {
  if (
    state.hook === zeroAddress &&
    state.signer === zeroAddress &&
    state.permissionFlag === "0x0000" &&
    state.policies.length === 0
  )
    return "absent";
  const signer = approval.packages[approval.packages.length - 1];
  if (
    state.hook !== NO_HOOK ||
    signer?.module !== state.signer ||
    state.permissionFlag !== "0x0002" ||
    state.policies.length !== approval.packages.length - 1 ||
    !state.policies.every(
      (policy, index) => policy === concat(["0x0002", approval.packages[index]!.module]),
    )
  )
    return inputInvalid("Kernel v3.3 permission state contradicts the retained approval");
  return "installed";
}

export function kernelV33EffectivePermissionNonce(
  state: Readonly<KernelV33PermissionState>,
): string {
  return (
    BigInt(state.currentNonce) + (state.validationNonce === state.currentNonce ? 1n : 0n)
  ).toString();
}

type KernelV33PermissionScope = Omit<
  KernelV33PermissionApproval,
  "version" | "digest" | "enableSignature"
>;

/** Installs the permission at exactly `nonce`; the first half of consuming it. */
function installCall(
  scope: Readonly<KernelV33PermissionScope>,
  nonce: bigint,
): Readonly<KernelCall> {
  const message = kernelV33PermissionEnableTypedData(scope).message;
  return Object.freeze({
    target: scope.account,
    value: "0",
    data: encodeFunctionData({
      abi: ABI,
      functionName: "installValidations",
      args: [
        [validationId(scope.permissionId)],
        [{ nonce: Number(nonce), hook: NO_HOOK }],
        [message.validatorData],
        ["0x"],
      ],
    }),
  });
}

/** Uninstall clears the permission and keeps its validation nonce. */
function uninstallCall(scope: Readonly<KernelV33PermissionScope>): Readonly<KernelCall> {
  return Object.freeze({
    target: scope.account,
    value: "0",
    data: encodeFunctionData({
      abi: ABI,
      functionName: "uninstallValidation",
      args: [
        validationId(scope.permissionId),
        encodeAbiParameters([{ type: "bytes[]" }], [scope.packages.map(() => "0x" as const)]),
        "0x",
      ],
    }),
  });
}

export function kernelV33PermissionRevocationCalls(
  value: Readonly<{
    approval: Readonly<KernelV33PermissionApproval>;
    state: Readonly<KernelV33PermissionState>;
  }>,
): readonly Readonly<KernelCall>[] {
  const record = exactInput(value, ["approval", "state"], "Kernel v3.3 revocation", new WeakSet());
  const approval = parseKernelV33PermissionApproval(record.approval);
  const state = parseKernelV33PermissionState(record.state);
  const status = kernelV33PermissionStatus(state, approval);
  const nonce = BigInt(kernelV33EffectivePermissionNonce(state));
  if (nonce < BigInt(approval.nonce))
    return inputInvalid("Kernel v3.3 revocation nonce has not reached the approval");
  if (status === "absent" && nonce > BigInt(approval.nonce)) return Object.freeze([]);
  const { version: _version, digest: _digest, enableSignature: _signature, ...scope } = approval;
  // An absent permission consumes just its own enable nonce. No application
  // call and no global nonce invalidation occur between installation and removal.
  return Object.freeze(
    status === "absent"
      ? [installCall(scope, nonce), uninstallCall(scope)]
      : [uninstallCall(scope)],
  );
}

/** Bounds one alignment operation's gas; larger gaps take several operations. */
export const KERNEL_V33_MAX_NONCE_ALIGNMENT_STEPS = 16;

/**
 * The throwaway permission alignment installs and removes: the reviewed ECDSA
 * signer bound to an unspendable address, with no policies. Its signer module
 * accepts a new install after each uninstall, which the permission being
 * aligned cannot: its own policies refuse a second install, so it never serves
 * as the vehicle.
 */
export const NONCE_ALIGNMENT_PERMISSION_ID = keccak256(
  stringToHex("@oaath/sdk:kernel-v33-nonce-alignment"),
).slice(0, 10) as `0x${string}`;
const NONCE_ALIGNMENT_SIGNER_ADDRESS = "0x000000000000000000000000000000000000dead" as const;

function alignmentValidatorData(signerModule: `0x${string}`): `0x${string}` {
  return encodeAbiParameters(
    [{ type: "bytes[]" }],
    [[concat(["0x0002", signerModule, NONCE_ALIGNMENT_SIGNER_ADDRESS])]],
  );
}

/**
 * Owner calls that raise an absent permission's effective enable nonce to
 * `nonce` on one chain, inside one atomic owner operation. Kernel advances its
 * current nonce each time an already-used validation is installed again, so
 * the throwaway permission is installed at every nonce up to the target and
 * removed after each install; it is absent again when the operation ends and
 * never validates anything. `validNonceFrom` never moves, so every installed
 * permission keeps validating. Other permissions' approvals that are signed
 * but not yet enabled on this chain need a new nonce afterwards. An installed
 * permission, a nonce already past the target, or a throwaway permission that
 * is not absent fails closed.
 */
export function kernelV33PermissionNonceAlignmentCalls(
  value: Readonly<{
    scope: Readonly<KernelV33PermissionScope>;
    state: Readonly<KernelV33PermissionState>;
    alignmentState: Readonly<KernelV33PermissionState>;
    signerModule: `0x${string}`;
    nonce: string;
  }>,
): readonly Readonly<KernelCall>[] {
  const record = exactInput(
    value,
    ["scope", "state", "alignmentState", "signerModule", "nonce"],
    "Kernel v3.3 nonce alignment",
    new WeakSet(),
  );
  const scope = record.scope as Readonly<KernelV33PermissionScope>;
  const state = parseKernelV33PermissionState(record.state);
  const alignment = parseKernelV33PermissionState(record.alignmentState);
  const signerModule = inputAddress(record.signerModule, "Kernel v3.3 alignment signer");
  const target = inputUint(record.nonce, MAX_NONCE, "Kernel v3.3 target nonce");
  if (scope.permissionId === NONCE_ALIGNMENT_PERMISSION_ID)
    return inputInvalid("Kernel v3.3 permission ID is reserved for nonce alignment");
  if (kernelV33PermissionStatus(state, scope) !== "absent")
    return runtimeFail(
      "kernel_runtime_binding_mismatch",
      "Kernel v3.3 permission is already installed on this chain",
    );
  if (
    alignment.currentNonce !== state.currentNonce ||
    kernelV33PermissionStatus(alignment, { packages: [] }) !== "absent"
  )
    return runtimeFail(
      "kernel_runtime_evidence_invalid",
      "Kernel v3.3 nonce alignment permission state is contradictory",
    );
  const effective = BigInt(kernelV33EffectivePermissionNonce(state));
  if (effective > target)
    return runtimeFail(
      "kernel_runtime_nonce_mismatch",
      "Kernel v3.3 enable nonce is already past the alignment target",
    );
  if (effective === target) return Object.freeze([]);
  // The first install bumps only if the throwaway permission already holds the
  // current nonce; each later install bumps exactly once. The aligned
  // permission never holds the final current nonce, so its enable nonce equals it.
  const current = BigInt(state.currentNonce);
  const first = BigInt(alignment.validationNonce) === current ? current + 1n : current;
  if (target - first + 1n > BigInt(KERNEL_V33_MAX_NONCE_ALIGNMENT_STEPS))
    return inputInvalid("Kernel v3.3 nonce alignment exceeds one operation's step bound");
  return alignmentCalls(scope.account, signerModule, first, target);
}

function alignmentCalls(
  account: `0x${string}`,
  signerModule: `0x${string}`,
  first: bigint,
  target: bigint,
): readonly Readonly<KernelCall>[] {
  const vId = validationId(NONCE_ALIGNMENT_PERMISSION_ID);
  const validatorData = alignmentValidatorData(signerModule);
  const uninstall = encodeFunctionData({
    abi: ABI,
    functionName: "uninstallValidation",
    args: [vId, encodeAbiParameters([{ type: "bytes[]" }], [["0x"]]), "0x"],
  });
  const calls: Readonly<KernelCall>[] = [];
  for (let nonce = first; nonce <= target; nonce++) {
    calls.push(
      Object.freeze({
        target: account,
        value: "0",
        data: encodeFunctionData({
          abi: ABI,
          functionName: "installValidations",
          args: [[vId], [{ nonce: Number(nonce), hook: NO_HOOK }], [validatorData], ["0x"]],
        }),
      }),
      Object.freeze({ target: account, value: "0", data: uninstall }),
    );
  }
  return Object.freeze(calls);
}

export interface VerifyKernelPermissionNonceAlignmentCallsInput {
  readonly account: `0x${string}`;
  readonly calls: readonly Readonly<KernelCall>[];
  readonly nonce: string;
}

export type KernelPermissionNonceAlignmentVerification =
  | Readonly<{ status: "verified" }>
  | Readonly<{
      status: "mismatch";
      field: "input" | "nonce" | "calls" | "target" | "value" | "data";
    }>;

/**
 * Verifies only the exact reserved-permission install/remove calls, never chain
 * state or authority. Empty calls are a valid no-op, not proof of nonce alignment.
 * Submit nonempty calls atomically as one owner operation; observe it before
 * preparing an approval. No other permission or global invalidation is accepted.
 */
export function verifyKernelPermissionNonceAlignmentCalls(
  value: VerifyKernelPermissionNonceAlignmentCallsInput,
): KernelPermissionNonceAlignmentVerification {
  const mismatch = (
    field: Extract<KernelPermissionNonceAlignmentVerification, { status: "mismatch" }>["field"],
  ): KernelPermissionNonceAlignmentVerification => Object.freeze({ status: "mismatch", field });
  try {
    const context = new WeakSet();
    const record = exactInput(
      value,
      ["account", "calls", "nonce"],
      "Kernel nonce alignment calls",
      context,
    );
    const account = inputAddress(record.account, "Kernel nonce alignment account");
    const nonce = inputUint(record.nonce, MAX_NONCE, "Kernel nonce alignment target");
    if (nonce === 0n) return mismatch("nonce");
    const calls = captureDenseArray(
      record.calls,
      "Kernel nonce alignment calls",
      context,
      inputInvalid,
    );
    if (calls.length % 2 !== 0 || calls.length > KERNEL_V33_MAX_NONCE_ALIGNMENT_STEPS * 2)
      return mismatch("calls");
    const first = nonce - BigInt(calls.length / 2) + 1n;
    if (first < 1n) return mismatch("nonce");
    const expected = alignmentCalls(account, resolvePinnedSigner("ecdsa"), first, nonce);
    for (let index = 0; index < calls.length; index++) {
      const call = exactInput(
        calls[index],
        ["target", "value", "data"],
        "Kernel alignment call",
        context,
      );
      if (inputAddress(call.target, "Kernel alignment target") !== account)
        return mismatch("target");
      if (call.value !== "0") return mismatch("value");
      if (call.data !== expected[index]!.data) return mismatch("data");
    }
    return Object.freeze({ status: "verified" });
  } catch {
    return mismatch("input");
  }
}
