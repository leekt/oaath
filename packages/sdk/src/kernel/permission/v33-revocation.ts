/** Kernel v3.3 revokes one permission without advancing the global validNonceFrom. */
import { captureDenseArray } from "@oaath/protocol";
import {
  concat,
  decodeFunctionResult,
  encodeAbiParameters,
  encodeFunctionData,
  encodeFunctionResult,
  pad,
  parseAbi,
  zeroAddress,
} from "viem";
import type { KernelV4Call } from "../../kernel-v4.js";
import { exactInput, inputAddress, inputInvalid, inputUint, isBytes } from "../internal.js";
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
  approval: Readonly<KernelV33PermissionApproval>,
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

export function kernelV33PermissionRevocationCalls(
  value: Readonly<{
    approval: Readonly<KernelV33PermissionApproval>;
    state: Readonly<KernelV33PermissionState>;
  }>,
): readonly Readonly<KernelV4Call>[] {
  const record = exactInput(value, ["approval", "state"], "Kernel v3.3 revocation", new WeakSet());
  const approval = parseKernelV33PermissionApproval(record.approval);
  const state = parseKernelV33PermissionState(record.state);
  const status = kernelV33PermissionStatus(state, approval);
  const nonce = BigInt(kernelV33EffectivePermissionNonce(state));
  if (nonce < BigInt(approval.nonce))
    return inputInvalid("Kernel v3.3 revocation nonce has not reached the approval");
  if (status === "absent" && nonce > BigInt(approval.nonce)) return Object.freeze([]);
  const vId = validationId(approval.permissionId);
  const calls: KernelV4Call[] = [];
  if (status === "absent") {
    // Consume just this permission's enable nonce. No application call and no
    // global nonce invalidation occur between installation and removal.
    const { version: _version, digest: _digest, enableSignature: _signature, ...scope } = approval;
    const message = kernelV33PermissionEnableTypedData(scope).message;
    calls.push({
      target: approval.account,
      value: "0",
      data: encodeFunctionData({
        abi: ABI,
        functionName: "installValidations",
        args: [[vId], [{ nonce: Number(nonce), hook: NO_HOOK }], [message.validatorData], ["0x"]],
      }),
    });
  }
  calls.push({
    target: approval.account,
    value: "0",
    data: encodeFunctionData({
      abi: ABI,
      functionName: "uninstallValidation",
      args: [
        vId,
        encodeAbiParameters([{ type: "bytes[]" }], [approval.packages.map(() => "0x" as const)]),
        "0x",
      ],
    }),
  });
  return Object.freeze(calls.map((call) => Object.freeze(call)));
}
