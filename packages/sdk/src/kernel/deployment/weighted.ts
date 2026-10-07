/** Bounded reads of the reviewed weighted modules' installed configuration. */
import {
  decodeAbiParameters,
  encodeAbiParameters,
  encodeFunctionData,
  padHex,
  parseAbi,
} from "cetane/utils";
import type { KernelV4ReadClient } from "../../kernel-v4.js";
import { isBytes, runtimeFail } from "../internal.js";
import { MAX_WEIGHTED_GUARDIANS, weightedPublicMaterial } from "../key/weighted-ecdsa.js";

export interface WeightedConfigurationRead {
  readonly type: "kernel_weighted_configuration";
  readonly chainId: number;
  readonly module: `0x${string}`;
  readonly account: `0x${string}`;
  readonly permissionId: `0x${string}` | null;
}
const VALIDATOR = parseAbi([
  "function weightedStorage(address account) view returns (uint24 totalWeight, uint24 threshold, address firstGuardian)",
  "function guardian(address guardian, address account) view returns (uint24 weight, address nextGuardian)",
  "function configurationEpoch(address account) view returns (uint256)",
]);
const SIGNER = parseAbi([
  "function weightedStorage(bytes32 id, address account) view returns (uint24 totalWeight, uint24 threshold, address firstGuardian)",
  "function guardian(address guardian, bytes32 id, address account) view returns (uint24 weight, address nextGuardian)",
  "function configurationEpoch(bytes32 id, address account) view returns (uint256)",
]);
const EVIDENCE = [{ type: "bytes" }, { type: "uint256" }] as const;
const ZERO = `0x${"00".repeat(20)}`;
const UINT = [{ type: "uint256" }] as const;
const STORAGE = [{ type: "uint24" }, { type: "uint24" }, { type: "address" }] as const;
const GUARDIAN = [{ type: "uint24" }, { type: "address" }] as const;

/** Canonical byte evidence, so caller-injected readers cannot supply mutable objects. */
export function captureWeightedConfiguration(
  value: unknown,
): Readonly<{ publicMaterial: `0x${string}`; epoch: bigint }> {
  try {
    if (!isBytes(value)) throw new Error();
    const [publicMaterial, epoch] = decodeAbiParameters(EVIDENCE, value);
    if (encodeAbiParameters(EVIDENCE, [publicMaterial, epoch]) !== value) throw new Error();
    return Object.freeze({ publicMaterial, epoch });
  } catch {
    return runtimeFail(
      "kernel_runtime_evidence_invalid",
      "Weighted configuration evidence is invalid",
    );
  }
}

export async function readWeightedConfiguration(
  client: KernelV4ReadClient,
  request: WeightedConfigurationRead,
): Promise<`0x${string}`> {
  const permission = request.permissionId !== null;
  const abi = permission ? SIGNER : VALIDATOR;
  const args = permission
    ? [padHex(request.permissionId!, { size: 32, dir: "right" }), request.account]
    : [request.account];
  async function call(
    functionName: "weightedStorage" | "guardian" | "configurationEpoch",
    callArgs: readonly unknown[],
  ) {
    const result = await client.call({
      to: request.module,
      data: encodeFunctionData({ abi, functionName, args: callArgs as never }),
    });
    if (!result.data) throw new Error("weighted_configuration_unreadable");
    return result.data.toLowerCase() as `0x${string}`;
  }
  async function epoch() {
    const data = await call("configurationEpoch", args);
    const [value] = decodeAbiParameters(UINT, data);
    if (encodeAbiParameters(UINT, [value]) !== data) throw new Error("weighted_epoch_noncanonical");
    return value;
  }
  const before = await epoch();
  const data = await call("weightedStorage", args);
  const [totalWeight, threshold, first] = decodeAbiParameters(STORAGE, data);
  if (encodeAbiParameters(STORAGE, [totalWeight, threshold, first]).toLowerCase() !== data)
    throw new Error("weighted_storage_noncanonical");
  const guardians: { address: `0x${string}`; weight: number }[] = [];
  let current = first.toLowerCase() as `0x${string}`;
  if (Number(totalWeight) === 0 && Number(threshold) === 0 && current === ZERO) {
    if ((await epoch()) !== before) throw new Error("weighted_configuration_changed");
    return encodeAbiParameters(EVIDENCE, ["0x", before]);
  }
  const visited = new Set<string>();
  while (current !== request.account) {
    if (current === ZERO || visited.has(current) || guardians.length >= MAX_WEIGHTED_GUARDIANS)
      throw new Error("weighted_guardian_list_invalid");
    visited.add(current);
    const data = await call("guardian", [current, ...args]);
    const [weight, next] = decodeAbiParameters(GUARDIAN, data);
    if (encodeAbiParameters(GUARDIAN, [weight, next]).toLowerCase() !== data)
      throw new Error("weighted_guardian_noncanonical");
    guardians.push({ address: current, weight: Number(weight) });
    current = next.toLowerCase() as `0x${string}`;
  }
  if (
    before === 0n ||
    (await epoch()) !== before ||
    guardians.reduce((sum, g) => sum + g.weight, 0) !== Number(totalWeight)
  )
    throw new Error("weighted_configuration_changed");
  return encodeAbiParameters(EVIDENCE, [
    weightedPublicMaterial(guardians, Number(threshold)),
    before,
  ]);
}
