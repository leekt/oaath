/** Weighted ECDSA public material, quorum collection and local verification. */
import {
  concatHex,
  decodeAbiParameters,
  encodeAbiParameters,
  hashTypedData,
  padHex,
  recoverAddress,
} from "cetane/utils";
import { parsePreparedUserOperation } from "../../prepared-user-operation.js";
import type { KernelDeployment } from "../deployment/profile.js";
import {
  captureInput,
  denseInput,
  exactInput,
  inputAddress,
  inputInvalid,
  inputUint,
  isBytes,
  isHash,
  runtimeFail,
} from "../internal.js";
import {
  exactKernelDeployment,
  KERNEL_WEIGHTED_SIGNER,
  KERNEL_WEIGHTED_VALIDATOR,
} from "../modules.js";
import type { KeyOperationContext, KeyProfile } from "../types.js";
import { ECDSA_DUMMY_SIGNATURE, type EcdsaKeyAccount, ecdsaKey } from "./ecdsa.js";

export interface WeightedEcdsaGuardian {
  readonly address: `0x${string}`;
  readonly weight: number;
}
export interface WeightedEcdsaKeyInput {
  /** Complete installed configuration, independent of the participating quorum. */
  readonly guardians: readonly WeightedEcdsaGuardian[];
  readonly threshold: number;
  /** Distinct participating digest signers whose combined weight meets threshold. */
  readonly signers: readonly EcdsaKeyAccount[];
}
const CONFIG = [{ type: "address[]" }, { type: "uint24[]" }, { type: "uint24" }] as const;
const MAX_WEIGHT = 0xffffff;
export const MAX_WEIGHTED_GUARDIANS = 32;
const ZERO = `0x${"00".repeat(32)}` as const;

function weight(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > MAX_WEIGHT)
    return inputInvalid("Weighted guardian weight or threshold is invalid");
  return value;
}

/** One canonical configuration: positive distinct guardians, sorted by address. */
export function weightedPublicMaterial(
  guardiansValue: unknown,
  thresholdValue: unknown,
): `0x${string}` {
  const context = new WeakSet();
  const entries = denseInput(guardiansValue, "Weighted guardians", context);
  if (entries.length < 1 || entries.length > MAX_WEIGHTED_GUARDIANS)
    return inputInvalid("Weighted guardian count is invalid");
  const guardians = entries
    .map((entry) => {
      const record = exactInput(entry, ["address", "weight"], "Weighted guardian", context);
      const address = inputAddress(record.address, "Weighted guardian");
      if (address === `0x${"00".repeat(20)}`)
        return inputInvalid("Weighted guardian cannot be zero");
      return { address, weight: weight(record.weight) };
    })
    .sort((a, b) => a.address.localeCompare(b.address));
  const threshold = weight(thresholdValue);
  const total = guardians.reduce((sum, guardian) => sum + guardian.weight, 0);
  if (
    total > MAX_WEIGHT ||
    threshold > total ||
    new Set(guardians.map((g) => g.address)).size !== guardians.length
  )
    return inputInvalid("Weighted configuration has duplicate guardians or an invalid threshold");
  return encodeAbiParameters(CONFIG, [
    guardians.map((g) => g.address),
    guardians.map((g) => g.weight),
    threshold,
  ]);
}

function operationDigests(
  hash: `0x${string}`,
  value: KeyOperationContext,
): readonly [`0x${string}`, `0x${string}`] {
  const record = exactInput(
    value,
    ["operation", "module", "permissionId", "configurationEpoch"],
    "Weighted signing context",
    new WeakSet(),
  );
  const operation = parsePreparedUserOperation(record.operation);
  const permissionId = record.permissionId;
  if (
    permissionId !== null &&
    (typeof permissionId !== "string" || !/^0x[0-9a-f]{8}$/u.test(permissionId))
  )
    return inputInvalid("Weighted signing permission is invalid");
  const module = permissionId === null ? KERNEL_WEIGHTED_VALIDATOR : KERNEL_WEIGHTED_SIGNER;
  const epoch = inputUint(
    record.configurationEpoch,
    (1n << 256n) - 1n,
    "Weighted configuration epoch",
  );
  if (
    epoch === 0n ||
    record.module !== module ||
    operation.userOperationHash !== hash ||
    operation.entryPoint.version !== "0.9"
  )
    return inputInvalid("Weighted signing context does not bind this operation");
  const nonce = BigInt(operation.userOperation.nonce);
  const replayable = (nonce & (0x40n << 248n)) !== 0n;
  const domain = {
    name: permissionId === null ? "WeightedECDSAValidator" : "WeightedECDSASigner",
    version: permissionId === null ? "0.0.5" : "0.0.3",
    ...(replayable ? {} : { chainId: operation.chainId }),
    verifyingContract: module,
  };
  return [
    hashTypedData({
      domain,
      primaryType: "Proposal",
      types: {
        Proposal: [
          { name: "account", type: "address" },
          { name: "id", type: "bytes32" },
          { name: "callData", type: "bytes" },
          { name: "nonce", type: "uint256" },
          { name: "configurationEpoch", type: "uint256" },
        ],
      },
      message: {
        account: operation.userOperation.sender,
        id:
          permissionId === null
            ? ZERO
            : padHex(permissionId as `0x${string}`, { size: 32, dir: "right" }),
        callData: operation.userOperation.callData,
        nonce,
        configurationEpoch: epoch,
      },
    }),
    hashTypedData({
      domain,
      primaryType: "WeightedUserOperation",
      types: {
        WeightedUserOperation: [
          { name: "userOpHash", type: "bytes32" },
          { name: "configurationEpoch", type: "uint256" },
        ],
      },
      message: { userOpHash: hash, configurationEpoch: epoch },
    }),
  ];
}

export function weightedEcdsaKey(value: WeightedEcdsaKeyInput): Readonly<KeyProfile> {
  const context = new WeakSet();
  const record = exactInput(
    value,
    ["guardians", "threshold", "signers"],
    "Weighted ECDSA key",
    context,
  );
  const publicMaterial = weightedPublicMaterial(record.guardians, record.threshold);
  const [addresses, weights, threshold] = decodeAbiParameters(CONFIG, publicMaterial);
  const weightByAddress = new Map(
    addresses.map((address, index) => [address.toLowerCase(), Number(weights[index])]),
  );
  const signers = denseInput(record.signers, "Weighted signers", context)
    .map((value) => {
      const account = captureInput(value, "Weighted signer", context);
      return ecdsaKey({
        account: account as unknown as EcdsaKeyAccount,
        validator: KERNEL_WEIGHTED_VALIDATOR,
      });
    })
    .sort((a, b) => a.publicMaterial.localeCompare(b.publicMaterial));
  if (
    signers.length === 0 ||
    signers.length > addresses.length ||
    new Set(signers.map((s) => s.publicMaterial)).size !== signers.length ||
    signers.some((s) => !weightByAddress.has(s.publicMaterial)) ||
    signers.reduce((sum, s) => sum + (weightByAddress.get(s.publicMaterial) ?? 0), 0) <
      Number(threshold)
  )
    return inputInvalid("Weighted signers do not form a distinct guardian quorum");

  async function verify(
    hash: `0x${string}`,
    signature: `0x${string}`,
    operation?: Readonly<KeyOperationContext>,
  ): Promise<boolean> {
    if (
      !isHash(hash) ||
      !isBytes(signature) ||
      signature.length <= 2 ||
      (signature.length - 2) % 130 !== 0
    )
      return false;
    const count = (signature.length - 2) / 130;
    if (count > addresses.length) return false;
    try {
      const [proposal, final] = operation ? operationDigests(hash, operation) : [hash, hash];
      const recovered = new Set<string>();
      let previous = "";
      let total = 0;
      for (let index = 0; index < count; index++) {
        const chunk = `0x${signature.slice(2 + index * 130, 2 + (index + 1) * 130)}` as const;
        const address = (
          await recoverAddress({ hash: index === count - 1 ? final : proposal, signature: chunk })
        ).toLowerCase();
        const guardianWeight = weightByAddress.get(address);
        if (
          !guardianWeight ||
          recovered.has(address) ||
          ((index < count - 1 || !operation) && address <= previous)
        )
          return false;
        recovered.add(address);
        previous = address;
        total += guardianWeight;
      }
      return total >= Number(threshold);
    } catch {
      return false;
    }
  }
  return Object.freeze({
    kind: "weighted-ecdsa" as const,
    publicMaterial,
    signerModule: null,
    // One non-guardian final signature returns signature failure without the
    // proposal path's ZeroWeightSigner revert. Callers supply quorum-sized gas.
    dummySignature: ECDSA_DUMMY_SIGNATURE,
    resolveValidator: (deployment: Readonly<KernelDeployment>) => {
      if (exactKernelDeployment(deployment).kernelVersion !== "0.4.0")
        return runtimeFail(
          "kernel_runtime_validator_unavailable",
          "Weighted V09 authority requires Kernel v4",
        );
      return KERNEL_WEIGHTED_VALIDATOR;
    },
    async sign(hash: `0x${string}`, operation?: Readonly<KeyOperationContext>) {
      if (!isHash(hash)) return inputInvalid("Weighted signing hash is invalid");
      const [proposal, final] = operation ? operationDigests(hash, operation) : [hash, hash];
      const signatures: `0x${string}`[] = [];
      for (let index = 0; index < signers.length; index++)
        signatures.push(
          await signers[index]!.sign(index === signers.length - 1 ? final : proposal),
        );
      const signature = concatHex(signatures);
      if (!(await verify(hash, signature, operation)))
        return runtimeFail(
          "kernel_runtime_signature_invalid",
          "Weighted signature does not meet the bound quorum",
        );
      return signature;
    },
    verify,
  });
}
