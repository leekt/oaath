/**
 * Draft ERC-7902 static-paymaster capture into OAAth's existing EntryPoint 0.7
 * `PreparedPaymaster` owner.
 *
 * This codec proves only syntax, bounds, immutability, and the deliberate wire
 * rename from `paymasterValidationGasLimit` to EntryPoint's verification-gas
 * field. It grants no authority and performs no policy lookup, estimation,
 * preparation, signing, persistence, submission, retry, or advertisement.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type CaptureContext, captureRecord } from "@oaath/protocol";
import { encodeAbiParameters, type Hash, keccak256 } from "viem";
import type { PreparedPaymaster } from "../prepared-user-operation.js";
import { capabilityInvalid } from "../routing/types.js";

const ADDRESS = /^0x[0-9a-f]{40}$/u;
const BYTES = /^0x(?:[0-9a-f]{2})*$/u;
const CANONICAL_QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/u;
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;
const MAX_UINT120 = (1n << 120n) - 1n;

const REQUIRED_KEYS = Object.freeze([
  "paymaster",
  "paymasterData",
  "paymasterValidationGasLimit",
  "paymasterPostOpGasLimit",
]);
const ALLOWED_KEYS = Object.freeze([...REQUIRED_KEYS, "optional"]);

export const ERC7902_STATIC_PAYMASTER_LIMITS = Object.freeze({
  /** Raw bytes; the Wallet Call provider separately owns its smaller aggregate JSON budget. */
  paymasterDataBytes: 64 * 1_024,
});

/** Domain that prevents this commitment from being reused as another OAAth hash. */
export const ERC7902_STATIC_PAYMASTER_CONFIGURATION_HASH_DOMAIN =
  "@oaath/sdk:erc-7902-static-paymaster-configuration/v1" as const;

const STATIC_PAYMASTER_CONFIGURATION_HASH_PARAMETERS = Object.freeze([
  Object.freeze({ name: "domain", type: "string" }),
  Object.freeze({ name: "paymaster", type: "address" }),
  Object.freeze({ name: "paymasterData", type: "bytes" }),
  Object.freeze({ name: "paymasterValidationGasLimit", type: "uint120" }),
  Object.freeze({ name: "paymasterPostOpGasLimit", type: "uint120" }),
] as const);

/**
 * One fully captured capability. `optional` is explicit even when absent on
 * the wire, while `paymaster` is already in the sole internal v0.7 shape that
 * final preparation and hashing understand.
 */
export interface Erc7902StaticPaymasterConfiguration {
  readonly optional: boolean;
  readonly paymaster: Readonly<PreparedPaymaster>;
}

function invalid(): never {
  return capabilityInvalid("ERC-7902 static paymaster configuration is invalid");
}

function exactConfigurationRecord(
  value: unknown,
  context: CaptureContext,
): Record<string, unknown> {
  const record = captureRecord(value, "ERC-7902 static paymaster configuration", context, invalid);
  for (const key of Object.keys(record)) {
    if (!ALLOWED_KEYS.includes(key)) invalid();
  }
  for (const key of REQUIRED_KEYS) {
    if (!Object.hasOwn(record, key)) invalid();
  }
  return record;
}

function address(value: unknown): `0x${string}` {
  if (typeof value !== "string" || !ADDRESS.test(value) || value === ZERO_ADDRESS) invalid();
  return value as `0x${string}`;
}

function bytes(value: unknown): `0x${string}` {
  if (
    typeof value !== "string" ||
    !BYTES.test(value) ||
    (value.length - 2) / 2 > ERC7902_STATIC_PAYMASTER_LIMITS.paymasterDataBytes
  ) {
    return invalid();
  }
  return value as `0x${string}`;
}

function quantity(value: unknown): string {
  if (typeof value !== "string" || !CANONICAL_QUANTITY.test(value)) invalid();
  const parsed = BigInt(value);
  if (parsed > MAX_UINT120) invalid();
  return parsed.toString(10);
}

/**
 * Hashes an already captured paymaster. Callers outside this module must first
 * use one of the exact capture owners above. Kept package-internal so the
 * public helper cannot accidentally bless an unvalidated internal shape.
 */
export function hashCapturedErc7902PreparedPaymaster(paymaster: Readonly<PreparedPaymaster>): Hash {
  return keccak256(
    encodeAbiParameters(STATIC_PAYMASTER_CONFIGURATION_HASH_PARAMETERS, [
      ERC7902_STATIC_PAYMASTER_CONFIGURATION_HASH_DOMAIN,
      paymaster.address,
      paymaster.data,
      BigInt(paymaster.verificationGasLimit),
      BigInt(paymaster.postOpGasLimit),
    ]),
  );
}

/**
 * Captures the exact experimental ERC-7902 capability shape once. The draft's
 * literal `paymasterValidationGasLimit` spelling is accepted; the common
 * `paymasterVerificationGasLimit` spelling is intentionally not an alias.
 */
export function captureErc7902StaticPaymasterConfiguration(
  value: unknown,
): Readonly<Erc7902StaticPaymasterConfiguration> {
  try {
    const record = exactConfigurationRecord(value, new WeakSet());
    const optional = Object.hasOwn(record, "optional") ? record.optional : false;
    if (typeof optional !== "boolean") invalid();
    return Object.freeze({
      optional,
      paymaster: Object.freeze({
        address: address(record.paymaster),
        // ERC-7902's Draft wire name differs from EntryPoint 0.7 and the
        // PreparedPaymaster owner. This codec is the only translation point.
        verificationGasLimit: quantity(record.paymasterValidationGasLimit),
        postOpGasLimit: quantity(record.paymasterPostOpGasLimit),
        data: bytes(record.paymasterData),
      }),
    });
  } catch {
    return invalid();
  }
}

/**
 * Returns the authenticated commitment for one exact Draft wire
 * configuration. `optional` controls negotiation only, so it is deliberately
 * excluded; the normalized address, data, and both uint120 gas limits are
 * bound in a domain-separated ABI encoding.
 */
export function hashErc7902StaticPaymasterConfiguration(value: unknown): Hash {
  const captured = captureErc7902StaticPaymasterConfiguration(value);
  return hashCapturedErc7902PreparedPaymaster(captured.paymaster);
}
