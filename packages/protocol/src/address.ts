import { isAddress } from "cetane/utils";

/**
 * Captures a single-case or EIP-55 address in canonical lowercase. Domain
 * owners retain their error codes and whether the zero address is meaningful.
 */
export function captureAddress(
  value: unknown,
  label: string,
  fail: (message: string, reason: "format" | "checksum" | "zero") => never,
  allowZero = false,
): `0x${string}` {
  if (!isAddress(value, { strict: false }))
    return fail(`${label} must be a 20-byte address`, "format");
  const digits = value.slice(2);
  if (digits !== digits.toLowerCase() && digits !== digits.toUpperCase() && !isAddress(value))
    return fail(`${label} has an invalid EIP-55 checksum`, "checksum");
  const canonical = value.toLowerCase() as `0x${string}`;
  if (!allowZero && canonical === `0x${"00".repeat(20)}`)
    return fail(`${label} must be nonzero`, "zero");
  return canonical;
}
