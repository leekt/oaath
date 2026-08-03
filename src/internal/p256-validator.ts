import { p256 } from "@noble/curves/nist.js";
import { encodeAbiParameters, hexToBytes } from "viem";

const PUBLIC_KEY = /^0x04[0-9a-f]{128}$/u;
const COMPACT_SIGNATURE = /^0x[0-9a-f]{128}$/u;
const P256_ORDER = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const P256_HALF_ORDER = P256_ORDER / 2n;

export type P256ValidatorFailure = (message: string) => never;

export function isP256PublicKeyEncoding(value: unknown): value is `0x${string}` {
  return typeof value === "string" && PUBLIC_KEY.test(value);
}

export function isP256CompactSignatureEncoding(value: unknown): value is `0x${string}` {
  return typeof value === "string" && COMPACT_SIGNATURE.test(value);
}

export function encodeP256ValidatorEnableData(
  publicKey: unknown,
  fail: P256ValidatorFailure,
): `0x${string}` {
  if (!isP256PublicKeyEncoding(publicKey)) {
    return fail("P-256 public key is invalid");
  }
  try {
    p256.ProjectivePoint.fromHex(publicKey.slice(2));
  } catch {
    return fail("P-256 public key is not on curve");
  }
  const x = BigInt(`0x${publicKey.slice(4, 68)}`);
  const y = BigInt(`0x${publicKey.slice(68)}`);
  return encodeAbiParameters(
    [
      { name: "x", type: "uint256" },
      { name: "y", type: "uint256" },
    ],
    [x, y],
  );
}

export function normalizeP256ValidatorSignature(
  value: unknown,
  hash: `0x${string}`,
  publicKey: `0x${string}`,
  fail: P256ValidatorFailure,
): `0x${string}` {
  if (!isP256CompactSignatureEncoding(value)) {
    return fail("P-256 signature is invalid");
  }
  const r = BigInt(`0x${value.slice(2, 66)}`);
  let s = BigInt(`0x${value.slice(66)}`);
  if (r <= 0n || r >= P256_ORDER || s <= 0n || s >= P256_ORDER) {
    return fail("P-256 signature is invalid");
  }
  if (s > P256_HALF_ORDER) s = P256_ORDER - s;
  const encoded = encodeAbiParameters(
    [
      { name: "r", type: "uint256" },
      { name: "s", type: "uint256" },
    ],
    [r, s],
  );
  let valid = false;
  try {
    valid = p256.verify(hexToBytes(encoded), hexToBytes(hash), hexToBytes(publicKey), {
      format: "compact",
      lowS: true,
      prehash: false,
    });
  } catch {}
  if (!valid) {
    return fail("P-256 signature does not match the selected public key");
  }
  return encoded;
}
