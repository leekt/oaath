/**
 * Raw P-256 KeyProfile. Private key material never enters this module: the
 * caller supplies a signing capability, exactly as kernel-v4.ts accepts a read
 * capability.
 *
 * @author taek <leekt216@gmail.com>
 */
import { p256 } from "@noble/curves/nist.js";
import { type CaptureContext, parseOwnerCredentialProfile } from "@oaath/protocol";
import { encodeAbiParameters, hexToBytes } from "viem";
import type { KernelV4Deployment } from "../../kernel-v4.js";
import {
  exactInput,
  inputCapability,
  inputInvalid,
  invokeCapability,
  isBytesOfLength,
  runtimeFail,
} from "../internal.js";
import { exactKernelDeployment, resolvePinnedValidator } from "../modules.js";
import type { KeyProfile } from "../types.js";

const P256_ORDER = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const P256_HALF_ORDER = P256_ORDER / 2n;
/** 64-byte low-s placeholder with no signing authority; used for gas estimation only. */
const DUMMY_SIGNATURE = `0x${"33".repeat(32)}${"44".repeat(32)}` as const;

const PUBLIC_MATERIAL_PARAMETERS = [
  { name: "x", type: "uint256" },
  { name: "y", type: "uint256" },
] as const;

export interface P256SignRequest {
  readonly hash: `0x${string}`;
}

export interface P256KeyInput {
  /** @oaath/protocol P-256 credential profile carrying the on-curve public key. */
  readonly credential: unknown;
  /** Caller-owned capability returning the compact 64-byte (r || s) signature. */
  readonly sign: (request: P256SignRequest) => Promise<unknown>;
}

export function p256Key(value: P256KeyInput): Readonly<KeyProfile> {
  const context: CaptureContext = new WeakSet();
  const record = exactInput(value, ["credential", "sign"], "P-256 key", context);
  const credential = parseOwnerCredentialProfile(record.credential);
  if (credential.kind !== "p256") {
    return inputInvalid("P-256 key credential profile is not a raw P-256 credential");
  }
  const publicKey = credential.publicKey;
  const sign = inputCapability<P256KeyInput["sign"]>(record.sign, "P-256 key sign capability");

  async function verify(hash: `0x${string}`, signature: `0x${string}`): Promise<boolean> {
    if (!isBytesOfLength(signature, 64) || !isBytesOfLength(hash, 32)) return false;
    try {
      return p256.verify(hexToBytes(signature), hexToBytes(hash), hexToBytes(publicKey), {
        format: "compact",
        lowS: true,
        prehash: false,
      });
    } catch {
      return false;
    }
  }

  return Object.freeze({
    kind: "p256" as const,
    publicMaterial: encodeAbiParameters(PUBLIC_MATERIAL_PARAMETERS, [
      BigInt(`0x${publicKey.slice(4, 68)}`),
      BigInt(`0x${publicKey.slice(68)}`),
    ]),
    resolveValidator: (deployment: Readonly<KernelV4Deployment>) =>
      resolvePinnedValidator(exactKernelDeployment(deployment), "p256"),
    dummySignature: DUMMY_SIGNATURE,
    async sign(hash: `0x${string}`): Promise<`0x${string}`> {
      const produced = await invokeCapability(
        sign,
        Object.freeze({ hash }),
        "P-256 key signing failed",
      );
      if (typeof produced !== "string" || !isBytesOfLength(produced.toLowerCase(), 64)) {
        return runtimeFail("kernel_runtime_signature_invalid", "P-256 signature is invalid");
      }
      const lowered = produced.toLowerCase();
      const r = BigInt(`0x${lowered.slice(2, 66)}`);
      const rawS = BigInt(`0x${lowered.slice(66)}`);
      if (r <= 0n || r >= P256_ORDER || rawS <= 0n || rawS >= P256_ORDER) {
        return runtimeFail("kernel_runtime_signature_invalid", "P-256 signature is invalid");
      }
      const s = rawS > P256_HALF_ORDER ? P256_ORDER - rawS : rawS;
      const signature = `0x${r.toString(16).padStart(64, "0")}${s
        .toString(16)
        .padStart(64, "0")}` as const;
      if (!(await verify(hash, signature))) {
        return runtimeFail(
          "kernel_runtime_signature_invalid",
          "P-256 signature does not match the bound key",
        );
      }
      return signature;
    },
    verify,
  });
}
