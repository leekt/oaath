/**
 * Shared exact-capture helpers for the Kernel composition axes. Every
 * caller-injected record, capability, and cryptographic artifact enters through
 * one of these so that typed composition code never repeats hostile-object
 * validation.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type CaptureContext,
  captureDenseArray,
  captureRecord,
  type ExactRecord,
  exactCapturedRecord,
} from "@oaath/protocol";
import { getAddress } from "viem";
import type { KernelV4Install } from "../kernel-v4.js";
import {
  type KernelBuiltInKeyKind,
  type KernelCustomKeyKind,
  type KernelRuntimeErrorCode,
  type KeyProfile,
  OaathKernelRuntimeError,
} from "./types.js";

const BYTES = /^0x(?:[0-9a-f]{2})*$/u;
const BYTES4 = /^0x[0-9a-f]{8}$/u;
const BYTES32 = /^0x[0-9a-f]{64}$/u;
const CUSTOM_KEY_KIND = /^custom:[a-z0-9][a-z0-9-]{0,31}$/u;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]{0,77})$/u;
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;

export function runtimeFail(code: KernelRuntimeErrorCode, message: string): never {
  throw new OaathKernelRuntimeError(code, message);
}

export function inputInvalid(message: string): never {
  return runtimeFail("kernel_runtime_input_invalid", message);
}

export function exactInput(
  value: unknown,
  keys: readonly string[],
  label: string,
  context: CaptureContext,
): ExactRecord {
  return exactCapturedRecord(
    captureRecord(value, label, context, inputInvalid),
    keys,
    label,
    inputInvalid,
  );
}

/** Captures one plain record without asserting its exact key set yet. */
export function captureInput(value: unknown, label: string, context: CaptureContext): ExactRecord {
  return captureRecord(value, label, context, inputInvalid);
}

/** Asserts the exact key set of an already captured record. */
export function exactCaptured(
  captured: ExactRecord,
  keys: readonly string[],
  label: string,
): ExactRecord {
  return exactCapturedRecord(captured, keys, label, inputInvalid);
}

export function denseInput(
  value: unknown,
  label: string,
  context: CaptureContext,
): readonly unknown[] {
  return captureDenseArray(value, label, context, inputInvalid);
}

export function inputAddress(value: unknown, label: string): `0x${string}` {
  if (typeof value !== "string") return inputInvalid(`${label} is invalid`);
  try {
    const canonical = getAddress(value).toLowerCase() as `0x${string}`;
    if (canonical === ZERO_ADDRESS) return inputInvalid(`${label} is invalid`);
    return canonical;
  } catch {
    return inputInvalid(`${label} is invalid`);
  }
}

export function inputSelector(value: unknown, label: string): `0x${string}` {
  if (typeof value !== "string" || !BYTES4.test(value)) return inputInvalid(`${label} is invalid`);
  return value as `0x${string}`;
}

export function inputUint(value: unknown, maximum: bigint, label: string): bigint {
  if (typeof value !== "string" || !DECIMAL_UINT.test(value))
    return inputInvalid(`${label} is invalid`);
  const parsed = BigInt(value);
  if (parsed > maximum) return inputInvalid(`${label} is invalid`);
  return parsed;
}

export function inputCapability<T>(value: unknown, label: string): T {
  if (typeof value !== "function") return inputInvalid(`${label} is invalid`);
  return value as T;
}

/** True for a lowercase even-length hex byte string of the given byte length. */
export function isBytesOfLength(value: unknown, byteLength: number): value is `0x${string}` {
  return typeof value === "string" && BYTES.test(value) && value.length === 2 + byteLength * 2;
}

export function isBytes(value: unknown): value is `0x${string}` {
  return typeof value === "string" && BYTES.test(value);
}

export function isHash(value: unknown): value is `0x${string}` {
  return typeof value === "string" && BYTES32.test(value);
}

/** True when two ERC-7579 install packages are the same install in every field. */
export function sameInstall(
  left: Readonly<KernelV4Install>,
  right: Readonly<KernelV4Install>,
): boolean {
  return (
    left.moduleType === right.moduleType &&
    left.module === right.module &&
    left.moduleData === right.moduleData &&
    left.internalData === right.internalData
  );
}

/** The exact key set every KeyProfile carries, reviewed or consumer-authored. */
export const KEY_PROFILE_KEYS: readonly string[] = Object.freeze([
  "kind",
  "publicMaterial",
  "resolveValidator",
  "signerModule",
  "dummySignature",
  "sign",
  "verify",
]);

/**
 * True for one credential kind this SDK authors. A reviewed kind resolves its
 * modules from the pinned registry and may not carry caller-bound ones.
 */
export function isBuiltInKeyKind(value: unknown): value is KernelBuiltInKeyKind {
  return value === "ecdsa" || value === "p256" || value === "webauthn";
}

/** True for one consumer-authored kind: `custom:` plus a bounded slug. */
export function isCustomKeyKind(value: unknown): value is KernelCustomKeyKind {
  return typeof value === "string" && CUSTOM_KEY_KIND.test(value);
}

/**
 * Captures one KeyProfile at an operator or runtime boundary. Both operators
 * accept any key kind, reviewed or consumer-authored, so only the shared
 * contract is asserted here.
 *
 * A consumer-authored profile is a hostile capability: nothing it claims is
 * trusted, and the two facts the SDK can check locally are enforced here rather
 * than in each operator. First, its kind must be bounded, which keeps it out of
 * the pinned registries a reviewed kind resolves through. Second, the captured
 * `sign` verifies every signature it produces against this profile's own bound
 * public material through the profile's own `verify`, so a signature that does
 * not belong to the installed key never reaches an authority envelope, a
 * bundler, or EntryPoint. The reviewed key profiles self-verify too; doing it at
 * the capture boundary means a consumer profile cannot opt out.
 */
export function captureKeyProfile(value: unknown): Readonly<KeyProfile> {
  const record = exactInput(value, KEY_PROFILE_KEYS, "Kernel key profile", new WeakSet());
  const kind = record.kind;
  if (!isCustomKeyKind(kind) && !isBuiltInKeyKind(kind)) {
    return inputInvalid("Kernel key profile kind is unsupported");
  }
  const custom = isCustomKeyKind(kind);
  if (!isBytes(record.publicMaterial) || record.publicMaterial === "0x") {
    return inputInvalid("Kernel key profile public material is invalid");
  }
  if (!isBytes(record.dummySignature) || record.dummySignature === "0x") {
    return inputInvalid("Kernel key profile dummy signature is invalid");
  }
  // A reviewed kind installs the permission signer module pinned to it, so a
  // caller-selected module on that axis is refused rather than honoured. A
  // consumer-authored kind may still carry none: an owner-only credential needs a
  // validator, and a session composed from a key that binds no signer module
  // fails closed on the signer axis instead of borrowing another kind's module.
  if (!custom && record.signerModule !== null) {
    return inputInvalid("Kernel key profile of a reviewed kind may not bind a signer module");
  }
  const signerModule =
    record.signerModule === null
      ? null
      : inputAddress(record.signerModule, "Kernel key profile signer module");
  const sign = inputCapability<KeyProfile["sign"]>(
    record.sign,
    "Kernel key profile sign capability",
  );
  const capabilityVerify = inputCapability<KeyProfile["verify"]>(
    record.verify,
    "Kernel key profile verify capability",
  );

  async function verify(hash: `0x${string}`, signature: `0x${string}`): Promise<boolean> {
    if (!isHash(hash) || typeof signature !== "string") return false;
    const lowered = signature.toLowerCase();
    if (!isBytes(lowered)) return false;
    try {
      return (await capabilityVerify(hash, lowered)) === true;
    } catch {
      return false;
    }
  }

  return Object.freeze({
    kind,
    publicMaterial: record.publicMaterial,
    signerModule,
    dummySignature: record.dummySignature,
    resolveValidator: inputCapability<KeyProfile["resolveValidator"]>(
      record.resolveValidator,
      "Kernel key profile validator resolution",
    ),
    async sign(hash: `0x${string}`): Promise<`0x${string}`> {
      if (!isHash(hash)) return inputInvalid("Kernel key profile signing hash is invalid");
      const produced = await invokeCapability(sign, hash, "Kernel key signing failed");
      if (typeof produced !== "string" || !isBytes(produced.toLowerCase()) || produced === "0x") {
        return runtimeFail("kernel_runtime_signature_invalid", "Kernel key signature is invalid");
      }
      const signature = produced.toLowerCase() as `0x${string}`;
      // Normalize-then-verify: the exact bytes that will be submitted are the
      // bytes verified against the bound public material.
      if (!(await verify(hash, signature))) {
        return runtimeFail(
          "kernel_runtime_signature_invalid",
          "Kernel key signature does not verify against the bound public material",
        );
      }
      return signature;
    },
    verify,
  });
}

/** Invokes a caller-supplied signing capability without leaking provider prose. */
export async function invokeCapability(
  capability: (request: never) => unknown,
  request: unknown,
  message: string,
): Promise<unknown> {
  try {
    return await Reflect.apply(capability, undefined, [request]);
  } catch (error) {
    if (error instanceof OaathKernelRuntimeError) throw error;
    return runtimeFail("kernel_runtime_signing_failed", message);
  }
}
