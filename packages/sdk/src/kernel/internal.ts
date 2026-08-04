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
import { type KernelRuntimeErrorCode, type KeyProfile, OaathKernelRuntimeError } from "./types.js";

const BYTES = /^0x(?:[0-9a-f]{2})*$/u;
const BYTES4 = /^0x[0-9a-f]{8}$/u;
const BYTES32 = /^0x[0-9a-f]{64}$/u;
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

/**
 * Captures one KeyProfile at an operator or runtime boundary. Both operators
 * accept any key kind, so only the shared contract is asserted here.
 */
export function captureKeyProfile(value: unknown): Readonly<KeyProfile> {
  const record = exactInput(
    value,
    ["kind", "publicMaterial", "resolveValidator", "dummySignature", "sign", "verify"],
    "Kernel key profile",
    new WeakSet(),
  );
  if (record.kind !== "ecdsa" && record.kind !== "p256" && record.kind !== "webauthn") {
    return inputInvalid("Kernel key profile kind is unsupported");
  }
  if (!isBytes(record.publicMaterial) || record.publicMaterial === "0x") {
    return inputInvalid("Kernel key profile public material is invalid");
  }
  if (!isBytes(record.dummySignature) || record.dummySignature === "0x") {
    return inputInvalid("Kernel key profile dummy signature is invalid");
  }
  return Object.freeze({
    kind: record.kind,
    publicMaterial: record.publicMaterial,
    dummySignature: record.dummySignature,
    resolveValidator: inputCapability<KeyProfile["resolveValidator"]>(
      record.resolveValidator,
      "Kernel key profile validator resolution",
    ),
    sign: inputCapability<KeyProfile["sign"]>(record.sign, "Kernel key profile sign capability"),
    verify: inputCapability<KeyProfile["verify"]>(
      record.verify,
      "Kernel key profile verify capability",
    ),
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
