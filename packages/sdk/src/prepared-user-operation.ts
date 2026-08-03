import { getUserOperationHash, type UserOperation } from "viem/account-abstraction";
import {
  type CaptureContext,
  captureRecord as captureExactRecord,
  type ExactRecord,
  exactCapturedRecord as exactCapturedRecordValue,
  exactRecord as exactRecordValue,
} from "./internal/exact-record.js";
import type { OperationIdentity, OperationKind } from "./operation.js";

export const OAATH_PREPARED_USER_OPERATION_VERSION = "oaath.prepared-user-operation/v1" as const;

const ADDRESS = /^0x[0-9a-f]{40}$/u;
const HEX = /^0x(?:[0-9a-f]{2})*$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]{0,77})$/u;
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;
const EIP_7702_FACTORY = `0x7702${"00".repeat(18)}`;
const MAX_UINT120 = (1n << 120n) - 1n;
const MAX_UINT256 = (1n << 256n) - 1n;
const MAX_GRANT_ID_LENGTH = 256;

export type PreparedUserOperationErrorCode =
  | "prepared_user_operation_input_invalid"
  | "prepared_user_operation_record_invalid";

export class OaathPreparedUserOperationError extends Error {
  readonly code: PreparedUserOperationErrorCode;

  constructor(code: PreparedUserOperationErrorCode, message: string) {
    super(message);
    this.name = "OaathPreparedUserOperationError";
    this.code = code;
  }
}

export interface PreparedEntryPoint {
  readonly version: "0.7";
  readonly address: `0x${string}`;
}

export interface PreparedFactory {
  readonly address: `0x${string}`;
  readonly data: `0x${string}`;
}

export interface PreparedPaymaster {
  readonly address: `0x${string}`;
  /** Canonical decimal uint120 string accepted by EntryPoint 0.7. */
  readonly verificationGasLimit: string;
  /** Canonical decimal uint120 string accepted by EntryPoint 0.7. */
  readonly postOpGasLimit: string;
  readonly data: `0x${string}`;
}

export interface UnsignedUserOperationV07 {
  readonly sender: `0x${string}`;
  /** Canonical decimal uint256 string. */
  readonly nonce: string;
  /** Exact Kernel call bytes. The Kernel adapter owns encoding reviewed logical calls into this field. */
  readonly callData: `0x${string}`;
  /** Canonical decimal uint120 string accepted by EntryPoint 0.7. */
  readonly callGasLimit: string;
  /** Canonical decimal uint120 string accepted by EntryPoint 0.7. */
  readonly verificationGasLimit: string;
  /** Canonical decimal uint120 string accepted by EntryPoint 0.7. */
  readonly preVerificationGas: string;
  /** Canonical decimal uint120 string accepted by EntryPoint 0.7. */
  readonly maxFeePerGas: string;
  /** Canonical decimal uint120 string accepted by EntryPoint 0.7. */
  readonly maxPriorityFeePerGas: string;
  readonly factory: Readonly<PreparedFactory> | null;
  readonly paymaster: Readonly<PreparedPaymaster> | null;
}

export interface PreparedUserOperation {
  readonly version: typeof OAATH_PREPARED_USER_OPERATION_VERSION;
  readonly kind: OperationKind;
  readonly grantId: string;
  readonly chainId: number;
  readonly entryPoint: Readonly<PreparedEntryPoint>;
  readonly userOperation: Readonly<UnsignedUserOperationV07>;
  readonly userOperationHash: `0x${string}`;
}

type PlainRecord = ExactRecord;

function invalid(code: PreparedUserOperationErrorCode, message: string): never {
  throw new OaathPreparedUserOperationError(code, message);
}

function captureFailure(code: PreparedUserOperationErrorCode): (message: string) => never {
  return (message) => invalid(code, message);
}

function captureRecord(
  value: unknown,
  label: string,
  code: PreparedUserOperationErrorCode,
  context: CaptureContext,
): PlainRecord {
  return captureExactRecord(value, label, context, captureFailure(code));
}

function exactRecord(
  value: unknown,
  keys: readonly string[],
  label: string,
  code: PreparedUserOperationErrorCode,
  context: CaptureContext,
): PlainRecord {
  return exactRecordValue(value, keys, label, context, captureFailure(code));
}

function operationKind(value: unknown, code: PreparedUserOperationErrorCode): OperationKind {
  if (value !== "execution" && value !== "revocation") {
    return invalid(code, "prepared UserOperation kind is unsupported");
  }
  return value;
}

function canonicalGrantId(value: unknown, code: PreparedUserOperationErrorCode): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > MAX_GRANT_ID_LENGTH ||
    value !== value.trim()
  ) {
    return invalid(code, "prepared UserOperation grantId must be a bounded canonical string");
  }
  return value;
}

function chainId(value: unknown, code: PreparedUserOperationErrorCode): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    return invalid(code, "prepared UserOperation chainId must be a positive safe integer");
  }
  return value;
}

function address(
  value: unknown,
  label: string,
  code: PreparedUserOperationErrorCode,
): `0x${string}` {
  if (typeof value !== "string" || !ADDRESS.test(value) || value === ZERO_ADDRESS) {
    return invalid(code, `${label} must be a nonzero lowercase 20-byte address`);
  }
  return value as `0x${string}`;
}

function hex(
  value: unknown,
  label: string,
  code: PreparedUserOperationErrorCode,
  allowBytes: boolean,
): `0x${string}` {
  if (allowBytes && isOwnedByteArray(value, label, code)) {
    const copied = Uint8Array.prototype.slice.call(value) as Uint8Array;
    let result = "0x";
    for (const byte of copied) result += byte.toString(16).padStart(2, "0");
    return result as `0x${string}`;
  }
  if (typeof value !== "string" || !HEX.test(value)) {
    return invalid(code, `${label} must be canonical lowercase bytes`);
  }
  return value as `0x${string}`;
}

function isOwnedByteArray(
  value: unknown,
  label: string,
  code: PreparedUserOperationErrorCode,
): value is Uint8Array {
  if (!value || typeof value !== "object") return false;
  let prototype: object | null;
  try {
    prototype = Reflect.getPrototypeOf(value);
  } catch {
    return invalid(code, `${label} byte array is unreadable`);
  }
  if (prototype !== Uint8Array.prototype) return false;

  try {
    const typedArrayPrototype = Reflect.getPrototypeOf(Uint8Array.prototype);
    const bufferGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, "buffer")?.get;
    const lengthGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, "length")?.get;
    if (!bufferGetter || !lengthGetter) {
      return invalid(code, `${label} byte array runtime is unsupported`);
    }
    const buffer = Reflect.apply(bufferGetter, value, []) as ArrayBufferLike;
    const length = Reflect.apply(lengthGetter, value, []) as number;
    if (typeof SharedArrayBuffer !== "undefined" && buffer instanceof SharedArrayBuffer) {
      return invalid(code, `${label} must not use shared memory`);
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== length || keys.some((key) => typeof key !== "string")) {
      return invalid(code, `${label} byte array contains extra fields`);
    }
    for (let index = 0; index < length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
        return invalid(code, `${label} byte array is not dense owned data`);
      }
    }
    Uint8Array.prototype.slice.call(value);
    return true;
  } catch {
    return invalid(code, `${label} byte array is unreadable`);
  }
}

function hash(value: unknown, label: string, code: PreparedUserOperationErrorCode): `0x${string}` {
  if (typeof value !== "string" || !HASH.test(value)) {
    return invalid(code, `${label} must be a lowercase 32-byte hash`);
  }
  return value as `0x${string}`;
}

function uint(
  value: unknown,
  label: string,
  maximum: bigint,
  code: PreparedUserOperationErrorCode,
): string {
  if (typeof value !== "string" || !DECIMAL_UINT.test(value) || BigInt(value) > maximum) {
    return invalid(code, `${label} must be a canonical bounded decimal integer`);
  }
  return value;
}

function parseEntryPoint(
  value: unknown,
  code: PreparedUserOperationErrorCode,
  context: CaptureContext,
): Readonly<PreparedEntryPoint> {
  const record = exactRecord(value, ["version", "address"], "prepared EntryPoint", code, context);
  if (record.version !== "0.7") {
    return invalid(code, "prepared EntryPoint version is unsupported");
  }
  return Object.freeze({
    version: record.version,
    address: address(record.address, "prepared EntryPoint address", code),
  });
}

function parseFactory(
  value: unknown,
  code: PreparedUserOperationErrorCode,
  context: CaptureContext,
  allowBytes: boolean,
): Readonly<PreparedFactory> | null {
  if (value === null) return null;
  const record = exactRecord(
    value,
    ["address", "data"],
    "prepared UserOperation factory",
    code,
    context,
  );
  const factoryAddress = address(record.address, "prepared UserOperation factory address", code);
  if (factoryAddress === EIP_7702_FACTORY) {
    return invalid(code, "prepared UserOperation EIP-7702 authorization is unsupported");
  }
  return Object.freeze({
    address: factoryAddress,
    data: hex(record.data, "prepared UserOperation factory data", code, allowBytes),
  });
}

function parsePaymaster(
  value: unknown,
  code: PreparedUserOperationErrorCode,
  context: CaptureContext,
  allowBytes: boolean,
): Readonly<PreparedPaymaster> | null {
  if (value === null) return null;
  const record = exactRecord(
    value,
    ["address", "verificationGasLimit", "postOpGasLimit", "data"],
    "prepared UserOperation paymaster",
    code,
    context,
  );
  return Object.freeze({
    address: address(record.address, "prepared UserOperation paymaster address", code),
    verificationGasLimit: uint(
      record.verificationGasLimit,
      "prepared UserOperation paymaster verification gas limit",
      MAX_UINT120,
      code,
    ),
    postOpGasLimit: uint(
      record.postOpGasLimit,
      "prepared UserOperation paymaster post-operation gas limit",
      MAX_UINT120,
      code,
    ),
    data: hex(record.data, "prepared UserOperation paymaster data", code, allowBytes),
  });
}

function parseUnsignedUserOperation(
  value: unknown,
  code: PreparedUserOperationErrorCode,
  context: CaptureContext,
  allowBytes: boolean,
): Readonly<UnsignedUserOperationV07> {
  const record = exactRecord(
    value,
    [
      "sender",
      "nonce",
      "callData",
      "callGasLimit",
      "verificationGasLimit",
      "preVerificationGas",
      "maxFeePerGas",
      "maxPriorityFeePerGas",
      "factory",
      "paymaster",
    ],
    "unsigned UserOperation",
    code,
    context,
  );
  const maxFeePerGas = uint(
    record.maxFeePerGas,
    "prepared UserOperation max fee per gas",
    MAX_UINT120,
    code,
  );
  const maxPriorityFeePerGas = uint(
    record.maxPriorityFeePerGas,
    "prepared UserOperation max priority fee per gas",
    MAX_UINT120,
    code,
  );
  if (BigInt(maxPriorityFeePerGas) > BigInt(maxFeePerGas)) {
    return invalid(code, "prepared UserOperation priority fee exceeds its maximum fee");
  }
  return Object.freeze({
    sender: address(record.sender, "prepared UserOperation sender", code),
    nonce: uint(record.nonce, "prepared UserOperation nonce", MAX_UINT256, code),
    callData: hex(record.callData, "prepared UserOperation callData", code, allowBytes),
    callGasLimit: uint(
      record.callGasLimit,
      "prepared UserOperation call gas limit",
      MAX_UINT120,
      code,
    ),
    verificationGasLimit: uint(
      record.verificationGasLimit,
      "prepared UserOperation verification gas limit",
      MAX_UINT120,
      code,
    ),
    preVerificationGas: uint(
      record.preVerificationGas,
      "prepared UserOperation pre-verification gas",
      MAX_UINT120,
      code,
    ),
    maxFeePerGas,
    maxPriorityFeePerGas,
    factory: parseFactory(record.factory, code, context, allowBytes),
    paymaster: parsePaymaster(record.paymaster, code, context, allowBytes),
  });
}

/**
 * Maps one prepared unsigned UserOperation into viem's flat v0.7 shape with an
 * empty signature, ready for signing and toPackedUserOperation submission.
 */
export function asViemUserOperation(value: UnsignedUserOperationV07): UserOperation<"0.7"> {
  return {
    sender: value.sender,
    nonce: BigInt(value.nonce),
    callData: value.callData,
    callGasLimit: BigInt(value.callGasLimit),
    verificationGasLimit: BigInt(value.verificationGasLimit),
    preVerificationGas: BigInt(value.preVerificationGas),
    maxFeePerGas: BigInt(value.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(value.maxPriorityFeePerGas),
    signature: "0x",
    ...(value.factory === null
      ? {}
      : { factory: value.factory.address, factoryData: value.factory.data }),
    ...(value.paymaster === null
      ? {}
      : {
          paymaster: value.paymaster.address,
          paymasterVerificationGasLimit: BigInt(value.paymaster.verificationGasLimit),
          paymasterPostOpGasLimit: BigInt(value.paymaster.postOpGasLimit),
          paymasterData: value.paymaster.data,
        }),
  };
}

function deriveUserOperationHash(value: {
  readonly chainId: number;
  readonly entryPoint: Readonly<PreparedEntryPoint>;
  readonly userOperation: Readonly<UnsignedUserOperationV07>;
}): `0x${string}` {
  return getUserOperationHash({
    chainId: value.chainId,
    entryPointAddress: value.entryPoint.address,
    entryPointVersion: value.entryPoint.version,
    userOperation: asViemUserOperation(value.userOperation),
  });
}

function capturePreparation(
  value: unknown,
  code: PreparedUserOperationErrorCode,
  context: CaptureContext,
): Omit<PreparedUserOperation, "version" | "userOperationHash"> {
  const record = exactRecord(
    value,
    ["kind", "grantId", "chainId", "entryPoint", "userOperation"],
    "prepared UserOperation input",
    code,
    context,
  );
  return {
    kind: operationKind(record.kind, code),
    grantId: canonicalGrantId(record.grantId, code),
    chainId: chainId(record.chainId, code),
    entryPoint: parseEntryPoint(record.entryPoint, code, context),
    userOperation: parseUnsignedUserOperation(record.userOperation, code, context, true),
  };
}

function parsePreparedUserOperationUnsafe(
  value: unknown,
  code: PreparedUserOperationErrorCode,
  context: CaptureContext,
): PreparedUserOperation {
  const captured = captureRecord(value, "prepared UserOperation record", code, context);
  const record = exactCapturedRecordValue(
    captured,
    ["version", "kind", "grantId", "chainId", "entryPoint", "userOperation", "userOperationHash"],
    "prepared UserOperation record",
    captureFailure(code),
  );
  if (record.version !== OAATH_PREPARED_USER_OPERATION_VERSION) {
    return invalid(code, "prepared UserOperation record version is unsupported");
  }
  const preparation = {
    kind: operationKind(record.kind, code),
    grantId: canonicalGrantId(record.grantId, code),
    chainId: chainId(record.chainId, code),
    entryPoint: parseEntryPoint(record.entryPoint, code, context),
    userOperation: parseUnsignedUserOperation(record.userOperation, code, context, false),
  };
  const recordedHash = hash(record.userOperationHash, "prepared UserOperation hash", code);
  if (recordedHash !== deriveUserOperationHash(preparation)) {
    return invalid(code, "prepared UserOperation hash does not match its exact fields");
  }
  return Object.freeze({
    version: OAATH_PREPARED_USER_OPERATION_VERSION,
    ...preparation,
    userOperationHash: recordedHash,
  });
}

export function prepareUserOperation(value: unknown): PreparedUserOperation {
  const code = "prepared_user_operation_input_invalid" as const;
  try {
    const preparation = capturePreparation(value, code, new WeakSet());
    return Object.freeze({
      version: OAATH_PREPARED_USER_OPERATION_VERSION,
      ...preparation,
      userOperationHash: deriveUserOperationHash(preparation),
    });
  } catch {
    throw new OaathPreparedUserOperationError(
      code,
      "prepared UserOperation input could not be captured safely",
    );
  }
}

export function parsePreparedUserOperation(value: unknown): PreparedUserOperation {
  const code = "prepared_user_operation_record_invalid" as const;
  try {
    return parsePreparedUserOperationUnsafe(value, code, new WeakSet());
  } catch {
    throw new OaathPreparedUserOperationError(
      code,
      "prepared UserOperation record could not be captured safely",
    );
  }
}

export function deriveOperationId(value: unknown): Readonly<OperationIdentity> {
  const prepared = parsePreparedUserOperation(value);
  return Object.freeze({
    kind: prepared.kind,
    grantId: prepared.grantId,
    chainId: prepared.chainId,
    entryPoint: prepared.entryPoint.address,
    account: prepared.userOperation.sender,
    nonce: prepared.userOperation.nonce,
    userOperationHash: prepared.userOperationHash,
  });
}
