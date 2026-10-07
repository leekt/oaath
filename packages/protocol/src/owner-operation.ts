/**
 * Current-version owner-operation wire owner: one exact Kernel 0.4.0 /
 * EntryPoint 0.9 UserOperation an account's root signs, and the signed
 * artifact a submitter carries. The UserOperation hash is the root's signing
 * digest, so chain, EntryPoint, account, nonce, calls, gas, factory and
 * paymaster are all bound by the one signature.
 *
 * The account is factory-derived, or an existing (imported) Kernel 0.4.0
 * account, which is already deployed and so carries no factory.
 *
 * Capture checks only facts derivable without deployment addresses: exact
 * shape, calls against callData, a root-validation nonce, and the hash. The
 * account's address (derived, or the existing profile's own), factory, and
 * EntryPoint belong to the deployment owner (SDK `verifyOwnerOperation`, Rust
 * `verify_owner_operation_binding`).
 * Nothing here verifies a signature or submits anything.
 *
 * @author taek <leekt216@gmail.com>
 */
import { getSigningHash, type Operation } from "cetane/execution/erc4337";
import { captureAddress } from "./address.js";
import { capturedByProtocol, protocolFailure } from "./errors.js";
import {
  captureKernelAccountProfile,
  isKernelExistingAccountProfile,
  type KernelDerivedAccountProfile,
  type KernelExistingAccountProfile,
} from "./identity-profile.js";
import { captureDenseArray, exactRecord } from "./internal/exact-record.js";
import { encodeKernelExecution } from "./internal/kernel-execution.js";

export const OAATH_OWNER_OPERATION_REQUEST_VERSION = "oaath.owner-operation-request/v1" as const;
export const OAATH_SIGNED_OWNER_OPERATION_VERSION = "oaath.signed-owner-operation/v1" as const;
/** The most calls one owner operation carries. */
export const MAX_OWNER_OPERATION_CALLS = 16;

const fail = protocolFailure("signing_request_invalid");
const BYTES = /^0x(?:[0-9a-f]{2})*$/u;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]{0,77})$/u;
const MAX_UINT120 = (1n << 120n) - 1n;
const MAX_UINT256 = (1n << 256n) - 1n;
const MAX_DATA_BYTES = 64 * 1024;
const MAX_SIGNATURE_BYTES = 8 * 1024;
/** EntryPoint 0.9's detached paymaster-signature suffix, which the hash omits. */
const PAYMASTER_SIGNATURE_MAGIC = "22e325a297439656";

export interface OwnerOperationCall {
  readonly target: `0x${string}`;
  /** Canonical decimal uint256 wei. */
  readonly value: string;
  readonly data: `0x${string}`;
}

/** EntryPoint 0.9's unpacked unsigned operation; integers are canonical decimal strings. */
export interface OwnerUserOperation {
  readonly sender: `0x${string}`;
  readonly nonce: string;
  readonly callData: `0x${string}`;
  readonly callGasLimit: string;
  readonly verificationGasLimit: string;
  readonly preVerificationGas: string;
  readonly maxFeePerGas: string;
  readonly maxPriorityFeePerGas: string;
  /** Present only while the account is undeployed. */
  readonly factory: Readonly<{ address: `0x${string}`; data: `0x${string}` }> | null;
  readonly paymaster: Readonly<{
    address: `0x${string}`;
    verificationGasLimit: string;
    postOpGasLimit: string;
    data: `0x${string}`;
  }> | null;
}

export interface OwnerOperationRequest {
  readonly version: typeof OAATH_OWNER_OPERATION_REQUEST_VERSION;
  readonly kind: "kernel-owner-operation";
  /** The factory-derived or existing Kernel 0.4.0 account whose root signs. */
  readonly account: Readonly<KernelDerivedAccountProfile | KernelExistingAccountProfile>;
  readonly chainId: number;
  readonly entryPoint: `0x${string}`;
  /** The exact calls the root reviews; `userOperation.callData` executes exactly these. */
  readonly calls: readonly Readonly<OwnerOperationCall>[];
  readonly userOperation: Readonly<OwnerUserOperation>;
  /** EntryPoint 0.9 `getUserOpHash`: the digest the root signs. */
  readonly userOperationHash: `0x${string}`;
}

/** A root's signature over one request, as the owner operator returns it (no envelope). */
export interface SignedOwnerOperation {
  readonly version: typeof OAATH_SIGNED_OWNER_OPERATION_VERSION;
  readonly request: Readonly<OwnerOperationRequest>;
  readonly signature: `0x${string}`;
}

function address(value: unknown, label: string, allowZero = false): `0x${string}` {
  return captureAddress(value, label, fail, allowZero);
}

function bytes(value: unknown, label: string, maximum = MAX_DATA_BYTES): `0x${string}` {
  if (typeof value !== "string" || !BYTES.test(value) || value.length > 2 + maximum * 2)
    return fail(`${label} must be bounded canonical lowercase bytes`);
  return value as `0x${string}`;
}

function uint(value: unknown, maximum: bigint, label: string): string {
  if (typeof value !== "string" || !DECIMAL_UINT.test(value) || BigInt(value) > maximum)
    return fail(`${label} must be a canonical bounded decimal integer`);
  return value;
}

function captureCalls(value: unknown, context: WeakSet<object>): readonly OwnerOperationCall[] {
  const entries = captureDenseArray(value, "owner operation calls", context, fail);
  if (entries.length < 1 || entries.length > MAX_OWNER_OPERATION_CALLS)
    return fail("owner operation call count is invalid");
  return Object.freeze(
    entries.map((entry, index) => {
      const call = exactRecord(
        entry,
        ["target", "value", "data"],
        `owner operation call ${index}`,
        context,
        fail,
      );
      return Object.freeze({
        target: address(call.target, "owner operation call target", true),
        value: uint(call.value, MAX_UINT256, "owner operation call value"),
        data: bytes(call.data, "owner operation call data"),
      });
    }),
  );
}

function captureUserOperation(
  value: unknown,
  context: WeakSet<object>,
): Readonly<OwnerUserOperation> {
  const op = exactRecord(
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
    "owner UserOperation",
    context,
    fail,
  );
  const gas = (field: unknown, label: string) => uint(field, MAX_UINT120, label);
  const maxFeePerGas = gas(op.maxFeePerGas, "owner UserOperation max fee per gas");
  const maxPriorityFeePerGas = gas(
    op.maxPriorityFeePerGas,
    "owner UserOperation max priority fee per gas",
  );
  if (BigInt(maxPriorityFeePerGas) > BigInt(maxFeePerGas))
    return fail("owner UserOperation priority fee exceeds its maximum fee");
  let factory: OwnerUserOperation["factory"] = null;
  if (op.factory !== null) {
    const record = exactRecord(
      op.factory,
      ["address", "data"],
      "owner UserOperation factory",
      context,
      fail,
    );
    factory = Object.freeze({
      address: address(record.address, "owner UserOperation factory address"),
      data: bytes(record.data, "owner UserOperation factory data"),
    });
  }
  let paymaster: OwnerUserOperation["paymaster"] = null;
  if (op.paymaster !== null) {
    const record = exactRecord(
      op.paymaster,
      ["address", "verificationGasLimit", "postOpGasLimit", "data"],
      "owner UserOperation paymaster",
      context,
      fail,
    );
    const data = bytes(record.data, "owner UserOperation paymaster data");
    // The hash would omit a detached paymaster signature; this artifact has none.
    if (data.endsWith(PAYMASTER_SIGNATURE_MAGIC))
      return fail("owner UserOperation paymaster data carries a detached signature marker");
    paymaster = Object.freeze({
      address: address(record.address, "owner UserOperation paymaster address"),
      verificationGasLimit: gas(
        record.verificationGasLimit,
        "owner UserOperation paymaster verification gas limit",
      ),
      postOpGasLimit: gas(record.postOpGasLimit, "owner UserOperation paymaster post-op gas limit"),
      data,
    });
  }
  return Object.freeze({
    sender: address(op.sender, "owner UserOperation sender"),
    nonce: uint(op.nonce, MAX_UINT256, "owner UserOperation nonce"),
    callData: bytes(op.callData, "owner UserOperation callData", MAX_DATA_BYTES * 2),
    callGasLimit: gas(op.callGasLimit, "owner UserOperation call gas limit"),
    verificationGasLimit: gas(
      op.verificationGasLimit,
      "owner UserOperation verification gas limit",
    ),
    preVerificationGas: gas(op.preVerificationGas, "owner UserOperation pre-verification gas"),
    maxFeePerGas,
    maxPriorityFeePerGas,
    factory,
    paymaster,
  });
}

/** Cetane's unpacked operation with an empty signature, for hashing and submission. */
export function ownerUserOperationForCetane(value: Readonly<OwnerUserOperation>): Operation {
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

function captureRequest(value: unknown, context: WeakSet<object>): Readonly<OwnerOperationRequest> {
  const record = exactRecord(
    value,
    [
      "version",
      "kind",
      "account",
      "chainId",
      "entryPoint",
      "calls",
      "userOperation",
      "userOperationHash",
    ],
    "owner operation request",
    context,
    fail,
  );
  if (
    record.version !== OAATH_OWNER_OPERATION_REQUEST_VERSION ||
    record.kind !== "kernel-owner-operation"
  )
    return fail("owner operation request version or kind is unsupported");
  const account = captureKernelAccountProfile(record.account, context, fail);
  const existing = isKernelExistingAccountProfile(account);
  if (existing ? account.kernelVersion !== "0.4.0" : account.factoryRoute !== "kernel_factory")
    return fail(
      "owner operation account must be factory-derived or an existing Kernel 0.4.0 account",
    );
  if (
    typeof record.chainId !== "number" ||
    !Number.isSafeInteger(record.chainId) ||
    record.chainId < 1
  )
    return fail("owner operation chain is invalid");
  const entryPoint = address(record.entryPoint, "owner operation EntryPoint");
  const calls = captureCalls(record.calls, context);
  const userOperation = captureUserOperation(record.userOperation, context);
  // An existing account is already deployed: nothing may deploy it.
  if (existing && userOperation.factory !== null)
    return fail("an existing account's owner operation carries no factory");
  // Standard-mode root validation: the 192-bit key is only the uint16 lane.
  if (BigInt(userOperation.nonce) >> 80n !== 0n)
    return fail("owner operation nonce must use root validation");
  if (userOperation.callData !== encodeKernelExecution(calls))
    return fail("owner operation callData does not execute exactly its calls");
  const hash = getSigningHash(
    ownerUserOperationForCetane(userOperation),
    record.chainId,
    entryPoint,
    "0.9",
  );
  if (record.userOperationHash !== hash)
    return fail("owner operation hash contradicts its operation");
  return Object.freeze({
    version: OAATH_OWNER_OPERATION_REQUEST_VERSION,
    kind: "kernel-owner-operation",
    account,
    chainId: record.chainId,
    entryPoint,
    calls,
    userOperation,
    userOperationHash: hash,
  });
}

/** Captures one exact owner-operation request and proves its callData and hash. */
export function parseOwnerOperationRequest(value: unknown): Readonly<OwnerOperationRequest> {
  return capturedByProtocol("signing_request_invalid", "owner operation request is invalid", () =>
    captureRequest(value, new WeakSet()),
  );
}

/** Captures a signed owner operation; the signature is shape-checked, not verified. */
export function parseSignedOwnerOperation(value: unknown): Readonly<SignedOwnerOperation> {
  return capturedByProtocol("signing_request_invalid", "signed owner operation is invalid", () => {
    const context = new WeakSet<object>();
    const record = exactRecord(
      value,
      ["version", "request", "signature"],
      "signed owner operation",
      context,
      fail,
    );
    if (record.version !== OAATH_SIGNED_OWNER_OPERATION_VERSION)
      return fail("signed owner operation version is unsupported");
    const signature = bytes(record.signature, "owner operation signature", MAX_SIGNATURE_BYTES);
    if (signature === "0x") return fail("owner operation signature is empty");
    return Object.freeze({
      version: OAATH_SIGNED_OWNER_OPERATION_VERSION,
      request: captureRequest(record.request, context),
      signature,
    });
  });
}
