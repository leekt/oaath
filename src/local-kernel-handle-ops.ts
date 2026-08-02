import { encodeCallDataEpV07 } from "@zerodev/sdk";
import { encodeFunctionData, recoverAddress } from "viem";
import {
  entryPoint07Abi,
  toPackedUserOperation,
  type UserOperation,
} from "viem/account-abstraction";
import {
  type CaptureContext,
  captureRecord,
  type ExactRecord,
  exactCapturedRecord,
} from "./internal/exact-record.js";
import type {
  OperationPreparationCapability,
  OperationSubmissionCapability,
  OperationSubmissionSession,
} from "./operation-runner.js";
import {
  type PreparedEntryPoint,
  type PreparedUserOperation,
  parsePreparedUserOperation,
  prepareUserOperation,
} from "./prepared-user-operation.js";
import type { OperationStoreKey } from "./store.js";

const ADDRESS = /^0x[0-9a-f]{40}$/u;
const BYTES = /^0x(?:[0-9a-f]{2})*$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const SIGNATURE = /^0x[0-9a-f]{130}$/u;
const VALIDATION_ID = /^0x[0-9a-f]{42}$/u;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]{0,77})$/u;
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;
const MAX_UINT120 = (1n << 120n) - 1n;
const MAX_UINT256 = (1n << 256n) - 1n;
const MAX_GRANT_ID_LENGTH = 256;

export type KernelHandleOpsAdapterErrorCode =
  | "kernel_handle_ops_input_invalid"
  | "kernel_handle_ops_capability_invalid"
  | "kernel_handle_ops_preparation_rejected"
  | "kernel_handle_ops_read_unavailable"
  | "kernel_handle_ops_signature_invalid"
  | "kernel_handle_ops_submission_ambiguous"
  | "kernel_handle_ops_result_invalid"
  | "kernel_handle_ops_identity_mismatch"
  | "kernel_handle_ops_closed"
  | "kernel_handle_ops_close_failed";

export class OgpKernelHandleOpsAdapterError extends Error {
  readonly code: KernelHandleOpsAdapterErrorCode;

  constructor(code: KernelHandleOpsAdapterErrorCode, message: string) {
    super(message);
    this.name = "OgpKernelHandleOpsAdapterError";
    this.code = code;
  }
}

export interface KernelExecutionCall {
  readonly target: `0x${string}`;
  readonly value: string;
  readonly data: `0x${string}`;
}

export interface KernelUserOperationGas {
  readonly callGasLimit: string;
  readonly verificationGasLimit: string;
  readonly preVerificationGas: string;
  readonly maxFeePerGas: string;
  readonly maxPriorityFeePerGas: string;
}

export type KernelPreparationReadRequest =
  | Readonly<{ type: "chain_id"; chainId: number }>
  | Readonly<{ type: "code"; chainId: number; address: `0x${string}` }>
  | Readonly<{
      type: "kernel_root_validator";
      chainId: number;
      account: `0x${string}`;
    }>
  | Readonly<{
      type: "kernel_ecdsa_owner";
      chainId: number;
      validator: `0x${string}`;
      account: `0x${string}`;
    }>
  | Readonly<{
      type: "entry_point_nonce";
      chainId: number;
      entryPoint: `0x${string}`;
      account: `0x${string}`;
      nonceKey: "0";
    }>;

export interface KernelPreparationReadCapability {
  readonly read: (request: KernelPreparationReadRequest) => Promise<unknown>;
  readonly close: () => Promise<void>;
}

export interface KernelEcdsaOwnerSignerCapability {
  readonly address: `0x${string}`;
  readonly signDigest: (
    request: Readonly<{
      chainId: number;
      entryPoint: `0x${string}`;
      account: `0x${string}`;
      userOperationHash: `0x${string}`;
    }>,
  ) => Promise<unknown>;
  readonly close: () => Promise<void>;
}

export interface EntryPointHandleOpsSubmitterCapability {
  readonly address: `0x${string}`;
  readonly sendHandleOps: (
    request: Readonly<{
      chainId: number;
      entryPoint: `0x${string}`;
      submitter: `0x${string}`;
      beneficiary: `0x${string}`;
      userOperationHash: `0x${string}`;
      calldata: `0x${string}`;
      gasLimit: string;
    }>,
  ) => Promise<unknown>;
  readonly close: () => Promise<void>;
}

export interface LocalKernelHandleOpsConfiguration {
  readonly profile: "kernel-v3.3-ecdsa-owner";
  readonly key: Readonly<OperationStoreKey>;
  readonly entryPoint: Readonly<PreparedEntryPoint>;
  readonly kernel: Readonly<{
    account: `0x${string}`;
    rootValidator: `0x${string}`;
    owner: `0x${string}`;
  }>;
  readonly call: Readonly<KernelExecutionCall>;
  readonly gas: Readonly<KernelUserOperationGas>;
  readonly handleOpsGasLimit: string;
  readonly preparationReads: KernelPreparationReadCapability;
  readonly userOperationSigner: KernelEcdsaOwnerSignerCapability;
  readonly handleOpsSubmitter: EntryPointHandleOpsSubmitterCapability;
}

export interface LocalKernelHandleOpsAdapter {
  readonly preparation: OperationPreparationCapability;
  readonly submission: OperationSubmissionCapability;
}

type CapturedConfiguration = Readonly<{
  key: Readonly<OperationStoreKey>;
  entryPoint: Readonly<PreparedEntryPoint>;
  kernel: Readonly<{
    account: `0x${string}`;
    rootValidator: `0x${string}`;
    owner: `0x${string}`;
  }>;
  call: Readonly<KernelExecutionCall>;
  gas: Readonly<KernelUserOperationGas>;
  handleOpsGasLimit: string;
  preparationReads: Readonly<KernelPreparationReadCapability>;
  userOperationSigner: Readonly<KernelEcdsaOwnerSignerCapability>;
  handleOpsSubmitter: Readonly<EntryPointHandleOpsSubmitterCapability>;
}>;

type CloseResource = { readonly close: () => Promise<unknown>; closed: boolean };

function adapterError(code: KernelHandleOpsAdapterErrorCode, message: string): never {
  throw new OgpKernelHandleOpsAdapterError(code, message);
}

function captureFailure(code: KernelHandleOpsAdapterErrorCode): (message: string) => never {
  return (message) => adapterError(code, message);
}

function exact(
  value: unknown,
  keys: readonly string[],
  label: string,
  code: KernelHandleOpsAdapterErrorCode,
  context: CaptureContext,
): ExactRecord {
  const fail = captureFailure(code);
  return exactCapturedRecord(captureRecord(value, label, context, fail), keys, label, fail);
}

function callable(value: unknown): (...args: unknown[]) => Promise<unknown> {
  if (typeof value !== "function") {
    return adapterError("kernel_handle_ops_capability_invalid", "adapter capability is invalid");
  }
  return value as (...args: unknown[]) => Promise<unknown>;
}

function address(value: unknown, code: KernelHandleOpsAdapterErrorCode): `0x${string}` {
  if (typeof value !== "string" || !ADDRESS.test(value) || value === ZERO_ADDRESS) {
    return adapterError(code, "adapter address is invalid");
  }
  return value as `0x${string}`;
}

function bytes(value: unknown, code: KernelHandleOpsAdapterErrorCode): `0x${string}` {
  if (typeof value !== "string" || !BYTES.test(value)) {
    return adapterError(code, "adapter bytes are invalid");
  }
  return value as `0x${string}`;
}

function uint(value: unknown, maximum: bigint, code: KernelHandleOpsAdapterErrorCode): string {
  if (typeof value !== "string" || !DECIMAL_UINT.test(value) || BigInt(value) > maximum) {
    return adapterError(code, "adapter integer is invalid");
  }
  return value;
}

function key(value: unknown, context: CaptureContext): Readonly<OperationStoreKey> {
  const record = exact(
    value,
    ["grantId", "chainId"],
    "Kernel adapter key",
    "kernel_handle_ops_capability_invalid",
    context,
  );
  if (
    typeof record.grantId !== "string" ||
    record.grantId.length < 1 ||
    record.grantId.length > MAX_GRANT_ID_LENGTH ||
    record.grantId !== record.grantId.trim() ||
    typeof record.chainId !== "number" ||
    !Number.isSafeInteger(record.chainId) ||
    record.chainId < 1
  ) {
    return adapterError("kernel_handle_ops_capability_invalid", "Kernel adapter key is invalid");
  }
  return Object.freeze({ grantId: record.grantId, chainId: record.chainId });
}

function capability(
  value: unknown,
  method: "read" | "signDigest" | "sendHandleOps",
  context: CaptureContext,
): Readonly<{
  address?: `0x${string}`;
  action: (...args: unknown[]) => Promise<unknown>;
  close: () => Promise<void>;
}> {
  const keys = method === "read" ? [method, "close"] : ["address", method, "close"];
  const record = exact(
    value,
    keys,
    "Kernel adapter capability",
    "kernel_handle_ops_capability_invalid",
    context,
  );
  const capturedAddress =
    method === "read" ? undefined : address(record.address, "kernel_handle_ops_capability_invalid");
  return Object.freeze({
    ...(capturedAddress === undefined ? {} : { address: capturedAddress }),
    action: callable(record[method]),
    close: callable(record.close) as () => Promise<void>,
  });
}

function captureConfiguration(value: unknown): CapturedConfiguration {
  try {
    const context: CaptureContext = new WeakSet();
    const record = exact(
      value,
      [
        "profile",
        "key",
        "entryPoint",
        "kernel",
        "call",
        "gas",
        "handleOpsGasLimit",
        "preparationReads",
        "userOperationSigner",
        "handleOpsSubmitter",
      ],
      "Kernel handleOps adapter configuration",
      "kernel_handle_ops_capability_invalid",
      context,
    );
    if (record.profile !== "kernel-v3.3-ecdsa-owner") {
      return adapterError(
        "kernel_handle_ops_capability_invalid",
        "Kernel adapter profile is invalid",
      );
    }
    const operationKey = key(record.key, context);
    const entryPointRecord = exact(
      record.entryPoint,
      ["version", "address"],
      "Kernel adapter EntryPoint",
      "kernel_handle_ops_capability_invalid",
      context,
    );
    if (entryPointRecord.version !== "0.7") {
      return adapterError(
        "kernel_handle_ops_capability_invalid",
        "Kernel adapter EntryPoint is invalid",
      );
    }
    const entryPoint = Object.freeze({
      version: "0.7" as const,
      address: address(entryPointRecord.address, "kernel_handle_ops_capability_invalid"),
    });
    const kernelRecord = exact(
      record.kernel,
      ["account", "rootValidator", "owner"],
      "Kernel adapter account",
      "kernel_handle_ops_capability_invalid",
      context,
    );
    const kernel = Object.freeze({
      account: address(kernelRecord.account, "kernel_handle_ops_capability_invalid"),
      rootValidator: address(kernelRecord.rootValidator, "kernel_handle_ops_capability_invalid"),
      owner: address(kernelRecord.owner, "kernel_handle_ops_capability_invalid"),
    });
    const callRecord = exact(
      record.call,
      ["target", "value", "data"],
      "Kernel adapter call",
      "kernel_handle_ops_capability_invalid",
      context,
    );
    const call = Object.freeze({
      target: address(callRecord.target, "kernel_handle_ops_capability_invalid"),
      value: uint(callRecord.value, MAX_UINT256, "kernel_handle_ops_capability_invalid"),
      data: bytes(callRecord.data, "kernel_handle_ops_capability_invalid"),
    });
    const gasRecord = exact(
      record.gas,
      [
        "callGasLimit",
        "verificationGasLimit",
        "preVerificationGas",
        "maxFeePerGas",
        "maxPriorityFeePerGas",
      ],
      "Kernel adapter gas",
      "kernel_handle_ops_capability_invalid",
      context,
    );
    const gas = Object.freeze({
      callGasLimit: uint(
        gasRecord.callGasLimit,
        MAX_UINT120,
        "kernel_handle_ops_capability_invalid",
      ),
      verificationGasLimit: uint(
        gasRecord.verificationGasLimit,
        MAX_UINT120,
        "kernel_handle_ops_capability_invalid",
      ),
      preVerificationGas: uint(
        gasRecord.preVerificationGas,
        MAX_UINT120,
        "kernel_handle_ops_capability_invalid",
      ),
      maxFeePerGas: uint(
        gasRecord.maxFeePerGas,
        MAX_UINT120,
        "kernel_handle_ops_capability_invalid",
      ),
      maxPriorityFeePerGas: uint(
        gasRecord.maxPriorityFeePerGas,
        MAX_UINT120,
        "kernel_handle_ops_capability_invalid",
      ),
    });
    if (BigInt(gas.maxPriorityFeePerGas) > BigInt(gas.maxFeePerGas)) {
      return adapterError("kernel_handle_ops_capability_invalid", "Kernel adapter gas is invalid");
    }
    const reads = capability(record.preparationReads, "read", context);
    const signer = capability(record.userOperationSigner, "signDigest", context);
    const submitter = capability(record.handleOpsSubmitter, "sendHandleOps", context);
    if (signer.address !== kernel.owner || submitter.address === kernel.owner) {
      return adapterError(
        "kernel_handle_ops_capability_invalid",
        "Kernel adapter authority is invalid",
      );
    }
    return Object.freeze({
      key: operationKey,
      entryPoint,
      kernel,
      call,
      gas,
      handleOpsGasLimit: uint(
        record.handleOpsGasLimit,
        MAX_UINT256,
        "kernel_handle_ops_capability_invalid",
      ),
      preparationReads: Object.freeze({
        read: reads.action as KernelPreparationReadCapability["read"],
        close: reads.close,
      }),
      userOperationSigner: Object.freeze({
        address: signer.address as `0x${string}`,
        signDigest: signer.action as KernelEcdsaOwnerSignerCapability["signDigest"],
        close: signer.close,
      }),
      handleOpsSubmitter: Object.freeze({
        address: submitter.address as `0x${string}`,
        sendHandleOps: submitter.action as EntryPointHandleOpsSubmitterCapability["sendHandleOps"],
        close: submitter.close,
      }),
    });
  } catch (error) {
    if (error instanceof OgpKernelHandleOpsAdapterError) throw error;
    return adapterError(
      "kernel_handle_ops_capability_invalid",
      "Kernel handleOps adapter configuration is invalid",
    );
  }
}

function sameKey(left: Readonly<OperationStoreKey>, right: Readonly<OperationStoreKey>): boolean {
  return left.grantId === right.grantId && left.chainId === right.chainId;
}

function preparedFingerprint(value: PreparedUserOperation): string {
  return JSON.stringify(value);
}

function signedUserOperation(
  prepared: PreparedUserOperation,
  signature: `0x${string}`,
): UserOperation<"0.7"> {
  const operation = prepared.userOperation;
  return {
    sender: operation.sender,
    nonce: BigInt(operation.nonce),
    callData: operation.callData,
    callGasLimit: BigInt(operation.callGasLimit),
    verificationGasLimit: BigInt(operation.verificationGasLimit),
    preVerificationGas: BigInt(operation.preVerificationGas),
    maxFeePerGas: BigInt(operation.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(operation.maxPriorityFeePerGas),
    signature,
  };
}

function capturedResult(value: unknown): ExactRecord {
  try {
    const context: CaptureContext = new WeakSet();
    return exact(
      value,
      ["chainId", "entryPoint", "submitter", "userOperationHash", "transactionHash"],
      "handleOps submission result",
      "kernel_handle_ops_result_invalid",
      context,
    );
  } catch (error) {
    if (error instanceof OgpKernelHandleOpsAdapterError) throw error;
    return adapterError("kernel_handle_ops_result_invalid", "handleOps result is invalid");
  }
}

/**
 * Creates one operation-bound Kernel 0.3.3 / EntryPoint 0.7 adapter.
 * Any positive chainId is accepted; chain support is not represented as a registry or policy.
 */
export function createLocalKernelHandleOpsAdapter(value: unknown): LocalKernelHandleOpsAdapter {
  const configuration = captureConfiguration(value);
  let latestPrepared: PreparedUserOperation | null = null;

  let preparationActive = 0;
  let preparationCloseRequested = false;
  let preparationClosed = false;
  let preparationClosing: Promise<void> | null = null;
  let preparationDrained: (() => void) | null = null;

  let submissionActive = 0;
  let submissionCloseRequested = false;
  let submissionClosed = false;
  let submissionClosing: Promise<void> | null = null;
  let submissionDrained: (() => void) | null = null;
  const sessions = new Set<{ closed: boolean; used: boolean }>();
  const submissionResources: CloseResource[] = [
    { close: configuration.userOperationSigner.close, closed: false },
    { close: configuration.handleOpsSubmitter.close, closed: false },
  ];

  function finishPreparation(): void {
    preparationActive -= 1;
    if (preparationActive === 0 && preparationDrained) {
      const resolve = preparationDrained;
      preparationDrained = null;
      resolve();
    }
  }

  function finishSubmission(): void {
    submissionActive -= 1;
    if (submissionActive === 0 && submissionDrained) {
      const resolve = submissionDrained;
      submissionDrained = null;
      resolve();
    }
  }

  async function read(request: KernelPreparationReadRequest): Promise<unknown> {
    try {
      return await configuration.preparationReads.read(Object.freeze(request));
    } catch {
      return adapterError("kernel_handle_ops_read_unavailable", "Kernel preparation read failed");
    }
  }

  async function requireCode(addressValue: `0x${string}`): Promise<void> {
    const result = await read({
      type: "code",
      chainId: configuration.key.chainId,
      address: addressValue,
    });
    if (typeof result !== "string" || !BYTES.test(result) || result === "0x") {
      return adapterError(
        "kernel_handle_ops_preparation_rejected",
        "Kernel contract code is absent",
      );
    }
  }

  async function prepare(requestValue: unknown): Promise<PreparedUserOperation> {
    if (preparationCloseRequested || preparationClosed || preparationClosing) {
      return adapterError("kernel_handle_ops_closed", "Kernel preparation is closing or closed");
    }
    preparationActive += 1;
    try {
      let request: ExactRecord;
      try {
        request = exact(
          requestValue,
          ["kind", "key"],
          "Kernel preparation request",
          "kernel_handle_ops_input_invalid",
          new WeakSet(),
        );
      } catch (error) {
        if (error instanceof OgpKernelHandleOpsAdapterError) throw error;
        return adapterError(
          "kernel_handle_ops_input_invalid",
          "Kernel preparation request is invalid",
        );
      }
      const requestKey = key(request.key, new WeakSet());
      if (request.kind !== "execution" || !sameKey(requestKey, configuration.key)) {
        return adapterError(
          "kernel_handle_ops_preparation_rejected",
          "Kernel preparation request does not match",
        );
      }

      if (
        (await read({ type: "chain_id", chainId: configuration.key.chainId })) !==
        configuration.key.chainId
      ) {
        return adapterError(
          "kernel_handle_ops_preparation_rejected",
          "Kernel chain evidence does not match",
        );
      }
      await requireCode(configuration.entryPoint.address);
      await requireCode(configuration.kernel.account);
      await requireCode(configuration.kernel.rootValidator);

      const expectedValidationId = `0x01${configuration.kernel.rootValidator.slice(2)}`;
      const validationId = await read({
        type: "kernel_root_validator",
        chainId: configuration.key.chainId,
        account: configuration.kernel.account,
      });
      if (
        typeof validationId !== "string" ||
        !VALIDATION_ID.test(validationId) ||
        validationId !== expectedValidationId
      ) {
        return adapterError(
          "kernel_handle_ops_preparation_rejected",
          "Kernel root validator does not match",
        );
      }
      const owner = await read({
        type: "kernel_ecdsa_owner",
        chainId: configuration.key.chainId,
        validator: configuration.kernel.rootValidator,
        account: configuration.kernel.account,
      });
      if (owner !== configuration.kernel.owner) {
        return adapterError(
          "kernel_handle_ops_preparation_rejected",
          "Kernel owner does not match",
        );
      }
      const nonceValue = await read({
        type: "entry_point_nonce",
        chainId: configuration.key.chainId,
        entryPoint: configuration.entryPoint.address,
        account: configuration.kernel.account,
        nonceKey: "0",
      });
      const nonce = uint(nonceValue, MAX_UINT256, "kernel_handle_ops_preparation_rejected");

      let callData: `0x${string}`;
      try {
        callData = await encodeCallDataEpV07([
          {
            to: configuration.call.target,
            value: BigInt(configuration.call.value),
            data: configuration.call.data,
          },
        ]);
      } catch {
        return adapterError(
          "kernel_handle_ops_preparation_rejected",
          "Kernel call encoding failed",
        );
      }
      const prepared = prepareUserOperation({
        kind: "execution",
        grantId: configuration.key.grantId,
        chainId: configuration.key.chainId,
        entryPoint: configuration.entryPoint,
        userOperation: {
          sender: configuration.kernel.account,
          nonce,
          callData,
          ...configuration.gas,
          factory: null,
          paymaster: null,
        },
      });
      latestPrepared = prepared;
      return prepared;
    } finally {
      finishPreparation();
    }
  }

  async function closePreparation(): Promise<void> {
    if (preparationClosed) return;
    preparationCloseRequested = true;
    if (preparationClosing) return preparationClosing;
    const attempt = Promise.resolve()
      .then(async () => {
        if (preparationActive > 0) {
          await new Promise<void>((resolve) => {
            preparationDrained = resolve;
          });
        }
        try {
          await configuration.preparationReads.close();
        } catch {
          return adapterError(
            "kernel_handle_ops_close_failed",
            "Kernel preparation cleanup is incomplete",
          );
        }
        preparationClosed = true;
      })
      .finally(() => {
        if (!preparationClosed) preparationClosing = null;
      });
    preparationClosing = attempt;
    return attempt;
  }

  async function openSubmission(
    preparedValue: PreparedUserOperation,
  ): Promise<OperationSubmissionSession> {
    if (submissionCloseRequested || submissionClosed || submissionClosing) {
      return adapterError("kernel_handle_ops_closed", "Kernel submission is closing or closed");
    }
    submissionActive += 1;
    try {
      let prepared: PreparedUserOperation;
      try {
        prepared = parsePreparedUserOperation(preparedValue);
      } catch {
        return adapterError(
          "kernel_handle_ops_identity_mismatch",
          "Prepared UserOperation is invalid",
        );
      }
      if (
        latestPrepared === null ||
        preparedFingerprint(prepared) !== preparedFingerprint(latestPrepared)
      ) {
        return adapterError(
          "kernel_handle_ops_identity_mismatch",
          "Prepared UserOperation was replaced",
        );
      }

      let signatureValue: unknown;
      try {
        signatureValue = await configuration.userOperationSigner.signDigest(
          Object.freeze({
            chainId: prepared.chainId,
            entryPoint: prepared.entryPoint.address,
            account: prepared.userOperation.sender,
            userOperationHash: prepared.userOperationHash,
          }),
        );
      } catch {
        return adapterError(
          "kernel_handle_ops_signature_invalid",
          "Kernel signature is unavailable",
        );
      }
      if (typeof signatureValue !== "string" || !SIGNATURE.test(signatureValue)) {
        return adapterError("kernel_handle_ops_signature_invalid", "Kernel signature is invalid");
      }
      const signature = signatureValue as `0x${string}`;
      let recovered: string;
      try {
        recovered = (
          await recoverAddress({ hash: prepared.userOperationHash, signature })
        ).toLowerCase();
      } catch {
        return adapterError("kernel_handle_ops_signature_invalid", "Kernel signature is invalid");
      }
      if (recovered !== configuration.kernel.owner) {
        return adapterError(
          "kernel_handle_ops_signature_invalid",
          "Kernel signature owner does not match",
        );
      }

      const calldata = encodeFunctionData({
        abi: entryPoint07Abi,
        functionName: "handleOps",
        args: [
          [toPackedUserOperation(signedUserOperation(prepared, signature))],
          configuration.handleOpsSubmitter.address,
        ],
      });
      const sessionState = { closed: false, used: false };
      sessions.add(sessionState);
      return Object.freeze({
        async submit() {
          if (
            sessionState.closed ||
            sessionState.used ||
            submissionCloseRequested ||
            submissionClosed ||
            submissionClosing
          ) {
            return adapterError(
              "kernel_handle_ops_closed",
              "Kernel submission session is unavailable",
            );
          }
          sessionState.used = true;
          submissionActive += 1;
          try {
            let resultValue: unknown;
            try {
              resultValue = await configuration.handleOpsSubmitter.sendHandleOps(
                Object.freeze({
                  chainId: prepared.chainId,
                  entryPoint: prepared.entryPoint.address,
                  submitter: configuration.handleOpsSubmitter.address,
                  beneficiary: configuration.handleOpsSubmitter.address,
                  userOperationHash: prepared.userOperationHash,
                  calldata,
                  gasLimit: configuration.handleOpsGasLimit,
                }),
              );
            } catch {
              return adapterError(
                "kernel_handle_ops_submission_ambiguous",
                "handleOps submission is ambiguous",
              );
            }
            const result = capturedResult(resultValue);
            if (
              result.chainId !== prepared.chainId ||
              result.entryPoint !== prepared.entryPoint.address ||
              result.submitter !== configuration.handleOpsSubmitter.address ||
              result.userOperationHash !== prepared.userOperationHash ||
              typeof result.transactionHash !== "string" ||
              !HASH.test(result.transactionHash)
            ) {
              return adapterError(
                "kernel_handle_ops_result_invalid",
                "handleOps result does not match",
              );
            }
            return Object.freeze({ userOperationHash: prepared.userOperationHash });
          } finally {
            finishSubmission();
          }
        },
        async close() {
          sessionState.closed = true;
          sessions.delete(sessionState);
        },
      });
    } finally {
      finishSubmission();
    }
  }

  async function closeSubmission(): Promise<void> {
    if (submissionClosed) return;
    submissionCloseRequested = true;
    if (submissionClosing) return submissionClosing;
    const attempt = Promise.resolve()
      .then(async () => {
        if (submissionActive > 0) {
          await new Promise<void>((resolve) => {
            submissionDrained = resolve;
          });
        }
        for (const session of sessions) session.closed = true;
        sessions.clear();
        let failed = false;
        for (const resource of submissionResources) {
          if (resource.closed) continue;
          try {
            await resource.close();
            resource.closed = true;
          } catch {
            failed = true;
          }
        }
        if (failed) {
          return adapterError(
            "kernel_handle_ops_close_failed",
            "Kernel submission cleanup is incomplete",
          );
        }
        submissionClosed = true;
      })
      .finally(() => {
        if (!submissionClosed) submissionClosing = null;
      });
    submissionClosing = attempt;
    return attempt;
  }

  return Object.freeze({
    preparation: Object.freeze({ prepare, close: closePreparation }),
    submission: Object.freeze({ openSubmission, close: closeSubmission }),
  });
}
