import type { ChainPermissionEvidence, MaterializationUnreadableReason } from "./grant.js";
import {
  type CaptureContext,
  captureRecord,
  type ExactRecord,
  exactCapturedRecord,
} from "./internal/exact-record.js";
import type { KernelPermissionUninstallDescriptor } from "./local-kernel-handle-ops.js";
import { type FinalizedOperation, type Operation, parseOperation } from "./operation.js";

const ADDRESS = /^0x[0-9a-f]{40}$/u;
const BYTES = /^0x(?:[0-9a-f]{2})*$/u;
const PERMISSION_ID = /^0x[0-9a-f]{8}$/u;
const VALIDATION_ID = /^0x[0-9a-f]{42}$/u;
const BYTES2 = /^0x[0-9a-f]{4}$/u;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]{0,77})$/u;
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;
const NO_HOOK_ADDRESS = `0x${"00".repeat(19)}01`;
const MAX_UINT32 = (1n << 32n) - 1n;
const MAX_GRANT_ID_LENGTH = 256;
const MAX_TIMEOUT_MS = 60_000;

export type KernelPermissionObserverErrorCode =
  | "kernel_permission_observer_input_invalid"
  | "kernel_permission_observer_capability_invalid"
  | "kernel_permission_observer_identity_mismatch"
  | "kernel_permission_observer_closed"
  | "kernel_permission_observer_close_failed";

export class OgpKernelPermissionObserverError extends Error {
  readonly code: KernelPermissionObserverErrorCode;

  constructor(code: KernelPermissionObserverErrorCode, message: string) {
    super(message);
    this.name = "OgpKernelPermissionObserverError";
    this.code = code;
  }
}

interface InclusionBlockRead {
  readonly chainId: number;
  readonly account: `0x${string}`;
  readonly blockNumber: string;
  readonly blockHash: `0x${string}`;
  readonly requireCanonical: true;
}

export type KernelPermissionStateReadRequest =
  | Readonly<{ type: "code" } & InclusionBlockRead>
  | Readonly<
      {
        type: "kernel_validation_config";
        validationId: `0x${string}`;
      } & InclusionBlockRead
    >
  | Readonly<
      {
        type: "kernel_permission_config";
        permissionId: `0x${string}`;
      } & InclusionBlockRead
    >;

export interface KernelPermissionStateReadCapability {
  /** Reads the exact requested state with EIP-1898 blockHash + requireCanonical semantics. */
  readonly read: (request: KernelPermissionStateReadRequest) => Promise<unknown>;
  readonly close: () => Promise<void>;
}

export type ObserveKernelPermissionRemovalResult =
  | Readonly<{
      status: "absent" | "present";
      evidence: Readonly<ChainPermissionEvidence>;
      operation: FinalizedOperation;
    }>
  | Readonly<{
      status: "unreadable";
      reason: MaterializationUnreadableReason;
      operation: FinalizedOperation;
    }>
  | Readonly<{
      status: "operation_unresolved";
      operation: Operation;
    }>
  | Readonly<{
      status: "operation_failed";
      reason: "operation_reverted" | "operation_dropped";
      operation: Operation;
    }>;

export interface KernelPermissionRemovalObserver {
  readonly observeRemoval: (input: unknown) => Promise<ObserveKernelPermissionRemovalResult>;
  readonly close: () => Promise<void>;
}

type CapturedCapability = Readonly<KernelPermissionStateReadCapability>;
type CapturedInput = Readonly<{
  descriptor: Readonly<KernelPermissionUninstallDescriptor>;
  operation: Operation;
  observedAt: number;
  timeoutMs: number;
}>;

class ReadFailure extends Error {}
class ReadTimeout extends Error {}

function observerError(code: KernelPermissionObserverErrorCode, message: string): never {
  throw new OgpKernelPermissionObserverError(code, message);
}

function captureFailure(code: KernelPermissionObserverErrorCode): (message: string) => never {
  return (message) => observerError(code, message);
}

function exact(
  value: unknown,
  keys: readonly string[],
  label: string,
  code: KernelPermissionObserverErrorCode,
  context: CaptureContext,
): ExactRecord {
  const fail = captureFailure(code);
  return exactCapturedRecord(captureRecord(value, label, context, fail), keys, label, fail);
}

function callable(value: unknown): (...args: unknown[]) => Promise<unknown> {
  if (typeof value !== "function") {
    return observerError(
      "kernel_permission_observer_capability_invalid",
      "permission observer capability is invalid",
    );
  }
  return value as (...args: unknown[]) => Promise<unknown>;
}

function captureCapability(value: unknown): CapturedCapability {
  try {
    const record = exact(
      value,
      ["read", "close"],
      "Kernel permission observer capability",
      "kernel_permission_observer_capability_invalid",
      new WeakSet(),
    );
    return Object.freeze({
      read: callable(record.read) as KernelPermissionStateReadCapability["read"],
      close: callable(record.close) as KernelPermissionStateReadCapability["close"],
    });
  } catch (error) {
    if (error instanceof OgpKernelPermissionObserverError) throw error;
    return observerError(
      "kernel_permission_observer_capability_invalid",
      "Kernel permission observer capability is invalid",
    );
  }
}

function safeInteger(value: unknown, minimum = 0): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    Object.is(value, -0) ||
    value < minimum
  ) {
    return observerError(
      "kernel_permission_observer_input_invalid",
      "permission observer integer is invalid",
    );
  }
  return value;
}

function address(value: unknown, allowZero = false): `0x${string}` {
  if (typeof value !== "string" || !ADDRESS.test(value) || (!allowZero && value === ZERO_ADDRESS)) {
    return observerError(
      "kernel_permission_observer_input_invalid",
      "permission observer address is invalid",
    );
  }
  return value as `0x${string}`;
}

function descriptor(
  value: unknown,
  context: CaptureContext,
): Readonly<KernelPermissionUninstallDescriptor> {
  const record = exact(
    value,
    [
      "kind",
      "grantId",
      "chainId",
      "entryPoint",
      "account",
      "permissionId",
      "validationId",
      "signer",
      "operator",
    ],
    "Kernel permission uninstall descriptor",
    "kernel_permission_observer_input_invalid",
    context,
  );
  if (
    record.kind !== "kernel-v3.3-permission-uninstall" ||
    typeof record.grantId !== "string" ||
    record.grantId.length < 1 ||
    record.grantId.length > MAX_GRANT_ID_LENGTH ||
    record.grantId !== record.grantId.trim() ||
    typeof record.permissionId !== "string" ||
    !PERMISSION_ID.test(record.permissionId) ||
    typeof record.validationId !== "string" ||
    !VALIDATION_ID.test(record.validationId) ||
    record.validationId !== `0x02${record.permissionId.slice(2)}${"00".repeat(16)}`
  ) {
    return observerError(
      "kernel_permission_observer_input_invalid",
      "permission observer descriptor is invalid",
    );
  }
  return Object.freeze({
    kind: record.kind,
    grantId: record.grantId,
    chainId: safeInteger(record.chainId, 1),
    entryPoint: address(record.entryPoint),
    account: address(record.account),
    permissionId: record.permissionId as `0x${string}`,
    validationId: record.validationId as `0x${string}`,
    signer: address(record.signer),
    operator: address(record.operator),
  });
}

function captureInput(value: unknown): CapturedInput {
  try {
    const context: CaptureContext = new WeakSet();
    const record = exact(
      value,
      ["descriptor", "operation", "observedAt", "timeoutMs"],
      "Kernel permission removal observation",
      "kernel_permission_observer_input_invalid",
      context,
    );
    const operation = parseOperation(record.operation);
    const observedAt = safeInteger(record.observedAt);
    const timeoutMs = safeInteger(record.timeoutMs, 1);
    if (observedAt < operation.updatedAt || timeoutMs > MAX_TIMEOUT_MS) {
      return observerError(
        "kernel_permission_observer_input_invalid",
        "permission observer timing is invalid",
      );
    }
    return Object.freeze({
      descriptor: descriptor(record.descriptor, context),
      operation,
      observedAt,
      timeoutMs,
    });
  } catch (error) {
    if (error instanceof OgpKernelPermissionObserverError) throw error;
    return observerError(
      "kernel_permission_observer_input_invalid",
      "Kernel permission removal observation is invalid",
    );
  }
}

function requireIdentity(input: CapturedInput): void {
  const identity = input.operation.identity;
  const expected = input.descriptor;
  if (
    identity.kind !== "revocation" ||
    identity.grantId !== expected.grantId ||
    identity.chainId !== expected.chainId ||
    identity.entryPoint !== expected.entryPoint ||
    identity.account !== expected.account
  ) {
    observerError(
      "kernel_permission_observer_identity_mismatch",
      "permission observer Operation identity does not match",
    );
  }
}

type EvidenceCapture =
  | Readonly<{ status: "ok"; record: ExactRecord }>
  | Readonly<{ status: "unreadable"; reason: MaterializationUnreadableReason }>;

function captureEvidence(
  value: unknown,
  keys: readonly string[],
  input: CapturedInput,
): EvidenceCapture {
  let record: ExactRecord;
  try {
    record = exact(
      value,
      keys,
      "Kernel permission state evidence",
      "kernel_permission_observer_input_invalid",
      new WeakSet(),
    );
  } catch {
    return Object.freeze({ status: "unreadable", reason: "state_invalid" });
  }
  const inclusion = input.operation.state === "finalized" ? input.operation.inclusion : null;
  if (!inclusion) return Object.freeze({ status: "unreadable", reason: "state_invalid" });
  if (
    record.blockNumber !== inclusion.blockNumber ||
    record.blockHash !== inclusion.blockHash ||
    record.requireCanonical !== true
  ) {
    return Object.freeze({ status: "unreadable", reason: "canonicality_unproven" });
  }
  if (record.chainId !== input.descriptor.chainId || record.account !== input.descriptor.account) {
    return Object.freeze({ status: "unreadable", reason: "state_invalid" });
  }
  return Object.freeze({ status: "ok", record });
}

function uint32(value: unknown): boolean {
  return typeof value === "string" && DECIMAL_UINT.test(value) && BigInt(value) <= MAX_UINT32;
}

function frozen<Result extends ObserveKernelPermissionRemovalResult>(result: Result): Result {
  return Object.freeze(result);
}

export function createKernelPermissionRemovalObserver(
  capabilityValue: unknown,
): KernelPermissionRemovalObserver {
  const capability = captureCapability(capabilityValue);
  let active = 0;
  let drained: (() => void) | null = null;
  let closeRequested = false;
  let closed = false;
  let closing: Promise<void> | null = null;

  async function observeRemoval(
    inputValue: unknown,
  ): Promise<ObserveKernelPermissionRemovalResult> {
    if (closeRequested || closed || closing) {
      return observerError(
        "kernel_permission_observer_closed",
        "Kernel permission observer is closing or closed",
      );
    }
    active += 1;
    try {
      const input = captureInput(inputValue);
      requireIdentity(input);
      if (input.operation.state === "dropped") {
        return frozen({
          status: "operation_failed",
          reason: "operation_dropped",
          operation: input.operation,
        });
      }
      if (input.operation.state !== "finalized") {
        return frozen({ status: "operation_unresolved", operation: input.operation });
      }
      if (input.operation.inclusion.outcome !== "success") {
        return frozen({
          status: "operation_failed",
          reason: "operation_reverted",
          operation: input.operation,
        });
      }

      const inclusion = input.operation.inclusion;
      const common = {
        chainId: input.descriptor.chainId,
        account: input.descriptor.account,
        blockNumber: inclusion.blockNumber,
        blockHash: inclusion.blockHash,
        requireCanonical: true as const,
      };
      const deadline = Date.now() + input.timeoutMs;
      async function read(request: KernelPermissionStateReadRequest): Promise<unknown> {
        const remaining = deadline - Date.now();
        if (remaining <= 0) throw new ReadTimeout();
        let timer: ReturnType<typeof setTimeout> | undefined;
        try {
          return await Promise.race([
            Promise.resolve().then(() => capability.read(Object.freeze(request))),
            new Promise<never>((_, reject) => {
              timer = setTimeout(() => reject(new ReadTimeout()), remaining);
            }),
          ]);
        } catch (error) {
          if (error instanceof ReadTimeout) throw error;
          throw new ReadFailure();
        } finally {
          if (timer !== undefined) clearTimeout(timer);
        }
      }

      let codeValue: unknown;
      let validationValue: unknown;
      let permissionValue: unknown;
      try {
        codeValue = await read(Object.freeze({ type: "code", ...common }));
        validationValue = await read(
          Object.freeze({
            type: "kernel_validation_config",
            ...common,
            validationId: input.descriptor.validationId,
          }),
        );
        permissionValue = await read(
          Object.freeze({
            type: "kernel_permission_config",
            ...common,
            permissionId: input.descriptor.permissionId,
          }),
        );
      } catch {
        return frozen({
          status: "unreadable",
          reason: "provider_unavailable",
          operation: input.operation,
        });
      }

      const code = captureEvidence(
        codeValue,
        ["chainId", "account", "blockNumber", "blockHash", "requireCanonical", "code"],
        input,
      );
      if (code.status === "unreadable") {
        return frozen({ ...code, operation: input.operation });
      }
      if (
        typeof code.record.code !== "string" ||
        !BYTES.test(code.record.code) ||
        code.record.code === "0x"
      ) {
        return frozen({
          status: "unreadable",
          reason: "state_invalid",
          operation: input.operation,
        });
      }

      const validation = captureEvidence(
        validationValue,
        [
          "chainId",
          "account",
          "validationId",
          "blockNumber",
          "blockHash",
          "requireCanonical",
          "nonce",
          "hook",
        ],
        input,
      );
      if (validation.status === "unreadable") {
        return frozen({ ...validation, operation: input.operation });
      }
      if (
        validation.record.validationId !== input.descriptor.validationId ||
        !uint32(validation.record.nonce) ||
        typeof validation.record.hook !== "string" ||
        !ADDRESS.test(validation.record.hook)
      ) {
        return frozen({
          status: "unreadable",
          reason: "state_invalid",
          operation: input.operation,
        });
      }

      const permission = captureEvidence(
        permissionValue,
        [
          "chainId",
          "account",
          "permissionId",
          "blockNumber",
          "blockHash",
          "requireCanonical",
          "permissionFlag",
          "signer",
          "policyCount",
        ],
        input,
      );
      if (permission.status === "unreadable") {
        return frozen({ ...permission, operation: input.operation });
      }
      if (
        permission.record.permissionId !== input.descriptor.permissionId ||
        typeof permission.record.permissionFlag !== "string" ||
        !BYTES2.test(permission.record.permissionFlag) ||
        typeof permission.record.signer !== "string" ||
        !ADDRESS.test(permission.record.signer) ||
        typeof permission.record.policyCount !== "number" ||
        !Number.isSafeInteger(permission.record.policyCount) ||
        Object.is(permission.record.policyCount, -0) ||
        permission.record.policyCount < 0
      ) {
        return frozen({
          status: "unreadable",
          reason: "state_invalid",
          operation: input.operation,
        });
      }

      const validationAbsent = validation.record.hook === ZERO_ADDRESS;
      const permissionAbsent =
        permission.record.permissionFlag === "0x0000" &&
        permission.record.signer === ZERO_ADDRESS &&
        permission.record.policyCount === 0;
      const validationPresent = validation.record.hook === NO_HOOK_ADDRESS;
      const permissionPresent =
        permission.record.permissionFlag === "0x0000" &&
        permission.record.signer === input.descriptor.signer &&
        permission.record.policyCount === 0;
      if ((!validationAbsent || !permissionAbsent) && (!validationPresent || !permissionPresent)) {
        return frozen({
          status: "unreadable",
          reason: "state_invalid",
          operation: input.operation,
        });
      }
      const status = validationAbsent ? "absent" : "present";
      const evidence = Object.freeze({
        kind: status === "absent" ? "permission_absent" : "permission_present",
        chainId: input.descriptor.chainId,
        account: input.descriptor.account,
        permissionId: input.descriptor.permissionId,
        blockNumber: inclusion.blockNumber,
        blockHash: inclusion.blockHash,
        observedAt: input.observedAt,
      }) as Readonly<ChainPermissionEvidence>;
      return frozen({ status, evidence, operation: input.operation });
    } finally {
      active -= 1;
      if (active === 0 && drained) {
        const resolve = drained;
        drained = null;
        resolve();
      }
    }
  }

  async function close(): Promise<void> {
    if (closed) return;
    closeRequested = true;
    if (closing) return closing;
    const attempt = Promise.resolve()
      .then(async () => {
        if (active > 0) {
          await new Promise<void>((resolve) => {
            drained = resolve;
          });
        }
        try {
          await capability.close();
        } catch {
          return observerError(
            "kernel_permission_observer_close_failed",
            "Kernel permission observer cleanup is incomplete",
          );
        }
        closed = true;
      })
      .finally(() => {
        if (!closed) closing = null;
      });
    closing = attempt;
    return attempt;
  }

  return Object.freeze({ observeRemoval, close });
}
