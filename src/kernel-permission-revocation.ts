import {
  advanceGrant,
  type ChainMaterialization,
  type ChainPermissionEvidence,
  type Grant,
  type MaterializationUnreadableReason,
  OgpGrantError,
} from "./grant.js";
import {
  type CaptureContext,
  captureRecord,
  type ExactRecord,
  exactCapturedRecord,
} from "./internal/exact-record.js";
import type { KernelPermissionRemovalObserver } from "./kernel-permission-observer.js";
import type {
  KernelPermissionUninstallDescriptor,
  LocalKernelPermissionUninstallAdapter,
} from "./local-kernel-handle-ops.js";
import { type FinalizedOperation, type Operation, parseOperation } from "./operation.js";
import type { OperationObserver } from "./operation-observer.js";
import {
  createOperationRunner,
  type OperationRunner,
  type OperationRunResult,
} from "./operation-runner.js";
import {
  GrantStore,
  type GrantStoreRecord,
  OgpStoreError,
  OperationStore,
  type OperationStoreRecord,
} from "./store.js";

const ADDRESS = /^0x[0-9a-f]{40}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const PERMISSION_ID = /^0x[0-9a-f]{8}$/u;
const VALIDATION_ID = /^0x[0-9a-f]{42}$/u;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]{0,77})$/u;
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;
const MAX_UINT256 = (1n << 256n) - 1n;
const MAX_GRANT_ID_LENGTH = 256;
const MAX_TIMEOUT_MS = 60_000;
const MAX_GRANT_CAS_ATTEMPTS = 8;

export type KernelPermissionRevocationErrorCode =
  | "kernel_permission_revocation_input_invalid"
  | "kernel_permission_revocation_capability_invalid"
  | "kernel_permission_revocation_identity_mismatch"
  | "kernel_permission_revocation_state_conflict"
  | "kernel_permission_revocation_store_unavailable"
  | "kernel_permission_revocation_store_uncertain"
  | "kernel_permission_revocation_observation_invalid"
  | "kernel_permission_revocation_closed"
  | "kernel_permission_revocation_close_failed";

export class OgpKernelPermissionRevocationError extends Error {
  readonly code: KernelPermissionRevocationErrorCode;

  constructor(code: KernelPermissionRevocationErrorCode, message: string) {
    super(message);
    this.name = "OgpKernelPermissionRevocationError";
    this.code = code;
  }
}

export interface KernelPermissionRevocationConfiguration {
  readonly grantStore: GrantStore;
  readonly operationStore: OperationStore;
  readonly operationObserver: OperationObserver;
  readonly uninstall: LocalKernelPermissionUninstallAdapter;
  readonly permissionObserver: KernelPermissionRemovalObserver;
}

export interface KernelPermissionRevocationInput {
  readonly revocationStartedAt: number;
  readonly chainRevocationStartedAt: number;
  readonly preparedAt: number;
  readonly attemptedAt: number;
  readonly submittedAt: number;
  readonly operationObservedAt: number;
  readonly permissionObservedAt: number;
  readonly timeoutMs: number;
}

type BoundResult<Status extends string, Extra extends object = object> = Readonly<
  { grant: GrantStoreRecord; operation: OperationStoreRecord; status: Status } & Extra
>;

export type KernelPermissionRevocationResult =
  | Readonly<{ status: "already_revoked"; grant: GrantStoreRecord }>
  | BoundResult<
      "submission_uncertain",
      { reason: Extract<OperationRunResult, { status: "submission_uncertain" }>["reason"] }
    >
  | BoundResult<
      "observation_unavailable",
      { reason: Extract<OperationRunResult, { status: "observation_unavailable" }>["reason"] }
    >
  | BoundResult<"state_conflict" | "operation_unresolved">
  | BoundResult<"operation_failed", { reason: "operation_reverted" | "operation_dropped" }>
  | BoundResult<"permission_present", { evidence: Readonly<ChainPermissionEvidence> }>
  | BoundResult<"permission_unreadable", { reason: MaterializationUnreadableReason }>
  | BoundResult<"revoked", { removal: Readonly<ChainPermissionEvidence> }>;

export interface KernelPermissionRevocationCoordinator {
  readonly descriptor: Readonly<KernelPermissionUninstallDescriptor>;
  readonly revoke: (input: unknown) => Promise<KernelPermissionRevocationResult>;
  readonly close: () => Promise<void>;
}

type CapturedConfiguration = Readonly<{
  grantStore: GrantStore;
  operationStore: OperationStore;
  operationObserver: Readonly<OperationObserver>;
  uninstall: Readonly<LocalKernelPermissionUninstallAdapter>;
  permissionObserver: Readonly<KernelPermissionRemovalObserver>;
}>;
type CapturedInput = Readonly<KernelPermissionRevocationInput>;
type CloseResource = { readonly close: () => Promise<unknown>; closed: boolean };

function coordinatorError(
  code: KernelPermissionRevocationErrorCode,
  message = "Kernel permission revocation failed",
): never {
  throw new OgpKernelPermissionRevocationError(code, message);
}

function captureFailure(code: KernelPermissionRevocationErrorCode): (message: string) => never {
  return (message) => coordinatorError(code, message);
}

function exact(
  value: unknown,
  keys: readonly string[],
  label: string,
  code: KernelPermissionRevocationErrorCode,
  context: CaptureContext,
): ExactRecord {
  const fail = captureFailure(code);
  return exactCapturedRecord(captureRecord(value, label, context, fail), keys, label, fail);
}

function callable(value: unknown): (...arguments_: readonly unknown[]) => Promise<unknown> {
  if (typeof value !== "function") {
    return coordinatorError("kernel_permission_revocation_capability_invalid");
  }
  return value as (...arguments_: readonly unknown[]) => Promise<unknown>;
}

function safeInteger(
  value: unknown,
  minimum = 0,
  code: KernelPermissionRevocationErrorCode = "kernel_permission_revocation_input_invalid",
): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    Object.is(value, -0) ||
    value < minimum
  ) {
    return coordinatorError(code, "Kernel permission revocation integer is invalid");
  }
  return value;
}

function address(value: unknown): `0x${string}` {
  if (typeof value !== "string" || !ADDRESS.test(value) || value === ZERO_ADDRESS) {
    return coordinatorError("kernel_permission_revocation_capability_invalid");
  }
  return value as `0x${string}`;
}

function captureDescriptor(
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
    "kernel_permission_revocation_capability_invalid",
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
    return coordinatorError("kernel_permission_revocation_capability_invalid");
  }
  return Object.freeze({
    kind: record.kind,
    grantId: record.grantId,
    chainId: safeInteger(record.chainId, 1, "kernel_permission_revocation_capability_invalid"),
    entryPoint: address(record.entryPoint),
    account: address(record.account),
    permissionId: record.permissionId as `0x${string}`,
    validationId: record.validationId as `0x${string}`,
    signer: address(record.signer),
    operator: address(record.operator),
  });
}

function captureConfiguration(value: unknown): CapturedConfiguration {
  try {
    const context: CaptureContext = new WeakSet();
    const record = exact(
      value,
      ["grantStore", "operationStore", "operationObserver", "uninstall", "permissionObserver"],
      "Kernel permission revocation configuration",
      "kernel_permission_revocation_capability_invalid",
      context,
    );
    if (
      !(record.grantStore instanceof GrantStore) ||
      !(record.operationStore instanceof OperationStore)
    ) {
      return coordinatorError("kernel_permission_revocation_capability_invalid");
    }
    const operationObserver = exact(
      record.operationObserver,
      ["observeOperation", "close"],
      "Operation observer",
      "kernel_permission_revocation_capability_invalid",
      context,
    );
    const uninstall = exact(
      record.uninstall,
      ["descriptor", "preparation", "submission"],
      "Kernel permission uninstall adapter",
      "kernel_permission_revocation_capability_invalid",
      context,
    );
    const preparation = exact(
      uninstall.preparation,
      ["prepare", "close"],
      "Kernel permission uninstall preparation",
      "kernel_permission_revocation_capability_invalid",
      context,
    );
    const submission = exact(
      uninstall.submission,
      ["openSubmission", "close"],
      "Kernel permission uninstall submission",
      "kernel_permission_revocation_capability_invalid",
      context,
    );
    const permissionObserver = exact(
      record.permissionObserver,
      ["observeRemoval", "close"],
      "Kernel permission removal observer",
      "kernel_permission_revocation_capability_invalid",
      context,
    );
    return Object.freeze({
      grantStore: record.grantStore,
      operationStore: record.operationStore,
      operationObserver: Object.freeze({
        observeOperation: callable(
          operationObserver.observeOperation,
        ) as OperationObserver["observeOperation"],
        close: callable(operationObserver.close) as OperationObserver["close"],
      }),
      uninstall: Object.freeze({
        descriptor: captureDescriptor(uninstall.descriptor, context),
        preparation: Object.freeze({
          prepare: callable(
            preparation.prepare,
          ) as LocalKernelPermissionUninstallAdapter["preparation"]["prepare"],
          close: callable(
            preparation.close,
          ) as LocalKernelPermissionUninstallAdapter["preparation"]["close"],
        }),
        submission: Object.freeze({
          openSubmission: callable(
            submission.openSubmission,
          ) as LocalKernelPermissionUninstallAdapter["submission"]["openSubmission"],
          close: callable(
            submission.close,
          ) as LocalKernelPermissionUninstallAdapter["submission"]["close"],
        }),
      }),
      permissionObserver: Object.freeze({
        observeRemoval: callable(
          permissionObserver.observeRemoval,
        ) as KernelPermissionRemovalObserver["observeRemoval"],
        close: callable(permissionObserver.close) as KernelPermissionRemovalObserver["close"],
      }),
    });
  } catch (error) {
    if (error instanceof OgpKernelPermissionRevocationError) throw error;
    return coordinatorError("kernel_permission_revocation_capability_invalid");
  }
}

function captureInput(value: unknown): CapturedInput {
  try {
    const context: CaptureContext = new WeakSet();
    const record = exact(
      value,
      [
        "revocationStartedAt",
        "chainRevocationStartedAt",
        "preparedAt",
        "attemptedAt",
        "submittedAt",
        "operationObservedAt",
        "permissionObservedAt",
        "timeoutMs",
      ],
      "Kernel permission revocation input",
      "kernel_permission_revocation_input_invalid",
      context,
    );
    const input = Object.freeze({
      revocationStartedAt: safeInteger(record.revocationStartedAt),
      chainRevocationStartedAt: safeInteger(record.chainRevocationStartedAt),
      preparedAt: safeInteger(record.preparedAt),
      attemptedAt: safeInteger(record.attemptedAt),
      submittedAt: safeInteger(record.submittedAt),
      operationObservedAt: safeInteger(record.operationObservedAt),
      permissionObservedAt: safeInteger(record.permissionObservedAt),
      timeoutMs: safeInteger(record.timeoutMs, 1),
    });
    if (
      input.revocationStartedAt > input.chainRevocationStartedAt ||
      input.chainRevocationStartedAt > input.preparedAt ||
      input.preparedAt > input.attemptedAt ||
      input.attemptedAt > input.submittedAt ||
      input.submittedAt > input.operationObservedAt ||
      input.operationObservedAt > input.permissionObservedAt ||
      input.timeoutMs > MAX_TIMEOUT_MS
    ) {
      return coordinatorError("kernel_permission_revocation_input_invalid");
    }
    return input;
  } catch (error) {
    if (error instanceof OgpKernelPermissionRevocationError) throw error;
    return coordinatorError("kernel_permission_revocation_input_invalid");
  }
}

function mapStoreError(error: unknown): never {
  if (
    error instanceof OgpStoreError &&
    (error.code === "store_commit_indeterminate" || error.code === "store_commit_unverified")
  ) {
    return coordinatorError("kernel_permission_revocation_store_uncertain");
  }
  return coordinatorError("kernel_permission_revocation_store_unavailable");
}

function transitionGrant(grant: Grant, transition: Parameters<typeof advanceGrant>[1]): Grant {
  try {
    return advanceGrant(grant, transition);
  } catch (error) {
    if (error instanceof OgpGrantError && error.code === "grant_identity_mismatch") {
      return coordinatorError("kernel_permission_revocation_identity_mismatch");
    }
    return coordinatorError("kernel_permission_revocation_state_conflict");
  }
}

function boundMaterialization(
  grant: Grant,
  descriptor: Readonly<KernelPermissionUninstallDescriptor>,
): Exclude<ChainMaterialization, { state: "unsupported" }> {
  const materialization = grant.materializations.find(
    (candidate) => candidate.chainId === descriptor.chainId,
  );
  if (!materialization || materialization.state === "unsupported") {
    return coordinatorError("kernel_permission_revocation_state_conflict");
  }
  if (
    materialization.account !== descriptor.account ||
    materialization.permissionId !== descriptor.permissionId
  ) {
    return coordinatorError("kernel_permission_revocation_identity_mismatch");
  }
  return materialization;
}

function hasInstalledEvidence(
  materialization: Exclude<ChainMaterialization, { state: "unsupported" }>,
): boolean {
  return (
    materialization.state === "installed" ||
    (materialization.state === "unreadable" &&
      materialization.priorState === "installed" &&
      materialization.installation !== null)
  );
}

async function readGrant(store: GrantStore, grantId: string): Promise<GrantStoreRecord> {
  try {
    const record = await store.get(grantId);
    if (record) return record;
    return coordinatorError("kernel_permission_revocation_state_conflict", "Grant is not durable");
  } catch (error) {
    if (error instanceof OgpKernelPermissionRevocationError) throw error;
    return mapStoreError(error);
  }
}

async function commitGrant(
  store: GrantStore,
  current: GrantStoreRecord,
  next: Grant,
): Promise<"committed" | "conflict"> {
  try {
    const result = await store.compareAndSwap({
      grantId: current.value.identity.grantId,
      expectedStoreRevision: current.storeRevision,
      next,
    });
    return result.status;
  } catch (error) {
    return mapStoreError(error);
  }
}

type RevokingGrantResult = Readonly<{
  record: GrantStoreRecord;
  alreadyRevoked: boolean;
}>;

async function ensureGrantRevoking(
  store: GrantStore,
  descriptor: Readonly<KernelPermissionUninstallDescriptor>,
  input: CapturedInput,
): Promise<RevokingGrantResult> {
  for (let attempt = 0; attempt < MAX_GRANT_CAS_ATTEMPTS; attempt += 1) {
    const current = await readGrant(store, descriptor.grantId);
    const grant = current.value;
    const materialization = boundMaterialization(grant, descriptor);
    if (grant.state === "active") {
      if (!hasInstalledEvidence(materialization)) {
        return coordinatorError("kernel_permission_revocation_state_conflict");
      }
      const next = transitionGrant(grant, {
        type: "begin_revocation",
        identity: grant.identity,
        revocationStartedAt: input.revocationStartedAt,
      });
      if ((await commitGrant(store, current, next)) === "committed") continue;
      continue;
    }
    if (grant.state !== "revoking") {
      return coordinatorError("kernel_permission_revocation_state_conflict");
    }
    if (materialization.state === "revoked") {
      return Object.freeze({ record: current, alreadyRevoked: true });
    }
    if (
      materialization.state === "revoking" ||
      (materialization.state === "unreadable" && materialization.priorState === "revoking")
    ) {
      if (materialization.installation === null) {
        return coordinatorError("kernel_permission_revocation_state_conflict");
      }
      return Object.freeze({ record: current, alreadyRevoked: false });
    }
    if (!hasInstalledEvidence(materialization)) {
      return coordinatorError("kernel_permission_revocation_state_conflict");
    }
    const next = transitionGrant(grant, {
      type: "begin_chain_revocation",
      identity: grant.identity,
      binding: {
        chainId: descriptor.chainId,
        account: descriptor.account,
        permissionId: descriptor.permissionId,
      },
      startedAt: input.chainRevocationStartedAt,
    });
    if ((await commitGrant(store, current, next)) === "committed") continue;
  }
  return coordinatorError("kernel_permission_revocation_state_conflict");
}

function sameOperation(left: Operation, right: Operation): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function requireOperationBinding(
  record: OperationStoreRecord,
  descriptor: Readonly<KernelPermissionUninstallDescriptor>,
): void {
  const identity = record.value.identity;
  if (
    identity.kind !== "revocation" ||
    identity.grantId !== descriptor.grantId ||
    identity.chainId !== descriptor.chainId ||
    identity.entryPoint !== descriptor.entryPoint ||
    identity.account !== descriptor.account
  ) {
    coordinatorError("kernel_permission_revocation_identity_mismatch");
  }
}

function uint256(value: unknown): string {
  if (typeof value !== "string" || !DECIMAL_UINT.test(value) || BigInt(value) > MAX_UINT256) {
    return coordinatorError("kernel_permission_revocation_observation_invalid");
  }
  return value;
}

function captureEvidence(
  value: unknown,
  expectedKind: "permission_present" | "permission_absent",
  descriptor: Readonly<KernelPermissionUninstallDescriptor>,
  operation: Operation,
  expectedObservedAt: number,
  context: CaptureContext,
): Readonly<ChainPermissionEvidence> {
  const record = exact(
    value,
    ["kind", "chainId", "account", "permissionId", "blockNumber", "blockHash", "observedAt"],
    "Kernel permission evidence",
    "kernel_permission_revocation_observation_invalid",
    context,
  );
  if (
    record.kind !== expectedKind ||
    record.chainId !== descriptor.chainId ||
    record.account !== descriptor.account ||
    record.permissionId !== descriptor.permissionId ||
    typeof record.blockHash !== "string" ||
    !HASH.test(record.blockHash) ||
    operation.state !== "finalized" ||
    record.blockNumber !== operation.inclusion.blockNumber ||
    record.blockHash !== operation.inclusion.blockHash ||
    record.observedAt !== expectedObservedAt
  ) {
    return coordinatorError("kernel_permission_revocation_observation_invalid");
  }
  return Object.freeze({
    kind: expectedKind,
    chainId: descriptor.chainId,
    account: descriptor.account,
    permissionId: descriptor.permissionId,
    blockNumber: uint256(record.blockNumber),
    blockHash: record.blockHash as `0x${string}`,
    observedAt: safeInteger(
      record.observedAt,
      0,
      "kernel_permission_revocation_observation_invalid",
    ),
  });
}

type CapturedRemoval =
  | Readonly<{
      status: "absent" | "present";
      evidence: Readonly<ChainPermissionEvidence>;
      operation: FinalizedOperation;
    }>
  | Readonly<{
      status: "unreadable";
      reason: MaterializationUnreadableReason;
      operation: FinalizedOperation;
    }>;

function captureRemovalResult(
  value: unknown,
  descriptor: Readonly<KernelPermissionUninstallDescriptor>,
  expectedOperation: FinalizedOperation,
  expectedObservedAt: number,
): CapturedRemoval {
  try {
    const context: CaptureContext = new WeakSet();
    const captured = captureRecord(
      value,
      "Kernel permission removal result",
      context,
      captureFailure("kernel_permission_revocation_observation_invalid"),
    );
    const status = captured.status;
    const keys =
      status === "absent" || status === "present"
        ? ["status", "evidence", "operation"]
        : ["status", "reason", "operation"];
    const record = exactCapturedRecord(
      captured,
      keys,
      "Kernel permission removal result",
      captureFailure("kernel_permission_revocation_observation_invalid"),
    );
    const operation = parseOperation(record.operation);
    if (!sameOperation(operation, expectedOperation)) {
      return coordinatorError("kernel_permission_revocation_identity_mismatch");
    }
    if (operation.state !== "finalized") {
      return coordinatorError("kernel_permission_revocation_observation_invalid");
    }
    if (status === "absent" || status === "present") {
      return Object.freeze({
        status,
        evidence: captureEvidence(
          record.evidence,
          status === "absent" ? "permission_absent" : "permission_present",
          descriptor,
          operation,
          expectedObservedAt,
          context,
        ),
        operation,
      });
    }
    if (
      status === "unreadable" &&
      (record.reason === "provider_unavailable" ||
        record.reason === "state_invalid" ||
        record.reason === "canonicality_unproven")
    ) {
      return Object.freeze({ status, reason: record.reason, operation });
    }
    return coordinatorError("kernel_permission_revocation_observation_invalid");
  } catch (error) {
    if (error instanceof OgpKernelPermissionRevocationError) throw error;
    return coordinatorError("kernel_permission_revocation_observation_invalid");
  }
}

type GrantReconciliation =
  | Readonly<{
      status: "unreadable";
      observedAt: number;
      reason: MaterializationUnreadableReason;
    }>
  | Readonly<{ status: "revoked"; removal: Readonly<ChainPermissionEvidence> }>;

async function reconcileGrant(
  store: GrantStore,
  descriptor: Readonly<KernelPermissionUninstallDescriptor>,
  reconciliation: GrantReconciliation,
): Promise<GrantStoreRecord> {
  for (let attempt = 0; attempt < MAX_GRANT_CAS_ATTEMPTS; attempt += 1) {
    const current = await readGrant(store, descriptor.grantId);
    const materialization = boundMaterialization(current.value, descriptor);
    if (current.value.state !== "revoking") {
      return coordinatorError("kernel_permission_revocation_state_conflict");
    }
    if (materialization.state === "revoked") return current;
    if (
      materialization.state !== "revoking" &&
      (materialization.state !== "unreadable" || materialization.priorState !== "revoking")
    ) {
      return coordinatorError("kernel_permission_revocation_state_conflict");
    }
    const binding = {
      chainId: descriptor.chainId,
      account: descriptor.account,
      permissionId: descriptor.permissionId,
    } as const;
    const next =
      reconciliation.status === "revoked"
        ? transitionGrant(current.value, {
            type: "record_chain_revoked",
            identity: current.value.identity,
            binding,
            removal: reconciliation.removal,
          })
        : transitionGrant(current.value, {
            type: "record_unreadable",
            identity: current.value.identity,
            binding,
            observedAt: reconciliation.observedAt,
            reason: reconciliation.reason,
          });
    if ((await commitGrant(store, current, next)) === "committed") {
      return readGrant(store, descriptor.grantId);
    }
  }
  return coordinatorError("kernel_permission_revocation_state_conflict");
}

function frozenResult<Result extends KernelPermissionRevocationResult>(result: Result): Result {
  return Object.freeze(result);
}

/**
 * Owns the durable ordering for one concrete Kernel permission uninstall.
 * Global Grant completion and non-chain cleanup effects are intentionally outside this unit.
 */
export function createKernelPermissionRevocationCoordinator(
  configurationValue: unknown,
): KernelPermissionRevocationCoordinator {
  const configuration = captureConfiguration(configurationValue);
  const descriptor = configuration.uninstall.descriptor;
  const runner: OperationRunner = createOperationRunner({
    terminalBehavior: "reuse_same_kind",
    store: configuration.operationStore,
    observer: configuration.operationObserver,
    preparation: configuration.uninstall.preparation,
    submission: configuration.uninstall.submission,
  });
  const resources: CloseResource[] = [
    { close: configuration.permissionObserver.close, closed: false },
    { close: runner.close, closed: false },
    { close: () => configuration.grantStore.close(), closed: false },
  ];
  let activeRevocations = 0;
  let drained: (() => void) | null = null;
  let closeRequested = false;
  let closed = false;
  let closing: Promise<void> | null = null;

  async function revoke(inputValue: unknown): Promise<KernelPermissionRevocationResult> {
    if (closeRequested || closed || closing) {
      return coordinatorError("kernel_permission_revocation_closed");
    }
    activeRevocations += 1;
    try {
      const input = captureInput(inputValue);
      const grantState = await ensureGrantRevoking(configuration.grantStore, descriptor, input);
      if (grantState.alreadyRevoked) {
        return frozenResult({ status: "already_revoked", grant: grantState.record });
      }

      const operationResult = await runner.runOperation({
        kind: "revocation",
        key: { grantId: descriptor.grantId, chainId: descriptor.chainId },
        preparedAt: input.preparedAt,
        attemptedAt: input.attemptedAt,
        submittedAt: input.submittedAt,
        observedAt: input.operationObservedAt,
        timeoutMs: input.timeoutMs,
      });
      requireOperationBinding(operationResult.record, descriptor);
      const common = { grant: grantState.record, operation: operationResult.record } as const;
      if (operationResult.status === "submission_uncertain") {
        return frozenResult({
          ...common,
          status: operationResult.status,
          reason: operationResult.reason,
        });
      }
      if (operationResult.status === "observation_unavailable") {
        return frozenResult({
          ...common,
          status: operationResult.status,
          reason: operationResult.reason,
        });
      }
      if (operationResult.status === "state_conflict") {
        return frozenResult({ ...common, status: operationResult.status });
      }

      const operation = operationResult.record.value;
      if (operation.state === "dropped") {
        return frozenResult({ ...common, status: "operation_failed", reason: "operation_dropped" });
      }
      if (operation.state !== "finalized") {
        return frozenResult({ ...common, status: "operation_unresolved" });
      }
      if (operation.inclusion.outcome !== "success") {
        return frozenResult({
          ...common,
          status: "operation_failed",
          reason: "operation_reverted",
        });
      }

      let removalValue: unknown;
      try {
        removalValue = await configuration.permissionObserver.observeRemoval(
          Object.freeze({
            descriptor,
            operation,
            observedAt: input.permissionObservedAt,
            timeoutMs: input.timeoutMs,
          }),
        );
      } catch {
        const grant = await reconcileGrant(configuration.grantStore, descriptor, {
          status: "unreadable",
          observedAt: input.permissionObservedAt,
          reason: "provider_unavailable",
        });
        const materialization = boundMaterialization(grant.value, descriptor);
        if (materialization.state === "revoked") {
          return frozenResult({
            status: "revoked",
            removal: materialization.removal,
            grant,
            operation: operationResult.record,
          });
        }
        return frozenResult({
          status: "permission_unreadable",
          reason: "provider_unavailable",
          grant,
          operation: operationResult.record,
        });
      }
      const removal = captureRemovalResult(
        removalValue,
        descriptor,
        operation,
        input.permissionObservedAt,
      );
      if (removal.status === "unreadable") {
        const grant = await reconcileGrant(configuration.grantStore, descriptor, {
          status: "unreadable",
          observedAt: input.permissionObservedAt,
          reason: removal.reason,
        });
        const materialization = boundMaterialization(grant.value, descriptor);
        if (materialization.state === "revoked") {
          return frozenResult({
            status: "revoked",
            removal: materialization.removal,
            grant,
            operation: operationResult.record,
          });
        }
        return frozenResult({
          status: "permission_unreadable",
          reason: removal.reason,
          grant,
          operation: operationResult.record,
        });
      }
      if (removal.status === "present") {
        return frozenResult({
          status: "permission_present",
          evidence: removal.evidence,
          ...common,
        });
      }
      const grant = await reconcileGrant(configuration.grantStore, descriptor, {
        status: "revoked",
        removal: removal.evidence,
      });
      const materialization = boundMaterialization(grant.value, descriptor);
      if (materialization.state !== "revoked") {
        return coordinatorError("kernel_permission_revocation_state_conflict");
      }
      return frozenResult({
        status: "revoked",
        removal: materialization.removal,
        grant,
        operation: operationResult.record,
      });
    } finally {
      activeRevocations -= 1;
      if (activeRevocations === 0 && drained) {
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
        if (activeRevocations > 0) {
          await new Promise<void>((resolve) => {
            drained = resolve;
          });
        }
        let failed = false;
        for (const resource of resources) {
          if (resource.closed) continue;
          try {
            await resource.close();
            resource.closed = true;
          } catch {
            failed = true;
          }
        }
        if (failed) {
          return coordinatorError("kernel_permission_revocation_close_failed");
        }
        closed = true;
      })
      .finally(() => {
        if (!closed) closing = null;
      });
    closing = attempt;
    return attempt;
  }

  return Object.freeze({ descriptor, revoke, close });
}
