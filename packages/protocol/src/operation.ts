import {
  type CaptureContext,
  captureRecord as captureExactRecord,
  type ExactRecord,
  exactCapturedRecord as exactCapturedRecordValue,
  exactRecord as exactRecordValue,
} from "./internal/exact-record.js";

export const OAATH_OPERATION_RECORD_VERSION = "oaath.operation/v1" as const;

const ADDRESS = /^0x[0-9a-f]{40}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]{0,77})$/u;
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;
const MAX_UINT256 = (1n << 256n) - 1n;
const MAX_GRANT_ID_LENGTH = 256;

export type OperationErrorCode =
  | "operation_input_invalid"
  | "operation_record_invalid"
  | "operation_transition_invalid"
  | "operation_identity_mismatch"
  | "operation_transition_forbidden"
  | "operation_revision_exhausted";

export class OaathOperationError extends Error {
  readonly code: OperationErrorCode;

  constructor(code: OperationErrorCode, message: string) {
    super(message);
    this.name = "OaathOperationError";
    this.code = code;
  }
}

export type OperationKind = "execution" | "revocation";
export type OperationOutcome = "success" | "reverted";

export interface UserOperationReference {
  readonly chainId: number;
  readonly entryPoint: `0x${string}`;
  readonly account: `0x${string}`;
  /** Canonical decimal uint256 string. */
  readonly nonce: string;
  readonly userOperationHash: `0x${string}`;
}

export interface OperationIdentity extends UserOperationReference {
  readonly kind: OperationKind;
  readonly grantId: string;
}

export type OperationWeakObservation =
  | Readonly<{
      status: "pending";
      observedAt: number;
      reason: "receipt_missing" | "timeout";
    }>
  | Readonly<{
      status: "unreadable";
      observedAt: number;
      reason:
        | "provider_unavailable"
        | "receipt_invalid"
        | "canonicality_unproven"
        | "finality_unproven";
    }>;

export interface OperationInclusion {
  readonly transactionHash: `0x${string}`;
  readonly blockNumber: string;
  readonly blockHash: `0x${string}`;
  readonly outcome: OperationOutcome;
  readonly observedAt: number;
}

export interface OperationFinality {
  readonly blockNumber: string;
  readonly blockHash: `0x${string}`;
  readonly observedAt: number;
}

export interface OperationDropEvidence {
  readonly kind: "finalized_nonce_replacement";
  readonly replacement: Readonly<{
    identity: Readonly<UserOperationReference>;
    inclusion: Readonly<OperationInclusion>;
    finality: Readonly<OperationFinality>;
  }>;
}

interface OperationCommon {
  readonly version: typeof OAATH_OPERATION_RECORD_VERSION;
  readonly identity: Readonly<OperationIdentity>;
  readonly revision: number;
  readonly preparedAt: number;
  readonly updatedAt: number;
  readonly observation: OperationWeakObservation | null;
}

export interface PreparedOperation extends OperationCommon {
  readonly state: "prepared";
}

export interface SubmissionAttemptedOperation extends OperationCommon {
  readonly state: "submission_attempted";
  readonly attemptedAt: number;
}

export interface SubmittedOperation extends OperationCommon {
  readonly state: "submitted";
  readonly attemptedAt: number;
  readonly submittedAt: number;
}

export interface IncludedOperation extends OperationCommon {
  readonly state: "included";
  readonly attemptedAt: number;
  /** Null when authoritative observation preceded adapter acknowledgement. */
  readonly submittedAt: number | null;
  readonly inclusion: Readonly<OperationInclusion>;
}

export interface FinalizedOperation extends OperationCommon {
  readonly state: "finalized";
  readonly attemptedAt: number;
  readonly submittedAt: number | null;
  readonly inclusion: Readonly<OperationInclusion>;
  readonly finality: Readonly<OperationFinality>;
  readonly observation: null;
}

export interface DroppedOperation extends OperationCommon {
  readonly state: "dropped";
  readonly attemptedAt: number;
  readonly submittedAt: number | null;
  readonly priorInclusion: Readonly<OperationInclusion> | null;
  readonly drop: Readonly<OperationDropEvidence>;
  readonly observation: null;
}

export type Operation =
  | PreparedOperation
  | SubmissionAttemptedOperation
  | SubmittedOperation
  | IncludedOperation
  | FinalizedOperation
  | DroppedOperation;

export type OperationTransition =
  | Readonly<{
      type: "mark_submission_attempted";
      identity: OperationIdentity;
      attemptedAt: number;
    }>
  | Readonly<{
      type: "mark_submitted";
      identity: OperationIdentity;
      returnedUserOperationHash: string;
      submittedAt: number;
    }>;

export type VerifiedOperationObservationTransition =
  | Readonly<{
      type: "record_pending";
      identity: OperationIdentity;
      observedAt: number;
      reason: "receipt_missing" | "timeout";
    }>
  | Readonly<{
      type: "record_unreadable";
      identity: OperationIdentity;
      observedAt: number;
      reason:
        | "provider_unavailable"
        | "receipt_invalid"
        | "canonicality_unproven"
        | "finality_unproven";
    }>
  | Readonly<{
      type: "record_included";
      identity: OperationIdentity;
      inclusion: OperationInclusion;
    }>
  | Readonly<{
      type: "record_finalized";
      identity: OperationIdentity;
      finality: OperationFinality;
    }>
  | Readonly<{
      type: "record_dropped";
      identity: OperationIdentity;
      drop: OperationDropEvidence;
    }>;

type InternalOperationTransition = OperationTransition | VerifiedOperationObservationTransition;

type PlainRecord = ExactRecord;

function invalid(code: OperationErrorCode, message: string): never {
  throw new OaathOperationError(code, message);
}

function captureFailure(code: OperationErrorCode): (message: string) => never {
  return (message) => invalid(code, message);
}

function captureRecord(
  value: unknown,
  label: string,
  code: OperationErrorCode,
  context: CaptureContext,
): PlainRecord {
  return captureExactRecord(value, label, context, captureFailure(code));
}

function exactCapturedRecord(
  captured: PlainRecord,
  keys: readonly string[],
  label: string,
  code: OperationErrorCode,
): PlainRecord {
  return exactCapturedRecordValue(captured, keys, label, captureFailure(code));
}

function exactRecord(
  value: unknown,
  keys: readonly string[],
  label: string,
  code: OperationErrorCode,
  context: CaptureContext,
): PlainRecord {
  return exactRecordValue(value, keys, label, context, captureFailure(code));
}

function safeInteger(value: unknown, label: string, code: OperationErrorCode, minimum = 0): number {
  if (!Number.isSafeInteger(value) || Object.is(value, -0) || (value as number) < minimum) {
    return invalid(code, `${label} must be a safe integer at least ${minimum}`);
  }
  return value as number;
}

function canonicalGrantId(value: unknown, code: OperationErrorCode): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > MAX_GRANT_ID_LENGTH ||
    value !== value.trim()
  ) {
    return invalid(code, "operation identity grantId must be a bounded canonical string");
  }
  return value;
}

function address(value: unknown, label: string, code: OperationErrorCode): `0x${string}` {
  if (typeof value !== "string" || !ADDRESS.test(value) || value === ZERO_ADDRESS) {
    return invalid(code, `${label} must be a nonzero lowercase 20-byte address`);
  }
  return value as `0x${string}`;
}

function hash(value: unknown, label: string, code: OperationErrorCode): `0x${string}` {
  if (typeof value !== "string" || !HASH.test(value)) {
    return invalid(code, `${label} must be a lowercase 32-byte hash`);
  }
  return value as `0x${string}`;
}

function uint256(value: unknown, label: string, code: OperationErrorCode): string {
  if (typeof value !== "string" || !DECIMAL_UINT.test(value) || BigInt(value) > MAX_UINT256) {
    return invalid(code, `${label} must be a canonical decimal uint256 string`);
  }
  return value;
}

function parseIdentity(
  value: unknown,
  code: OperationErrorCode,
  context: CaptureContext,
): Readonly<OperationIdentity> {
  const record = exactRecord(
    value,
    ["kind", "grantId", "chainId", "entryPoint", "account", "nonce", "userOperationHash"],
    "operation identity",
    code,
    context,
  );
  if (record.kind !== "execution" && record.kind !== "revocation") {
    return invalid(code, "operation identity kind is unsupported");
  }
  return Object.freeze({
    kind: record.kind,
    grantId: canonicalGrantId(record.grantId, code),
    chainId: safeInteger(record.chainId, "operation identity chainId", code, 1),
    entryPoint: address(record.entryPoint, "operation identity entryPoint", code),
    account: address(record.account, "operation identity account", code),
    nonce: uint256(record.nonce, "operation identity nonce", code),
    userOperationHash: hash(record.userOperationHash, "operation identity userOperationHash", code),
  });
}

function parseUserOperationReference(
  value: unknown,
  code: OperationErrorCode,
  context: CaptureContext,
): Readonly<UserOperationReference> {
  const record = exactRecord(
    value,
    ["chainId", "entryPoint", "account", "nonce", "userOperationHash"],
    "UserOperation reference",
    code,
    context,
  );
  return Object.freeze({
    chainId: safeInteger(record.chainId, "UserOperation reference chainId", code, 1),
    entryPoint: address(record.entryPoint, "UserOperation reference entryPoint", code),
    account: address(record.account, "UserOperation reference account", code),
    nonce: uint256(record.nonce, "UserOperation reference nonce", code),
    userOperationHash: hash(
      record.userOperationHash,
      "UserOperation reference userOperationHash",
      code,
    ),
  });
}

function parseWeakObservation(
  value: unknown,
  code: OperationErrorCode,
  context: CaptureContext,
): OperationWeakObservation | null {
  if (value === null) return null;
  const captured = captureRecord(value, "operation observation", code, context);
  const status = captured.status;
  const record = exactCapturedRecord(
    captured,
    ["status", "observedAt", "reason"],
    "operation observation",
    code,
  );
  const observedAt = safeInteger(record.observedAt, "operation observation observedAt", code);
  if (status === "pending") {
    if (record.reason !== "receipt_missing" && record.reason !== "timeout") {
      return invalid(code, "pending operation observation reason is unsupported");
    }
    return Object.freeze({ status, observedAt, reason: record.reason });
  }
  if (status === "unreadable") {
    if (
      record.reason !== "provider_unavailable" &&
      record.reason !== "receipt_invalid" &&
      record.reason !== "canonicality_unproven" &&
      record.reason !== "finality_unproven"
    ) {
      return invalid(code, "unreadable operation observation reason is unsupported");
    }
    return Object.freeze({ status, observedAt, reason: record.reason });
  }
  return invalid(code, "operation observation status is unsupported");
}

function parseInclusion(
  value: unknown,
  code: OperationErrorCode,
  context: CaptureContext,
): Readonly<OperationInclusion> {
  const record = exactRecord(
    value,
    ["transactionHash", "blockNumber", "blockHash", "outcome", "observedAt"],
    "operation inclusion",
    code,
    context,
  );
  if (record.outcome !== "success" && record.outcome !== "reverted") {
    return invalid(code, "operation inclusion outcome is unsupported");
  }
  return Object.freeze({
    transactionHash: hash(record.transactionHash, "operation inclusion transactionHash", code),
    blockNumber: uint256(record.blockNumber, "operation inclusion blockNumber", code),
    blockHash: hash(record.blockHash, "operation inclusion blockHash", code),
    outcome: record.outcome,
    observedAt: safeInteger(record.observedAt, "operation inclusion observedAt", code),
  });
}

function parseFinality(
  value: unknown,
  code: OperationErrorCode,
  context: CaptureContext,
): Readonly<OperationFinality> {
  const record = exactRecord(
    value,
    ["blockNumber", "blockHash", "observedAt"],
    "operation finality",
    code,
    context,
  );
  return Object.freeze({
    blockNumber: uint256(record.blockNumber, "operation finality blockNumber", code),
    blockHash: hash(record.blockHash, "operation finality blockHash", code),
    observedAt: safeInteger(record.observedAt, "operation finality observedAt", code),
  });
}

function parseDrop(
  value: unknown,
  identity: OperationIdentity,
  code: OperationErrorCode,
  context: CaptureContext,
): Readonly<OperationDropEvidence> {
  const record = exactRecord(
    value,
    ["kind", "replacement"],
    "operation drop evidence",
    code,
    context,
  );
  if (record.kind !== "finalized_nonce_replacement") {
    return invalid(code, "operation drop evidence kind is unsupported");
  }
  const replacementRecord = exactRecord(
    record.replacement,
    ["identity", "inclusion", "finality"],
    "operation drop replacement",
    code,
    context,
  );
  const replacementIdentity = parseUserOperationReference(
    replacementRecord.identity,
    code,
    context,
  );
  if (
    replacementIdentity.chainId !== identity.chainId ||
    replacementIdentity.entryPoint !== identity.entryPoint ||
    replacementIdentity.account !== identity.account ||
    replacementIdentity.nonce !== identity.nonce ||
    replacementIdentity.userOperationHash === identity.userOperationHash
  ) {
    return invalid(code, "operation drop replacement does not identify a distinct same-lane op");
  }
  const inclusion = parseInclusion(replacementRecord.inclusion, code, context);
  const finality = parseFinality(replacementRecord.finality, code, context);
  if (
    finality.observedAt < inclusion.observedAt ||
    BigInt(finality.blockNumber) < BigInt(inclusion.blockNumber) ||
    (finality.blockNumber === inclusion.blockNumber && finality.blockHash !== inclusion.blockHash)
  ) {
    return invalid(code, "operation drop replacement finality contradicts inclusion");
  }
  const replacement = Object.freeze({
    identity: replacementIdentity,
    inclusion,
    finality,
  });
  return Object.freeze({
    kind: record.kind,
    replacement,
  });
}

function parseNullableTime(value: unknown, label: string, code: OperationErrorCode): number | null {
  return value === null ? null : safeInteger(value, label, code);
}

function parseNullableInclusion(
  value: unknown,
  code: OperationErrorCode,
  context: CaptureContext,
): Readonly<OperationInclusion> | null {
  return value === null ? null : parseInclusion(value, code, context);
}

function assertTimeOrder(condition: boolean, label: string, code: OperationErrorCode): void {
  if (!condition) invalid(code, `${label} is chronologically contradictory`);
}

function baseRecord(record: PlainRecord, code: OperationErrorCode, context: CaptureContext) {
  if (record.version !== OAATH_OPERATION_RECORD_VERSION) {
    return invalid(code, "operation record version is unsupported");
  }
  return {
    version: OAATH_OPERATION_RECORD_VERSION,
    identity: parseIdentity(record.identity, code, context),
    revision: safeInteger(record.revision, "operation revision", code),
    preparedAt: safeInteger(record.preparedAt, "operation preparedAt", code),
    updatedAt: safeInteger(record.updatedAt, "operation updatedAt", code),
    observation: parseWeakObservation(record.observation, code, context),
  } as const;
}

function parseOperationUnsafe(value: unknown, context: CaptureContext): Operation {
  const code = "operation_record_invalid" as const;
  const captured = captureRecord(value, "operation record", code, context);
  const state = captured.state;
  const commonKeys = [
    "version",
    "identity",
    "revision",
    "state",
    "preparedAt",
    "updatedAt",
    "observation",
  ] as const;

  if (state === "prepared") {
    const record = exactCapturedRecord(captured, commonKeys, "prepared operation record", code);
    const base = baseRecord(record, code, context);
    assertTimeOrder(base.revision === 0, "prepared operation revision", code);
    assertTimeOrder(base.updatedAt === base.preparedAt, "prepared operation time", code);
    assertTimeOrder(base.observation === null, "prepared operation observation", code);
    return Object.freeze({ ...base, state });
  }

  if (state === "submission_attempted") {
    const record = exactCapturedRecord(
      captured,
      [...commonKeys, "attemptedAt"],
      "attempted operation record",
      code,
    );
    const base = baseRecord(record, code, context);
    const attemptedAt = safeInteger(record.attemptedAt, "operation attemptedAt", code);
    assertTimeOrder(
      attemptedAt >= base.preparedAt && attemptedAt <= base.updatedAt,
      "attempted operation time",
      code,
    );
    if (base.observation) {
      assertTimeOrder(base.revision >= 2, "observed attempted operation revision", code);
      assertTimeOrder(
        base.observation.observedAt === base.updatedAt &&
          base.observation.observedAt >= attemptedAt,
        "attempted operation observation",
        code,
      );
    } else {
      assertTimeOrder(base.revision === 1, "attempted operation revision", code);
      assertTimeOrder(base.updatedAt === attemptedAt, "attempted operation update", code);
    }
    return Object.freeze({ ...base, state, attemptedAt });
  }

  if (state === "submitted") {
    const record = exactCapturedRecord(
      captured,
      [...commonKeys, "attemptedAt", "submittedAt"],
      "submitted operation record",
      code,
    );
    const base = baseRecord(record, code, context);
    const attemptedAt = safeInteger(record.attemptedAt, "operation attemptedAt", code);
    const submittedAt = safeInteger(record.submittedAt, "operation submittedAt", code);
    assertTimeOrder(
      base.revision >= (base.observation === null ? 2 : 3),
      "submitted operation revision",
      code,
    );
    assertTimeOrder(
      attemptedAt >= base.preparedAt && submittedAt >= attemptedAt && submittedAt <= base.updatedAt,
      "submitted operation time",
      code,
    );
    if (base.observation) {
      assertTimeOrder(
        base.observation.observedAt === base.updatedAt &&
          base.observation.observedAt >= submittedAt,
        "submitted operation observation",
        code,
      );
    } else {
      assertTimeOrder(base.updatedAt === submittedAt, "submitted operation update", code);
    }
    return Object.freeze({ ...base, state, attemptedAt, submittedAt });
  }

  if (state === "included") {
    const record = exactCapturedRecord(
      captured,
      [...commonKeys, "attemptedAt", "submittedAt", "inclusion"],
      "included operation record",
      code,
    );
    const base = baseRecord(record, code, context);
    const attemptedAt = safeInteger(record.attemptedAt, "operation attemptedAt", code);
    const submittedAt = parseNullableTime(record.submittedAt, "operation submittedAt", code);
    const inclusion = parseInclusion(record.inclusion, code, context);
    const minimumRevision =
      2 + (submittedAt === null ? 0 : 1) + (base.observation === null ? 0 : 1);
    assertTimeOrder(base.revision >= minimumRevision, "included operation revision", code);
    assertTimeOrder(
      attemptedAt >= base.preparedAt &&
        (submittedAt === null || submittedAt >= attemptedAt) &&
        inclusion.observedAt >= (submittedAt ?? attemptedAt) &&
        inclusion.observedAt <= base.updatedAt,
      "included operation time",
      code,
    );
    if (base.observation) {
      assertTimeOrder(
        base.observation.observedAt === base.updatedAt &&
          base.observation.observedAt >= inclusion.observedAt,
        "included operation observation",
        code,
      );
    } else {
      assertTimeOrder(base.updatedAt === inclusion.observedAt, "included operation update", code);
    }
    return Object.freeze({ ...base, state, attemptedAt, submittedAt, inclusion });
  }

  if (state === "finalized") {
    const record = exactCapturedRecord(
      captured,
      [...commonKeys, "attemptedAt", "submittedAt", "inclusion", "finality"],
      "finalized operation record",
      code,
    );
    const base = baseRecord(record, code, context);
    const attemptedAt = safeInteger(record.attemptedAt, "operation attemptedAt", code);
    const submittedAt = parseNullableTime(record.submittedAt, "operation submittedAt", code);
    const inclusion = parseInclusion(record.inclusion, code, context);
    const finality = parseFinality(record.finality, code, context);
    assertTimeOrder(
      base.revision >= 3 + (submittedAt === null ? 0 : 1),
      "finalized operation revision",
      code,
    );
    assertTimeOrder(
      attemptedAt >= base.preparedAt &&
        (submittedAt === null || submittedAt >= attemptedAt) &&
        inclusion.observedAt >= (submittedAt ?? attemptedAt) &&
        finality.observedAt >= inclusion.observedAt &&
        BigInt(finality.blockNumber) >= BigInt(inclusion.blockNumber) &&
        (finality.blockNumber !== inclusion.blockNumber ||
          finality.blockHash === inclusion.blockHash) &&
        base.updatedAt === finality.observedAt,
      "finalized operation time",
      code,
    );
    assertTimeOrder(base.observation === null, "finalized operation observation", code);
    return Object.freeze({
      ...base,
      state,
      attemptedAt,
      submittedAt,
      inclusion,
      finality,
      observation: null,
    });
  }

  if (state === "dropped") {
    const record = exactCapturedRecord(
      captured,
      [...commonKeys, "attemptedAt", "submittedAt", "priorInclusion", "drop"],
      "dropped operation record",
      code,
    );
    const base = baseRecord(record, code, context);
    const attemptedAt = safeInteger(record.attemptedAt, "operation attemptedAt", code);
    const submittedAt = parseNullableTime(record.submittedAt, "operation submittedAt", code);
    const priorInclusion = parseNullableInclusion(record.priorInclusion, code, context);
    const drop = parseDrop(record.drop, base.identity, code, context);
    if (
      priorInclusion !== null &&
      inclusionOccurrenceEqual(priorInclusion, drop.replacement.inclusion)
    ) {
      return invalid(code, "operation drop replacement reuses the target inclusion");
    }
    const minimumRevision = 2 + (submittedAt === null ? 0 : 1) + (priorInclusion === null ? 0 : 1);
    assertTimeOrder(base.revision >= minimumRevision, "dropped operation revision", code);
    assertTimeOrder(
      attemptedAt >= base.preparedAt &&
        (submittedAt === null || submittedAt >= attemptedAt) &&
        (priorInclusion === null || priorInclusion.observedAt >= (submittedAt ?? attemptedAt)) &&
        drop.replacement.finality.observedAt >=
          (priorInclusion?.observedAt ?? submittedAt ?? attemptedAt) &&
        base.updatedAt === drop.replacement.finality.observedAt,
      "dropped operation time",
      code,
    );
    assertTimeOrder(base.observation === null, "dropped operation observation", code);
    return Object.freeze({
      ...base,
      state,
      attemptedAt,
      submittedAt,
      priorInclusion,
      drop,
      observation: null,
    });
  }

  return invalid(code, "operation record state is unsupported");
}

export function parseOperation(value: unknown): Operation {
  try {
    return parseOperationUnsafe(value, new WeakSet());
  } catch {
    throw new OaathOperationError(
      "operation_record_invalid",
      "operation record could not be captured safely",
    );
  }
}

export function createOperation(value: unknown): PreparedOperation {
  try {
    const context: CaptureContext = new WeakSet();
    const record = exactRecord(
      value,
      ["identity", "preparedAt"],
      "operation preparation",
      "operation_input_invalid",
      context,
    );
    const preparedAt = safeInteger(
      record.preparedAt,
      "operation preparation preparedAt",
      "operation_input_invalid",
    );
    return Object.freeze({
      version: OAATH_OPERATION_RECORD_VERSION,
      identity: parseIdentity(record.identity, "operation_input_invalid", context),
      revision: 0,
      state: "prepared",
      preparedAt,
      updatedAt: preparedAt,
      observation: null,
    });
  } catch {
    throw new OaathOperationError(
      "operation_input_invalid",
      "operation preparation could not be captured safely",
    );
  }
}

export function operationOccupiesLane(value: unknown): boolean {
  const operation = parseOperation(value);
  return operation.state !== "finalized" && operation.state !== "dropped";
}

function parseTransition(value: unknown): InternalOperationTransition {
  const code = "operation_transition_invalid" as const;
  const context: CaptureContext = new WeakSet();
  const captured = captureRecord(value, "operation transition", code, context);
  const type = captured.type;

  if (type === "mark_submission_attempted") {
    const record = exactCapturedRecord(
      captured,
      ["type", "identity", "attemptedAt"],
      "submission-attempt transition",
      code,
    );
    return Object.freeze({
      type,
      identity: parseIdentity(record.identity, code, context),
      attemptedAt: safeInteger(record.attemptedAt, "transition attemptedAt", code),
    });
  }

  if (type === "mark_submitted") {
    const record = exactCapturedRecord(
      captured,
      ["type", "identity", "returnedUserOperationHash", "submittedAt"],
      "submitted transition",
      code,
    );
    return Object.freeze({
      type,
      identity: parseIdentity(record.identity, code, context),
      returnedUserOperationHash: hash(
        record.returnedUserOperationHash,
        "transition returnedUserOperationHash",
        code,
      ),
      submittedAt: safeInteger(record.submittedAt, "transition submittedAt", code),
    });
  }

  if (type === "record_pending") {
    const record = exactCapturedRecord(
      captured,
      ["type", "identity", "observedAt", "reason"],
      "pending transition",
      code,
    );
    if (record.reason !== "receipt_missing" && record.reason !== "timeout") {
      return invalid(code, "pending transition reason is unsupported");
    }
    return Object.freeze({
      type,
      identity: parseIdentity(record.identity, code, context),
      observedAt: safeInteger(record.observedAt, "transition observedAt", code),
      reason: record.reason,
    });
  }

  if (type === "record_unreadable") {
    const record = exactCapturedRecord(
      captured,
      ["type", "identity", "observedAt", "reason"],
      "unreadable transition",
      code,
    );
    if (
      record.reason !== "provider_unavailable" &&
      record.reason !== "receipt_invalid" &&
      record.reason !== "canonicality_unproven" &&
      record.reason !== "finality_unproven"
    ) {
      return invalid(code, "unreadable transition reason is unsupported");
    }
    return Object.freeze({
      type,
      identity: parseIdentity(record.identity, code, context),
      observedAt: safeInteger(record.observedAt, "transition observedAt", code),
      reason: record.reason,
    });
  }

  if (type === "record_included") {
    const record = exactCapturedRecord(
      captured,
      ["type", "identity", "inclusion"],
      "included transition",
      code,
    );
    return Object.freeze({
      type,
      identity: parseIdentity(record.identity, code, context),
      inclusion: parseInclusion(record.inclusion, code, context),
    });
  }

  if (type === "record_finalized") {
    const record = exactCapturedRecord(
      captured,
      ["type", "identity", "finality"],
      "finalized transition",
      code,
    );
    return Object.freeze({
      type,
      identity: parseIdentity(record.identity, code, context),
      finality: parseFinality(record.finality, code, context),
    });
  }

  if (type === "record_dropped") {
    const record = exactCapturedRecord(
      captured,
      ["type", "identity", "drop"],
      "dropped transition",
      code,
    );
    const identity = parseIdentity(record.identity, code, context);
    return Object.freeze({
      type,
      identity,
      drop: parseDrop(record.drop, identity, code, context),
    });
  }

  return invalid(code, "operation transition type is unsupported");
}

function sameIdentity(left: OperationIdentity, right: OperationIdentity): boolean {
  return (
    left.kind === right.kind &&
    left.grantId === right.grantId &&
    left.chainId === right.chainId &&
    left.entryPoint === right.entryPoint &&
    left.account === right.account &&
    left.nonce === right.nonce &&
    left.userOperationHash === right.userOperationHash
  );
}

function nextRevision(operation: Operation): number {
  if (operation.revision === Number.MAX_SAFE_INTEGER) {
    return invalid("operation_revision_exhausted", "operation revision is exhausted");
  }
  return operation.revision + 1;
}

function requireIdentity(operation: Operation, identity: OperationIdentity): void {
  if (!sameIdentity(operation.identity, identity)) {
    invalid("operation_identity_mismatch", "operation transition identity does not match");
  }
}

function requireTime(operation: Operation, time: number): void {
  if (time < operation.updatedAt) {
    invalid("operation_transition_invalid", "operation transition time regresses");
  }
}

function forbidden(operation: Operation, transition: InternalOperationTransition): never {
  return invalid(
    "operation_transition_forbidden",
    `operation transition ${transition.type} is forbidden from ${operation.state}`,
  );
}

function inclusionOccurrenceEqual(left: OperationInclusion, right: OperationInclusion): boolean {
  return (
    left.transactionHash === right.transactionHash &&
    left.blockNumber === right.blockNumber &&
    left.blockHash === right.blockHash
  );
}

function captureTransition(transitionValue: unknown): InternalOperationTransition {
  try {
    return parseTransition(transitionValue);
  } catch {
    throw new OaathOperationError(
      "operation_transition_invalid",
      "operation transition could not be captured safely",
    );
  }
}

function advanceParsedOperation(
  operation: Operation,
  transition: InternalOperationTransition,
): Operation {
  requireIdentity(operation, transition.identity);

  if (transition.type === "mark_submission_attempted") {
    if (operation.state !== "prepared") return forbidden(operation, transition);
    requireTime(operation, transition.attemptedAt);
    return Object.freeze({
      ...operation,
      revision: nextRevision(operation),
      state: "submission_attempted",
      attemptedAt: transition.attemptedAt,
      updatedAt: transition.attemptedAt,
      observation: null,
    });
  }

  if (transition.type === "mark_submitted") {
    if (operation.state !== "submission_attempted") return forbidden(operation, transition);
    if (transition.returnedUserOperationHash !== operation.identity.userOperationHash) {
      return invalid(
        "operation_identity_mismatch",
        "submitted operation hash does not match prepared identity",
      );
    }
    requireTime(operation, transition.submittedAt);
    return Object.freeze({
      ...operation,
      revision: nextRevision(operation),
      state: "submitted",
      submittedAt: transition.submittedAt,
      updatedAt: transition.submittedAt,
      observation: null,
    });
  }

  if (transition.type === "record_pending" || transition.type === "record_unreadable") {
    if (operation.state === "prepared") return forbidden(operation, transition);
    if (operation.state === "finalized" || operation.state === "dropped") {
      return operation;
    }
    requireTime(operation, transition.observedAt);
    const observation = Object.freeze({
      status: transition.type === "record_pending" ? ("pending" as const) : ("unreadable" as const),
      observedAt: transition.observedAt,
      reason: transition.reason,
    }) as OperationWeakObservation;
    return Object.freeze({
      ...operation,
      revision: nextRevision(operation),
      updatedAt: transition.observedAt,
      observation,
    });
  }

  if (transition.type === "record_included") {
    if (
      operation.state !== "submission_attempted" &&
      operation.state !== "submitted" &&
      operation.state !== "included"
    ) {
      return forbidden(operation, transition);
    }
    requireTime(operation, transition.inclusion.observedAt);
    if (
      operation.state === "included" &&
      (!inclusionOccurrenceEqual(operation.inclusion, transition.inclusion) ||
        operation.inclusion.outcome !== transition.inclusion.outcome)
    ) {
      return invalid(
        "operation_transition_invalid",
        "included operation evidence contradicts prior inclusion",
      );
    }
    const submittedAt =
      operation.state === "submitted"
        ? operation.submittedAt
        : operation.state === "included"
          ? operation.submittedAt
          : null;
    return Object.freeze({
      ...operation,
      revision: nextRevision(operation),
      state: "included",
      submittedAt,
      inclusion: transition.inclusion,
      updatedAt: transition.inclusion.observedAt,
      observation: null,
    });
  }

  if (transition.type === "record_finalized") {
    if (operation.state !== "included") return forbidden(operation, transition);
    requireTime(operation, transition.finality.observedAt);
    if (BigInt(transition.finality.blockNumber) < BigInt(operation.inclusion.blockNumber)) {
      return invalid("operation_transition_invalid", "finality block precedes operation inclusion");
    }
    if (
      transition.finality.blockNumber === operation.inclusion.blockNumber &&
      transition.finality.blockHash !== operation.inclusion.blockHash
    ) {
      return invalid(
        "operation_transition_invalid",
        "finality block contradicts operation inclusion",
      );
    }
    return Object.freeze({
      ...operation,
      revision: nextRevision(operation),
      state: "finalized",
      finality: transition.finality,
      updatedAt: transition.finality.observedAt,
      observation: null,
    });
  }

  if (transition.type === "record_dropped") {
    if (
      operation.state === "prepared" ||
      operation.state === "finalized" ||
      operation.state === "dropped"
    ) {
      return forbidden(operation, transition);
    }
    if (
      operation.state === "included" &&
      inclusionOccurrenceEqual(operation.inclusion, transition.drop.replacement.inclusion)
    ) {
      return invalid(
        "operation_transition_invalid",
        "operation drop replacement reuses the target inclusion",
      );
    }
    requireTime(operation, transition.drop.replacement.finality.observedAt);
    const attemptedAt = operation.attemptedAt;
    const submittedAt =
      operation.state === "submitted" || operation.state === "included"
        ? operation.submittedAt
        : null;
    const priorInclusion = operation.state === "included" ? operation.inclusion : null;
    return Object.freeze({
      version: operation.version,
      identity: operation.identity,
      revision: nextRevision(operation),
      state: "dropped",
      preparedAt: operation.preparedAt,
      attemptedAt,
      submittedAt,
      priorInclusion,
      drop: transition.drop,
      updatedAt: transition.drop.replacement.finality.observedAt,
      observation: null,
    });
  }

  return forbidden(operation, transition);
}

export function advanceOperation(value: unknown, transitionValue: unknown): Operation {
  const operation = parseOperation(value);
  const transition = captureTransition(transitionValue);
  if (transition.type !== "mark_submission_attempted" && transition.type !== "mark_submitted") {
    return invalid(
      "operation_transition_forbidden",
      "verified observation transitions are owned by OperationObserver",
    );
  }
  return advanceParsedOperation(operation, transition);
}

/** Internal owner used only after evidence has been verified by OperationObserver. */
export function applyVerifiedOperationObservation(
  value: unknown,
  transitionValue: unknown,
): Operation {
  const operation = parseOperation(value);
  const transition = captureTransition(transitionValue);
  if (transition.type === "mark_submission_attempted" || transition.type === "mark_submitted") {
    return invalid(
      "operation_transition_forbidden",
      "submission transitions are not verified observations",
    );
  }
  return advanceParsedOperation(operation, transition);
}
