/**
 * Durable owner for one-time ERC-7836 prepared-call contexts.
 *
 * ```text
 * state and owner     PreparedCallStore owns prepared -> consumed | expired |
 *                     invalidated_as_stale and no other transition
 * persisted evidence provider scope, Grant/account/chain, exact calls,
 *                     signer/custody/materialization, quote/route, prepared
 *                     UserOperation, digest, and preallocated bundle identity
 * resource occupied? preparation occupies no Operation lane; consumed records
 *                     permanently fence the one context use
 * retry safe?         only one prepared revision can win the terminal CAS
 * crash or reload     every decision is reconstructed from the retained record
 * cleanup owner       records are tombstones; this owner exposes no deletion
 * ```
 *
 * The store owns no signing, routing, persistence implementation, or provider
 * response. It captures one immutable context and atomically records which
 * single terminal outcome consumed it.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type CaptureContext,
  captureDenseArray,
  captureRecord as captureRecordValue,
  exactCapturedRecord,
  exactRecord as exactRecordValue,
} from "@oaath/protocol";
import type { Hash } from "viem";
import {
  type PreparedUserOperation,
  parsePreparedUserOperation,
} from "../prepared-user-operation.js";
import { OaathStoreError, type StoreErrorCode, type StoreRecord } from "../store.js";
import { hashWalletCallBundleProvenance } from "./capture.js";

export const OAATH_PREPARED_CALL_CONTEXT_VERSION = "oaath.prepared-call-context/v2" as const;
export const OAATH_PREPARED_CALL_STORE_RECORD_VERSION =
  "oaath.prepared-call-store-record/v2" as const;
/** Exclusive local lifetime of one prepared context, owned by this durable codec. */
export const OAATH_PREPARED_CALL_CONTEXT_LIFETIME_SECONDS = 300;

const ADDRESS = /^0x[0-9a-f]{40}$/u;
const BYTES = /^0x(?:[0-9a-f]{2})*$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const BYTES4 = /^0x[0-9a-f]{8}$/u;
const UNCOMPRESSED_SECP256K1_PUBLIC_KEY = /^0x04[0-9a-f]{128}$/u;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]{0,77})$/u;
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;
const MAX_UINT64 = (1n << 64n) - 1n;
const MAX_UINT48 = (1n << 48n) - 1n;
const MAX_UINT192 = (1n << 192n) - 1n;
const MAX_UINT256 = (1n << 256n) - 1n;
const MAX_CALLS = 64;
const MAX_CALLDATA_BYTES = 128 * 1024;
const MAX_BUNDLE_ID_LENGTH = 4_096;
const MAX_GRANT_ID_LENGTH = 256;
const MAX_PROVIDER_ID_LENGTH = 256;
const MAX_PUBLIC_KEY_BYTES = 4_096;
const MAX_STORE_REVISION = Number.MAX_SAFE_INTEGER;

export interface PreparedCallKey {
  readonly providerScopeId: Hash;
  readonly contextId: Hash;
}

export type PreparedCallKeyHint = Readonly<{
  type: "secp256k1" | "webauthn-p256";
  publicKey: `0x${string}`;
  prehash: false;
}>;

export type PreparedCallCustody =
  | Readonly<{ mode: "frontend"; providerId: null }>
  | Readonly<{ mode: "application_backend"; providerId: string }>;

export interface PreparedCallMaterialization {
  readonly mode: "standard" | "enable-replayable";
  readonly permissionId: `0x${string}`;
}

export interface PreparedCallQuote {
  /** Canonical decimal uint192 EntryPoint nonce key. */
  readonly nonceKey: string;
  /** Canonical decimal uint64 sequence. */
  readonly sequence: string;
}

export interface PreparedCallFeePayer {
  readonly address: `0x${string}`;
  readonly balance: string;
}

export type PreparedCallDecision =
  | Readonly<{ route: "bundler"; feePayer: null }>
  | Readonly<{ route: "direct"; feePayer: Readonly<PreparedCallFeePayer> }>;

export interface PreparedCallInput {
  readonly target: `0x${string}`;
  readonly value: string;
  readonly data: `0x${string}`;
}

export interface PreparedCallValidityTimeRange {
  /** Canonical decimal uint48 lower bound, inclusive. */
  readonly validAfter: string;
  /** Canonical nonzero decimal uint48 upper bound, inclusive. */
  readonly validUntil: string;
}

export interface PreparedCallImmutableFields {
  readonly version: typeof OAATH_PREPARED_CALL_CONTEXT_VERSION;
  readonly providerScopeId: Hash;
  readonly contextId: Hash;
  readonly grantId: string;
  readonly account: `0x${string}`;
  readonly chainId: number;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly validityTimeRange: Readonly<PreparedCallValidityTimeRange> | null;
  readonly requestHash: Hash;
  readonly keyHint: Readonly<PreparedCallKeyHint>;
  readonly custody: Readonly<PreparedCallCustody>;
  readonly materialization: Readonly<PreparedCallMaterialization>;
  readonly quote: Readonly<PreparedCallQuote>;
  readonly decision: Readonly<PreparedCallDecision>;
  readonly calls: readonly Readonly<PreparedCallInput>[];
  readonly prepared: Readonly<PreparedUserOperation>;
  /** Always exactly `prepared.userOperationHash`. */
  readonly digest: Hash;
  /** Preallocated while prepared; never exposed by the opaque context token. */
  readonly bundleId: string;
  readonly bundleGeneration: Hash;
  readonly bundleRequestHash: Hash;
  readonly operationRequestHash: Hash;
}

export type PreparedCallContextRecord = Readonly<
  | (PreparedCallImmutableFields & {
      readonly state: "prepared";
      readonly publicationExpiresAt: null;
    })
  | (PreparedCallImmutableFields & {
      readonly state: "consumed";
      readonly consumedAt: number;
      readonly publicationExpiresAt: number;
    })
  | (PreparedCallImmutableFields & {
      readonly state: "expired" | "invalidated_as_stale";
      readonly terminalAt: number;
      readonly publicationExpiresAt: null;
    })
>;

export type PreparedCallStoreRecord = Readonly<
  StoreRecord<PreparedCallContextRecord, typeof OAATH_PREPARED_CALL_STORE_RECORD_VERSION>
>;

/** Raw persistence capability. It interprets no record and owns no transition. */
export interface PreparedCallStoreAdapter {
  readonly get: (key: Readonly<PreparedCallKey>) => Promise<unknown>;
  readonly compareAndSwap: (input: {
    readonly key: Readonly<PreparedCallKey>;
    readonly expectedStoreRevision: number | null;
    readonly next: Readonly<StoreRecord<unknown>>;
  }) => Promise<unknown>;
  readonly close: () => Promise<unknown>;
}

interface AdapterCapabilities extends PreparedCallStoreAdapter {
  readonly get: (key: Readonly<PreparedCallKey>) => Promise<unknown>;
  readonly compareAndSwap: (
    input: Parameters<PreparedCallStoreAdapter["compareAndSwap"]>[0],
  ) => Promise<unknown>;
  readonly close: () => Promise<unknown>;
}

export type PreparedCallMutationResult =
  | Readonly<{ status: "committed"; record: PreparedCallStoreRecord }>
  | Readonly<{ status: "conflict"; current?: PreparedCallStoreRecord }>;

function invalid(code: StoreErrorCode, message: string): never {
  throw new OaathStoreError(code, message);
}

function failFor(code: StoreErrorCode): (message: string) => never {
  return (message) => invalid(code, message);
}

function exactRecord(
  value: unknown,
  keys: readonly string[],
  label: string,
  code: StoreErrorCode,
  context: CaptureContext = new WeakSet(),
): Record<string, unknown> {
  return exactRecordValue(value, keys, label, context, failFor(code));
}

function capability(
  value: unknown,
  label: string,
): (...arguments_: readonly unknown[]) => Promise<unknown> {
  if (typeof value !== "function") {
    return invalid("store_input_invalid", `${label} must be a function capability`);
  }
  return value as (...arguments_: readonly unknown[]) => Promise<unknown>;
}

function captureAdapter(value: unknown): AdapterCapabilities {
  const record = exactRecord(
    value,
    ["get", "compareAndSwap", "close"],
    "Prepared call store adapter",
    "store_input_invalid",
  );
  const get = capability(record.get, "Prepared call store get");
  const compareAndSwap = capability(record.compareAndSwap, "Prepared call store compareAndSwap");
  const close = capability(record.close, "Prepared call store close");
  return Object.freeze({
    get: (key: Readonly<PreparedCallKey>) => get(key),
    compareAndSwap: (input: Parameters<PreparedCallStoreAdapter["compareAndSwap"]>[0]) =>
      compareAndSwap(input),
    close: () => close(),
  });
}

function safeInteger(value: unknown, label: string, code: StoreErrorCode, minimum: 0 | 1): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    Object.is(value, -0) ||
    value < minimum
  ) {
    return invalid(
      code,
      `${label} must be a ${minimum === 0 ? "nonnegative" : "positive"} safe integer`,
    );
  }
  return value;
}

function hash(value: unknown, label: string, code: StoreErrorCode): Hash {
  if (typeof value !== "string" || !HASH.test(value)) {
    return invalid(code, `${label} must be a lowercase 32-byte hash`);
  }
  return value as Hash;
}

function boundedString(
  value: unknown,
  maximum: number,
  label: string,
  code: StoreErrorCode,
): string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum) {
    return invalid(code, `${label} must be a bounded nonempty string`);
  }
  return value;
}

function grantId(value: unknown, code: StoreErrorCode): string {
  const captured = boundedString(value, MAX_GRANT_ID_LENGTH, "Prepared call grantId", code);
  if (captured !== captured.trim()) {
    return invalid(code, "Prepared call grantId must be canonical");
  }
  return captured;
}

function chainId(value: unknown, code: StoreErrorCode): number {
  return safeInteger(value, "Prepared call chainId", code, 1);
}

function address(value: unknown, label: string, code: StoreErrorCode): `0x${string}` {
  if (typeof value !== "string" || !ADDRESS.test(value) || value === ZERO_ADDRESS) {
    return invalid(code, `${label} must be a nonzero lowercase address`);
  }
  return value as `0x${string}`;
}

function bytes(value: unknown, label: string, code: StoreErrorCode): `0x${string}` {
  if (typeof value !== "string" || !BYTES.test(value)) {
    return invalid(code, `${label} must be canonical lowercase bytes`);
  }
  return value as `0x${string}`;
}

function decimal(value: unknown, maximum: bigint, label: string, code: StoreErrorCode): string {
  if (typeof value !== "string" || !DECIMAL_UINT.test(value) || BigInt(value) > maximum) {
    return invalid(code, `${label} must be a canonical bounded decimal integer`);
  }
  return value;
}

function parseKeyHint(
  value: unknown,
  context: CaptureContext,
  code: StoreErrorCode,
): Readonly<PreparedCallKeyHint> {
  const record = exactRecord(
    value,
    ["type", "publicKey", "prehash"],
    "Prepared call key hint",
    code,
    context,
  );
  if (record.type !== "secp256k1" && record.type !== "webauthn-p256") {
    return invalid(code, "Prepared call key hint type is unsupported");
  }
  const publicKey = bytes(record.publicKey, "Prepared call public key", code);
  if (publicKey === "0x" || (publicKey.length - 2) / 2 > MAX_PUBLIC_KEY_BYTES) {
    return invalid(code, "Prepared call public key is empty or too large");
  }
  if (record.type === "secp256k1" && !UNCOMPRESSED_SECP256K1_PUBLIC_KEY.test(publicKey)) {
    return invalid(code, "Prepared call secp256k1 public key must be uncompressed");
  }
  if (record.prehash !== false) {
    return invalid(code, "Prepared call key hint must not prehash the digest");
  }
  return Object.freeze({ type: record.type, publicKey, prehash: false as const });
}

function parseCustody(
  value: unknown,
  context: CaptureContext,
  code: StoreErrorCode,
): Readonly<PreparedCallCustody> {
  const record = exactRecord(value, ["mode", "providerId"], "Prepared call custody", code, context);
  if (record.mode === "frontend") {
    if (record.providerId !== null) {
      return invalid(code, "Frontend prepared-call custody names no provider");
    }
    return Object.freeze({ mode: "frontend" as const, providerId: null });
  }
  if (record.mode !== "application_backend") {
    return invalid(code, "Prepared call custody mode is unsupported");
  }
  return Object.freeze({
    mode: "application_backend" as const,
    providerId: boundedString(
      record.providerId,
      MAX_PROVIDER_ID_LENGTH,
      "Prepared call custody providerId",
      code,
    ),
  });
}

function parseMaterialization(
  value: unknown,
  context: CaptureContext,
  code: StoreErrorCode,
): Readonly<PreparedCallMaterialization> {
  const record = exactRecord(
    value,
    ["mode", "permissionId"],
    "Prepared call materialization",
    code,
    context,
  );
  if (record.mode !== "standard" && record.mode !== "enable-replayable") {
    return invalid(code, "Prepared call materialization mode is unsupported");
  }
  if (typeof record.permissionId !== "string" || !BYTES4.test(record.permissionId)) {
    return invalid(code, "Prepared call permissionId must be lowercase bytes4");
  }
  return Object.freeze({
    mode: record.mode,
    permissionId: record.permissionId as `0x${string}`,
  });
}

function parseQuote(
  value: unknown,
  context: CaptureContext,
  code: StoreErrorCode,
): Readonly<PreparedCallQuote> {
  const record = exactRecord(value, ["nonceKey", "sequence"], "Prepared call quote", code, context);
  return Object.freeze({
    nonceKey: decimal(record.nonceKey, MAX_UINT192, "Prepared call nonce key", code),
    sequence: decimal(record.sequence, MAX_UINT64, "Prepared call nonce sequence", code),
  });
}

function parseValidityTimeRange(
  value: unknown,
  context: CaptureContext,
  code: StoreErrorCode,
): Readonly<PreparedCallValidityTimeRange> | null {
  if (value === null) return null;
  const record = exactRecord(
    value,
    ["validAfter", "validUntil"],
    "Prepared call validity time range",
    code,
    context,
  );
  const validAfter = decimal(
    record.validAfter,
    MAX_UINT48,
    "Prepared call validity validAfter",
    code,
  );
  const validUntil = decimal(
    record.validUntil,
    MAX_UINT48,
    "Prepared call validity validUntil",
    code,
  );
  if (validUntil === "0" || BigInt(validAfter) >= BigInt(validUntil)) {
    return invalid(code, "Prepared call validity range must be nonempty and bounded");
  }
  return Object.freeze({ validAfter, validUntil });
}

function parseFeePayer(
  value: unknown,
  context: CaptureContext,
  code: StoreErrorCode,
): Readonly<PreparedCallFeePayer> {
  const record = exactRecord(
    value,
    ["address", "balance"],
    "Prepared call fee payer",
    code,
    context,
  );
  return Object.freeze({
    address: address(record.address, "Prepared call fee payer address", code),
    balance: decimal(record.balance, MAX_UINT256, "Prepared call fee payer balance", code),
  });
}

function parseDecision(
  value: unknown,
  context: CaptureContext,
  code: StoreErrorCode,
): Readonly<PreparedCallDecision> {
  const record = exactRecord(value, ["route", "feePayer"], "Prepared call decision", code, context);
  if (record.route === "bundler") {
    if (record.feePayer !== null) {
      return invalid(code, "Bundler prepared-call route cannot bind a direct fee payer");
    }
    return Object.freeze({ route: "bundler" as const, feePayer: null });
  }
  if (record.route !== "direct" || record.feePayer === null) {
    return invalid(code, "Direct prepared-call route requires a fee payer");
  }
  return Object.freeze({
    route: "direct" as const,
    feePayer: parseFeePayer(record.feePayer, context, code),
  });
}

function parseCalls(
  value: unknown,
  context: CaptureContext,
  code: StoreErrorCode,
): readonly Readonly<PreparedCallInput>[] {
  const entries = captureDenseArray(value, "Prepared calls", context, failFor(code));
  if (entries.length < 1 || entries.length > MAX_CALLS) {
    return invalid(code, "Prepared calls must contain 1 to 64 calls");
  }
  let calldataBytes = 0;
  const calls = entries.map((entry, index) => {
    const record = exactRecord(
      entry,
      ["target", "value", "data"],
      `Prepared call ${index}`,
      code,
      context,
    );
    const data = bytes(record.data, `Prepared call ${index} data`, code);
    calldataBytes += (data.length - 2) / 2;
    if (calldataBytes > MAX_CALLDATA_BYTES) {
      return invalid(code, "Prepared call calldata exceeds its aggregate bound");
    }
    return Object.freeze({
      target: address(record.target, `Prepared call ${index} target`, code),
      value: decimal(record.value, MAX_UINT256, `Prepared call ${index} value`, code),
      data,
    });
  });
  return Object.freeze(calls);
}

function parsePrepared(
  value: unknown,
  label: string,
  code: StoreErrorCode,
): Readonly<PreparedUserOperation> {
  try {
    return parsePreparedUserOperation(value);
  } catch {
    return invalid(code, `${label} is invalid`);
  }
}

function parseImmutableFields(
  record: Record<string, unknown>,
  context: CaptureContext,
  code: StoreErrorCode,
): Readonly<PreparedCallImmutableFields> {
  if (record.version !== OAATH_PREPARED_CALL_CONTEXT_VERSION) {
    return invalid(code, "Prepared call context version is unsupported");
  }
  const providerScopeId = hash(record.providerScopeId, "Prepared call providerScopeId", code);
  const contextId = hash(record.contextId, "Prepared call contextId", code);
  const capturedGrantId = grantId(record.grantId, code);
  const capturedAccount = address(record.account, "Prepared call account", code);
  const capturedChainId = chainId(record.chainId, code);
  const createdAt = safeInteger(record.createdAt, "Prepared call creation time", code, 0);
  const expiresAt = safeInteger(record.expiresAt, "Prepared call expiry time", code, 1);
  const validityTimeRange = parseValidityTimeRange(record.validityTimeRange, context, code);
  if (
    createdAt >= expiresAt ||
    expiresAt - createdAt > OAATH_PREPARED_CALL_CONTEXT_LIFETIME_SECONDS
  ) {
    return invalid(code, "Prepared call context expiry is outside its owned lifetime");
  }
  if (validityTimeRange !== null && BigInt(expiresAt) > BigInt(validityTimeRange.validUntil) + 1n) {
    return invalid(code, "Prepared call context expiry exceeds its validity range");
  }
  const quote = parseQuote(record.quote, context, code);
  const prepared = parsePrepared(record.prepared, "Prepared call UserOperation", code);
  const digest = hash(record.digest, "Prepared call digest", code);
  const bundleRequestHash = hash(
    record.bundleRequestHash,
    "Prepared call bundle request hash",
    code,
  );
  const bundleGeneration = hash(record.bundleGeneration, "Prepared call bundle generation", code);
  const operationRequestHash = hash(
    record.operationRequestHash,
    "Prepared call operation request hash",
    code,
  );
  if (
    prepared.kind !== "execution" ||
    prepared.grantId !== capturedGrantId ||
    prepared.chainId !== capturedChainId ||
    prepared.userOperation.sender !== capturedAccount ||
    digest !== prepared.userOperationHash
  ) {
    return invalid(code, "Prepared call UserOperation contradicts its context");
  }
  if (
    operationRequestHash !== hashWalletCallBundleProvenance(bundleRequestHash, bundleGeneration)
  ) {
    return invalid(code, "Prepared call operation provenance contradicts its bundle identity");
  }
  return Object.freeze({
    version: OAATH_PREPARED_CALL_CONTEXT_VERSION,
    providerScopeId,
    contextId,
    grantId: capturedGrantId,
    account: capturedAccount,
    chainId: capturedChainId,
    createdAt,
    expiresAt,
    validityTimeRange,
    requestHash: hash(record.requestHash, "Prepared call requestHash", code),
    keyHint: parseKeyHint(record.keyHint, context, code),
    custody: parseCustody(record.custody, context, code),
    materialization: parseMaterialization(record.materialization, context, code),
    quote,
    decision: parseDecision(record.decision, context, code),
    calls: parseCalls(record.calls, context, code),
    prepared,
    digest,
    bundleId: boundedString(record.bundleId, MAX_BUNDLE_ID_LENGTH, "Prepared call bundleId", code),
    bundleGeneration,
    bundleRequestHash,
    operationRequestHash,
  });
}

const IMMUTABLE_KEYS = Object.freeze([
  "version",
  "providerScopeId",
  "contextId",
  "grantId",
  "account",
  "chainId",
  "createdAt",
  "expiresAt",
  "validityTimeRange",
  "requestHash",
  "keyHint",
  "custody",
  "materialization",
  "quote",
  "decision",
  "calls",
  "prepared",
  "digest",
  "bundleId",
  "bundleGeneration",
  "bundleRequestHash",
  "operationRequestHash",
]);

/** Captures one current-version durable prepared-call value. */
export function parsePreparedCallRecord(value: unknown): Readonly<PreparedCallContextRecord> {
  const code: StoreErrorCode = "store_record_invalid";
  const context: CaptureContext = new WeakSet();
  const captured = captureRecordValue(
    value,
    "Prepared call context record",
    context,
    failFor(code),
  );
  const state = captured.state;
  const keys =
    state === "prepared"
      ? [...IMMUTABLE_KEYS, "state", "publicationExpiresAt"]
      : state === "consumed"
        ? [...IMMUTABLE_KEYS, "state", "consumedAt", "publicationExpiresAt"]
        : state === "expired" || state === "invalidated_as_stale"
          ? [...IMMUTABLE_KEYS, "state", "terminalAt", "publicationExpiresAt"]
          : [...IMMUTABLE_KEYS, "state"];
  const record = exactCapturedRecord(captured, keys, "Prepared call context record", failFor(code));
  const immutable = parseImmutableFields(record, context, code);

  if (state === "prepared") {
    if (record.publicationExpiresAt !== null) {
      return invalid(code, "A prepared context has no publication lease");
    }
    return Object.freeze({ ...immutable, state, publicationExpiresAt: null });
  }
  if (state === "consumed") {
    const consumedAt = safeInteger(record.consumedAt, "Prepared call consumption time", code, 0);
    const publicationExpiresAt = safeInteger(
      record.publicationExpiresAt,
      "Prepared call publication expiry",
      code,
      1,
    );
    if (
      consumedAt < immutable.createdAt ||
      consumedAt >= immutable.expiresAt ||
      publicationExpiresAt <= consumedAt
    ) {
      return invalid(code, "Prepared call consumption times are contradictory");
    }
    return Object.freeze({
      ...immutable,
      state,
      consumedAt,
      publicationExpiresAt,
    });
  }
  if (state === "expired" || state === "invalidated_as_stale") {
    if (record.publicationExpiresAt !== null) {
      return invalid(code, "An unconsumed terminal context has no publication lease");
    }
    const terminalAt = safeInteger(record.terminalAt, "Prepared call terminal time", code, 0);
    if (
      terminalAt < immutable.createdAt ||
      (state === "expired" && terminalAt < immutable.expiresAt)
    ) {
      return invalid(code, "Prepared call terminal time contradicts its state");
    }
    return Object.freeze({ ...immutable, state, terminalAt, publicationExpiresAt: null });
  }
  return invalid(code, "Prepared call context state is unsupported");
}

/** Captures one exact provider-scoped context key without normalization. */
export function parsePreparedCallKey(value: unknown): Readonly<PreparedCallKey> {
  const code: StoreErrorCode = "store_input_invalid";
  const record = exactRecord(value, ["providerScopeId", "contextId"], "Prepared call key", code);
  return Object.freeze({
    providerScopeId: hash(record.providerScopeId, "Prepared call key providerScopeId", code),
    contextId: hash(record.contextId, "Prepared call key contextId", code),
  });
}

function inputRecord(value: unknown): Readonly<PreparedCallContextRecord> {
  try {
    return parsePreparedCallRecord(value);
  } catch {
    return invalid("store_input_invalid", "Prepared call context value is invalid");
  }
}

function storedRecord(value: unknown): Readonly<PreparedCallContextRecord> {
  try {
    return parsePreparedCallRecord(value);
  } catch {
    return invalid("store_record_invalid", "Stored prepared call context value is invalid");
  }
}

function sameKey(left: PreparedCallKey, right: PreparedCallKey): boolean {
  return left.providerScopeId === right.providerScopeId && left.contextId === right.contextId;
}

function immutableFields(value: PreparedCallContextRecord): Readonly<PreparedCallImmutableFields> {
  return Object.freeze({
    version: value.version,
    providerScopeId: value.providerScopeId,
    contextId: value.contextId,
    grantId: value.grantId,
    account: value.account,
    chainId: value.chainId,
    createdAt: value.createdAt,
    expiresAt: value.expiresAt,
    validityTimeRange: value.validityTimeRange,
    requestHash: value.requestHash,
    keyHint: value.keyHint,
    custody: value.custody,
    materialization: value.materialization,
    quote: value.quote,
    decision: value.decision,
    calls: value.calls,
    prepared: value.prepared,
    digest: value.digest,
    bundleId: value.bundleId,
    bundleGeneration: value.bundleGeneration,
    bundleRequestHash: value.bundleRequestHash,
    operationRequestHash: value.operationRequestHash,
  });
}

function sameValue(left: PreparedCallContextRecord, right: PreparedCallContextRecord): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function sameImmutableIdentity(
  left: PreparedCallContextRecord,
  right: PreparedCallContextRecord,
): boolean {
  return JSON.stringify(immutableFields(left)) === JSON.stringify(immutableFields(right));
}

function sameStoreRecord(
  left: PreparedCallStoreRecord | undefined,
  right: PreparedCallStoreRecord,
): boolean {
  return (
    left !== undefined &&
    left.version === right.version &&
    left.storeRevision === right.storeRevision &&
    left.updatedAt === right.updatedAt &&
    sameValue(left.value, right.value)
  );
}

function requiredRevision(value: PreparedCallContextRecord): 0 | 1 {
  return value.state === "prepared" ? 0 : 1;
}

function recordTime(value: PreparedCallContextRecord): number {
  if (value.state === "prepared") return value.createdAt;
  if (value.state === "consumed") return value.consumedAt;
  return value.terminalAt;
}

function requireCompatibleHistory(
  previous: PreparedCallStoreRecord,
  current: PreparedCallStoreRecord,
): void {
  if (!sameImmutableIdentity(previous.value, current.value)) {
    invalid("store_identity_mismatch", "Prepared call immutable identity changed");
  }
  if (
    previous.value.state !== "prepared" ||
    current.value.state === "prepared" ||
    current.storeRevision !== previous.storeRevision + 1 ||
    current.updatedAt < previous.updatedAt
  ) {
    invalid("store_record_invalid", "Prepared call history is not monotonic");
  }
}

function conflict(
  current?: PreparedCallStoreRecord,
): Readonly<{ status: "conflict"; current?: PreparedCallStoreRecord }> {
  return Object.freeze({ status: "conflict" as const, ...(current ? { current } : {}) });
}

function nextRevision(current: number | null): number {
  if (current === MAX_STORE_REVISION) {
    return invalid("store_revision_exhausted", "Prepared call store revision is exhausted");
  }
  return current === null ? 0 : current + 1;
}

function reserveInput(value: unknown): Readonly<{
  key: Readonly<PreparedCallKey>;
  record: Readonly<PreparedCallContextRecord>;
}> {
  const record = exactRecord(
    value,
    [
      "key",
      "grantId",
      "account",
      "chainId",
      "createdAt",
      "expiresAt",
      "validityTimeRange",
      "requestHash",
      "keyHint",
      "custody",
      "materialization",
      "quote",
      "decision",
      "calls",
      "prepared",
      "digest",
      "bundleId",
      "bundleGeneration",
      "bundleRequestHash",
      "operationRequestHash",
    ],
    "Prepared call reservation",
    "store_input_invalid",
  );
  const key = parsePreparedCallKey(record.key);
  return Object.freeze({
    key,
    record: inputRecord({
      version: OAATH_PREPARED_CALL_CONTEXT_VERSION,
      providerScopeId: key.providerScopeId,
      contextId: key.contextId,
      grantId: record.grantId,
      account: record.account,
      chainId: record.chainId,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
      validityTimeRange: record.validityTimeRange,
      requestHash: record.requestHash,
      keyHint: record.keyHint,
      custody: record.custody,
      materialization: record.materialization,
      quote: record.quote,
      decision: record.decision,
      calls: record.calls,
      prepared: record.prepared,
      digest: record.digest,
      bundleId: record.bundleId,
      bundleGeneration: record.bundleGeneration,
      bundleRequestHash: record.bundleRequestHash,
      operationRequestHash: record.operationRequestHash,
      state: "prepared",
      publicationExpiresAt: null,
    }),
  });
}

function expectedRevision(value: unknown): number {
  return safeInteger(value, "Prepared call expected store revision", "store_input_invalid", 0);
}

function consumeInput(value: unknown): Readonly<{
  key: Readonly<PreparedCallKey>;
  expectedStoreRevision: number;
  consumedAt: number;
  publicationExpiresAt: number;
}> {
  const record = exactRecord(
    value,
    ["key", "expectedStoreRevision", "consumedAt", "publicationExpiresAt"],
    "Prepared call consumption",
    "store_input_invalid",
  );
  return Object.freeze({
    key: parsePreparedCallKey(record.key),
    expectedStoreRevision: expectedRevision(record.expectedStoreRevision),
    consumedAt: safeInteger(
      record.consumedAt,
      "Prepared call consumption time",
      "store_input_invalid",
      0,
    ),
    publicationExpiresAt: safeInteger(
      record.publicationExpiresAt,
      "Prepared call publication expiry",
      "store_input_invalid",
      1,
    ),
  });
}

function terminalInput(
  value: unknown,
  label: string,
): Readonly<{
  key: Readonly<PreparedCallKey>;
  expectedStoreRevision: number;
  terminalAt: number;
}> {
  const record = exactRecord(
    value,
    ["key", "expectedStoreRevision", "terminalAt"],
    label,
    "store_input_invalid",
  );
  return Object.freeze({
    key: parsePreparedCallKey(record.key),
    expectedStoreRevision: expectedRevision(record.expectedStoreRevision),
    terminalAt: safeInteger(
      record.terminalAt,
      "Prepared call terminal time",
      "store_input_invalid",
      0,
    ),
  });
}

/** One current-version prepared-call state machine over an injected raw adapter. */
export class PreparedCallStore {
  readonly #adapter: AdapterCapabilities;
  #closed = false;
  #closing: Promise<void> | undefined;

  constructor(adapter: unknown) {
    this.#adapter = captureAdapter(adapter);
  }

  async get(key: unknown): Promise<PreparedCallStoreRecord | undefined> {
    const captured = parsePreparedCallKey(key);
    this.#assertOpen();
    return this.#read(captured);
  }

  async reservePrepared(value: unknown): Promise<PreparedCallMutationResult> {
    const input = reserveInput(value);
    this.#assertOpen();
    const current = await this.#read(input.key);
    if (current !== undefined) return conflict(current);
    return this.#compareAndSwap(input.key, null, input.record, input.record.createdAt);
  }

  async consume(value: unknown): Promise<PreparedCallMutationResult> {
    const input = consumeInput(value);
    this.#assertOpen();
    const current = await this.#read(input.key);
    if (
      current === undefined ||
      current.storeRevision !== input.expectedStoreRevision ||
      current.value.state !== "prepared"
    ) {
      return conflict(current);
    }
    const next = inputRecord({
      ...immutableFields(current.value),
      state: "consumed",
      consumedAt: input.consumedAt,
      publicationExpiresAt: input.publicationExpiresAt,
    });
    return this.#compareAndSwap(
      input.key,
      input.expectedStoreRevision,
      next,
      input.consumedAt,
      current,
    );
  }

  async markExpired(value: unknown): Promise<PreparedCallMutationResult> {
    return this.#terminalTransition(value, "expired", "Prepared call expiry");
  }

  async markStale(value: unknown): Promise<PreparedCallMutationResult> {
    return this.#terminalTransition(
      value,
      "invalidated_as_stale",
      "Prepared call stale invalidation",
    );
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    if (!this.#closing) {
      this.#closing = (async () => {
        try {
          await this.#adapter.close();
        } catch {
          return invalid("store_unavailable", "Prepared call store close failed");
        }
        this.#closed = true;
      })();
    }
    try {
      await this.#closing;
    } finally {
      if (!this.#closed) this.#closing = undefined;
    }
  }

  async #terminalTransition(
    value: unknown,
    state: "expired" | "invalidated_as_stale",
    label: string,
  ): Promise<PreparedCallMutationResult> {
    const input = terminalInput(value, label);
    this.#assertOpen();
    const current = await this.#read(input.key);
    if (
      current === undefined ||
      current.storeRevision !== input.expectedStoreRevision ||
      current.value.state !== "prepared"
    ) {
      return conflict(current);
    }
    const next = inputRecord({
      ...immutableFields(current.value),
      state,
      terminalAt: input.terminalAt,
      publicationExpiresAt: null,
    });
    return this.#compareAndSwap(
      input.key,
      input.expectedStoreRevision,
      next,
      input.terminalAt,
      current,
    );
  }

  async #read(key: Readonly<PreparedCallKey>): Promise<PreparedCallStoreRecord | undefined> {
    let raw: unknown;
    try {
      raw = await this.#adapter.get(key);
    } catch {
      return invalid("store_unavailable", "Prepared call store read is unavailable");
    }
    if (raw === undefined) return undefined;
    const envelope = exactRecord(
      raw,
      ["version", "storeRevision", "updatedAt", "value"],
      "Stored prepared call envelope",
      "store_record_invalid",
    );
    if (envelope.version !== OAATH_PREPARED_CALL_STORE_RECORD_VERSION) {
      return invalid("store_record_invalid", "Stored prepared call envelope is unsupported");
    }
    const value = storedRecord(envelope.value);
    if (!sameKey({ providerScopeId: value.providerScopeId, contextId: value.contextId }, key)) {
      return invalid("store_key_mismatch", "Stored prepared call belongs to another key");
    }
    const storeRevision = safeInteger(
      envelope.storeRevision,
      "Stored prepared call revision",
      "store_record_invalid",
      0,
    );
    const updatedAt = safeInteger(
      envelope.updatedAt,
      "Stored prepared call update time",
      "store_record_invalid",
      0,
    );
    if (storeRevision !== requiredRevision(value) || updatedAt !== recordTime(value)) {
      return invalid("store_record_invalid", "Stored prepared call envelope contradicts its value");
    }
    return Object.freeze({
      version: OAATH_PREPARED_CALL_STORE_RECORD_VERSION,
      storeRevision,
      updatedAt,
      value,
    });
  }

  async #compareAndSwap(
    key: Readonly<PreparedCallKey>,
    expectedStoreRevision: number | null,
    value: Readonly<PreparedCallContextRecord>,
    updatedAt: number,
    previous?: PreparedCallStoreRecord,
  ): Promise<PreparedCallMutationResult> {
    const next: PreparedCallStoreRecord = Object.freeze({
      version: OAATH_PREPARED_CALL_STORE_RECORD_VERSION,
      storeRevision: nextRevision(expectedStoreRevision),
      updatedAt,
      value,
    });
    let swapped: unknown;
    try {
      swapped = await this.#adapter.compareAndSwap(
        Object.freeze({ key, expectedStoreRevision, next }),
      );
    } catch {
      return invalid(
        "store_commit_indeterminate",
        "Prepared call compare-and-swap completion is indeterminate",
      );
    }
    if (typeof swapped !== "boolean") {
      return invalid("store_commit_indeterminate", "Prepared call CAS result is invalid");
    }

    let retained: PreparedCallStoreRecord | undefined;
    try {
      retained = await this.#read(key);
    } catch {
      return swapped
        ? invalid("store_commit_unverified", "Prepared call commit could not be verified")
        : invalid("store_commit_indeterminate", "Prepared call conflict could not be verified");
    }
    if (swapped) {
      if (retained !== undefined && sameStoreRecord(retained, next)) {
        return Object.freeze({ status: "committed" as const, record: retained });
      }
      return invalid("store_commit_unverified", "Prepared call store did not retain the write");
    }
    if (retained === undefined) {
      return invalid("store_commit_indeterminate", "Prepared call conflict is unverified");
    }
    if (expectedStoreRevision !== null) {
      if (retained.storeRevision <= expectedStoreRevision) {
        return invalid("store_commit_indeterminate", "Prepared call conflict is unverified");
      }
      if (previous === undefined) {
        return invalid("store_commit_indeterminate", "Prepared call history is unavailable");
      }
      requireCompatibleHistory(previous, retained);
    }
    return conflict(retained);
  }

  #assertOpen(): void {
    if (this.#closed) invalid("store_closed", "Prepared call store is closed");
  }
}
