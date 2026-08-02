import type { Grant } from "./grant.js";
import { parseGrant } from "./grant.js";
import { type CaptureContext, exactRecord as exactRecordValue } from "./internal/exact-record.js";
import type { Operation } from "./operation.js";
import { operationOccupiesLane, parseOperation } from "./operation.js";

export const OGP_GRANT_STORE_RECORD_VERSION = "ogp.grant-store-record/v1" as const;
export const OGP_OPERATION_STORE_RECORD_VERSION = "ogp.operation-store-record/v1" as const;

const MAX_GRANT_ID_LENGTH = 256;
const MAX_STORE_REVISION = Number.MAX_SAFE_INTEGER;

export type StoreErrorCode =
  | "store_input_invalid"
  | "store_closed"
  | "store_unavailable"
  | "store_record_invalid"
  | "store_key_mismatch"
  | "store_lane_occupied"
  | "store_revision_exhausted"
  | "store_commit_indeterminate"
  | "store_commit_unverified";

export class OgpStoreError extends Error {
  readonly code: StoreErrorCode;

  constructor(code: StoreErrorCode, message: string) {
    super(message);
    this.name = "OgpStoreError";
    this.code = code;
  }
}

export interface StoreRecord<Value, Version extends string = string> {
  readonly version: Version;
  /** Monotonic store revision, independent from the aggregate revision. */
  readonly storeRevision: number;
  readonly updatedAt: number;
  readonly value: Value;
}

export type GrantStoreRecord = Readonly<StoreRecord<Grant, typeof OGP_GRANT_STORE_RECORD_VERSION>>;
export type OperationStoreRecord = Readonly<
  StoreRecord<Operation, typeof OGP_OPERATION_STORE_RECORD_VERSION>
>;

export interface GrantStoreAdapter {
  get(grantId: string): Promise<unknown>;
  compareAndSwap(input: {
    readonly grantId: string;
    readonly expectedStoreRevision: number | null;
    readonly next: Readonly<StoreRecord<unknown>>;
  }): Promise<unknown>;
  close(): Promise<unknown>;
}

export interface OperationStoreKey {
  readonly grantId: string;
  readonly chainId: number;
}

export interface OperationStoreAdapter {
  get(key: Readonly<OperationStoreKey>): Promise<unknown>;
  compareAndSwap(input: {
    readonly key: Readonly<OperationStoreKey>;
    readonly expectedStoreRevision: number | null;
    readonly next: Readonly<StoreRecord<unknown>>;
  }): Promise<unknown>;
  close(): Promise<unknown>;
}

export type GrantStoreCompareAndSwapResult =
  | Readonly<{ status: "committed"; record: GrantStoreRecord }>
  | Readonly<{ status: "conflict"; current?: GrantStoreRecord }>;

export type OperationStoreCompareAndSwapResult =
  | Readonly<{ status: "committed"; record: OperationStoreRecord }>
  | Readonly<{ status: "conflict"; current?: OperationStoreRecord }>;

type AdapterCapabilities<Key> = Readonly<{
  get: (key: Key) => Promise<unknown>;
  compareAndSwap: (
    key: Key,
    expectedStoreRevision: number | null,
    next: Readonly<StoreRecord<unknown>>,
  ) => Promise<unknown>;
  close: () => Promise<unknown>;
}>;

type AggregateAccess<Value, Key, Version extends string> = Readonly<{
  version: Version;
  parse: (value: unknown) => Value;
  keyMatches: (value: Value, key: Key) => boolean;
  updatedAt: (value: Value) => number;
  validateNext?: (current: Value | undefined, next: Value) => void;
}>;

function invalid(code: StoreErrorCode, message: string): never {
  throw new OgpStoreError(code, message);
}

function exactRecord(
  value: unknown,
  keys: readonly string[],
  label: string,
  code: StoreErrorCode,
  context: CaptureContext = new WeakSet(),
): Record<string, unknown> {
  return exactRecordValue(value, keys, label, context, (message) => invalid(code, message));
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

function captureAdapter(
  value: unknown,
  kind: "Grant" | "Operation",
): {
  readonly get: (...arguments_: readonly unknown[]) => Promise<unknown>;
  readonly compareAndSwap: (...arguments_: readonly unknown[]) => Promise<unknown>;
  readonly close: (...arguments_: readonly unknown[]) => Promise<unknown>;
} {
  const record = exactRecord(
    value,
    ["get", "compareAndSwap", "close"],
    `${kind} store adapter`,
    "store_input_invalid",
  );
  return Object.freeze({
    get: capability(record.get, `${kind} store get`),
    compareAndSwap: capability(record.compareAndSwap, `${kind} store compareAndSwap`),
    close: capability(record.close, `${kind} store close`),
  });
}

function canonicalGrantId(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > MAX_GRANT_ID_LENGTH ||
    value !== value.trim()
  ) {
    return invalid("store_input_invalid", "store grantId must be a bounded canonical string");
  }
  return value;
}

function canonicalChainId(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    return invalid("store_input_invalid", "store chainId must be a positive safe integer");
  }
  return value;
}

function parseOperationKey(value: unknown): Readonly<OperationStoreKey> {
  const record = exactRecord(
    value,
    ["grantId", "chainId"],
    "Operation store key",
    "store_input_invalid",
  );
  return Object.freeze({
    grantId: canonicalGrantId(record.grantId),
    chainId: canonicalChainId(record.chainId),
  });
}

function expectedStoreRevision(value: unknown): number | null {
  if (value === null) return null;
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    Object.is(value, -0) ||
    value < 0
  ) {
    return invalid("store_input_invalid", "store expected revision is invalid");
  }
  return value;
}

function storeRevision(value: unknown): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    Object.is(value, -0) ||
    value < 0
  ) {
    return invalid("store_record_invalid", "stored revision is invalid");
  }
  return value;
}

function safeUpdatedAt(value: unknown): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    Object.is(value, -0) ||
    value < 0
  ) {
    return invalid("store_record_invalid", "stored update time is invalid");
  }
  return value;
}

function nextStoreRevision(current: number | null): number {
  if (current === MAX_STORE_REVISION) {
    return invalid("store_revision_exhausted", "store revision is exhausted");
  }
  return current === null ? 0 : current + 1;
}

function sameValue(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function sameOperationIdentity(left: Operation, right: Operation): boolean {
  return sameValue(left.identity, right.identity);
}

function sameStoreRecord<Value>(
  left: StoreRecord<Value> | undefined,
  right: StoreRecord<Value>,
): boolean {
  return (
    left !== undefined &&
    left.version === right.version &&
    left.storeRevision === right.storeRevision &&
    left.updatedAt === right.updatedAt &&
    sameValue(left.value, right.value)
  );
}

class AggregateStore<Value, Key, Version extends string> {
  readonly #adapter: AdapterCapabilities<Key>;
  readonly #access: AggregateAccess<Value, Key, Version>;
  #closed = false;
  #closing: Promise<void> | undefined;

  constructor(adapter: AdapterCapabilities<Key>, access: AggregateAccess<Value, Key, Version>) {
    this.#adapter = adapter;
    this.#access = access;
  }

  async get(key: Key): Promise<Readonly<StoreRecord<Value, Version>> | undefined> {
    this.#assertOpen();
    let raw: unknown;
    try {
      raw = await this.#adapter.get(key);
    } catch {
      return invalid("store_unavailable", "store read is unavailable");
    }
    return this.#parseRead(raw, key);
  }

  async compareAndSwap(
    key: Key,
    expectedStoreRevision: number | null,
    nextValue: Value,
  ): Promise<
    | Readonly<{ status: "committed"; record: Readonly<StoreRecord<Value, Version>> }>
    | Readonly<{ status: "conflict"; current?: Readonly<StoreRecord<Value, Version>> }>
  > {
    this.#assertOpen();
    const current = await this.get(key);
    if (
      (expectedStoreRevision === null && current !== undefined) ||
      (expectedStoreRevision !== null && current?.storeRevision !== expectedStoreRevision)
    ) {
      return Object.freeze({ status: "conflict", ...(current ? { current } : {}) });
    }
    this.#access.validateNext?.(current?.value, nextValue);

    const next = Object.freeze({
      version: this.#access.version,
      storeRevision: nextStoreRevision(expectedStoreRevision),
      updatedAt: this.#access.updatedAt(nextValue),
      value: nextValue,
    });
    let swapped: unknown;
    try {
      swapped = await this.#adapter.compareAndSwap(key, expectedStoreRevision, next);
    } catch {
      return invalid(
        "store_commit_indeterminate",
        "store compare-and-swap completion is indeterminate",
      );
    }
    if (typeof swapped !== "boolean") {
      return invalid("store_commit_indeterminate", "store compare-and-swap result is invalid");
    }

    let retained: Readonly<StoreRecord<Value, Version>> | undefined;
    try {
      retained = await this.get(key);
    } catch {
      if (swapped) {
        return invalid("store_commit_unverified", "store commit could not be verified");
      }
      return invalid("store_commit_indeterminate", "store conflict could not be verified");
    }
    if (swapped) {
      if (retained && sameStoreRecord(retained, next)) {
        return Object.freeze({ status: "committed", record: retained });
      }
      return invalid("store_commit_unverified", "store did not retain the committed record");
    }
    if (
      retained === undefined ||
      (expectedStoreRevision !== null && retained.storeRevision === expectedStoreRevision)
    ) {
      return invalid("store_commit_indeterminate", "store returned an unverified conflict");
    }
    return Object.freeze({ status: "conflict", current: retained });
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    if (!this.#closing) {
      this.#closing = (async () => {
        try {
          await this.#adapter.close();
        } catch {
          return invalid("store_unavailable", "store close failed");
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

  #parseRead(raw: unknown, key: Key): Readonly<StoreRecord<Value, Version>> | undefined {
    if (raw === undefined) return undefined;
    let record: Record<string, unknown>;
    let value: Value;
    try {
      record = exactRecord(
        raw,
        ["version", "storeRevision", "updatedAt", "value"],
        "stored aggregate envelope",
        "store_record_invalid",
      );
      value = this.#access.parse(record.value);
    } catch {
      return invalid("store_record_invalid", "stored aggregate record is invalid");
    }
    if (record.version !== this.#access.version) {
      return invalid("store_record_invalid", "stored aggregate version is unsupported");
    }
    if (!this.#access.keyMatches(value, key)) {
      return invalid("store_key_mismatch", "stored aggregate belongs to another key");
    }
    const revision = storeRevision(record.storeRevision);
    const updatedAt = safeUpdatedAt(record.updatedAt);
    if (updatedAt !== this.#access.updatedAt(value)) {
      return invalid("store_record_invalid", "stored update time conflicts with its aggregate");
    }
    return Object.freeze({
      version: this.#access.version,
      storeRevision: revision,
      updatedAt,
      value,
    });
  }

  #assertOpen(): void {
    if (this.#closed) invalid("store_closed", "store is closed");
  }
}

export class GrantStore {
  readonly #store: AggregateStore<Grant, string, typeof OGP_GRANT_STORE_RECORD_VERSION>;

  constructor(adapter: unknown) {
    const captured = captureAdapter(adapter, "Grant");
    this.#store = new AggregateStore(
      {
        get: (grantId) => captured.get(grantId),
        compareAndSwap: (grantId, expectedStoreRevision, next) =>
          captured.compareAndSwap(Object.freeze({ grantId, expectedStoreRevision, next })),
        close: () => captured.close(),
      },
      {
        version: OGP_GRANT_STORE_RECORD_VERSION,
        parse: parseGrant,
        keyMatches: (grant, grantId) => grant.identity.grantId === grantId,
        updatedAt: (grant) => grant.updatedAt,
      },
    );
  }

  get(grantId: unknown): Promise<GrantStoreRecord | undefined> {
    return this.#store.get(canonicalGrantId(grantId));
  }

  compareAndSwap(value: unknown): Promise<GrantStoreCompareAndSwapResult> {
    const context: CaptureContext = new WeakSet();
    const record = exactRecord(
      value,
      ["grantId", "expectedStoreRevision", "next"],
      "Grant store compare-and-swap",
      "store_input_invalid",
      context,
    );
    const grantId = canonicalGrantId(record.grantId);
    const expected = expectedStoreRevision(record.expectedStoreRevision);
    let next: Grant;
    try {
      next = parseGrant(record.next);
    } catch {
      return invalid("store_input_invalid", "next Grant record is invalid");
    }
    if (next.identity.grantId !== grantId) {
      return invalid("store_key_mismatch", "next Grant belongs to another key");
    }
    return this.#store.compareAndSwap(grantId, expected, next);
  }

  close(): Promise<void> {
    return this.#store.close();
  }
}

export class OperationStore {
  readonly #store: AggregateStore<
    Operation,
    Readonly<OperationStoreKey>,
    typeof OGP_OPERATION_STORE_RECORD_VERSION
  >;

  constructor(adapter: unknown) {
    const captured = captureAdapter(adapter, "Operation");
    this.#store = new AggregateStore(
      {
        get: (key) => captured.get(key),
        compareAndSwap: (key, expectedStoreRevision, next) =>
          captured.compareAndSwap(Object.freeze({ key, expectedStoreRevision, next })),
        close: () => captured.close(),
      },
      {
        version: OGP_OPERATION_STORE_RECORD_VERSION,
        parse: parseOperation,
        keyMatches: (operation, key) =>
          operation.identity.grantId === key.grantId && operation.identity.chainId === key.chainId,
        updatedAt: (operation) => operation.updatedAt,
        validateNext: (current, next) => {
          if (
            current !== undefined &&
            !sameOperationIdentity(current, next) &&
            operationOccupiesLane(current)
          ) {
            invalid("store_lane_occupied", "another Operation still occupies this chain lane");
          }
        },
      },
    );
  }

  get(key: unknown): Promise<OperationStoreRecord | undefined> {
    return this.#store.get(parseOperationKey(key));
  }

  compareAndSwap(value: unknown): Promise<OperationStoreCompareAndSwapResult> {
    const context: CaptureContext = new WeakSet();
    const record = exactRecord(
      value,
      ["key", "expectedStoreRevision", "next"],
      "Operation store compare-and-swap",
      "store_input_invalid",
      context,
    );
    const key = parseOperationKey(record.key);
    const expected = expectedStoreRevision(record.expectedStoreRevision);
    let next: Operation;
    try {
      next = parseOperation(record.next);
    } catch {
      return invalid("store_input_invalid", "next Operation record is invalid");
    }
    if (next.identity.grantId !== key.grantId || next.identity.chainId !== key.chainId) {
      return invalid("store_key_mismatch", "next Operation belongs to another key");
    }
    return this.#store.compareAndSwap(key, expected, next);
  }

  close(): Promise<void> {
    return this.#store.close();
  }
}
