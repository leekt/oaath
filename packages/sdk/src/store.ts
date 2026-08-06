import {
  type CaptureContext,
  exactRecord as exactRecordValue,
  type Grant,
  type Operation,
  type OperationKind,
  operationOccupiesLane,
  parseGrant,
  parseOperation,
  sameGrantIdentity as sameGrantIdentityValue,
} from "@oaath/protocol";

export const OAATH_GRANT_STORE_RECORD_VERSION = "oaath.grant-store-record/v1" as const;
export const OAATH_OPERATION_STORE_RECORD_VERSION = "oaath.operation-store-record/v1" as const;

const MAX_GRANT_ID_LENGTH = 256;
const MAX_STORE_REVISION = Number.MAX_SAFE_INTEGER;
const HASH = /^0x[0-9a-f]{64}$/u;

export type StoreErrorCode =
  | "store_input_invalid"
  | "store_closed"
  | "store_unavailable"
  | "store_record_invalid"
  | "store_key_mismatch"
  | "store_identity_mismatch"
  | "store_lane_occupied"
  | "store_revision_exhausted"
  | "store_commit_indeterminate"
  | "store_commit_unverified";

export class OaathStoreError extends Error {
  readonly code: StoreErrorCode;

  constructor(code: StoreErrorCode, message: string) {
    super(message);
    this.name = "OaathStoreError";
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

export type GrantStoreRecord = Readonly<
  StoreRecord<Grant, typeof OAATH_GRANT_STORE_RECORD_VERSION>
>;
export type OperationStoreRecord = Readonly<
  StoreRecord<Operation, typeof OAATH_OPERATION_STORE_RECORD_VERSION>
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

/**
 * One lane per authority: execution work is session-signed and revocation work
 * is owner-signed, so the two kinds never queue behind or replace one another —
 * a revocation can proceed while an execution is still in flight on the same
 * chain.
 */
export interface OperationStoreKey {
  readonly grantId: string;
  readonly chainId: number;
  readonly kind: OperationKind;
}

export interface OperationStoreArchive {
  readonly userOperationHash: `0x${string}`;
  readonly record: Readonly<StoreRecord<unknown>>;
}

export interface OperationStoreAdapter {
  get(key: Readonly<OperationStoreKey>): Promise<unknown>;
  getArchived(input: {
    readonly key: Readonly<OperationStoreKey>;
    readonly userOperationHash: `0x${string}`;
  }): Promise<unknown>;
  compareAndSwap(input: {
    readonly key: Readonly<OperationStoreKey>;
    readonly expectedStoreRevision: number | null;
    readonly next: Readonly<StoreRecord<unknown>>;
    readonly archive: Readonly<OperationStoreArchive> | null;
  }): Promise<unknown>;
  close(): Promise<unknown>;
}

export type GrantStoreCompareAndSwapResult =
  | Readonly<{ status: "committed"; record: GrantStoreRecord }>
  | Readonly<{ status: "conflict"; current?: GrantStoreRecord }>;

export type OperationStoreCompareAndSwapResult =
  | Readonly<{ status: "committed"; record: OperationStoreRecord }>
  | Readonly<{ status: "conflict"; current?: OperationStoreRecord }>;

type AdapterCapabilities<Value, Key, Version extends string> = Readonly<{
  get: (key: Key) => Promise<unknown>;
  compareAndSwap: (
    key: Key,
    expectedStoreRevision: number | null,
    next: Readonly<StoreRecord<Value, Version>>,
    current: Readonly<StoreRecord<Value, Version>> | undefined,
  ) => Promise<unknown>;
  verifyCommitted?: (
    key: Key,
    current: Readonly<StoreRecord<Value, Version>> | undefined,
    next: Readonly<StoreRecord<Value, Version>>,
  ) => Promise<void>;
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
  throw new OaathStoreError(code, message);
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
  readonly getArchived?: (...arguments_: readonly unknown[]) => Promise<unknown>;
  readonly compareAndSwap: (...arguments_: readonly unknown[]) => Promise<unknown>;
  readonly close: (...arguments_: readonly unknown[]) => Promise<unknown>;
} {
  const keys =
    kind === "Operation"
      ? ["get", "getArchived", "compareAndSwap", "close"]
      : ["get", "compareAndSwap", "close"];
  const record = exactRecord(value, keys, `${kind} store adapter`, "store_input_invalid");
  return Object.freeze({
    get: capability(record.get, `${kind} store get`),
    ...(kind === "Operation"
      ? { getArchived: capability(record.getArchived, "Operation store getArchived") }
      : {}),
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

function canonicalOperationKind(value: unknown): OperationKind {
  if (value !== "execution" && value !== "revocation") {
    return invalid("store_input_invalid", "store kind must be execution or revocation");
  }
  return value;
}

function canonicalUserOperationHash(value: unknown): `0x${string}` {
  if (typeof value !== "string" || !HASH.test(value)) {
    return invalid(
      "store_input_invalid",
      "store UserOperation hash must be a lowercase 32-byte hash",
    );
  }
  return value as `0x${string}`;
}

function parseOperationKey(value: unknown): Readonly<OperationStoreKey> {
  const record = exactRecord(
    value,
    ["grantId", "chainId", "kind"],
    "Operation store key",
    "store_input_invalid",
  );
  return Object.freeze({
    grantId: canonicalGrantId(record.grantId),
    chainId: canonicalChainId(record.chainId),
    kind: canonicalOperationKind(record.kind),
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

function sameGrantIdentity(left: Grant, right: Grant): boolean {
  return sameGrantIdentityValue(left.identity, right.identity);
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
  readonly #adapter: AdapterCapabilities<Value, Key, Version>;
  readonly #access: AggregateAccess<Value, Key, Version>;
  #closed = false;
  #closing: Promise<void> | undefined;

  constructor(
    adapter: AdapterCapabilities<Value, Key, Version>,
    access: AggregateAccess<Value, Key, Version>,
  ) {
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
      swapped = await this.#adapter.compareAndSwap(key, expectedStoreRevision, next, current);
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
        try {
          await this.#adapter.verifyCommitted?.(key, current, next);
        } catch {
          return invalid("store_commit_unverified", "store commit evidence could not be verified");
        }
        return Object.freeze({ status: "committed", record: retained });
      }
      return invalid("store_commit_unverified", "store did not retain the committed record");
    }
    if (
      retained === undefined ||
      (expectedStoreRevision !== null && retained.storeRevision <= expectedStoreRevision)
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

  parse(raw: unknown, key: Key): Readonly<StoreRecord<Value, Version>> | undefined {
    this.#assertOpen();
    return this.#parseRead(raw, key);
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
  readonly #store: AggregateStore<Grant, string, typeof OAATH_GRANT_STORE_RECORD_VERSION>;

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
        version: OAATH_GRANT_STORE_RECORD_VERSION,
        parse: parseGrant,
        keyMatches: (grant, grantId) => grant.identity.grantId === grantId,
        updatedAt: (grant) => grant.updatedAt,
        validateNext: (current, next) => {
          if (current !== undefined && !sameGrantIdentity(current, next)) {
            invalid("store_identity_mismatch", "next Grant identity does not match current Grant");
          }
        },
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
    typeof OAATH_OPERATION_STORE_RECORD_VERSION
  >;
  readonly #getArchived: (
    input: Readonly<{
      key: Readonly<OperationStoreKey>;
      userOperationHash: `0x${string}`;
    }>,
  ) => Promise<unknown>;

  constructor(adapter: unknown) {
    const captured = captureAdapter(adapter, "Operation");
    const getArchived = captured.getArchived;
    if (!getArchived) invalid("store_input_invalid", "Operation store getArchived is unavailable");
    let store: AggregateStore<
      Operation,
      Readonly<OperationStoreKey>,
      typeof OAATH_OPERATION_STORE_RECORD_VERSION
    >;
    const archiveFor = (
      current: OperationStoreRecord | undefined,
      next: OperationStoreRecord,
    ): Readonly<OperationStoreArchive> | null => {
      if (current === undefined || sameOperationIdentity(current.value, next.value)) return null;
      return Object.freeze({
        userOperationHash: current.value.identity.userOperationHash,
        record: current,
      });
    };
    store = new AggregateStore(
      {
        get: (key) => captured.get(key),
        compareAndSwap: (key, expectedStoreRevision, next, current) =>
          captured.compareAndSwap(
            Object.freeze({
              key,
              expectedStoreRevision,
              next,
              archive: archiveFor(current, next),
            }),
          ),
        verifyCommitted: async (key, current, next) => {
          const archive = archiveFor(current, next);
          if (archive === null) return;
          const raw = await getArchived(
            Object.freeze({ key, userOperationHash: archive.userOperationHash }),
          );
          const retained = store.parse(raw, key);
          if (
            current === undefined ||
            retained === undefined ||
            !sameStoreRecord(retained, current) ||
            retained.value.identity.userOperationHash !== archive.userOperationHash ||
            operationOccupiesLane(retained.value)
          ) {
            throw new Error("Operation archive does not retain the exact terminal record");
          }
        },
        close: () => captured.close(),
      },
      {
        version: OAATH_OPERATION_STORE_RECORD_VERSION,
        parse: parseOperation,
        keyMatches: (operation, key) =>
          operation.identity.grantId === key.grantId &&
          operation.identity.chainId === key.chainId &&
          operation.identity.kind === key.kind,
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
    this.#store = store;
    this.#getArchived = (input) => getArchived(input);
  }

  get(key: unknown): Promise<OperationStoreRecord | undefined> {
    return this.#store.get(parseOperationKey(key));
  }

  async getExact(
    keyValue: unknown,
    expectedUserOperationHashValue: unknown,
  ): Promise<OperationStoreRecord | undefined> {
    const key = parseOperationKey(keyValue);
    const expectedUserOperationHash = canonicalUserOperationHash(expectedUserOperationHashValue);
    const current = await this.#store.get(key);
    if (current?.value.identity.userOperationHash === expectedUserOperationHash) return current;

    let raw: unknown;
    try {
      raw = await this.#getArchived(
        Object.freeze({ key, userOperationHash: expectedUserOperationHash }),
      );
    } catch {
      return invalid("store_unavailable", "Operation archive read is unavailable");
    }
    const archived = this.#store.parse(raw, key);
    if (archived === undefined) return undefined;
    if (archived.value.identity.userOperationHash !== expectedUserOperationHash) {
      return invalid("store_identity_mismatch", "archived Operation has another identity");
    }
    if (operationOccupiesLane(archived.value)) {
      return invalid("store_record_invalid", "archived Operation is not terminal");
    }
    return archived;
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
    if (
      next.identity.grantId !== key.grantId ||
      next.identity.chainId !== key.chainId ||
      next.identity.kind !== key.kind
    ) {
      return invalid("store_key_mismatch", "next Operation belongs to another key");
    }
    return this.#store.compareAndSwap(key, expected, next);
  }

  close(): Promise<void> {
    return this.#store.close();
  }
}
