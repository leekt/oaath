/**
 * Durable fact owner for Final EIP-5792 wallet-call bundle identities.
 *
 * A present key reserves the application-provided ID regardless of chain. State
 * advances once through compare-and-swap, and only an expired terminal record
 * can be removed. Adapter acknowledgements are never trusted without a fresh
 * retained-record read.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type CaptureContext, exactRecord as exactRecordValue } from "@oaath/protocol";
import type { Hash } from "viem";
import {
  OAATH_WALLET_CALL_BUNDLE_STORE_RECORD_VERSION,
  OAATH_WALLET_CALL_BUNDLE_VERSION,
  parseWalletCallBundleKey,
  parseWalletCallBundleRecord,
  type WalletCallBundleKey,
  type WalletCallBundleOperation,
  type WalletCallBundleRecord,
  type WalletCallBundleStoreAdapter,
  type WalletCallBundleStoreRecord,
} from "../persistence/interfaces.js";
import {
  OaathStoreError,
  type OperationStoreKey,
  type StoreErrorCode,
  type StoreRecord,
} from "../store.js";

export const WALLET_CALL_BUNDLE_RETENTION_SECONDS = 86_400;

const HASH = /^0x[0-9a-f]{64}$/u;
const MAX_OPERATION_GRANT_ID_LENGTH = 256;
const MAX_STORE_REVISION = Number.MAX_SAFE_INTEGER;

interface AdapterCapabilities extends WalletCallBundleStoreAdapter {
  readonly get: (key: Readonly<WalletCallBundleKey>) => Promise<unknown>;
  readonly compareAndSwap: (
    input: Readonly<{
      key: Readonly<WalletCallBundleKey>;
      expectedStoreRevision: number | null;
      next: Readonly<StoreRecord<unknown>>;
    }>,
  ) => Promise<unknown>;
  readonly compareAndDelete: (
    input: Readonly<{
      key: Readonly<WalletCallBundleKey>;
      expectedStoreRevision: number;
    }>,
  ) => Promise<unknown>;
  readonly close: () => Promise<unknown>;
}

export type WalletCallBundleMutationResult =
  | Readonly<{ status: "committed"; record: WalletCallBundleStoreRecord }>
  | Readonly<{ status: "conflict"; current?: WalletCallBundleStoreRecord }>;

export type DeleteExpiredWalletCallBundleResult =
  | Readonly<{ status: "deleted" }>
  | Readonly<{ status: "absent" }>
  | Readonly<{ status: "conflict"; current: WalletCallBundleStoreRecord }>;

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

function captureAdapter(value: unknown): AdapterCapabilities {
  const record = exactRecord(
    value,
    ["get", "compareAndSwap", "compareAndDelete", "close"],
    "Wallet call bundle store adapter",
    "store_input_invalid",
  );
  const get = capability(record.get, "Wallet call bundle store get");
  const compareAndSwap = capability(
    record.compareAndSwap,
    "Wallet call bundle store compareAndSwap",
  );
  const compareAndDelete = capability(
    record.compareAndDelete,
    "Wallet call bundle store compareAndDelete",
  );
  const close = capability(record.close, "Wallet call bundle store close");
  return Object.freeze({
    get: (key: Readonly<WalletCallBundleKey>) => get(key),
    compareAndSwap: (input: Parameters<WalletCallBundleStoreAdapter["compareAndSwap"]>[0]) =>
      compareAndSwap(input),
    compareAndDelete: (input: Parameters<WalletCallBundleStoreAdapter["compareAndDelete"]>[0]) =>
      compareAndDelete(input),
    close: () => close(),
  });
}

function inputKey(value: unknown): Readonly<WalletCallBundleKey> {
  try {
    return parseWalletCallBundleKey(value);
  } catch {
    return invalid("store_input_invalid", "Wallet call bundle key is invalid");
  }
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

function hash(value: unknown, label: string): Hash {
  if (typeof value !== "string" || !HASH.test(value)) {
    return invalid("store_input_invalid", `${label} must be a lowercase 32-byte hash`);
  }
  return value as Hash;
}

function operationGrantId(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > MAX_OPERATION_GRANT_ID_LENGTH ||
    value !== value.trim()
  ) {
    return invalid("store_input_invalid", "Wallet call bundle operation grantId is invalid");
  }
  return value;
}

function inputOperation(value: unknown): Readonly<WalletCallBundleOperation> {
  const context: CaptureContext = new WeakSet();
  const operation = exactRecord(
    value,
    ["key", "userOperationHash"],
    "Wallet call bundle operation binding",
    "store_input_invalid",
    context,
  );
  const key = exactRecord(
    operation.key,
    ["grantId", "chainId", "kind"],
    "Wallet call bundle operation key",
    "store_input_invalid",
    context,
  );
  if (key.kind !== "execution") {
    return invalid(
      "store_input_invalid",
      "Wallet call bundle operation must use an execution lane",
    );
  }
  return Object.freeze({
    key: Object.freeze({
      grantId: operationGrantId(key.grantId),
      chainId: safeInteger(
        key.chainId,
        "Wallet call bundle operation chainId",
        "store_input_invalid",
        1,
      ),
      kind: "execution",
    }),
    userOperationHash: hash(operation.userOperationHash, "Wallet call bundle userOperationHash"),
  });
}

function inputBundleRecord(value: unknown): Readonly<WalletCallBundleRecord> {
  try {
    return parseWalletCallBundleRecord(value);
  } catch {
    return invalid("store_input_invalid", "Wallet call bundle value is invalid");
  }
}

function storedBundleRecord(value: unknown): Readonly<WalletCallBundleRecord> {
  try {
    return parseWalletCallBundleRecord(value);
  } catch {
    return invalid("store_record_invalid", "Stored wallet call bundle value is invalid");
  }
}

function sameKey(left: WalletCallBundleKey, right: WalletCallBundleKey): boolean {
  return (
    left.providerScopeId === right.providerScopeId &&
    left.account === right.account &&
    left.id === right.id
  );
}

function sameOperationKey(left: OperationStoreKey, right: OperationStoreKey): boolean {
  return (
    left.grantId === right.grantId && left.chainId === right.chainId && left.kind === right.kind
  );
}

function sameOperation(
  left: Readonly<WalletCallBundleOperation> | null,
  right: Readonly<WalletCallBundleOperation> | null,
): boolean {
  if (left === null || right === null) return left === right;
  return (
    left.userOperationHash === right.userOperationHash && sameOperationKey(left.key, right.key)
  );
}

function sameValue(left: WalletCallBundleRecord, right: WalletCallBundleRecord): boolean {
  return (
    left.version === right.version &&
    left.providerScopeId === right.providerScopeId &&
    left.id === right.id &&
    left.account === right.account &&
    left.chainId === right.chainId &&
    left.createdAt === right.createdAt &&
    left.requestHash === right.requestHash &&
    sameOperation(left.operation, right.operation) &&
    left.state === right.state
  );
}

function sameStoreRecord(
  left: WalletCallBundleStoreRecord | undefined,
  right: WalletCallBundleStoreRecord,
): boolean {
  return (
    left !== undefined &&
    left.version === right.version &&
    left.storeRevision === right.storeRevision &&
    left.updatedAt === right.updatedAt &&
    sameValue(left.value, right.value)
  );
}

function sameImmutableIdentity(
  left: WalletCallBundleRecord,
  right: WalletCallBundleRecord,
): boolean {
  return (
    left.version === right.version &&
    left.providerScopeId === right.providerScopeId &&
    left.id === right.id &&
    left.account === right.account &&
    left.chainId === right.chainId &&
    left.createdAt === right.createdAt &&
    left.requestHash === right.requestHash
  );
}

function stateRank(state: WalletCallBundleRecord["state"]): number {
  if (state === "accepted") return 0;
  if (state === "operation_bound") return 1;
  return 2;
}

function requireCompatibleHistory(
  previous: WalletCallBundleStoreRecord,
  current: WalletCallBundleStoreRecord,
): void {
  if (!sameImmutableIdentity(previous.value, current.value)) {
    invalid("store_identity_mismatch", "Wallet call bundle immutable identity changed");
  }
  if (
    stateRank(current.value.state) < stateRank(previous.value.state) ||
    current.updatedAt < previous.updatedAt
  ) {
    invalid("store_record_invalid", "Wallet call bundle history moved backward");
  }
  if (
    previous.value.operation !== null &&
    !sameOperation(previous.value.operation, current.value.operation)
  ) {
    invalid("store_identity_mismatch", "Wallet call bundle operation binding changed");
  }
}

function conflict(
  current?: WalletCallBundleStoreRecord,
): Readonly<{ status: "conflict"; current?: WalletCallBundleStoreRecord }> {
  return Object.freeze({ status: "conflict" as const, ...(current ? { current } : {}) });
}

function nextStoreRevision(current: number | null): number {
  if (current === MAX_STORE_REVISION) {
    return invalid("store_revision_exhausted", "Wallet call bundle store revision is exhausted");
  }
  return current === null ? 0 : current + 1;
}

function reserveInput(value: unknown): Readonly<{
  key: Readonly<WalletCallBundleKey>;
  record: Readonly<WalletCallBundleRecord>;
}> {
  const input = exactRecord(
    value,
    ["key", "chainId", "createdAt", "requestHash"],
    "Wallet call bundle reservation",
    "store_input_invalid",
  );
  const key = inputKey(input.key);
  const record = inputBundleRecord({
    version: OAATH_WALLET_CALL_BUNDLE_VERSION,
    providerScopeId: key.providerScopeId,
    id: key.id,
    account: key.account,
    chainId: input.chainId,
    createdAt: input.createdAt,
    requestHash: input.requestHash,
    operation: null,
    state: "accepted",
  });
  return Object.freeze({ key, record });
}

function bindInput(value: unknown): Readonly<{
  key: Readonly<WalletCallBundleKey>;
  operation: Readonly<WalletCallBundleOperation>;
  updatedAt: number;
}> {
  const input = exactRecord(
    value,
    ["key", "operation", "updatedAt"],
    "Wallet call bundle operation binding",
    "store_input_invalid",
  );
  return Object.freeze({
    key: inputKey(input.key),
    operation: inputOperation(input.operation),
    updatedAt: safeInteger(
      input.updatedAt,
      "Wallet call bundle transition time",
      "store_input_invalid",
      0,
    ),
  });
}

function terminalInput(value: unknown): Readonly<{
  key: Readonly<WalletCallBundleKey>;
  updatedAt: number;
}> {
  const input = exactRecord(
    value,
    ["key", "updatedAt"],
    "Wallet call bundle terminal transition",
    "store_input_invalid",
  );
  return Object.freeze({
    key: inputKey(input.key),
    updatedAt: safeInteger(
      input.updatedAt,
      "Wallet call bundle transition time",
      "store_input_invalid",
      0,
    ),
  });
}

/**
 * The sole state-machine and retention owner for durable wallet-call bundles.
 * All methods capture caller input before invoking an adapter capability.
 */
export class WalletCallBundleStore {
  readonly #adapter: AdapterCapabilities;
  #closed = false;
  #closing: Promise<void> | undefined;

  constructor(adapter: unknown) {
    this.#adapter = captureAdapter(adapter);
  }

  async get(key: unknown): Promise<WalletCallBundleStoreRecord | undefined> {
    const captured = inputKey(key);
    this.#assertOpen();
    return this.#read(captured);
  }

  async reserveAccepted(value: unknown): Promise<WalletCallBundleMutationResult> {
    const input = reserveInput(value);
    this.#assertOpen();
    const current = await this.#read(input.key);
    if (current !== undefined) return conflict(current);
    return this.#compareAndSwap(input.key, null, input.record, input.record.createdAt);
  }

  async bindOperation(value: unknown): Promise<WalletCallBundleMutationResult> {
    const input = bindInput(value);
    this.#assertOpen();
    const current = await this.#read(input.key);
    if (
      current === undefined ||
      current.value.state !== "accepted" ||
      input.updatedAt < current.updatedAt
    ) {
      return conflict(current);
    }
    if (input.operation.key.chainId !== current.value.chainId) {
      return invalid("store_input_invalid", "Wallet call bundle operation chainId does not match");
    }
    const next = inputBundleRecord({
      ...current.value,
      operation: input.operation,
      state: "operation_bound",
    });
    return this.#compareAndSwap(input.key, current.storeRevision, next, input.updatedAt, current);
  }

  async markTerminal(value: unknown): Promise<WalletCallBundleMutationResult> {
    const input = terminalInput(value);
    this.#assertOpen();
    const current = await this.#read(input.key);
    if (
      current === undefined ||
      current.value.state === "terminal" ||
      input.updatedAt < current.updatedAt
    ) {
      return conflict(current);
    }
    const next = inputBundleRecord({ ...current.value, state: "terminal" });
    return this.#compareAndSwap(input.key, current.storeRevision, next, input.updatedAt, current);
  }

  async deleteExpiredTerminal(
    key: unknown,
    now: unknown,
    retentionSeconds: unknown = WALLET_CALL_BUNDLE_RETENTION_SECONDS,
  ): Promise<DeleteExpiredWalletCallBundleResult> {
    const capturedKey = inputKey(key);
    const capturedNow = safeInteger(
      now,
      "Wallet call bundle cleanup time",
      "store_input_invalid",
      0,
    );
    const capturedRetention = safeInteger(
      retentionSeconds,
      "Wallet call bundle retention",
      "store_input_invalid",
      0,
    );
    this.#assertOpen();

    const current = await this.#read(capturedKey);
    if (current === undefined) return Object.freeze({ status: "absent" as const });
    if (
      current.value.state !== "terminal" ||
      capturedNow < current.updatedAt ||
      capturedNow - current.updatedAt < capturedRetention
    ) {
      return Object.freeze({ status: "conflict" as const, current });
    }
    return this.#compareAndDelete(capturedKey, current);
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    if (!this.#closing) {
      this.#closing = (async () => {
        try {
          await this.#adapter.close();
        } catch {
          return invalid("store_unavailable", "Wallet call bundle store close failed");
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

  async #read(
    key: Readonly<WalletCallBundleKey>,
  ): Promise<WalletCallBundleStoreRecord | undefined> {
    let raw: unknown;
    try {
      raw = await this.#adapter.get(key);
    } catch {
      return invalid("store_unavailable", "Wallet call bundle store read is unavailable");
    }
    return this.#parseRead(raw, key);
  }

  #parseRead(
    raw: unknown,
    key: Readonly<WalletCallBundleKey>,
  ): WalletCallBundleStoreRecord | undefined {
    if (raw === undefined) return undefined;
    let envelope: Record<string, unknown>;
    let value: Readonly<WalletCallBundleRecord>;
    try {
      envelope = exactRecord(
        raw,
        ["version", "storeRevision", "updatedAt", "value"],
        "Stored wallet call bundle envelope",
        "store_record_invalid",
      );
      value = storedBundleRecord(envelope.value);
    } catch {
      return invalid("store_record_invalid", "Stored wallet call bundle record is invalid");
    }
    if (envelope.version !== OAATH_WALLET_CALL_BUNDLE_STORE_RECORD_VERSION) {
      return invalid("store_record_invalid", "Stored wallet call bundle envelope is unsupported");
    }
    const valueKey = Object.freeze({
      providerScopeId: value.providerScopeId,
      account: value.account,
      id: value.id,
    });
    if (!sameKey(valueKey, key)) {
      return invalid("store_key_mismatch", "Stored wallet call bundle belongs to another key");
    }
    const storeRevision = safeInteger(
      envelope.storeRevision,
      "Stored wallet call bundle revision",
      "store_record_invalid",
      0,
    );
    const updatedAt = safeInteger(
      envelope.updatedAt,
      "Stored wallet call bundle update time",
      "store_record_invalid",
      0,
    );
    if (updatedAt < value.createdAt) {
      return invalid("store_record_invalid", "Stored wallet call bundle predates its creation");
    }
    return Object.freeze({
      version: OAATH_WALLET_CALL_BUNDLE_STORE_RECORD_VERSION,
      storeRevision,
      updatedAt,
      value,
    });
  }

  async #compareAndSwap(
    key: Readonly<WalletCallBundleKey>,
    expectedStoreRevision: number | null,
    value: Readonly<WalletCallBundleRecord>,
    updatedAt: number,
    previous?: WalletCallBundleStoreRecord,
  ): Promise<WalletCallBundleMutationResult> {
    const next: WalletCallBundleStoreRecord = Object.freeze({
      version: OAATH_WALLET_CALL_BUNDLE_STORE_RECORD_VERSION,
      storeRevision: nextStoreRevision(expectedStoreRevision),
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
        "Wallet call bundle compare-and-swap completion is indeterminate",
      );
    }
    if (typeof swapped !== "boolean") {
      return invalid(
        "store_commit_indeterminate",
        "Wallet call bundle compare-and-swap result is invalid",
      );
    }

    let retained: WalletCallBundleStoreRecord | undefined;
    try {
      retained = await this.#read(key);
    } catch {
      return swapped
        ? invalid("store_commit_unverified", "Wallet call bundle commit could not be verified")
        : invalid(
            "store_commit_indeterminate",
            "Wallet call bundle conflict could not be verified",
          );
    }
    if (swapped) {
      if (retained !== undefined && sameStoreRecord(retained, next)) {
        return Object.freeze({ status: "committed" as const, record: retained });
      }
      return invalid(
        "store_commit_unverified",
        "Wallet call bundle store did not retain the write",
      );
    }
    if (
      retained === undefined ||
      (expectedStoreRevision !== null && retained.storeRevision <= expectedStoreRevision)
    ) {
      return invalid("store_commit_indeterminate", "Wallet call bundle conflict is unverified");
    }
    if (previous !== undefined) requireCompatibleHistory(previous, retained);
    return conflict(retained);
  }

  async #compareAndDelete(
    key: Readonly<WalletCallBundleKey>,
    previous: WalletCallBundleStoreRecord,
  ): Promise<DeleteExpiredWalletCallBundleResult> {
    let deleted: unknown;
    try {
      deleted = await this.#adapter.compareAndDelete(
        Object.freeze({ key, expectedStoreRevision: previous.storeRevision }),
      );
    } catch {
      return invalid(
        "store_commit_indeterminate",
        "Wallet call bundle compare-and-delete completion is indeterminate",
      );
    }
    if (typeof deleted !== "boolean") {
      return invalid(
        "store_commit_indeterminate",
        "Wallet call bundle compare-and-delete result is invalid",
      );
    }

    let retained: WalletCallBundleStoreRecord | undefined;
    try {
      retained = await this.#read(key);
    } catch {
      return deleted
        ? invalid("store_commit_unverified", "Wallet call bundle deletion could not be verified")
        : invalid(
            "store_commit_indeterminate",
            "Wallet call bundle delete conflict could not be verified",
          );
    }
    if (deleted) {
      if (retained === undefined) return Object.freeze({ status: "deleted" as const });
      return invalid(
        "store_commit_unverified",
        "Wallet call bundle store retained a deleted record",
      );
    }
    if (retained === undefined) return Object.freeze({ status: "absent" as const });
    if (retained.storeRevision <= previous.storeRevision) {
      return invalid(
        "store_commit_indeterminate",
        "Wallet call bundle delete conflict is unverified",
      );
    }
    requireCompatibleHistory(previous, retained);
    return Object.freeze({ status: "conflict" as const, current: retained });
  }

  #assertOpen(): void {
    if (this.#closed) invalid("store_closed", "Wallet call bundle store is closed");
  }
}
