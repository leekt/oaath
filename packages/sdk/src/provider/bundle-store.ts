/**
 * Durable fact owner for Final EIP-5792 wallet-call bundle identities.
 *
 * A present provider-and-account-scoped key permanently reserves the
 * application-provided ID regardless of Grant or chain. State advances monotonically
 * through compare-and-swap, and terminal records remain durable tombstones.
 * Adapter acknowledgements are never trusted without a retained-record read.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type CaptureContext,
  exactRecord as exactRecordValue,
  parseOperationIdentity,
} from "@oaath/protocol";
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
import { OaathStoreError, type StoreErrorCode, type StoreRecord } from "../store.js";
import { captureWalletCallResultCapabilities } from "./result-capabilities.js";

export const WALLET_CALL_BUNDLE_PUBLICATION_LEASE_SECONDS = 30;

const HASH = /^0x[0-9a-f]{64}$/u;
const MAX_STORE_REVISION = Number.MAX_SAFE_INTEGER;

interface AdapterCapabilities extends WalletCallBundleStoreAdapter {
  readonly get: (key: Readonly<WalletCallBundleKey>) => Promise<unknown>;
  readonly compareAndSwap: (
    input: Readonly<{
      key: Readonly<WalletCallBundleKey>;
      expectedStoreRevision: number | null;
      expectedGeneration: Hash | null;
      next: Readonly<StoreRecord<unknown>>;
    }>,
  ) => Promise<unknown>;
  readonly close: () => Promise<unknown>;
}

export type WalletCallBundleMutationResult =
  | Readonly<{ status: "committed"; record: WalletCallBundleStoreRecord }>
  | Readonly<{ status: "conflict"; current?: WalletCallBundleStoreRecord }>;

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
    ["get", "compareAndSwap", "close"],
    "Wallet call bundle store adapter",
    "store_input_invalid",
  );
  const get = capability(record.get, "Wallet call bundle store get");
  const compareAndSwap = capability(
    record.compareAndSwap,
    "Wallet call bundle store compareAndSwap",
  );
  const close = capability(record.close, "Wallet call bundle store close");
  return Object.freeze({
    get: (key: Readonly<WalletCallBundleKey>) => get(key),
    compareAndSwap: (input: Parameters<WalletCallBundleStoreAdapter["compareAndSwap"]>[0]) =>
      compareAndSwap(input),
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

function inputOperation(value: unknown): Readonly<WalletCallBundleOperation> {
  const context: CaptureContext = new WeakSet();
  const operation = exactRecord(
    value,
    ["identity", "resultCapabilities"],
    "Wallet call bundle operation reservation",
    "store_input_invalid",
    context,
  );
  try {
    const identity = parseOperationIdentity(operation.identity);
    if (identity.kind !== "execution" || identity.requestHash === null) {
      return invalid(
        "store_input_invalid",
        "Wallet call bundle operation must be a provider execution identity",
      );
    }
    const resultCapabilities =
      operation.resultCapabilities === null
        ? null
        : captureWalletCallResultCapabilities(operation.resultCapabilities, context, (message) =>
            invalid("store_input_invalid", message),
          );
    return Object.freeze({ identity, resultCapabilities });
  } catch (error) {
    if (error instanceof OaathStoreError) throw error;
    return invalid("store_input_invalid", "Wallet call bundle operation identity is invalid");
  }
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

function sameOperation(
  left: Readonly<WalletCallBundleOperation> | null,
  right: Readonly<WalletCallBundleOperation> | null,
): boolean {
  if (left === null || right === null) return left === right;
  return JSON.stringify(left) === JSON.stringify(right);
}

function sameValue(left: WalletCallBundleRecord, right: WalletCallBundleRecord): boolean {
  return (
    left.version === right.version &&
    left.providerScopeId === right.providerScopeId &&
    left.grantId === right.grantId &&
    left.generation === right.generation &&
    left.id === right.id &&
    left.account === right.account &&
    left.chainId === right.chainId &&
    left.createdAt === right.createdAt &&
    left.publicationExpiresAt === right.publicationExpiresAt &&
    left.publicationReleasedAt === right.publicationReleasedAt &&
    left.requestHash === right.requestHash &&
    sameOperation(left.operation, right.operation) &&
    left.state === right.state &&
    left.terminalFrom === right.terminalFrom
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
    left.grantId === right.grantId &&
    left.generation === right.generation &&
    left.id === right.id &&
    left.account === right.account &&
    left.chainId === right.chainId &&
    left.createdAt === right.createdAt &&
    left.publicationExpiresAt === right.publicationExpiresAt &&
    left.requestHash === right.requestHash
  );
}

function stateRank(state: WalletCallBundleRecord["state"]): number {
  if (state === "accepted") return 0;
  if (state === "operation_reserved") return 1;
  if (state === "operation_bound") return 2;
  return 3;
}

function requiredStoreRevision(value: WalletCallBundleRecord): number {
  const releaseRevision = value.publicationReleasedAt === null ? 0 : 1;
  if (value.state !== "terminal") return stateRank(value.state) + releaseRevision;
  if (value.terminalFrom === null) {
    return invalid("store_record_invalid", "Wallet call bundle terminal origin is missing");
  }
  return stateRank(value.terminalFrom) + releaseRevision + 1;
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
  if (current.value.state === "terminal") {
    const terminalFrom = current.value.terminalFrom;
    if (terminalFrom === null) {
      invalid("store_record_invalid", "Wallet call bundle terminal origin is missing");
    }
    if (previous.value.state === "terminal") {
      if (previous.value.terminalFrom !== terminalFrom) {
        invalid("store_record_invalid", "Wallet call bundle terminal origin changed");
      }
    } else {
      const requiredRevisions =
        requiredStoreRevision(current.value) - requiredStoreRevision(previous.value);
      if (
        requiredRevisions < 1 ||
        current.storeRevision - previous.storeRevision < requiredRevisions
      ) {
        invalid("store_record_invalid", "Wallet call bundle terminal origin is not reachable");
      }
    }
  }
  if (
    previous.value.operation !== null &&
    !sameOperation(previous.value.operation, current.value.operation)
  ) {
    invalid("store_identity_mismatch", "Wallet call bundle operation binding changed");
  }
  if (
    previous.value.publicationReleasedAt !== null &&
    current.value.publicationReleasedAt !== previous.value.publicationReleasedAt
  ) {
    invalid("store_record_invalid", "Wallet call bundle publication release changed");
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
    [
      "key",
      "grantId",
      "generation",
      "account",
      "chainId",
      "createdAt",
      "publicationExpiresAt",
      "requestHash",
    ],
    "Wallet call bundle reservation",
    "store_input_invalid",
  );
  const key = inputKey(input.key);
  const record = inputBundleRecord({
    version: OAATH_WALLET_CALL_BUNDLE_VERSION,
    providerScopeId: key.providerScopeId,
    grantId: input.grantId,
    generation: hash(input.generation, "Wallet call bundle generation"),
    id: key.id,
    account: input.account,
    chainId: input.chainId,
    createdAt: input.createdAt,
    publicationExpiresAt: input.publicationExpiresAt,
    publicationReleasedAt: null,
    requestHash: input.requestHash,
    operation: null,
    state: "accepted",
    terminalFrom: null,
  });
  if (record.account !== key.account) {
    return invalid("store_input_invalid", "Wallet call bundle account contradicts its key");
  }
  return Object.freeze({ key, record });
}

function reserveOperationInput(value: unknown): Readonly<{
  key: Readonly<WalletCallBundleKey>;
  expectedStoreRevision: number;
  expectedGeneration: Hash;
  operation: Readonly<WalletCallBundleOperation>;
  updatedAt: number;
}> {
  const input = exactRecord(
    value,
    ["key", "expectedStoreRevision", "expectedGeneration", "operation", "updatedAt"],
    "Wallet call bundle operation binding",
    "store_input_invalid",
  );
  const key = inputKey(input.key);
  const operation = inputOperation(input.operation);
  return Object.freeze({
    key,
    expectedStoreRevision: safeInteger(
      input.expectedStoreRevision,
      "Wallet call bundle expected store revision",
      "store_input_invalid",
      0,
    ),
    expectedGeneration: hash(input.expectedGeneration, "Wallet call bundle expected generation"),
    operation,
    updatedAt: safeInteger(
      input.updatedAt,
      "Wallet call bundle transition time",
      "store_input_invalid",
      0,
    ),
  });
}

function fencedTransitionInput(
  value: unknown,
  label: string,
): Readonly<{
  key: Readonly<WalletCallBundleKey>;
  expectedStoreRevision: number;
  expectedGeneration: Hash;
  updatedAt: number;
}> {
  const input = exactRecord(
    value,
    ["key", "expectedStoreRevision", "expectedGeneration", "updatedAt"],
    label,
    "store_input_invalid",
  );
  return Object.freeze({
    key: inputKey(input.key),
    expectedStoreRevision: safeInteger(
      input.expectedStoreRevision,
      "Wallet call bundle expected store revision",
      "store_input_invalid",
      0,
    ),
    expectedGeneration: hash(input.expectedGeneration, "Wallet call bundle expected generation"),
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
    return this.#compareAndSwap(input.key, null, null, input.record, input.record.createdAt);
  }

  async reserveOperation(value: unknown): Promise<WalletCallBundleMutationResult> {
    const input = reserveOperationInput(value);
    this.#assertOpen();
    const current = await this.#read(input.key);
    if (
      current === undefined ||
      current.storeRevision !== input.expectedStoreRevision ||
      current.value.generation !== input.expectedGeneration ||
      current.value.state !== "accepted" ||
      input.updatedAt < current.updatedAt
    ) {
      return conflict(current);
    }
    if (input.operation.identity.chainId !== current.value.chainId) {
      return invalid("store_input_invalid", "Wallet call bundle operation chainId does not match");
    }
    if (input.operation.identity.account !== current.value.account) {
      return invalid("store_input_invalid", "Wallet call bundle operation account does not match");
    }
    if (input.operation.identity.grantId !== current.value.grantId) {
      return invalid("store_input_invalid", "Wallet call bundle operation grantId does not match");
    }
    const next = inputBundleRecord({
      ...current.value,
      operation: input.operation,
      state: "operation_reserved",
    });
    return this.#compareAndSwap(
      input.key,
      input.expectedStoreRevision,
      input.expectedGeneration,
      next,
      input.updatedAt,
      current,
    );
  }

  async confirmOperationPublished(value: unknown): Promise<WalletCallBundleMutationResult> {
    const input = fencedTransitionInput(
      value,
      "Wallet call bundle operation publication confirmation",
    );
    this.#assertOpen();
    const current = await this.#read(input.key);
    if (
      current === undefined ||
      current.storeRevision !== input.expectedStoreRevision ||
      current.value.generation !== input.expectedGeneration ||
      current.value.state !== "operation_reserved" ||
      input.updatedAt < current.updatedAt
    ) {
      return conflict(current);
    }
    const next = inputBundleRecord({ ...current.value, state: "operation_bound" });
    return this.#compareAndSwap(
      input.key,
      input.expectedStoreRevision,
      input.expectedGeneration,
      next,
      input.updatedAt,
      current,
    );
  }

  async releaseOperationPublication(value: unknown): Promise<WalletCallBundleMutationResult> {
    const input = fencedTransitionInput(value, "Wallet call bundle publication release");
    this.#assertOpen();
    const current = await this.#read(input.key);
    if (
      current === undefined ||
      current.storeRevision !== input.expectedStoreRevision ||
      current.value.generation !== input.expectedGeneration ||
      current.value.state !== "operation_bound" ||
      current.value.publicationReleasedAt !== null ||
      input.updatedAt < current.updatedAt
    ) {
      return conflict(current);
    }
    const next = inputBundleRecord({
      ...current.value,
      publicationReleasedAt: input.updatedAt,
    });
    return this.#compareAndSwap(
      input.key,
      input.expectedStoreRevision,
      input.expectedGeneration,
      next,
      input.updatedAt,
      current,
    );
  }

  async markTerminal(value: unknown): Promise<WalletCallBundleMutationResult> {
    const input = fencedTransitionInput(value, "Wallet call bundle terminal transition");
    this.#assertOpen();
    const current = await this.#read(input.key);
    if (
      current === undefined ||
      current.storeRevision !== input.expectedStoreRevision ||
      current.value.generation !== input.expectedGeneration ||
      input.updatedAt < current.updatedAt
    ) {
      return conflict(current);
    }
    const terminalFrom = current.value.state;
    if (terminalFrom === "terminal") return conflict(current);
    const next = inputBundleRecord({ ...current.value, state: "terminal", terminalFrom });
    return this.#compareAndSwap(
      input.key,
      input.expectedStoreRevision,
      input.expectedGeneration,
      next,
      input.updatedAt,
      current,
    );
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
    if (storeRevision !== requiredStoreRevision(value)) {
      return invalid(
        "store_record_invalid",
        "Stored wallet call bundle revision contradicts its state",
      );
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
    expectedGeneration: Hash | null,
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
        Object.freeze({ key, expectedStoreRevision, expectedGeneration, next }),
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
    } catch (error) {
      if (!swapped && error instanceof OaathStoreError && error.code === "store_record_invalid") {
        throw error;
      }
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
    if (retained === undefined) {
      return invalid("store_commit_indeterminate", "Wallet call bundle conflict is unverified");
    }
    if (expectedGeneration !== null && retained.value.generation !== expectedGeneration) {
      return conflict(retained);
    }
    if (expectedStoreRevision !== null && retained.storeRevision <= expectedStoreRevision) {
      return invalid("store_commit_indeterminate", "Wallet call bundle conflict is unverified");
    }
    if (previous !== undefined) requireCompatibleHistory(previous, retained);
    return conflict(retained);
  }

  #assertOpen(): void {
    if (this.#closed) invalid("store_closed", "Wallet call bundle store is closed");
  }
}
