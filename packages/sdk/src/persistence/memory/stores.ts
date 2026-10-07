/**
 * In-memory persistence backends: one owner per fact, no shared record table.
 *
 * These are the reference implementations of the browser contracts and the only
 * ones tests should reach for when durability is not the subject. They keep the
 * exact same rules as the IndexedDB backends — one current version, key custody
 * refuses extractable handles, and compare-and-swap compares the stored
 * revision (and generation where that fact owns one) — so a test that passes
 * here proves the contract, not the medium.
 *
 * ponytail: one file for seven small backends; split when one grows past its
 * factory.
 *
 * @author taek <leekt216@gmail.com>
 */

import {
  type PreparedCallKey,
  type PreparedCallStoreAdapter,
  parsePreparedCallKey,
} from "../../provider/prepared-call-store.js";
import type {
  GrantStoreAdapter,
  OperationStoreAdapter,
  OperationStoreKey,
  OperationStoreScope,
  StoreRecord,
} from "../../store.js";
import {
  matchesExpectedRevision,
  matchesExpectedRevisionAndGeneration,
} from "../indexeddb/database.js";
import {
  MAX_WALLET_CALL_BUNDLE_RECORDS_PER_SCOPE,
  type OaathCleanupCheckpoint,
  type OaathCleanupCheckpointStore,
  type OaathClientContext,
  type OaathContextStore,
  type OaathKeyStore,
  type OaathPendingAuthorizationWrite,
  parseWalletCallBundleKey,
  persistenceFail,
  persistenceId,
  requireNonExtractableKey,
  WALLET_CALL_BUNDLE_SCOPE_CAPACITY_EXHAUSTED,
  type WalletCallBundleKey,
  type WalletCallBundleStoreAdapter,
} from "../interfaces.js";

function assertOpen(closed: boolean): void {
  if (closed) persistenceFail("persistence_unavailable", "memory store is closed");
}

function operationScopeParts(
  input: Readonly<OperationStoreScope>,
): readonly [string, number, string] {
  const chainId = input.chainId;
  if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId < 1) {
    return persistenceFail("persistence_input_invalid", "memory chainId must be positive");
  }
  if (input.kind !== "execution" && input.kind !== "revocation") {
    return persistenceFail("persistence_input_invalid", "memory kind must name a lane");
  }
  return [persistenceId(input.grantId, "memory grantId"), chainId, input.kind];
}

/** The default lane is 0; a reserved lane key is always positive. */
function operationKeyParts(
  input: Readonly<OperationStoreKey>,
): readonly [string, number, string, number] {
  const lane = input.lane ?? 0;
  if (!Number.isSafeInteger(lane) || lane < 0) {
    return persistenceFail("persistence_input_invalid", "memory lane must be a lane key");
  }
  return [...operationScopeParts(input), lane];
}

function operationKey(input: Readonly<OperationStoreKey>): string {
  // The array form keeps a grantId containing a separator from colliding with
  // another lane, the same way the IndexedDB backend uses a composite key.
  return JSON.stringify(["lane", ...operationKeyParts(input)]);
}

function operationArchiveKey(
  input: Readonly<OperationStoreKey>,
  userOperationHash: string,
): string {
  if (!/^0x[0-9a-f]{64}$/u.test(userOperationHash)) {
    return persistenceFail(
      "persistence_input_invalid",
      "memory UserOperation hash must be a lowercase 32-byte hash",
    );
  }
  return JSON.stringify(["archive", ...operationKeyParts(input), userOperationHash]);
}

function walletCallBundleKey(input: Readonly<WalletCallBundleKey>): string {
  const key = parseWalletCallBundleKey(input);
  return JSON.stringify([key.providerScopeId, key.account, key.id]);
}

function preparedCallKey(input: Readonly<PreparedCallKey>): string {
  const key = parsePreparedCallKey(input);
  return JSON.stringify([key.providerScopeId, key.contextId]);
}

function compareAndSwap(
  records: Map<string, Readonly<StoreRecord<unknown>>>,
  key: string,
  expectedStoreRevision: number | null,
  next: Readonly<StoreRecord<unknown>>,
): boolean {
  const current = records.get(key);
  if (
    expectedStoreRevision === null
      ? current !== undefined
      : current?.storeRevision !== expectedStoreRevision
  ) {
    return false;
  }
  records.set(key, next);
  return true;
}

export function createMemoryGrantStoreAdapter(): GrantStoreAdapter {
  const records = new Map<string, Readonly<StoreRecord<unknown>>>();
  let closed = false;
  const adapter: GrantStoreAdapter = {
    async get(grantId: string) {
      assertOpen(closed);
      return records.get(persistenceId(grantId, "memory grantId"));
    },
    async compareAndSwap(input) {
      assertOpen(closed);
      return compareAndSwap(
        records,
        persistenceId(input.grantId, "memory grantId"),
        input.expectedStoreRevision,
        input.next,
      );
    },
    async close() {
      closed = true;
    },
  };
  return Object.freeze(adapter);
}

export function createMemoryOperationStoreAdapter(): OperationStoreAdapter {
  const records = new Map<string, Readonly<StoreRecord<unknown>>>();
  const archives = new Map<string, Readonly<StoreRecord<unknown>>>();
  let closed = false;
  const adapter: OperationStoreAdapter = {
    async get(key) {
      assertOpen(closed);
      return records.get(operationKey(key));
    },
    async list(scope) {
      assertOpen(closed);
      const prefix = JSON.stringify(["lane", ...operationScopeParts(scope)]).slice(0, -1);
      return [...records]
        .filter(([key]) => key.startsWith(`${prefix},`))
        .map(([, record]) => record);
    },
    async getArchived(input) {
      assertOpen(closed);
      return archives.get(operationArchiveKey(input.key, input.userOperationHash));
    },
    async compareAndSwap(input) {
      assertOpen(closed);
      const lane = operationKey(input.key);
      const expectedAbsentArchive = operationArchiveKey(
        input.key,
        input.expectedArchiveAbsentUserOperationHash,
      );
      const current = records.get(lane);
      if (
        input.expectedStoreRevision === null
          ? current !== undefined
          : current?.storeRevision !== input.expectedStoreRevision
      ) {
        return false;
      }
      if (archives.has(expectedAbsentArchive)) return false;
      if (input.archive !== null) {
        if (input.archive.userOperationHash === input.expectedArchiveAbsentUserOperationHash) {
          return false;
        }
        const archive = operationArchiveKey(input.key, input.archive.userOperationHash);
        if (
          current === undefined ||
          JSON.stringify(current) !== JSON.stringify(input.archive.record) ||
          archives.has(archive)
        ) {
          return false;
        }
        archives.set(archive, input.archive.record);
      }
      records.set(lane, input.next);
      return true;
    },
    async close() {
      closed = true;
    },
  };
  return Object.freeze(adapter);
}

export function createMemoryWalletCallBundleStoreAdapter(
  options: Readonly<{ maxRecordsPerScope?: number }> = {},
): WalletCallBundleStoreAdapter {
  const maxRecordsPerScope = options.maxRecordsPerScope ?? MAX_WALLET_CALL_BUNDLE_RECORDS_PER_SCOPE;
  if (!Number.isSafeInteger(maxRecordsPerScope) || maxRecordsPerScope < 1) {
    persistenceFail(
      "persistence_input_invalid",
      "wallet call bundle scope budget must be a positive safe integer",
    );
  }
  const records = new Map<string, Readonly<StoreRecord<unknown>>>();
  let closed = false;
  const scopeRecordCount = (scope: string): number => {
    let count = 0;
    for (const key of records.keys()) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(key);
      } catch {
        continue;
      }
      if (Array.isArray(parsed) && parsed[0] === scope) count += 1;
    }
    return count;
  };
  const adapter: WalletCallBundleStoreAdapter = {
    async get(key: Readonly<WalletCallBundleKey>) {
      assertOpen(closed);
      return records.get(walletCallBundleKey(key));
    },
    async compareAndSwap(input) {
      assertOpen(closed);
      const key = walletCallBundleKey(input.key);
      const current = records.get(key);
      if (
        !matchesExpectedRevisionAndGeneration(
          current,
          input.expectedStoreRevision,
          input.expectedGeneration,
        )
      ) {
        return false;
      }
      if (input.expectedStoreRevision === null && input.expectedGeneration === null) {
        if (scopeRecordCount(input.key.providerScopeId) >= maxRecordsPerScope) {
          return WALLET_CALL_BUNDLE_SCOPE_CAPACITY_EXHAUSTED;
        }
      }
      records.set(key, input.next);
      return true;
    },
    async close() {
      closed = true;
    },
  };
  return Object.freeze(adapter);
}

export function createMemoryPreparedCallStoreAdapter(): PreparedCallStoreAdapter {
  const records = new Map<string, Readonly<StoreRecord<unknown>>>();
  let closed = false;
  const adapter: PreparedCallStoreAdapter = {
    async get(key: Readonly<PreparedCallKey>) {
      assertOpen(closed);
      return records.get(preparedCallKey(key));
    },
    async compareAndSwap(input) {
      assertOpen(closed);
      const key = preparedCallKey(input.key);
      const current = records.get(key);
      if (!matchesExpectedRevision(current, input.expectedStoreRevision)) return false;
      records.set(key, input.next);
      return true;
    },
    async close() {
      closed = true;
    },
  };
  return Object.freeze(adapter);
}

export function createMemoryKeyStore(): OaathKeyStore {
  const handles = new Map<string, CryptoKey>();
  let closed = false;
  return Object.freeze({
    async store(input: Readonly<{ keyId: string; key: CryptoKey }>) {
      assertOpen(closed);
      handles.set(persistenceId(input.keyId, "memory keyId"), requireNonExtractableKey(input.key));
    },
    async get(keyId: string) {
      assertOpen(closed);
      const handle = handles.get(persistenceId(keyId, "memory keyId"));
      return handle === undefined ? undefined : requireNonExtractableKey(handle);
    },
    async delete(keyId: string) {
      assertOpen(closed);
      handles.delete(persistenceId(keyId, "memory keyId"));
    },
    async close() {
      closed = true;
    },
  });
}

export function createMemoryCleanupStore(): OaathCleanupCheckpointStore {
  const checkpoints = new Map<string, Readonly<OaathCleanupCheckpoint>>();
  let closed = false;
  return Object.freeze({
    async read(cleanupId: string) {
      assertOpen(closed);
      return checkpoints.get(persistenceId(cleanupId, "memory cleanupId"));
    },
    async write(checkpoint: Readonly<OaathCleanupCheckpoint>) {
      assertOpen(closed);
      checkpoints.set(persistenceId(checkpoint.cleanupId, "memory cleanupId"), checkpoint);
    },
    async clear(cleanupId: string) {
      assertOpen(closed);
      checkpoints.delete(persistenceId(cleanupId, "memory cleanupId"));
    },
    async close() {
      closed = true;
    },
  });
}

export function createMemoryContextStore(): OaathContextStore {
  const contexts = new Map<string, unknown>();
  let closed = false;
  return Object.freeze({
    async read(bindingId: string) {
      assertOpen(closed);
      return contexts.get(persistenceId(bindingId, "memory bindingId"));
    },
    async write(context: Readonly<OaathClientContext>) {
      assertOpen(closed);
      contexts.set(persistenceId(context.bindingId, "memory bindingId"), context);
    },
    async compareAndSwapPending(input: Readonly<OaathPendingAuthorizationWrite>) {
      assertOpen(closed);
      const key = persistenceId(input.bindingId, "pending bindingId");
      if (
        input.next.bindingId !== key ||
        input.next.storeRevision !== (input.expectedStoreRevision ?? 0) + 1
      )
        return false;
      if (!matchesExpectedRevision(contexts.get(key), input.expectedStoreRevision)) return false;
      contexts.set(key, Object.freeze({ ...input.next }));
      return true;
    },
    async clear(bindingId: string) {
      assertOpen(closed);
      contexts.delete(persistenceId(bindingId, "memory bindingId"));
    },
    async close() {
      closed = true;
    },
  });
}
