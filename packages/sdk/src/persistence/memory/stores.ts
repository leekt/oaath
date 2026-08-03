/**
 * In-memory persistence backends: one owner per fact, no shared record table.
 *
 * These are the reference implementations of the browser contracts and the only
 * ones tests should reach for when durability is not the subject. They keep the
 * exact same rules as the IndexedDB backends — one current version, key custody
 * refuses extractable handles, and compare-and-swap compares the stored
 * revision — so a test that passes here proves the contract, not the medium.
 *
 * ponytail: one file for five small backends; split when one grows past its
 * factory.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { GrantStoreAdapter, OperationStoreAdapter, StoreRecord } from "../../store.js";
import {
  type OaathCleanupCheckpoint,
  type OaathCleanupCheckpointStore,
  type OaathClientContext,
  type OaathContextStore,
  type OaathKeyStore,
  persistenceFail,
  persistenceId,
  requireNonExtractableKey,
} from "../interfaces.js";

function assertOpen(closed: boolean): void {
  if (closed) persistenceFail("persistence_unavailable", "memory store is closed");
}

function operationKey(input: Readonly<{ grantId: string; chainId: number }>): string {
  const chainId = input.chainId;
  if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId < 1) {
    return persistenceFail("persistence_input_invalid", "memory chainId must be positive");
  }
  // The array form keeps a grantId containing a separator from colliding with
  // another lane, the same way the IndexedDB backend uses a composite key.
  return JSON.stringify([persistenceId(input.grantId, "memory grantId"), chainId]);
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
  let closed = false;
  const adapter: OperationStoreAdapter = {
    async get(key) {
      assertOpen(closed);
      return records.get(operationKey(key));
    },
    async compareAndSwap(input) {
      assertOpen(closed);
      return compareAndSwap(
        records,
        operationKey(input.key),
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
  const contexts = new Map<string, Readonly<OaathClientContext>>();
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
    async clear(bindingId: string) {
      assertOpen(closed);
      contexts.delete(persistenceId(bindingId, "memory bindingId"));
    },
    async close() {
      closed = true;
    },
  });
}
