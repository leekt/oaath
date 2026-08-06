/**
 * `@oaath/sdk/persistence` — the IndexedDB adapters and the persisted record
 * contracts, for applications that genuinely need direct access to the
 * realm's durable state.
 *
 * @author taek <leekt216@gmail.com>
 */
export { createIndexedDbCleanupStore } from "./persistence/indexeddb/cleanup-store.js";
export { createIndexedDbContextStore } from "./persistence/indexeddb/context-store.js";
export type {
  OaathDatabase,
  OaathObjectStoreName,
} from "./persistence/indexeddb/database.js";
export {
  OAATH_INDEXEDDB_NAME,
  OAATH_INDEXEDDB_STORES,
  OAATH_INDEXEDDB_VERSION,
  openOaathDatabase,
} from "./persistence/indexeddb/database.js";
export { createIndexedDbGrantStoreAdapter } from "./persistence/indexeddb/grant-store.js";
export { createIndexedDbKeyStore } from "./persistence/indexeddb/key-store.js";
export { createIndexedDbOperationStoreAdapter } from "./persistence/indexeddb/operation-store.js";
export type {
  OaathCleanupCheckpoint,
  OaathCleanupCheckpointStore,
  OaathCleanupEffectName,
  OaathClientContext,
  OaathContextStore,
  OaathKeyStore,
  PersistenceErrorCode,
} from "./persistence/interfaces.js";
export {
  isCleanupEffectName,
  OAATH_CLEANUP_CHECKPOINT_VERSION,
  OAATH_CLIENT_CONTEXT_VERSION,
  OaathPersistenceError,
  parseCleanupCheckpoint,
  parseClientContext,
  requireNonExtractableKey,
} from "./persistence/interfaces.js";
