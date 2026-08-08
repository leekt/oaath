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
export { createIndexedDbPreparedCallStoreAdapter } from "./persistence/indexeddb/prepared-call-store.js";
export { createIndexedDbWalletCallBundleStoreAdapter } from "./persistence/indexeddb/wallet-call-bundle-store.js";
export type {
  OaathCleanupCheckpoint,
  OaathCleanupCheckpointStore,
  OaathCleanupEffectName,
  OaathClientContext,
  OaathContextStore,
  OaathKeyStore,
  PersistenceErrorCode,
  WalletCallBundleKey,
  WalletCallBundleOperation,
  WalletCallBundleRecord,
  WalletCallBundleStoreAdapter,
  WalletCallBundleStoreRecord,
} from "./persistence/interfaces.js";
export {
  isCleanupEffectName,
  OAATH_CLEANUP_CHECKPOINT_VERSION,
  OAATH_CLIENT_CONTEXT_VERSION,
  OAATH_WALLET_CALL_BUNDLE_STORE_RECORD_VERSION,
  OAATH_WALLET_CALL_BUNDLE_VERSION,
  OaathPersistenceError,
  parseCleanupCheckpoint,
  parseClientContext,
  requireNonExtractableKey,
} from "./persistence/interfaces.js";
export type {
  PreparedCallContextRecord,
  PreparedCallKey,
  PreparedCallStoreAdapter,
  PreparedCallStoreRecord,
  PreparedCallValidityTimeRange,
} from "./provider/prepared-call-store.js";
