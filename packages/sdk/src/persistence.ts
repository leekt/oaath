/**
 * `@oaath/sdk/persistence` — the full IndexedDB store set and the persisted
 * record contracts, for applications that genuinely need direct access to the
 * realm's durable state. `createOAAth` options take
 * `stores: { kind: "indexeddb" }` instead.
 *
 * @author taek <leekt216@gmail.com>
 */
export { openIndexedDbStores } from "./client/stores.js";
export {
  OAATH_INDEXEDDB_NAME,
  OAATH_INDEXEDDB_STORES,
  OAATH_INDEXEDDB_VERSION,
} from "./persistence/indexeddb/database.js";
export type {
  OaathCleanupCheckpoint,
  OaathCleanupCheckpointStore,
  OaathCleanupEffectName,
  OaathClientContext,
  OaathContextStore,
  OaathKeyStore,
  OaathPendingAuthorizationEnvelope,
  OaathPendingAuthorizationWrite,
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
