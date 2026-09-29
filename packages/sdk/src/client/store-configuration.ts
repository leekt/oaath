/** Capture caller-owned store capabilities before any local persistence access. */
import type { CaptureContext } from "@oaath/protocol";
import type { OaathStoreConfiguration } from "../create-oaath.js";
import type {
  OaathCleanupCheckpointStore,
  OaathContextStore,
  OaathKeyStore,
  WalletCallBundleStoreAdapter,
} from "../persistence/interfaces.js";
import type { PreparedCallStoreAdapter } from "../provider/prepared-call-store.js";
import type { GrantStoreAdapter, OperationStoreAdapter } from "../store.js";
import { clientCapability, exactClientRecord } from "./errors.js";

const STORE_KEYS: readonly string[] = Object.freeze([
  "grants",
  "operations",
  "walletCallBundles",
  "preparedCallContexts",
  "keys",
  "cleanup",
  "context",
]);

function storePort<Port>(
  value: unknown,
  methods: readonly string[],
  label: string,
  context: CaptureContext,
): Port {
  const record = exactClientRecord(
    value,
    methods,
    label,
    context,
    "oaath_client_capability_invalid",
  );
  for (const method of methods) clientCapability(record[method], `${label} ${method}`);
  return value as Port;
}

export function captureStoreConfiguration(
  value: unknown,
  context: CaptureContext = new WeakSet(),
): Readonly<OaathStoreConfiguration> {
  const storeRecord = exactClientRecord(
    value,
    STORE_KEYS,
    "OAAth stores",
    context,
    "oaath_client_capability_invalid",
  );
  return Object.freeze({
    grants: storePort<GrantStoreAdapter>(
      storeRecord.grants,
      ["get", "compareAndSwap", "close"],
      "Grant store",
      context,
    ),
    operations: storePort<OperationStoreAdapter>(
      storeRecord.operations,
      ["get", "getArchived", "list", "compareAndSwap", "close"],
      "Operation store",
      context,
    ),
    walletCallBundles: storePort<WalletCallBundleStoreAdapter>(
      storeRecord.walletCallBundles,
      ["get", "compareAndSwap", "close"],
      "wallet call bundle store",
      context,
    ),
    preparedCallContexts: storePort<PreparedCallStoreAdapter>(
      storeRecord.preparedCallContexts,
      ["get", "compareAndSwap", "close"],
      "prepared call context store",
      context,
    ),
    keys: storePort<OaathKeyStore>(
      storeRecord.keys,
      ["store", "get", "delete", "close"],
      "key store",
      context,
    ),
    cleanup: storePort<OaathCleanupCheckpointStore>(
      storeRecord.cleanup,
      ["read", "write", "clear", "close"],
      "cleanup store",
      context,
    ),
    context: storePort<OaathContextStore>(
      storeRecord.context,
      ["read", "write", "clear", "close"],
      "context store",
      context,
    ),
  });
}
