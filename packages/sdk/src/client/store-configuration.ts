/** Capture caller-owned store capabilities before any local persistence access. */
import type { CaptureContext } from "@oaath/protocol";
import type { OaathStoreConfiguration } from "../create-oaath.js";
import { clientCapability, exactClientRecord } from "./errors.js";

export type OaathStoreName = keyof OaathStoreConfiguration;

/** The one method set each store port carries, and its diagnostic label. */
const STORE_PORTS: Readonly<
  Record<OaathStoreName, Readonly<{ label: string; methods: readonly string[] }>>
> = Object.freeze({
  grants: { label: "Grant store", methods: ["get", "compareAndSwap", "close"] },
  operations: {
    label: "Operation store",
    methods: ["get", "getArchived", "list", "compareAndSwap", "close"],
  },
  walletCallBundles: {
    label: "wallet call bundle store",
    methods: ["get", "compareAndSwap", "close"],
  },
  preparedCallContexts: {
    label: "prepared call context store",
    methods: ["get", "compareAndSwap", "close"],
  },
  keys: { label: "key store", methods: ["store", "get", "delete", "close"] },
  cleanup: { label: "cleanup store", methods: ["read", "write", "clear", "close"] },
  context: {
    label: "context store",
    methods: ["read", "write", "clear", "close"],
  },
});

export const STORE_NAMES = Object.freeze(Object.keys(STORE_PORTS)) as readonly OaathStoreName[];

export function captureStorePort<Name extends OaathStoreName>(
  name: Name,
  value: unknown,
  context: CaptureContext,
): OaathStoreConfiguration[Name] {
  const { label, methods } = STORE_PORTS[name];
  const record = exactClientRecord(
    value,
    methods,
    label,
    context,
    "oaath_client_capability_invalid",
  );
  for (const method of methods) clientCapability(record[method], `${label} ${method}`);
  return value as OaathStoreConfiguration[Name];
}

export function captureStoreConfiguration(
  value: unknown,
  context: CaptureContext = new WeakSet(),
): Readonly<OaathStoreConfiguration> {
  const storeRecord = exactClientRecord(
    value,
    STORE_NAMES,
    "OAAth stores",
    context,
    "oaath_client_capability_invalid",
  );
  return Object.freeze(
    Object.fromEntries(
      STORE_NAMES.map((name) => [name, captureStorePort(name, storeRecord[name], context)]),
    ) as unknown as OaathStoreConfiguration,
  );
}
