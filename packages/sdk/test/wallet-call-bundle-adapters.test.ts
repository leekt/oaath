/**
 * Adapter parity for the durable wallet-call bundle state owner.
 *
 * @author taek <leekt216@gmail.com>
 */
import { IDBFactory } from "fake-indexeddb";
import { describe, expect, it } from "vitest";
import {
  createIndexedDbWalletCallBundleStoreAdapter,
  type OaathDatabase,
  openOaathDatabase,
  type WalletCallBundleKey,
  type WalletCallBundleOperation,
  type WalletCallBundleRecord,
  type WalletCallBundleStoreAdapter,
  type WalletCallBundleStoreRecord,
} from "../src/persistence.js";
import {
  WALLET_CALL_BUNDLE_RETENTION_SECONDS,
  type WalletCallBundleMutationResult,
  WalletCallBundleStore,
} from "../src/provider/bundle-store.js";
import { OaathStoreError, type StoreRecord } from "../src/store.js";
import { createMemoryWalletCallBundleStoreAdapter } from "../src/testing.js";

const SCOPE = `0x${"61".repeat(32)}` as const;
const OTHER_SCOPE = `0x${"62".repeat(32)}` as const;
const ACCOUNT = `0x${"71".repeat(20)}` as const;
const OTHER_ACCOUNT = `0x${"72".repeat(20)}` as const;
const REQUEST_HASH = `0x${"81".repeat(32)}` as const;
const OTHER_REQUEST_HASH = `0x${"82".repeat(32)}` as const;
const USER_OPERATION_HASH = `0x${"91".repeat(32)}` as const;
const CHAIN_ID = 31_337;

interface OpenedBackend {
  readonly adapter: WalletCallBundleStoreAdapter;
  readonly dispose: () => void;
}

interface BackendCase {
  readonly name: string;
  readonly open: () => Promise<OpenedBackend>;
}

const BACKENDS: readonly BackendCase[] = [
  {
    name: "memory",
    async open() {
      return {
        adapter: createMemoryWalletCallBundleStoreAdapter(),
        dispose() {},
      };
    },
  },
  {
    name: "IndexedDB",
    async open() {
      const database = await openOaathDatabase({ factory: new IDBFactory() });
      return {
        adapter: createIndexedDbWalletCallBundleStoreAdapter(database),
        dispose: () => database.close(),
      };
    },
  },
];

function key(
  id = "bundle",
  providerScopeId: WalletCallBundleKey["providerScopeId"] = SCOPE,
  account: WalletCallBundleKey["account"] = ACCOUNT,
): Readonly<WalletCallBundleKey> {
  return Object.freeze({ providerScopeId, account, id });
}

function operation(): Readonly<WalletCallBundleOperation> {
  return Object.freeze({
    key: Object.freeze({ grantId: "grant", chainId: CHAIN_ID, kind: "execution" as const }),
    userOperationHash: USER_OPERATION_HASH,
  });
}

function reserve(
  store: WalletCallBundleStore,
  bundleKey: Readonly<WalletCallBundleKey> = key(),
  chainId = CHAIN_ID,
  createdAt = 10,
  requestHash: WalletCallBundleRecord["requestHash"] = REQUEST_HASH,
): Promise<WalletCallBundleMutationResult> {
  return store.reserveAccepted({ key: bundleKey, chainId, createdAt, requestHash });
}

function requireCommitted(result: WalletCallBundleMutationResult): WalletCallBundleStoreRecord {
  if (result.status !== "committed") throw new Error("expected a committed bundle mutation");
  return result.record;
}

async function expectStoreError(
  action: () => Promise<unknown>,
  code: OaathStoreError["code"],
): Promise<void> {
  try {
    await action();
  } catch (error) {
    expect(error).toBeInstanceOf(OaathStoreError);
    expect((error as OaathStoreError).code).toBe(code);
    return;
  }
  throw new Error(`Expected ${code}`);
}

for (const backendCase of BACKENDS) {
  describe(`${backendCase.name} wallet-call bundle adapter`, () => {
    it("moves opaque envelopes without parsing domain values", async () => {
      const backend = await backendCase.open();
      try {
        const opaque: Readonly<StoreRecord<unknown>> = Object.freeze({
          version: "opaque/v1",
          storeRevision: 0,
          updatedAt: 0,
          value: Object.freeze({ not: "a wallet-call bundle" }),
        });
        await expect(
          backend.adapter.compareAndSwap({
            key: key(),
            expectedStoreRevision: null,
            next: opaque,
          }),
        ).resolves.toBe(true);
        await expect(backend.adapter.get(key())).resolves.toEqual(opaque);
      } finally {
        backend.dispose();
      }
    });

    it("resolves a concurrent reservation race with exactly one winner", async () => {
      const backend = await backendCase.open();
      try {
        const stores = [
          new WalletCallBundleStore(backend.adapter),
          new WalletCallBundleStore(backend.adapter),
        ];
        const results = await Promise.all(stores.map((store) => reserve(store)));
        expect(results.filter((result) => result.status === "committed")).toHaveLength(1);
        expect(results.filter((result) => result.status === "conflict")).toHaveLength(1);
        expect(results.find((result) => result.status === "conflict")).toMatchObject({
          status: "conflict",
          current: { storeRevision: 0, value: { state: "accepted" } },
        });
      } finally {
        backend.dispose();
      }
    });

    it("retains the accepted, operation-bound, and terminal sequence", async () => {
      const backend = await backendCase.open();
      try {
        const store = new WalletCallBundleStore(backend.adapter);
        expect(requireCommitted(await reserve(store)).storeRevision).toBe(0);
        const bound = requireCommitted(
          await store.bindOperation({ key: key(), operation: operation(), updatedAt: 20 }),
        );
        expect(bound).toMatchObject({
          storeRevision: 1,
          updatedAt: 20,
          value: { operation: operation(), state: "operation_bound" },
        });
        const terminal = requireCommitted(await store.markTerminal({ key: key(), updatedAt: 30 }));
        expect(terminal).toMatchObject({
          storeRevision: 2,
          updatedAt: 30,
          value: { operation: operation(), state: "terminal" },
        });
        await expect(store.get(key())).resolves.toEqual(terminal);
      } finally {
        backend.dispose();
      }
    });

    it("rejects an exact duplicate key even when the requested chain differs", async () => {
      const backend = await backendCase.open();
      try {
        const store = new WalletCallBundleStore(backend.adapter);
        requireCommitted(await reserve(store));
        await expect(
          reserve(store, key(), CHAIN_ID + 1, 11, OTHER_REQUEST_HASH),
        ).resolves.toMatchObject({
          status: "conflict",
          current: {
            storeRevision: 0,
            value: { chainId: CHAIN_ID, requestHash: REQUEST_HASH },
          },
        });
      } finally {
        backend.dispose();
      }
    });

    it("isolates the same ID by exact provider scope and account", async () => {
      const backend = await backendCase.open();
      try {
        const store = new WalletCallBundleStore(backend.adapter);
        const keys = [
          key("same-id"),
          key("same-id", OTHER_SCOPE),
          key("same-id", SCOPE, OTHER_ACCOUNT),
        ] as const;
        for (const [index, bundleKey] of keys.entries()) {
          requireCommitted(await reserve(store, bundleKey, CHAIN_ID + index));
        }
        await expect(Promise.all(keys.map((bundleKey) => store.get(bundleKey)))).resolves.toEqual([
          expect.objectContaining({ value: expect.objectContaining({ chainId: CHAIN_ID }) }),
          expect.objectContaining({ value: expect.objectContaining({ chainId: CHAIN_ID + 1 }) }),
          expect.objectContaining({ value: expect.objectContaining({ chainId: CHAIN_ID + 2 }) }),
        ]);
      } finally {
        backend.dispose();
      }
    });

    it("reports a CAD revision race, then deletes the retained terminal revision", async () => {
      const backend = await backendCase.open();
      let racedRecord: WalletCallBundleStoreRecord | undefined;
      const racingAdapter: WalletCallBundleStoreAdapter = Object.freeze({
        get: (bundleKey: Readonly<WalletCallBundleKey>) => backend.adapter.get(bundleKey),
        compareAndSwap: (input: Parameters<WalletCallBundleStoreAdapter["compareAndSwap"]>[0]) =>
          backend.adapter.compareAndSwap(input),
        async compareAndDelete(
          input: Parameters<WalletCallBundleStoreAdapter["compareAndDelete"]>[0],
        ) {
          if (racedRecord !== undefined) {
            const next = racedRecord;
            racedRecord = undefined;
            const swapped = await backend.adapter.compareAndSwap({
              key: input.key,
              expectedStoreRevision: input.expectedStoreRevision,
              next,
            });
            if (swapped !== true) throw new Error("failed to install the racing revision");
          }
          return backend.adapter.compareAndDelete(input);
        },
        close: () => backend.adapter.close(),
      });
      try {
        const store = new WalletCallBundleStore(racingAdapter);
        requireCommitted(await reserve(store));
        const terminal = requireCommitted(await store.markTerminal({ key: key(), updatedAt: 20 }));
        racedRecord = Object.freeze({
          ...terminal,
          storeRevision: terminal.storeRevision + 1,
          updatedAt: terminal.updatedAt + 1,
        });

        await expect(
          store.deleteExpiredTerminal(
            key(),
            20 + WALLET_CALL_BUNDLE_RETENTION_SECONDS,
            WALLET_CALL_BUNDLE_RETENTION_SECONDS,
          ),
        ).resolves.toMatchObject({ status: "conflict", current: { storeRevision: 2 } });
        await expect(
          store.deleteExpiredTerminal(
            key(),
            21 + WALLET_CALL_BUNDLE_RETENTION_SECONDS,
            WALLET_CALL_BUNDLE_RETENTION_SECONDS,
          ),
        ).resolves.toEqual({ status: "deleted" });
        await expect(store.get(key())).resolves.toBeUndefined();
      } finally {
        backend.dispose();
      }
    });

    it("closes the state owner once and rejects every later access", async () => {
      const backend = await backendCase.open();
      try {
        const store = new WalletCallBundleStore(backend.adapter);
        requireCommitted(await reserve(store));
        await Promise.all([store.close(), store.close()]);
        await store.close();
        await expectStoreError(() => store.get(key()), "store_closed");
        await expectStoreError(() => reserve(store), "store_closed");
        await expectStoreError(() => store.deleteExpiredTerminal(key(), 100_000), "store_closed");
      } finally {
        backend.dispose();
      }
    });
  });
}

describe("IndexedDB wallet-call bundle durability", () => {
  it("retains the exact record across database, adapter, and state-owner recreation", async () => {
    const factory = new IDBFactory();
    const firstDatabase = await openOaathDatabase({ factory });
    const firstStore = new WalletCallBundleStore(
      createIndexedDbWalletCallBundleStoreAdapter(firstDatabase),
    );
    requireCommitted(await reserve(firstStore));
    const retained = requireCommitted(
      await firstStore.bindOperation({ key: key(), operation: operation(), updatedAt: 20 }),
    );
    await firstStore.close();
    firstDatabase.close();

    let secondDatabase: OaathDatabase | undefined;
    try {
      secondDatabase = await openOaathDatabase({ factory });
      const restored = new WalletCallBundleStore(
        createIndexedDbWalletCallBundleStoreAdapter(secondDatabase),
      );
      await expect(restored.get(key())).resolves.toEqual(retained);
      await restored.close();
    } finally {
      secondDatabase?.close();
    }
  });
});
