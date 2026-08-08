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
const ENTRY_POINT = `0x${"92".repeat(20)}` as const;
const GENERATION_A = `0x${"a1".repeat(32)}` as const;
const GENERATION_B = `0x${"b2".repeat(32)}` as const;
const CHAIN_ID = 31_337;
const GRANT_ID = "grant";
const OTHER_GRANT_ID = "other-grant";

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

function operation(grantId = GRANT_ID): Readonly<WalletCallBundleOperation> {
  return Object.freeze({
    identity: Object.freeze({
      kind: "execution" as const,
      grantId,
      chainId: CHAIN_ID,
      entryPoint: ENTRY_POINT,
      account: ACCOUNT,
      nonce: "0",
      userOperationHash: USER_OPERATION_HASH,
      requestHash: REQUEST_HASH,
    }),
    resultCapabilities: null,
  });
}

function reserve(
  store: WalletCallBundleStore,
  bundleKey: Readonly<WalletCallBundleKey> = key(),
  chainId = CHAIN_ID,
  createdAt = 10,
  requestHash: WalletCallBundleRecord["requestHash"] = REQUEST_HASH,
  generation: WalletCallBundleRecord["generation"] = GENERATION_A,
  account: WalletCallBundleRecord["account"] = bundleKey.account,
  grantId: WalletCallBundleRecord["grantId"] = GRANT_ID,
): Promise<WalletCallBundleMutationResult> {
  return store.reserveAccepted({
    key: bundleKey,
    grantId,
    generation,
    account,
    chainId,
    createdAt,
    publicationExpiresAt: createdAt + 30,
    requestHash,
  });
}

function reservePendingConfirmation(
  store: WalletCallBundleStore,
): Promise<WalletCallBundleMutationResult> {
  return store.reservePendingConfirmation({
    key: key(),
    grantId: GRANT_ID,
    generation: GENERATION_A,
    account: ACCOUNT,
    chainId: CHAIN_ID,
    createdAt: 10,
    confirmationExpiresAt: 310,
    requestHash: REQUEST_HASH,
  });
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
            expectedGeneration: null,
            next: opaque,
          }),
        ).resolves.toBe(true);
        await expect(backend.adapter.get(key())).resolves.toEqual(opaque);
      } finally {
        backend.dispose();
      }
    });

    it("uses provider scope, account, and ID as physical key axes", async () => {
      const backend = await backendCase.open();
      try {
        const firstKey = key("same-id");
        const first: Readonly<StoreRecord<unknown>> = Object.freeze({
          version: "opaque/v1",
          storeRevision: 0,
          updatedAt: 0,
          value: Object.freeze({ marker: "first" }),
        });
        const otherGrant: Readonly<StoreRecord<unknown>> = Object.freeze({
          ...first,
          value: Object.freeze({ marker: "other-grant" }),
        });
        const otherAccountKey = key("same-id", SCOPE, OTHER_ACCOUNT);
        const otherAccount: Readonly<StoreRecord<unknown>> = Object.freeze({
          ...first,
          value: Object.freeze({ marker: "other-account" }),
        });
        await expect(
          backend.adapter.compareAndSwap({
            key: firstKey,
            expectedStoreRevision: null,
            expectedGeneration: null,
            next: first,
          }),
        ).resolves.toBe(true);
        await expect(
          backend.adapter.compareAndSwap({
            key: firstKey,
            expectedStoreRevision: null,
            expectedGeneration: null,
            next: otherGrant,
          }),
        ).resolves.toBe(false);
        await expect(
          backend.adapter.compareAndSwap({
            key: otherAccountKey,
            expectedStoreRevision: null,
            expectedGeneration: null,
            next: otherAccount,
          }),
        ).resolves.toBe(true);
        await expect(backend.adapter.get(firstKey)).resolves.toEqual(first);
        await expect(backend.adapter.get(otherAccountKey)).resolves.toEqual(otherAccount);
      } finally {
        backend.dispose();
      }
    });

    it("rejects a stale update after a generation revision collision", async () => {
      const backend = await backendCase.open();
      try {
        const generationA: Readonly<StoreRecord<unknown>> = Object.freeze({
          version: "opaque/v1",
          storeRevision: 0,
          updatedAt: 10,
          value: Object.freeze({ generation: GENERATION_A, marker: "generation-a" }),
        });
        const generationB: Readonly<StoreRecord<unknown>> = Object.freeze({
          ...generationA,
          storeRevision: 1,
          updatedAt: 20,
          value: Object.freeze({ generation: GENERATION_B, marker: "generation-b" }),
        });
        await expect(
          backend.adapter.compareAndSwap({
            key: key(),
            expectedStoreRevision: null,
            expectedGeneration: GENERATION_A,
            next: generationA,
          }),
        ).resolves.toBe(false);
        await expect(backend.adapter.get(key())).resolves.toBeUndefined();
        await expect(
          backend.adapter.compareAndSwap({
            key: key(),
            expectedStoreRevision: null,
            expectedGeneration: null,
            next: generationA,
          }),
        ).resolves.toBe(true);
        await expect(
          backend.adapter.compareAndSwap({
            key: key(),
            expectedStoreRevision: generationA.storeRevision,
            expectedGeneration: GENERATION_A,
            next: generationB,
          }),
        ).resolves.toBe(true);

        await expect(
          backend.adapter.compareAndSwap({
            key: key(),
            expectedStoreRevision: generationA.storeRevision,
            expectedGeneration: GENERATION_A,
            next: Object.freeze({ ...generationA, storeRevision: 1 }),
          }),
        ).resolves.toBe(false);
        await expect(backend.adapter.get(key())).resolves.toEqual(generationB);
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

    it("lets one store reserve and approve a preconfirmation while its peer only conflicts", async () => {
      const backend = await backendCase.open();
      try {
        const stores = [
          new WalletCallBundleStore(backend.adapter),
          new WalletCallBundleStore(backend.adapter),
        ];
        const results = await Promise.all(stores.map(reservePendingConfirmation));
        expect(results.filter((result) => result.status === "committed")).toHaveLength(1);
        expect(results.filter((result) => result.status === "conflict")).toHaveLength(1);
        const pending = results.find((result) => result.status === "committed");
        if (pending?.status !== "committed") throw new Error("expected one pending winner");
        const approved = await stores[0]?.approveConfirmation({
          key: key(),
          expectedStoreRevision: pending.record.storeRevision,
          expectedGeneration: pending.record.value.generation,
          approvedAt: 300,
          publicationExpiresAt: 330,
        });
        expect(approved).toMatchObject({
          status: "committed",
          record: {
            storeRevision: 1,
            value: { state: "accepted", publicationExpiresAt: 330 },
          },
        });
      } finally {
        backend.dispose();
      }
    });

    it("retains the accepted, reserved, bound, and terminal sequence", async () => {
      const backend = await backendCase.open();
      try {
        const store = new WalletCallBundleStore(backend.adapter);
        const accepted = requireCommitted(await reserve(store));
        expect(accepted.storeRevision).toBe(0);
        expect(accepted.value.terminalFrom).toBeNull();
        const reserved = requireCommitted(
          await store.reserveOperation({
            key: key(),
            expectedStoreRevision: accepted.storeRevision,
            expectedGeneration: accepted.value.generation,
            operation: operation(),
            updatedAt: 20,
          }),
        );
        expect(reserved).toMatchObject({
          storeRevision: 1,
          updatedAt: 20,
          value: { operation: operation(), state: "operation_reserved", terminalFrom: null },
        });
        const bound = requireCommitted(
          await store.confirmOperationPublished({
            key: key(),
            expectedStoreRevision: reserved.storeRevision,
            expectedGeneration: reserved.value.generation,
            updatedAt: 30,
          }),
        );
        expect(bound).toMatchObject({
          storeRevision: 2,
          updatedAt: 30,
          value: { operation: operation(), state: "operation_bound", terminalFrom: null },
        });
        const terminal = requireCommitted(
          await store.markTerminal({
            key: key(),
            expectedStoreRevision: bound.storeRevision,
            expectedGeneration: bound.value.generation,
            updatedAt: 40,
          }),
        );
        expect(terminal).toMatchObject({
          storeRevision: 3,
          updatedAt: 40,
          value: {
            operation: operation(),
            state: "terminal",
            terminalFrom: "operation_bound",
          },
        });
        await expect(store.get(key())).resolves.toEqual(terminal);
      } finally {
        backend.dispose();
      }
    });

    it("retains accepted and reserved terminal origins", async () => {
      const backend = await backendCase.open();
      try {
        const store = new WalletCallBundleStore(backend.adapter);
        const acceptedKey = key("accepted-terminal");
        const accepted = requireCommitted(await reserve(store, acceptedKey));
        const acceptedTerminal = requireCommitted(
          await store.markTerminal({
            key: acceptedKey,
            expectedStoreRevision: accepted.storeRevision,
            expectedGeneration: accepted.value.generation,
            updatedAt: 20,
          }),
        );
        expect(acceptedTerminal.value).toMatchObject({
          state: "terminal",
          terminalFrom: "accepted",
          operation: null,
        });

        const reservedKey = key("reserved-terminal");
        const acceptedForReservation = requireCommitted(await reserve(store, reservedKey));
        const reserved = requireCommitted(
          await store.reserveOperation({
            key: reservedKey,
            expectedStoreRevision: acceptedForReservation.storeRevision,
            expectedGeneration: acceptedForReservation.value.generation,
            operation: operation(),
            updatedAt: 20,
          }),
        );
        const reservedTerminal = requireCommitted(
          await store.markTerminal({
            key: reservedKey,
            expectedStoreRevision: reserved.storeRevision,
            expectedGeneration: reserved.value.generation,
            updatedAt: 21,
          }),
        );
        expect(reservedTerminal.value).toMatchObject({
          state: "terminal",
          terminalFrom: "operation_reserved",
          operation: operation(),
        });
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

    it("isolates the same ID by provider scope and account while Grant stays record evidence", async () => {
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
        await expect(
          reserve(
            store,
            key("same-id"),
            CHAIN_ID + 2,
            10,
            REQUEST_HASH,
            GENERATION_B,
            ACCOUNT,
            OTHER_GRANT_ID,
          ),
        ).resolves.toMatchObject({
          status: "conflict",
          current: { value: { grantId: GRANT_ID } },
        });
        await expect(Promise.all(keys.map((bundleKey) => store.get(bundleKey)))).resolves.toEqual([
          expect.objectContaining({ value: expect.objectContaining({ chainId: CHAIN_ID }) }),
          expect.objectContaining({ value: expect.objectContaining({ chainId: CHAIN_ID + 1 }) }),
          expect.objectContaining({
            value: expect.objectContaining({
              account: OTHER_ACCOUNT,
              chainId: CHAIN_ID + 2,
            }),
          }),
        ]);
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
    const accepted = requireCommitted(await reserve(firstStore));
    const reserved = requireCommitted(
      await firstStore.reserveOperation({
        key: key(),
        expectedStoreRevision: accepted.storeRevision,
        expectedGeneration: accepted.value.generation,
        operation: operation(),
        updatedAt: 20,
      }),
    );
    const retained = requireCommitted(
      await firstStore.confirmOperationPublished({
        key: key(),
        expectedStoreRevision: reserved.storeRevision,
        expectedGeneration: reserved.value.generation,
        updatedAt: 21,
      }),
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
