import { IDBFactory } from "fake-indexeddb";
import type { Hash } from "viem";
import { describe, expect, it } from "vitest";
import {
  createIndexedDbPreparedCallStoreAdapter,
  type OaathDatabase,
  openOaathDatabase,
} from "../src/persistence.js";
import {
  type PreparedUserOperation,
  prepareUserOperation,
} from "../src/prepared-user-operation.js";
import { hashWalletCallBundleProvenance } from "../src/provider/capture.js";
import {
  OAATH_PREPARED_CALL_STORE_RECORD_VERSION,
  type PreparedCallKey,
  type PreparedCallMutationResult,
  PreparedCallStore,
  type PreparedCallStoreAdapter,
  type PreparedCallStoreRecord,
  parsePreparedCallKey,
  parsePreparedCallRecord,
} from "../src/provider/prepared-call-store.js";
import { OaathStoreError, type StoreRecord } from "../src/store.js";
import { createMemoryPreparedCallStoreAdapter } from "../src/testing.js";

const PROVIDER_SCOPE_ID = hashOf("11");
const CONTEXT_ID = hashOf("22");
const SECOND_CONTEXT_ID = hashOf("23");
const ACCOUNT = addressOf("33");
const OTHER_ACCOUNT = addressOf("34");
const TARGET = addressOf("44");
const ENTRY_POINT = "0x0000000071727de22e5e9d8baf0edac6f37da032";
const GRANT_ID = "grant-prepared-call";
const CHAIN_ID = 31_337;

function hashOf(byte: string): Hash {
  return `0x${byte.repeat(32)}` as Hash;
}

function addressOf(byte: string): `0x${string}` {
  return `0x${byte.repeat(20)}`;
}

function clone<Value>(value: Value): Value {
  return JSON.parse(JSON.stringify(value)) as Value;
}

function mapKey(key: { readonly providerScopeId: Hash; readonly contextId: Hash }): string {
  return `${key.providerScopeId}:${key.contextId}`;
}

class MemoryPreparedCallAdapter implements PreparedCallStoreAdapter {
  readonly #records = new Map<string, unknown>();
  readonly adapter: PreparedCallStoreAdapter;
  compareAndSwapCalls = 0;
  closeCalls = 0;

  constructor() {
    this.adapter = Object.freeze({
      get: (key: { readonly providerScopeId: Hash; readonly contextId: Hash }) => this.get(key),
      compareAndSwap: (input: Parameters<PreparedCallStoreAdapter["compareAndSwap"]>[0]) =>
        this.compareAndSwap(input),
      close: () => this.close(),
    });
  }

  async get(key: { readonly providerScopeId: Hash; readonly contextId: Hash }): Promise<unknown> {
    const value = this.#records.get(mapKey(key));
    return value === undefined ? undefined : clone(value);
  }

  async compareAndSwap(
    input: Parameters<PreparedCallStoreAdapter["compareAndSwap"]>[0],
  ): Promise<unknown> {
    this.compareAndSwapCalls += 1;
    const selectedKey = mapKey(input.key);
    const current = this.#records.get(selectedKey) as Readonly<StoreRecord<unknown>> | undefined;
    const currentRevision = current?.storeRevision ?? null;
    if (currentRevision !== input.expectedStoreRevision) return false;
    this.#records.set(selectedKey, clone(input.next));
    return true;
  }

  async close(): Promise<void> {
    this.closeCalls += 1;
  }

  overwrite(
    key: { readonly providerScopeId: Hash; readonly contextId: Hash },
    value: unknown,
  ): void {
    this.#records.set(mapKey(key), clone(value));
  }
}

function preparedOperation(
  overrides: Readonly<{
    kind?: "execution" | "revocation";
    grantId?: string;
    chainId?: number;
    account?: `0x${string}`;
    nonce?: string;
  }> = {},
): PreparedUserOperation {
  return prepareUserOperation({
    kind: overrides.kind ?? "execution",
    grantId: overrides.grantId ?? GRANT_ID,
    chainId: overrides.chainId ?? CHAIN_ID,
    entryPoint: {
      version: "0.7",
      address: ENTRY_POINT,
    },
    userOperation: {
      sender: overrides.account ?? ACCOUNT,
      nonce: overrides.nonce ?? "7",
      callData: "0xabcdef",
      callGasLimit: "100000",
      verificationGasLimit: "200000",
      preVerificationGas: "30000",
      maxFeePerGas: "1000000000",
      maxPriorityFeePerGas: "100000000",
      factory: null,
      paymaster: null,
    },
  });
}

function reservation(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const prepared = Object.hasOwn(overrides, "prepared")
    ? (overrides.prepared as PreparedUserOperation)
    : preparedOperation();
  const value: Record<string, unknown> = {
    key: {
      providerScopeId: PROVIDER_SCOPE_ID,
      contextId: CONTEXT_ID,
    },
    grantId: GRANT_ID,
    account: ACCOUNT,
    chainId: CHAIN_ID,
    createdAt: 10,
    expiresAt: 100,
    requestHash: hashOf("55"),
    keyHint: {
      type: "secp256k1",
      publicKey: `0x04${"66".repeat(64)}`,
      prehash: false,
    },
    custody: {
      mode: "frontend",
      providerId: null,
    },
    materialization: {
      mode: "standard",
      permissionId: "0x77777777",
    },
    quote: {
      nonceKey: "0",
      sequence: "7",
    },
    decision: {
      route: "bundler",
      feePayer: null,
    },
    calls: [
      {
        target: TARGET,
        value: "0",
        data: "0x1234",
      },
    ],
    prepared,
    digest: prepared.userOperationHash,
    bundleId: "prepared-bundle",
    bundleGeneration: hashOf("88"),
    bundleRequestHash: hashOf("99"),
    ...overrides,
  };
  value.operationRequestHash = Object.hasOwn(overrides, "operationRequestHash")
    ? overrides.operationRequestHash
    : hashWalletCallBundleProvenance(
        value.bundleRequestHash as Hash,
        value.bundleGeneration as Hash,
      );
  return value;
}

function requireCommitted(result: PreparedCallMutationResult): PreparedCallStoreRecord {
  expect(result.status).toBe("committed");
  if (result.status !== "committed") throw new Error("Expected a committed mutation");
  return result.record;
}

async function expectStoreError(
  action: () => unknown | Promise<unknown>,
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

describe("PreparedCallStore", () => {
  it("captures one exact prepared record and consumes its preallocated identity once", async () => {
    const adapter = new MemoryPreparedCallAdapter();
    const store = new PreparedCallStore(adapter.adapter);
    const input = reservation();
    const calls = input.calls as Record<string, unknown>[];
    const keyHint = input.keyHint as Record<string, unknown>;

    const pending = store.reservePrepared(input);
    input.grantId = "mutated-after-capture";
    calls[0] = { target: OTHER_ACCOUNT, value: "9", data: "0x" };
    keyHint.publicKey = `0x04${"ff".repeat(64)}`;

    const prepared = requireCommitted(await pending);
    expect(prepared).toEqual({
      version: OAATH_PREPARED_CALL_STORE_RECORD_VERSION,
      storeRevision: 0,
      updatedAt: 10,
      value: expect.objectContaining({
        providerScopeId: PROVIDER_SCOPE_ID,
        contextId: CONTEXT_ID,
        grantId: GRANT_ID,
        account: ACCOUNT,
        state: "prepared",
        publicationExpiresAt: null,
        bundleId: "prepared-bundle",
        bundleGeneration: hashOf("88"),
        bundleRequestHash: hashOf("99"),
        operationRequestHash: hashWalletCallBundleProvenance(hashOf("99"), hashOf("88")),
      }),
    });
    expect(prepared.value.calls).toEqual([{ target: TARGET, value: "0", data: "0x1234" }]);
    expect(prepared.value.keyHint.publicKey).toBe(`0x04${"66".repeat(64)}`);
    expect(prepared.value.digest).toBe(prepared.value.prepared.userOperationHash);
    expect(Object.isFrozen(prepared.value.calls)).toBe(true);
    expect(Object.isFrozen(prepared.value.calls[0])).toBe(true);

    const consumed = requireCommitted(
      await store.consume({
        key: { providerScopeId: PROVIDER_SCOPE_ID, contextId: CONTEXT_ID },
        expectedStoreRevision: prepared.storeRevision,
        consumedAt: 20,
        publicationExpiresAt: 50,
      }),
    );
    expect(consumed.storeRevision).toBe(1);
    expect(consumed.updatedAt).toBe(20);
    expect(consumed.value).toEqual({
      ...prepared.value,
      state: "consumed",
      consumedAt: 20,
      publicationExpiresAt: 50,
    });
    expect(consumed.value).not.toHaveProperty("terminalAt");
    expect(await store.get({ providerScopeId: PROVIDER_SCOPE_ID, contextId: CONTEXT_ID })).toEqual(
      consumed,
    );

    const replay = await store.consume({
      key: { providerScopeId: PROVIDER_SCOPE_ID, contextId: CONTEXT_ID },
      expectedStoreRevision: prepared.storeRevision,
      consumedAt: 21,
      publicationExpiresAt: 51,
    });
    expect(replay).toEqual({ status: "conflict", current: consumed });
    expect(adapter.compareAndSwapCalls).toBe(2);
  });

  it("allows exactly one concurrent prepared-to-consumed CAS winner", async () => {
    const adapter = new MemoryPreparedCallAdapter();
    const first = new PreparedCallStore(adapter.adapter);
    const second = new PreparedCallStore(adapter.adapter);
    const prepared = requireCommitted(await first.reservePrepared(reservation()));

    const results = await Promise.all([
      first.consume({
        key: { providerScopeId: PROVIDER_SCOPE_ID, contextId: CONTEXT_ID },
        expectedStoreRevision: prepared.storeRevision,
        consumedAt: 20,
        publicationExpiresAt: 50,
      }),
      second.consume({
        key: { providerScopeId: PROVIDER_SCOPE_ID, contextId: CONTEXT_ID },
        expectedStoreRevision: prepared.storeRevision,
        consumedAt: 21,
        publicationExpiresAt: 51,
      }),
    ]);

    expect(results.filter((result) => result.status === "committed")).toHaveLength(1);
    expect(results.filter((result) => result.status === "conflict")).toHaveLength(1);
    const retained = await first.get({
      providerScopeId: PROVIDER_SCOPE_ID,
      contextId: CONTEXT_ID,
    });
    expect(retained?.storeRevision).toBe(1);
    expect(retained?.value.state).toBe("consumed");
    expect(adapter.compareAndSwapCalls).toBe(3);
  });

  it("retains expiration and stale invalidation as incompatible terminal tombstones", async () => {
    const adapter = new MemoryPreparedCallAdapter();
    const store = new PreparedCallStore(adapter.adapter);
    const expiredPrepared = requireCommitted(await store.reservePrepared(reservation()));
    const stalePrepared = requireCommitted(
      await store.reservePrepared(
        reservation({
          key: { providerScopeId: PROVIDER_SCOPE_ID, contextId: SECOND_CONTEXT_ID },
          bundleId: "stale-bundle",
          bundleGeneration: hashOf("89"),
          keyHint: { type: "webauthn-p256", publicKey: "0x0102", prehash: false },
          custody: { mode: "application_backend", providerId: "signing-service" },
          materialization: { mode: "enable-replayable", permissionId: "0x78787878" },
          decision: {
            route: "direct",
            feePayer: { address: addressOf("45"), balance: "1000000000000000" },
          },
        }),
      ),
    );

    await expectStoreError(
      () =>
        store.markExpired({
          key: { providerScopeId: PROVIDER_SCOPE_ID, contextId: CONTEXT_ID },
          expectedStoreRevision: expiredPrepared.storeRevision,
          terminalAt: 99,
        }),
      "store_input_invalid",
    );

    const expired = requireCommitted(
      await store.markExpired({
        key: { providerScopeId: PROVIDER_SCOPE_ID, contextId: CONTEXT_ID },
        expectedStoreRevision: expiredPrepared.storeRevision,
        terminalAt: 100,
      }),
    );
    const stale = requireCommitted(
      await store.markStale({
        key: { providerScopeId: PROVIDER_SCOPE_ID, contextId: SECOND_CONTEXT_ID },
        expectedStoreRevision: stalePrepared.storeRevision,
        terminalAt: 20,
      }),
    );

    expect(expired.value).toEqual({
      ...expiredPrepared.value,
      state: "expired",
      terminalAt: 100,
      publicationExpiresAt: null,
    });
    expect(stale.value).toEqual({
      ...stalePrepared.value,
      state: "invalidated_as_stale",
      terminalAt: 20,
      publicationExpiresAt: null,
    });
    expect(stale.value).toMatchObject({
      keyHint: { type: "webauthn-p256", publicKey: "0x0102", prehash: false },
      custody: { mode: "application_backend", providerId: "signing-service" },
      materialization: { mode: "enable-replayable", permissionId: "0x78787878" },
      decision: {
        route: "direct",
        feePayer: { address: addressOf("45"), balance: "1000000000000000" },
      },
    });
    expect(expired.value).not.toHaveProperty("consumedAt");
    expect(stale.value).not.toHaveProperty("consumedAt");

    for (const terminal of [expired, stale]) {
      const transition = await store.consume({
        key: {
          providerScopeId: terminal.value.providerScopeId,
          contextId: terminal.value.contextId,
        },
        expectedStoreRevision: terminal.storeRevision,
        consumedAt: 30,
        publicationExpiresAt: 60,
      });
      expect(transition).toEqual({ status: "conflict", current: terminal });
    }

    await expectStoreError(
      () => parsePreparedCallRecord({ ...expired.value, consumedAt: 20 }),
      "store_record_invalid",
    );
    await expectStoreError(
      () => parsePreparedCallRecord({ ...stale.value, publicationExpiresAt: 50 }),
      "store_record_invalid",
    );
  });

  it("rejects malformed hostile input and every prepared-operation boundary mismatch", async () => {
    const adapter = new MemoryPreparedCallAdapter();
    const store = new PreparedCallStore(adapter.adapter);
    let accessorCalls = 0;
    const hostileKey = { providerScopeId: PROVIDER_SCOPE_ID };
    Object.defineProperty(hostileKey, "contextId", {
      enumerable: true,
      get() {
        accessorCalls += 1;
        return CONTEXT_ID;
      },
    });
    await expectStoreError(() => parsePreparedCallKey(hostileKey), "store_input_invalid");
    expect(accessorCalls).toBe(0);

    const revocation = preparedOperation({ kind: "revocation" });
    const mismatches = [
      reservation({ grantId: "another-grant" }),
      reservation({ account: OTHER_ACCOUNT }),
      reservation({ chainId: 1 }),
      reservation({ prepared: revocation, digest: revocation.userOperationHash }),
      reservation({ digest: hashOf("ab") }),
      reservation({ quote: { nonceKey: "0", sequence: (1n << 64n).toString(10) } }),
      reservation({
        keyHint: { type: "secp256k1", publicKey: "0x", prehash: false },
      }),
      reservation({
        keyHint: { type: "secp256k1", publicKey: "0x01", prehash: false },
      }),
      reservation({ custody: { mode: "frontend", providerId: "unexpected" } }),
      reservation({ decision: { route: "bundler", feePayer: { address: ACCOUNT, balance: "1" } } }),
      reservation({ decision: { route: "direct", feePayer: null } }),
      { ...reservation(), unexpected: true },
    ];
    for (const mismatch of mismatches) {
      await expectStoreError(() => store.reservePrepared(mismatch), "store_input_invalid");
    }
    expect(adapter.compareAndSwapCalls).toBe(0);

    const committed = requireCommitted(await store.reservePrepared(reservation()));
    const malformed = clone(committed) as unknown as {
      version: string;
      storeRevision: number;
      updatedAt: number;
      value: Record<string, unknown>;
    };
    malformed.value = {
      ...malformed.value,
      state: "consumed",
      consumedAt: 20,
      publicationExpiresAt: null,
    };
    adapter.overwrite({ providerScopeId: PROVIDER_SCOPE_ID, contextId: CONTEXT_ID }, malformed);
    await expectStoreError(
      () => store.get({ providerScopeId: PROVIDER_SCOPE_ID, contextId: CONTEXT_ID }),
      "store_record_invalid",
    );
  });
});

const ADAPTER_SCOPE = `0x${"11".repeat(32)}` as const;
const OTHER_ADAPTER_SCOPE = `0x${"12".repeat(32)}` as const;
const ADAPTER_CONTEXT = `0x${"21".repeat(32)}` as const;
const OTHER_ADAPTER_CONTEXT = `0x${"22".repeat(32)}` as const;

interface OpenedPreparedCallBackend {
  readonly adapter: PreparedCallStoreAdapter;
  readonly dispose: () => void;
}

const PREPARED_CALL_BACKENDS = [
  {
    name: "memory",
    async open(): Promise<OpenedPreparedCallBackend> {
      return { adapter: createMemoryPreparedCallStoreAdapter(), dispose() {} };
    },
  },
  {
    name: "IndexedDB",
    async open(): Promise<OpenedPreparedCallBackend> {
      const database = await openOaathDatabase({ factory: new IDBFactory() });
      return {
        adapter: createIndexedDbPreparedCallStoreAdapter(database),
        dispose: () => database.close(),
      };
    },
  },
] as const;

function adapterKey(
  providerScopeId: PreparedCallKey["providerScopeId"] = ADAPTER_SCOPE,
  contextId: PreparedCallKey["contextId"] = ADAPTER_CONTEXT,
): Readonly<PreparedCallKey> {
  return Object.freeze({ providerScopeId, contextId });
}

function opaqueRecord(storeRevision: number, marker: string): Readonly<StoreRecord<unknown>> {
  return Object.freeze({
    version: "opaque/v1",
    storeRevision,
    updatedAt: storeRevision,
    value: Object.freeze({ marker }),
  });
}

for (const backendCase of PREPARED_CALL_BACKENDS) {
  describe(`${backendCase.name} prepared-call adapter`, () => {
    it("keys opaque records by exact provider scope and context ID", async () => {
      const backend = await backendCase.open();
      try {
        const retained = opaqueRecord(0, "retained");
        await expect(
          backend.adapter.compareAndSwap({
            key: adapterKey(),
            expectedStoreRevision: null,
            next: retained,
          }),
        ).resolves.toBe(true);
        await expect(backend.adapter.get(adapterKey())).resolves.toEqual(retained);
        await expect(backend.adapter.get(adapterKey(OTHER_ADAPTER_SCOPE))).resolves.toBeUndefined();
        await expect(
          backend.adapter.get(adapterKey(ADAPTER_SCOPE, OTHER_ADAPTER_CONTEXT)),
        ).resolves.toBeUndefined();
      } finally {
        backend.dispose();
      }
    });

    it("atomically admits one writer for an expected revision", async () => {
      const backend = await backendCase.open();
      try {
        await expect(
          backend.adapter.compareAndSwap({
            key: adapterKey(),
            expectedStoreRevision: null,
            next: opaqueRecord(0, "initial"),
          }),
        ).resolves.toBe(true);

        const contenders = await Promise.all([
          backend.adapter.compareAndSwap({
            key: adapterKey(),
            expectedStoreRevision: 0,
            next: opaqueRecord(1, "first"),
          }),
          backend.adapter.compareAndSwap({
            key: adapterKey(),
            expectedStoreRevision: 0,
            next: opaqueRecord(1, "second"),
          }),
        ]);
        expect(contenders.filter((result) => result === true)).toHaveLength(1);
        expect(contenders.filter((result) => result === false)).toHaveLength(1);
        await expect(
          backend.adapter.compareAndSwap({
            key: adapterKey(),
            expectedStoreRevision: 0,
            next: opaqueRecord(1, "stale"),
          }),
        ).resolves.toBe(false);
        await expect(backend.adapter.get(adapterKey())).resolves.toMatchObject({
          storeRevision: 1,
        });
      } finally {
        backend.dispose();
      }
    });
  });
}

describe("IndexedDB prepared-call durability", () => {
  it("recreates the lifecycle owner and keeps a consumed context non-reusable", async () => {
    const factory = new IDBFactory();
    const firstDatabase = await openOaathDatabase({ factory });
    const firstStore = new PreparedCallStore(
      createIndexedDbPreparedCallStoreAdapter(firstDatabase),
    );
    const prepared = requireCommitted(await firstStore.reservePrepared(reservation()));
    const consumed = requireCommitted(
      await firstStore.consume({
        key: { providerScopeId: PROVIDER_SCOPE_ID, contextId: CONTEXT_ID },
        expectedStoreRevision: prepared.storeRevision,
        consumedAt: 20,
        publicationExpiresAt: 40,
      }),
    );
    await firstStore.close();
    firstDatabase.close();

    let secondDatabase: OaathDatabase | undefined;
    let secondStore: PreparedCallStore | undefined;
    try {
      secondDatabase = await openOaathDatabase({ factory });
      secondStore = new PreparedCallStore(createIndexedDbPreparedCallStoreAdapter(secondDatabase));
      const key = { providerScopeId: PROVIDER_SCOPE_ID, contextId: CONTEXT_ID };
      await expect(secondStore.get(key)).resolves.toEqual(consumed);
      await expect(
        secondStore.consume({
          key,
          expectedStoreRevision: consumed.storeRevision,
          consumedAt: 30,
          publicationExpiresAt: 50,
        }),
      ).resolves.toEqual({ status: "conflict", current: consumed });
    } finally {
      await secondStore?.close();
      secondDatabase?.close();
    }
  });
});
