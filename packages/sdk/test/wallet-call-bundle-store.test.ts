/**
 * Durable wallet-call bundle state, concurrency, and retention invariants.
 *
 * @author taek <leekt216@gmail.com>
 */
import { describe, expect, it } from "vitest";
import {
  OAATH_WALLET_CALL_BUNDLE_STORE_RECORD_VERSION,
  OAATH_WALLET_CALL_BUNDLE_VERSION,
  OaathPersistenceError,
  parseWalletCallBundleKey,
  parseWalletCallBundleRecord,
  type WalletCallBundleKey,
  type WalletCallBundleOperation,
  type WalletCallBundleRecord,
  type WalletCallBundleStoreAdapter,
  type WalletCallBundleStoreRecord,
} from "../src/persistence/interfaces.js";
import {
  WALLET_CALL_BUNDLE_RETENTION_SECONDS,
  type WalletCallBundleMutationResult,
  WalletCallBundleStore,
} from "../src/provider/bundle-store.js";
import { OaathStoreError, type StoreRecord } from "../src/store.js";

const SCOPE = `0x${"11".repeat(32)}` as const;
const OTHER_SCOPE = `0x${"12".repeat(32)}` as const;
const ACCOUNT = `0x${"22".repeat(20)}` as const;
const OTHER_ACCOUNT = `0x${"23".repeat(20)}` as const;
const REQUEST_HASH = `0x${"33".repeat(32)}` as const;
const OTHER_REQUEST_HASH = `0x${"34".repeat(32)}` as const;
const USER_OPERATION_HASH = `0x${"44".repeat(32)}` as const;
const OTHER_USER_OPERATION_HASH = `0x${"45".repeat(32)}` as const;
const CHAIN_ID = 31_337;

function key(
  id = "bundle",
  providerScopeId: WalletCallBundleKey["providerScopeId"] = SCOPE,
  account: WalletCallBundleKey["account"] = ACCOUNT,
): Readonly<WalletCallBundleKey> {
  return Object.freeze({ providerScopeId, account, id });
}

function operation(
  chainId = CHAIN_ID,
  userOperationHash: WalletCallBundleOperation["userOperationHash"] = USER_OPERATION_HASH,
): Readonly<WalletCallBundleOperation> {
  return Object.freeze({
    key: Object.freeze({ grantId: "grant", chainId, kind: "execution" as const }),
    userOperationHash,
  });
}

function bundleRecord(
  overrides: Partial<WalletCallBundleRecord> = {},
): Readonly<WalletCallBundleRecord> {
  return {
    version: OAATH_WALLET_CALL_BUNDLE_VERSION,
    providerScopeId: SCOPE,
    id: "bundle",
    account: ACCOUNT,
    chainId: CHAIN_ID,
    createdAt: 10,
    requestHash: REQUEST_HASH,
    operation: null,
    state: "accepted",
    ...overrides,
  };
}

function envelope(
  value: Readonly<WalletCallBundleRecord> = bundleRecord(),
  storeRevision = 0,
  updatedAt = value.createdAt,
): WalletCallBundleStoreRecord {
  return {
    version: OAATH_WALLET_CALL_BUNDLE_STORE_RECORD_VERSION,
    storeRevision,
    updatedAt,
    value,
  };
}

function clone<Value>(value: Value): Value {
  if (value === undefined) return value;
  return JSON.parse(JSON.stringify(value)) as Value;
}

function mapKey(value: Readonly<WalletCallBundleKey>): string {
  return JSON.stringify([value.providerScopeId, value.account, value.id]);
}

interface MemoryAdapter {
  readonly adapter: WalletCallBundleStoreAdapter;
  readonly raw: (value: Readonly<WalletCallBundleKey>) => unknown;
  readonly set: (value: Readonly<WalletCallBundleKey>, record: unknown) => void;
  readonly casCalls: () => number;
  readonly deleteCalls: () => number;
  readonly closeCalls: () => number;
}

function memoryAdapter(
  entries: readonly (readonly [Readonly<WalletCallBundleKey>, unknown])[] = [],
): MemoryAdapter {
  const records = new Map(entries.map(([entryKey, value]) => [mapKey(entryKey), clone(value)]));
  let casCalls = 0;
  let deleteCalls = 0;
  let closeCalls = 0;
  const adapter: WalletCallBundleStoreAdapter = {
    async get(entryKey) {
      return clone(records.get(mapKey(entryKey)));
    },
    async compareAndSwap({ key: entryKey, expectedStoreRevision, next }) {
      casCalls += 1;
      const serialized = mapKey(entryKey);
      const current = records.get(serialized) as { storeRevision?: unknown } | undefined;
      if (
        expectedStoreRevision === null
          ? current !== undefined
          : current?.storeRevision !== expectedStoreRevision
      ) {
        return false;
      }
      records.set(serialized, clone(next));
      return true;
    },
    async compareAndDelete({ key: entryKey, expectedStoreRevision }) {
      deleteCalls += 1;
      const serialized = mapKey(entryKey);
      const current = records.get(serialized) as { storeRevision?: unknown } | undefined;
      if (current?.storeRevision !== expectedStoreRevision) return false;
      records.delete(serialized);
      return true;
    },
    async close() {
      closeCalls += 1;
    },
  };
  return {
    adapter,
    raw: (entryKey) => clone(records.get(mapKey(entryKey))),
    set: (entryKey, value) => records.set(mapKey(entryKey), clone(value)),
    casCalls: () => casCalls,
    deleteCalls: () => deleteCalls,
    closeCalls: () => closeCalls,
  };
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

function expectPersistenceError(action: () => unknown, code: OaathPersistenceError["code"]): void {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(OaathPersistenceError);
    expect((error as OaathPersistenceError).code).toBe(code);
    return;
  }
  throw new Error(`Expected ${code}`);
}

function requireCommitted(result: WalletCallBundleMutationResult): WalletCallBundleStoreRecord {
  if (result.status !== "committed") throw new Error("expected a committed bundle mutation");
  return result.record;
}

async function reserve(
  store: WalletCallBundleStore,
  entryKey: Readonly<WalletCallBundleKey> = key(),
  chainId = CHAIN_ID,
  createdAt = 10,
  requestHash: WalletCallBundleRecord["requestHash"] = REQUEST_HASH,
): Promise<WalletCallBundleMutationResult> {
  return store.reserveAccepted({ key: entryKey, chainId, createdAt, requestHash });
}

describe("wallet-call bundle persistence parser", () => {
  it("captures arbitrary bounded UTF-8 IDs exactly and freezes the current v1 record", () => {
    const id = " app:\u0000/日本語/😀/not-hex ";
    const capturedKey = parseWalletCallBundleKey(key(id));
    expect(capturedKey.id).toBe(id);
    expect(Object.isFrozen(capturedKey)).toBe(true);

    const exactBoundary = "😀".repeat(1_024);
    expect(parseWalletCallBundleKey(key(exactBoundary)).id).toBe(exactBoundary);
    expectPersistenceError(
      () => parseWalletCallBundleKey(key(`${exactBoundary}a`)),
      "persistence_input_invalid",
    );

    const binding = operation();
    const captured = parseWalletCallBundleRecord(
      bundleRecord({ id, operation: binding, state: "operation_bound" }),
    );
    expect(captured).toEqual(bundleRecord({ id, operation: binding, state: "operation_bound" }));
    expect(Object.isFrozen(captured)).toBe(true);
    expect(Object.isFrozen(captured.operation)).toBe(true);
    expect(Object.isFrozen(captured.operation?.key)).toBe(true);
  });

  it("rejects hostile records without invoking accessors", () => {
    let accesses = 0;
    const hostileKey = { account: ACCOUNT, id: "bundle" } as Record<string, unknown>;
    Object.defineProperty(hostileKey, "providerScopeId", {
      enumerable: true,
      get() {
        accesses += 1;
        return SCOPE;
      },
    });
    expectPersistenceError(() => parseWalletCallBundleKey(hostileKey), "persistence_input_invalid");

    const hostileRecord = bundleRecord() as Record<string, unknown>;
    Object.defineProperty(hostileRecord, "requestHash", {
      enumerable: true,
      get() {
        accesses += 1;
        return REQUEST_HASH;
      },
    });
    expectPersistenceError(
      () => parseWalletCallBundleRecord(hostileRecord),
      "persistence_record_invalid",
    );
    expect(accesses).toBe(0);
  });

  it("rejects wrong versions, fields, canonical forms, and state contradictions", () => {
    const wrongValues: unknown[] = [
      { ...bundleRecord(), version: "oaath.wallet-call-bundle/v0" },
      { ...bundleRecord(), extra: true },
      { ...bundleRecord(), providerScopeId: SCOPE.toUpperCase() },
      { ...bundleRecord(), account: ACCOUNT.toUpperCase() },
      { ...bundleRecord(), chainId: 0 },
      { ...bundleRecord(), chainId: Number.MAX_SAFE_INTEGER + 1 },
      { ...bundleRecord(), createdAt: -0 },
      { ...bundleRecord(), requestHash: REQUEST_HASH.toUpperCase() },
      { ...bundleRecord(), state: "unknown" },
      { ...bundleRecord(), operation: operation(), state: "accepted" },
      { ...bundleRecord(), operation: null, state: "operation_bound" },
      {
        ...bundleRecord(),
        operation: { ...operation(), extra: true },
        state: "operation_bound",
      },
      {
        ...bundleRecord(),
        operation: { ...operation(), userOperationHash: USER_OPERATION_HASH.toUpperCase() },
        state: "operation_bound",
      },
      {
        ...bundleRecord(),
        operation: { ...operation(), key: { ...operation().key, kind: "revocation" } },
        state: "operation_bound",
      },
      {
        ...bundleRecord(),
        operation: operation(CHAIN_ID + 1),
        state: "operation_bound",
      },
    ];
    for (const value of wrongValues) {
      expectPersistenceError(
        () => parseWalletCallBundleRecord(value),
        "persistence_record_invalid",
      );
    }

    for (const invalidKey of [
      { ...key(), providerScopeId: SCOPE.toUpperCase() },
      { ...key(), account: ACCOUNT.toUpperCase() },
      { ...key(), id: "" },
      { ...key(), extra: true },
    ]) {
      expectPersistenceError(
        () => parseWalletCallBundleKey(invalidKey),
        "persistence_input_invalid",
      );
    }

    expect(parseWalletCallBundleRecord(bundleRecord({ state: "terminal" })).operation).toBeNull();
    expect(
      parseWalletCallBundleRecord(bundleRecord({ operation: operation(), state: "terminal" }))
        .operation,
    ).toEqual(operation());
  });

  it("rejects malformed, wrong-envelope-version, and every key mismatch", async () => {
    const memory = memoryAdapter([[key(), {}]]);
    const store = new WalletCallBundleStore(memory.adapter);
    await expectStoreError(() => store.get(key()), "store_record_invalid");
    await expectStoreError(() => store.get({ ...key(), id: "" }), "store_input_invalid");
    await expectStoreError(
      () =>
        store.reserveAccepted({ key: key(), chainId: 0, createdAt: 10, requestHash: REQUEST_HASH }),
      "store_input_invalid",
    );

    memory.set(key(), { ...envelope(), value: {} });
    await expectStoreError(() => store.get(key()), "store_record_invalid");

    memory.set(key(), {
      ...envelope(),
      version: "oaath.wallet-call-bundle-store-record/v0",
    });
    await expectStoreError(() => store.get(key()), "store_record_invalid");

    for (const value of [
      bundleRecord({ providerScopeId: OTHER_SCOPE }),
      bundleRecord({ account: OTHER_ACCOUNT }),
      bundleRecord({ id: "other" }),
    ]) {
      memory.set(key(), envelope(value));
      await expectStoreError(() => store.get(key()), "store_key_mismatch");
    }

    memory.set(key(), { ...envelope(), updatedAt: 9 });
    await expectStoreError(() => store.get(key()), "store_record_invalid");
    const negativeZeroStore = new WalletCallBundleStore({
      async get() {
        return { ...envelope(), storeRevision: -0 };
      },
      async compareAndSwap() {
        return false;
      },
      async compareAndDelete() {
        return false;
      },
      async close() {},
    });
    await expectStoreError(() => negativeZeroStore.get(key()), "store_record_invalid");
    memory.set(key(), { ...envelope(), extra: true });
    await expectStoreError(() => store.get(key()), "store_record_invalid");
  });
});

describe("wallet-call bundle transitions and uniqueness", () => {
  it("commits every allowed transition and retains immutable operation evidence", async () => {
    const memory = memoryAdapter();
    const store = new WalletCallBundleStore(memory.adapter);

    const accepted = requireCommitted(await reserve(store));
    expect(accepted).toEqual(envelope());

    const bound = requireCommitted(
      await store.bindOperation({ key: key(), operation: operation(), updatedAt: 20 }),
    );
    expect(bound).toEqual(
      envelope(bundleRecord({ operation: operation(), state: "operation_bound" }), 1, 20),
    );

    const terminal = requireCommitted(await store.markTerminal({ key: key(), updatedAt: 30 }));
    expect(terminal).toEqual(
      envelope(bundleRecord({ operation: operation(), state: "terminal" }), 2, 30),
    );
    expect((await store.get(key()))?.value.operation).toEqual(operation());
  });

  it("supports conclusive accepted-to-terminal failure without an operation", async () => {
    const store = new WalletCallBundleStore(memoryAdapter().adapter);
    requireCommitted(await reserve(store));
    const terminal = requireCommitted(await store.markTerminal({ key: key(), updatedAt: 10 }));
    expect(terminal).toMatchObject({
      storeRevision: 1,
      updatedAt: 10,
      value: { state: "terminal", operation: null },
    });
  });

  it("rejects every backward transition and exact rebind without an adapter write", async () => {
    const memory = memoryAdapter();
    const store = new WalletCallBundleStore(memory.adapter);
    requireCommitted(await reserve(store));
    requireCommitted(
      await store.bindOperation({ key: key(), operation: operation(), updatedAt: 20 }),
    );
    const writesAfterBind = memory.casCalls();

    await expect(
      store.bindOperation({
        key: key(),
        operation: operation(CHAIN_ID, OTHER_USER_OPERATION_HASH),
        updatedAt: 21,
      }),
    ).resolves.toMatchObject({
      status: "conflict",
      current: { value: { state: "operation_bound" } },
    });
    await expect(store.markTerminal({ key: key(), updatedAt: 19 })).resolves.toMatchObject({
      status: "conflict",
      current: { value: { state: "operation_bound" } },
    });
    expect(memory.casCalls()).toBe(writesAfterBind);

    requireCommitted(await store.markTerminal({ key: key(), updatedAt: 20 }));
    const writesAfterTerminal = memory.casCalls();
    await expect(store.markTerminal({ key: key(), updatedAt: 21 })).resolves.toMatchObject({
      status: "conflict",
      current: { value: { state: "terminal" } },
    });
    await expect(
      store.bindOperation({ key: key(), operation: operation(), updatedAt: 21 }),
    ).resolves.toMatchObject({ status: "conflict", current: { value: { state: "terminal" } } });
    expect(memory.casCalls()).toBe(writesAfterTerminal);
  });

  it("captures all mutation input before adapter access and rejects a wrong operation chain", async () => {
    let calls = 0;
    let accesses = 0;
    const store = new WalletCallBundleStore({
      async get() {
        calls += 1;
      },
      async compareAndSwap() {
        calls += 1;
        return false;
      },
      async compareAndDelete() {
        calls += 1;
        return false;
      },
      async close() {},
    });
    const hostile = { chainId: CHAIN_ID, createdAt: 10, requestHash: REQUEST_HASH } as Record<
      string,
      unknown
    >;
    Object.defineProperty(hostile, "key", {
      enumerable: true,
      get() {
        accesses += 1;
        return key();
      },
    });
    await expectStoreError(() => store.reserveAccepted(hostile), "store_input_invalid");
    expect({ accesses, calls }).toEqual({ accesses: 0, calls: 0 });

    const memory = memoryAdapter();
    const persisted = new WalletCallBundleStore(memory.adapter);
    requireCommitted(await reserve(persisted));
    await expectStoreError(
      () =>
        persisted.bindOperation({
          key: key(),
          operation: operation(CHAIN_ID + 1),
          updatedAt: 20,
        }),
      "store_input_invalid",
    );
    expect(memory.casCalls()).toBe(1);

    for (const invalidOperation of [
      { ...operation(), key: { ...operation().key, chainId: 0 } },
      { ...operation(), key: { ...operation().key, grantId: " grant " } },
      { ...operation(), key: { ...operation().key, kind: "revocation" } },
      { ...operation(), userOperationHash: USER_OPERATION_HASH.toUpperCase() },
    ]) {
      await expectStoreError(
        () => persisted.bindOperation({ key: key(), operation: invalidOperation, updatedAt: 20 }),
        "store_input_invalid",
      );
    }
    expect(memory.casCalls()).toBe(1);
  });

  it("keeps exact IDs and isolates scope/account while excluding chain from uniqueness", async () => {
    const memory = memoryAdapter();
    const store = new WalletCallBundleStore(memory.adapter);
    const unicode = " 日本語/😀/\u0000 ";
    const first = key(unicode);
    const anotherScope = key(unicode, OTHER_SCOPE);
    const anotherAccount = key(unicode, SCOPE, OTHER_ACCOUNT);
    const caseDistinct = key(`${unicode}A`);

    requireCommitted(await reserve(store, first, 1));
    requireCommitted(await reserve(store, anotherScope, 1));
    requireCommitted(await reserve(store, anotherAccount, 1));
    requireCommitted(await reserve(store, caseDistinct, 1));
    const writes = memory.casCalls();

    const duplicateAcrossChain = await reserve(store, first, 2, 11, OTHER_REQUEST_HASH);
    expect(duplicateAcrossChain).toMatchObject({
      status: "conflict",
      current: { value: { id: unicode, chainId: 1, requestHash: REQUEST_HASH } },
    });
    expect(memory.casCalls()).toBe(writes);
  });

  it("reports absent bind/terminal mutations as conflicts without writing", async () => {
    const memory = memoryAdapter();
    const store = new WalletCallBundleStore(memory.adapter);
    await expect(
      store.bindOperation({ key: key(), operation: operation(), updatedAt: 20 }),
    ).resolves.toEqual({ status: "conflict" });
    await expect(store.markTerminal({ key: key(), updatedAt: 20 })).resolves.toEqual({
      status: "conflict",
    });
    expect(memory.casCalls()).toBe(0);
  });
});

function racingAdapter(initial?: WalletCallBundleStoreRecord): WalletCallBundleStoreAdapter {
  let raw: unknown = clone(initial);
  let reads = 0;
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  return {
    async get() {
      reads += 1;
      const observed = clone(raw);
      if (reads <= 2) {
        if (reads === 2) release();
        await gate;
      }
      return observed;
    },
    async compareAndSwap({ expectedStoreRevision, next }) {
      const current = raw as { storeRevision?: unknown } | undefined;
      if (
        expectedStoreRevision === null
          ? current !== undefined
          : current?.storeRevision !== expectedStoreRevision
      ) {
        return false;
      }
      raw = clone(next);
      return true;
    },
    async compareAndDelete() {
      return false;
    },
    async close() {},
  };
}

describe("wallet-call bundle races and retained-write verification", () => {
  it("resolves an absent reservation race as one commit and one current conflict", async () => {
    const adapter = racingAdapter();
    const stores = [new WalletCallBundleStore(adapter), new WalletCallBundleStore(adapter)];
    const results = await Promise.all(stores.map((store) => reserve(store)));
    expect(results.filter((result) => result.status === "committed")).toHaveLength(1);
    const conflicts = results.filter((result) => result.status === "conflict");
    expect(conflicts).toHaveLength(1);
    expect(conflicts[0]).toMatchObject({
      status: "conflict",
      current: { storeRevision: 0, value: { state: "accepted" } },
    });
  });

  it("fails one bind-vs-terminal race closed and exposes the winner", async () => {
    const adapter = racingAdapter(envelope());
    const bindStore = new WalletCallBundleStore(adapter);
    const terminalStore = new WalletCallBundleStore(adapter);
    const results = await Promise.all([
      bindStore.bindOperation({ key: key(), operation: operation(), updatedAt: 20 }),
      terminalStore.markTerminal({ key: key(), updatedAt: 20 }),
    ]);
    expect(results.filter((result) => result.status === "committed")).toHaveLength(1);
    const conflictResult = results.find((result) => result.status === "conflict");
    expect(conflictResult).toMatchObject({ status: "conflict", current: { storeRevision: 1 } });
    if (conflictResult?.status !== "conflict" || conflictResult.current === undefined) {
      throw new Error("expected the winning record");
    }
    expect(["operation_bound", "terminal"]).toContain(conflictResult.current.value.state);
  });

  it("never overwrites an unreadable record", async () => {
    let writes = 0;
    const store = new WalletCallBundleStore({
      async get() {
        return { unreadable: true };
      },
      async compareAndSwap() {
        writes += 1;
        return true;
      },
      async compareAndDelete() {
        writes += 1;
        return true;
      },
      async close() {},
    });
    await expectStoreError(() => reserve(store), "store_record_invalid");
    await expectStoreError(
      () => store.deleteExpiredTerminal(key(), 100_000),
      "store_record_invalid",
    );
    expect(writes).toBe(0);
  });

  it("classifies thrown, malformed, and unproven CAS outcomes as indeterminate", async () => {
    for (const compareAndSwap of [
      async () => {
        throw new Error("ack lost");
      },
      async () => "committed",
      async () => false,
    ]) {
      const store = new WalletCallBundleStore({
        async get() {},
        compareAndSwap,
        async compareAndDelete() {
          return false;
        },
        async close() {},
      });
      await expectStoreError(() => reserve(store), "store_commit_indeterminate");
    }

    let reads = 0;
    const sameRevision = new WalletCallBundleStore({
      async get() {
        reads += 1;
        return reads === 1 ? envelope() : envelope();
      },
      async compareAndSwap() {
        return false;
      },
      async compareAndDelete() {
        return false;
      },
      async close() {},
    });
    await expectStoreError(
      () => sameRevision.markTerminal({ key: key(), updatedAt: 20 }),
      "store_commit_indeterminate",
    );

    const exhausted = new WalletCallBundleStore(
      memoryAdapter([[key(), envelope(bundleRecord(), Number.MAX_SAFE_INTEGER)]]).adapter,
    );
    await expectStoreError(
      () => exhausted.markTerminal({ key: key(), updatedAt: 20 }),
      "store_revision_exhausted",
    );
  });

  it("detects lying success and preserves a visible write after an indeterminate throw", async () => {
    const lying = new WalletCallBundleStore({
      async get() {},
      async compareAndSwap() {
        return true;
      },
      async compareAndDelete() {
        return false;
      },
      async close() {},
    });
    await expectStoreError(() => reserve(lying), "store_commit_unverified");

    let raw: Readonly<StoreRecord<unknown>> | undefined;
    const altered = new WalletCallBundleStore({
      async get() {
        return raw;
      },
      async compareAndSwap(input: { next: Readonly<StoreRecord<unknown>> }) {
        raw = { ...input.next, storeRevision: input.next.storeRevision + 1 };
        return true;
      },
      async compareAndDelete() {
        return false;
      },
      async close() {},
    });
    await expectStoreError(() => reserve(altered), "store_commit_unverified");

    raw = undefined;
    const ambiguous = new WalletCallBundleStore({
      async get() {
        return raw;
      },
      async compareAndSwap(input: { next: Readonly<StoreRecord<unknown>> }) {
        raw = input.next;
        throw new Error("acknowledgement lost");
      },
      async compareAndDelete() {
        return false;
      },
      async close() {},
    });
    await expectStoreError(() => reserve(ambiguous), "store_commit_indeterminate");
    await expect(ambiguous.get(key())).resolves.toMatchObject({
      storeRevision: 0,
      value: { state: "accepted" },
    });

    let reads = 0;
    const unavailableVerification = new WalletCallBundleStore({
      async get() {
        reads += 1;
        if (reads > 1) throw new Error("read unavailable");
      },
      async compareAndSwap() {
        return true;
      },
      async compareAndDelete() {
        return false;
      },
      async close() {},
    });
    await expectStoreError(() => reserve(unavailableVerification), "store_commit_unverified");
  });

  it("rejects every immutable identity mutation and nonnull operation rebind in a CAS race", async () => {
    const replacements: readonly Readonly<WalletCallBundleRecord>[] = [
      bundleRecord({ chainId: CHAIN_ID + 1 }),
      bundleRecord({ createdAt: 11 }),
      bundleRecord({ requestHash: OTHER_REQUEST_HASH }),
    ];
    for (const replacement of replacements) {
      let reads = 0;
      const store = new WalletCallBundleStore({
        async get() {
          reads += 1;
          return reads === 1 ? envelope() : envelope(replacement, 1, replacement.createdAt);
        },
        async compareAndSwap() {
          return false;
        },
        async compareAndDelete() {
          return false;
        },
        async close() {},
      });
      await expectStoreError(
        () => store.markTerminal({ key: key(), updatedAt: 20 }),
        "store_identity_mismatch",
      );
    }

    const bound = bundleRecord({ operation: operation(), state: "operation_bound" });
    const rebound = bundleRecord({
      operation: operation(CHAIN_ID, OTHER_USER_OPERATION_HASH),
      state: "terminal",
    });
    let reads = 0;
    const rebindStore = new WalletCallBundleStore({
      async get() {
        reads += 1;
        return reads === 1 ? envelope(bound, 1, 20) : envelope(rebound, 2, 21);
      },
      async compareAndSwap() {
        return false;
      },
      async compareAndDelete() {
        return false;
      },
      async close() {},
    });
    await expectStoreError(
      () => rebindStore.markTerminal({ key: key(), updatedAt: 21 }),
      "store_identity_mismatch",
    );

    for (const replacement of [
      bundleRecord({ providerScopeId: OTHER_SCOPE }),
      bundleRecord({ account: OTHER_ACCOUNT }),
      bundleRecord({ id: "other" }),
    ]) {
      reads = 0;
      const store = new WalletCallBundleStore({
        async get() {
          reads += 1;
          return reads === 1 ? envelope() : envelope(replacement, 1, 20);
        },
        async compareAndSwap() {
          return false;
        },
        async compareAndDelete() {
          return false;
        },
        async close() {},
      });
      await expectStoreError(
        () => store.markTerminal({ key: key(), updatedAt: 20 }),
        "store_commit_indeterminate",
      );
    }
  });

  it("rejects backward state and transition-time evidence from a racing writer", async () => {
    const bound = bundleRecord({ operation: operation(), state: "operation_bound" });
    for (const raced of [envelope(bundleRecord(), 2, 21), envelope(bound, 2, 19)]) {
      let reads = 0;
      const store = new WalletCallBundleStore({
        async get() {
          reads += 1;
          return reads === 1 ? envelope(bound, 1, 20) : raced;
        },
        async compareAndSwap() {
          return false;
        },
        async compareAndDelete() {
          return false;
        },
        async close() {},
      });
      await expectStoreError(
        () => store.markTerminal({ key: key(), updatedAt: 21 }),
        "store_record_invalid",
      );
    }
  });
});

describe("wallet-call bundle terminal retention", () => {
  it("deletes only at the exact terminal-age boundary", async () => {
    const terminal = bundleRecord({ state: "terminal" });
    const memory = memoryAdapter([[key(), envelope(terminal, 1, 20)]]);
    const store = new WalletCallBundleStore(memory.adapter);

    await expect(
      store.deleteExpiredTerminal(key(), 20 + WALLET_CALL_BUNDLE_RETENTION_SECONDS - 1),
    ).resolves.toMatchObject({ status: "conflict", current: { updatedAt: 20 } });
    expect(memory.deleteCalls()).toBe(0);

    await expect(
      store.deleteExpiredTerminal(key(), 20 + WALLET_CALL_BUNDLE_RETENTION_SECONDS),
    ).resolves.toEqual({ status: "deleted" });
    expect(memory.deleteCalls()).toBe(1);
    await expect(store.deleteExpiredTerminal(key(), 200_000)).resolves.toEqual({
      status: "absent",
    });
  });

  it("never cleans accepted or operation-bound work even long past 24 hours", async () => {
    const acceptedKey = key("accepted");
    const boundKey = key("bound");
    const accepted = bundleRecord({ id: acceptedKey.id });
    const bound = bundleRecord({
      id: boundKey.id,
      operation: operation(),
      state: "operation_bound",
    });
    const memory = memoryAdapter([
      [acceptedKey, envelope(accepted, 0, 10)],
      [boundKey, envelope(bound, 1, 20)],
    ]);
    const store = new WalletCallBundleStore(memory.adapter);
    const farFuture = 10 * WALLET_CALL_BUNDLE_RETENTION_SECONDS;

    await expect(store.deleteExpiredTerminal(acceptedKey, farFuture)).resolves.toMatchObject({
      status: "conflict",
      current: { value: { state: "accepted" } },
    });
    await expect(store.deleteExpiredTerminal(boundKey, farFuture)).resolves.toMatchObject({
      status: "conflict",
      current: { value: { state: "operation_bound" } },
    });
    expect(memory.deleteCalls()).toBe(0);
  });

  it("uses the caller's exact time and configurable nonnegative retention", async () => {
    const terminal = bundleRecord({ state: "terminal" });
    const memory = memoryAdapter([[key(), envelope(terminal, 1, 20)]]);
    const store = new WalletCallBundleStore(memory.adapter);
    await expect(store.deleteExpiredTerminal(key(), 19, 0)).resolves.toMatchObject({
      status: "conflict",
    });
    await expect(store.deleteExpiredTerminal(key(), 20, 0)).resolves.toEqual({
      status: "deleted",
    });

    for (const invalidValue of [-1, -0, Number.MAX_SAFE_INTEGER + 1]) {
      await expectStoreError(
        () => store.deleteExpiredTerminal(key(), invalidValue),
        "store_input_invalid",
      );
      await expectStoreError(
        () => store.deleteExpiredTerminal(key(), 20, invalidValue),
        "store_input_invalid",
      );
    }
  });

  it("reports compare-and-delete races as explicit conflict or absence", async () => {
    const terminal = bundleRecord({ state: "terminal" });
    let raw: WalletCallBundleStoreRecord | undefined = envelope(terminal, 1, 20);
    let mode: "conflict" | "absent" = "conflict";
    const store = new WalletCallBundleStore({
      async get() {
        return clone(raw);
      },
      async compareAndSwap() {
        return false;
      },
      async compareAndDelete() {
        if (mode === "conflict") raw = envelope(terminal, 2, 21);
        else raw = undefined;
        return false;
      },
      async close() {},
    });

    await expect(store.deleteExpiredTerminal(key(), 100_000, 0)).resolves.toMatchObject({
      status: "conflict",
      current: { storeRevision: 2 },
    });
    mode = "absent";
    raw = envelope(terminal, 3, 22);
    await expect(store.deleteExpiredTerminal(key(), 100_000, 0)).resolves.toEqual({
      status: "absent",
    });
  });

  it("rejects indeterminate or unverified compare-and-delete outcomes", async () => {
    const terminalEnvelope = envelope(bundleRecord({ state: "terminal" }), 1, 20);
    for (const compareAndDelete of [
      async () => {
        throw new Error("ack lost");
      },
      async () => "deleted",
      async () => false,
    ]) {
      const store = new WalletCallBundleStore({
        async get() {
          return terminalEnvelope;
        },
        async compareAndSwap() {
          return false;
        },
        compareAndDelete,
        async close() {},
      });
      await expectStoreError(
        () => store.deleteExpiredTerminal(key(), 100_000, 0),
        "store_commit_indeterminate",
      );
    }

    const lying = new WalletCallBundleStore({
      async get() {
        return terminalEnvelope;
      },
      async compareAndSwap() {
        return false;
      },
      async compareAndDelete() {
        return true;
      },
      async close() {},
    });
    await expectStoreError(
      () => lying.deleteExpiredTerminal(key(), 100_000, 0),
      "store_commit_unverified",
    );

    for (const deleted of [true, false]) {
      let reads = 0;
      const unavailableVerification = new WalletCallBundleStore({
        async get() {
          reads += 1;
          if (reads > 1) throw new Error("read unavailable");
          return terminalEnvelope;
        },
        async compareAndSwap() {
          return false;
        },
        async compareAndDelete() {
          return deleted;
        },
        async close() {},
      });
      await expectStoreError(
        () => unavailableVerification.deleteExpiredTerminal(key(), 100_000, 0),
        deleted ? "store_commit_unverified" : "store_commit_indeterminate",
      );
    }
  });
});

describe("wallet-call bundle store capability and close boundary", () => {
  it("rejects hostile or expanded adapters without invoking accessors", () => {
    let accesses = 0;
    const hostile = {
      compareAndSwap: async () => false,
      compareAndDelete: async () => false,
      close: async () => {},
    } as Record<string, unknown>;
    Object.defineProperty(hostile, "get", {
      enumerable: true,
      get() {
        accesses += 1;
        return async () => undefined;
      },
    });
    expect(() => new WalletCallBundleStore(hostile)).toThrowError(
      expect.objectContaining({ code: "store_input_invalid" }),
    );
    expect(accesses).toBe(0);

    const valid = memoryAdapter().adapter;
    expect(() => new WalletCallBundleStore({ ...valid, extra: true })).toThrowError(
      expect.objectContaining({ code: "store_input_invalid" }),
    );
    expect(() => new WalletCallBundleStore({ ...valid, get: null })).toThrowError(
      expect.objectContaining({ code: "store_input_invalid" }),
    );
    expect(() => new WalletCallBundleStore(Object.create(valid))).toThrowError(
      expect.objectContaining({ code: "store_input_invalid" }),
    );
  });

  it("keeps close retryable, deduplicates concurrent close, and rejects later access", async () => {
    let closeCalls = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const store = new WalletCallBundleStore({
      async get() {},
      async compareAndSwap() {
        return false;
      },
      async compareAndDelete() {
        return false;
      },
      async close() {
        closeCalls += 1;
        if (closeCalls === 1) throw new Error("still open");
        await gate;
      },
    });

    await expectStoreError(() => store.close(), "store_unavailable");
    await expect(store.get(key())).resolves.toBeUndefined();
    const closing = Promise.all([store.close(), store.close()]);
    await Promise.resolve();
    expect(closeCalls).toBe(2);
    release();
    await closing;
    await store.close();
    expect(closeCalls).toBe(2);

    await expectStoreError(() => store.get(key()), "store_closed");
    await expectStoreError(() => reserve(store), "store_closed");
    await expectStoreError(
      () => store.bindOperation({ key: key(), operation: operation(), updatedAt: 20 }),
      "store_closed",
    );
    await expectStoreError(() => store.markTerminal({ key: key(), updatedAt: 20 }), "store_closed");
    await expectStoreError(() => store.deleteExpiredTerminal(key(), 100_000), "store_closed");
  });
});
