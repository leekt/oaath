import {
  advanceGrant,
  createGrant,
  createOperation,
  type Grant,
  type GrantIdentity,
  type Operation,
  type OperationIdentity,
} from "@oaath/protocol";
import { describe, expect, it } from "vitest";
import {
  GrantStore,
  type GrantStoreAdapter,
  OAATH_GRANT_STORE_RECORD_VERSION,
  OaathStoreError,
  OperationStore,
  type StoreRecord,
} from "../src/index.js";

const grantIdentity: GrantIdentity = {
  grantId: "grant-store",
  chainScope: "all",
  application: {
    applicationId: "oaath-tests",
    clientId: "store",
    origin: "https://store.example",
    deviceId: "store-device",
  },
  logicalAccount: {
    version: "oaath.kernel-account-profile/v1",
    kind: "kernel",
    accountIndex: "0",
    kernelVersion: "0.4.0",
    factoryRoute: "meta_factory",
    entryPoint: { version: "0.7" },
    ownerCredential: {
      version: "oaath.owner-credential-profile/v1",
      kind: "ecdsa",
      address: `0x${"11".repeat(20)}`,
    },
  },
  operatorCredential: {
    version: "oaath.operator-credential-profile/v1",
    kind: "ecdsa",
    address: `0x${"22".repeat(20)}`,
  },
  policyHash: `0x${"33".repeat(32)}`,
};

function requestedGrant(): Grant {
  return createGrant({ identity: grantIdentity, requestedAt: 10, expiresAt: 100 });
}

function approvedGrant(): Grant {
  return advanceGrant(requestedGrant(), {
    type: "approve",
    identity: grantIdentity,
    approval: {
      approvalHash: `0x${"44".repeat(32)}`,
      capabilityHash: `0x${"55".repeat(32)}`,
      approvedAt: 20,
    },
  });
}

function operationIdentity(chainId = 31_337, seed = "6"): OperationIdentity {
  return {
    kind: "execution",
    grantId: grantIdentity.grantId,
    chainId,
    entryPoint: `0x${"11".repeat(20)}`,
    account: `0x${"22".repeat(20)}`,
    nonce: seed,
    userOperationHash: `0x${seed.repeat(64)}`,
  };
}

function preparedOperation(chainId = 31_337, seed = "6"): Operation {
  return createOperation({ identity: operationIdentity(chainId, seed), preparedAt: 10 });
}

function clone<Value>(value: Value): Value {
  if (value === undefined) return value;
  return JSON.parse(JSON.stringify(value)) as Value;
}

function memoryGrantAdapter(initial?: unknown): {
  adapter: GrantStoreAdapter;
  raw: () => unknown;
  set: (value: unknown) => void;
} {
  let raw = initial;
  return {
    adapter: {
      async get() {
        return clone(raw);
      },
      async compareAndSwap({ expectedStoreRevision, next }) {
        const current = raw as { storeRevision?: unknown } | undefined;
        if (
          (expectedStoreRevision === null && current !== undefined) ||
          (expectedStoreRevision !== null && current?.storeRevision !== expectedStoreRevision)
        ) {
          return false;
        }
        raw = clone(next);
        return true;
      },
      async close() {},
    },
    raw: () => raw,
    set: (value) => {
      raw = value;
    },
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

function expectStoreConstructorError(action: () => unknown, code: OaathStoreError["code"]): void {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(OaathStoreError);
    expect((error as OaathStoreError).code).toBe(code);
    return;
  }
  throw new Error(`Expected ${code}`);
}

describe("aggregate store boundary", () => {
  it("uses a store revision independent from the aggregate revision", async () => {
    const memory = memoryGrantAdapter();
    const store = new GrantStore(memory.adapter);

    const first = await store.compareAndSwap({
      grantId: grantIdentity.grantId,
      expectedStoreRevision: null,
      next: requestedGrant(),
    });
    expect(first).toMatchObject({
      status: "committed",
      record: { storeRevision: 0, value: { revision: 0, state: "requested" } },
    });

    const second = await store.compareAndSwap({
      grantId: grantIdentity.grantId,
      expectedStoreRevision: 0,
      next: approvedGrant(),
    });
    expect(second).toMatchObject({
      status: "committed",
      record: { storeRevision: 1, value: { revision: 1, state: "approved" } },
    });
  });

  it("rejects same-key Grant identity replacement before the adapter write", async () => {
    const memory = memoryGrantAdapter();
    const store = new GrantStore(memory.adapter);
    await store.compareAndSwap({
      grantId: grantIdentity.grantId,
      expectedStoreRevision: null,
      next: requestedGrant(),
    });
    const retained = clone(memory.raw());

    for (const application of [
      { ...grantIdentity.application, applicationId: "other-app" },
      { ...grantIdentity.application, clientId: "other-client" },
      { ...grantIdentity.application, origin: "https://other.example" },
      { ...grantIdentity.application, deviceId: "other-device" },
    ]) {
      const replacement = createGrant({
        identity: { ...grantIdentity, application },
        requestedAt: 10,
        expiresAt: 100,
      });
      await expectStoreError(
        () =>
          store.compareAndSwap({
            grantId: grantIdentity.grantId,
            expectedStoreRevision: 0,
            next: replacement,
          }),
        "store_identity_mismatch",
      );
      expect(memory.raw()).toEqual(retained);
    }

    for (const identity of [
      {
        ...grantIdentity,
        logicalAccount: { ...grantIdentity.logicalAccount, accountIndex: "1" },
      },
      {
        ...grantIdentity,
        logicalAccount: {
          ...grantIdentity.logicalAccount,
          factoryRoute: "kernel_factory" as const,
        },
      },
      {
        ...grantIdentity,
        logicalAccount: {
          ...grantIdentity.logicalAccount,
          ownerCredential: {
            version: "oaath.owner-credential-profile/v1" as const,
            kind: "ecdsa" as const,
            address: `0x${"44".repeat(20)}` as const,
          },
        },
      },
      {
        ...grantIdentity,
        operatorCredential: {
          version: "oaath.operator-credential-profile/v1" as const,
          kind: "ecdsa" as const,
          address: `0x${"55".repeat(20)}` as const,
        },
      },
    ]) {
      const replacement = createGrant({ identity, requestedAt: 10, expiresAt: 100 });
      await expectStoreError(
        () =>
          store.compareAndSwap({
            grantId: grantIdentity.grantId,
            expectedStoreRevision: 0,
            next: replacement,
          }),
        "store_identity_mismatch",
      );
      expect(memory.raw()).toEqual(retained);
    }
  });

  it("captures caller input before the adapter can observe later mutation", async () => {
    let releaseRead: (() => void) | undefined;
    const readGate = new Promise<void>((resolve) => {
      releaseRead = resolve;
    });
    let retained: unknown;
    const store = new GrantStore({
      async get() {
        await readGate;
        return clone(retained);
      },
      async compareAndSwap(input: { next: Readonly<StoreRecord<unknown>> }) {
        retained = clone(input.next);
        return true;
      },
      async close() {},
    });
    const mutable = clone(requestedGrant()) as unknown as {
      identity: { grantId: string };
    };
    const pending = store.compareAndSwap({
      grantId: grantIdentity.grantId,
      expectedStoreRevision: null,
      next: mutable,
    });
    mutable.identity.grantId = "substituted";
    releaseRead?.();

    await expect(pending).resolves.toMatchObject({
      status: "committed",
      record: { value: { identity: { grantId: grantIdentity.grantId } } },
    });
  });

  it("rejects malformed, wrong-version, and wrong-key durable evidence", async () => {
    const memory = memoryGrantAdapter({});
    const store = new GrantStore(memory.adapter);
    await expectStoreError(() => store.get(grantIdentity.grantId), "store_record_invalid");

    memory.set({
      version: "oaath.grant-store-record/v2",
      storeRevision: 0,
      updatedAt: 10,
      value: requestedGrant(),
    });
    await expectStoreError(() => store.get(grantIdentity.grantId), "store_record_invalid");

    memory.set({
      version: OAATH_GRANT_STORE_RECORD_VERSION,
      storeRevision: 0,
      updatedAt: 10,
      value: createGrant({
        identity: { ...grantIdentity, grantId: "another-grant" },
        requestedAt: 10,
        expiresAt: 100,
      }),
    });
    await expectStoreError(() => store.get(grantIdentity.grantId), "store_key_mismatch");

    memory.set({
      version: OAATH_GRANT_STORE_RECORD_VERSION,
      storeRevision: 0,
      updatedAt: 11,
      value: requestedGrant(),
    });
    await expectStoreError(() => store.get(grantIdentity.grantId), "store_record_invalid");

    memory.set({
      version: OAATH_GRANT_STORE_RECORD_VERSION,
      storeRevision: 0,
      updatedAt: 10,
      value: requestedGrant(),
      extra: true,
    });
    await expectStoreError(() => store.get(grantIdentity.grantId), "store_record_invalid");
  });

  it("rejects accessors at adapter and durable-result boundaries without invoking them", async () => {
    let accesses = 0;
    const hostileAdapter = {
      compareAndSwap: async () => false,
      close: async () => {},
    } as Record<string, unknown>;
    Object.defineProperty(hostileAdapter, "get", {
      enumerable: true,
      get() {
        accesses += 1;
        return async () => undefined;
      },
    });
    expectStoreConstructorError(() => new GrantStore(hostileAdapter), "store_input_invalid");
    expect(accesses).toBe(0);

    const validAdapter = {
      get: async () => undefined,
      compareAndSwap: async () => false,
      close: async () => {},
    };
    expectStoreConstructorError(
      () => new GrantStore({ ...validAdapter, extra: true }),
      "store_input_invalid",
    );
    expectStoreConstructorError(
      () => new GrantStore({ get: validAdapter.get, close: validAdapter.close }),
      "store_input_invalid",
    );
    expectStoreConstructorError(
      () => new GrantStore(Object.create(validAdapter)),
      "store_input_invalid",
    );
    const symbolAdapter = { ...validAdapter } as Record<PropertyKey, unknown>;
    symbolAdapter[Symbol("extra")] = true;
    expectStoreConstructorError(() => new GrantStore(symbolAdapter), "store_input_invalid");
    const nonEnumerableAdapter = { ...validAdapter };
    Object.defineProperty(nonEnumerableAdapter, "close", {
      value: validAdapter.close,
      enumerable: false,
    });
    expectStoreConstructorError(() => new GrantStore(nonEnumerableAdapter), "store_input_invalid");

    const hostileResult = {} as Record<string, unknown>;
    Object.defineProperty(hostileResult, "version", {
      enumerable: true,
      get() {
        accesses += 1;
        return OAATH_GRANT_STORE_RECORD_VERSION;
      },
    });
    const store = new GrantStore({
      async get() {
        return hostileResult;
      },
      async compareAndSwap() {
        return false;
      },
      async close() {},
    });
    await expectStoreError(() => store.get(grantIdentity.grantId), "store_record_invalid");
    expect(accesses).toBe(0);
  });

  it("rejects hostile CAS envelopes before invoking the adapter", async () => {
    let calls = 0;
    let accesses = 0;
    const store = new GrantStore({
      async get() {
        calls += 1;
      },
      async compareAndSwap() {
        calls += 1;
        return false;
      },
      async close() {},
    });
    const hostile = {
      expectedStoreRevision: null,
      next: requestedGrant(),
    } as Record<string, unknown>;
    Object.defineProperty(hostile, "grantId", {
      enumerable: true,
      get() {
        accesses += 1;
        return grantIdentity.grantId;
      },
    });
    await expectStoreError(() => store.compareAndSwap(hostile), "store_input_invalid");
    expect({ accesses, calls }).toEqual({ accesses: 0, calls: 0 });

    const extra = {
      grantId: grantIdentity.grantId,
      expectedStoreRevision: null,
      next: requestedGrant(),
      extra: true,
    };
    await expectStoreError(() => store.compareAndSwap(extra), "store_input_invalid");
    expect(calls).toBe(0);
  });

  it("distinguishes absence from unavailable and indeterminate storage", async () => {
    const absent = new GrantStore({
      async get() {},
      async compareAndSwap() {
        return false;
      },
      async close() {},
    });
    await expect(absent.get(grantIdentity.grantId)).resolves.toBeUndefined();

    const unavailable = new GrantStore({
      async get() {
        throw new Error("not retained");
      },
      async compareAndSwap() {
        return false;
      },
      async close() {},
    });
    await expectStoreError(() => unavailable.get(grantIdentity.grantId), "store_unavailable");

    const indeterminate = new GrantStore({
      async get() {},
      async compareAndSwap() {
        throw new Error("outcome unknown");
      },
      async close() {},
    });
    await expectStoreError(
      () =>
        indeterminate.compareAndSwap({
          grantId: grantIdentity.grantId,
          expectedStoreRevision: null,
          next: requestedGrant(),
        }),
      "store_commit_indeterminate",
    );

    const invalidResult = new GrantStore({
      async get() {},
      async compareAndSwap() {
        return "conflict";
      },
      async close() {},
    });
    await expectStoreError(
      () =>
        invalidResult.compareAndSwap({
          grantId: grantIdentity.grantId,
          expectedStoreRevision: null,
          next: requestedGrant(),
        }),
      "store_commit_indeterminate",
    );
  });

  it("accepts false as conflict only when fresh evidence proves a competing revision", async () => {
    const absent = new GrantStore({
      async get() {},
      async compareAndSwap() {
        return false;
      },
      async close() {},
    });
    await expectStoreError(
      () =>
        absent.compareAndSwap({
          grantId: grantIdentity.grantId,
          expectedStoreRevision: null,
          next: requestedGrant(),
        }),
      "store_commit_indeterminate",
    );

    let reads = 0;
    const raced = new GrantStore({
      async get() {
        reads += 1;
        if (reads === 1) return undefined;
        const competitor = createGrant({
          identity: grantIdentity,
          requestedAt: 11,
          expiresAt: 101,
        });
        return {
          version: OAATH_GRANT_STORE_RECORD_VERSION,
          storeRevision: 0,
          updatedAt: competitor.updatedAt,
          value: competitor,
        };
      },
      async compareAndSwap() {
        return false;
      },
      async close() {},
    });
    await expect(
      raced.compareAndSwap({
        grantId: grantIdentity.grantId,
        expectedStoreRevision: null,
        next: requestedGrant(),
      }),
    ).resolves.toMatchObject({ status: "conflict", current: { storeRevision: 0 } });

    let recovered: Readonly<StoreRecord<unknown>> | undefined;
    const recoveredCommit = new GrantStore({
      async get() {
        return recovered;
      },
      async compareAndSwap(input: { next: Readonly<StoreRecord<unknown>> }) {
        recovered = input.next;
        return false;
      },
      async close() {},
    });
    await expect(
      recoveredCommit.compareAndSwap({
        grantId: grantIdentity.grantId,
        expectedStoreRevision: null,
        next: requestedGrant(),
      }),
    ).resolves.toMatchObject({ status: "conflict", current: { storeRevision: 0 } });

    const current = {
      version: OAATH_GRANT_STORE_RECORD_VERSION,
      storeRevision: 0,
      updatedAt: requestedGrant().updatedAt,
      value: requestedGrant(),
    };
    const sameRevision = new GrantStore({
      async get() {
        return current;
      },
      async compareAndSwap() {
        return false;
      },
      async close() {},
    });
    await expectStoreError(
      () =>
        sameRevision.compareAndSwap({
          grantId: grantIdentity.grantId,
          expectedStoreRevision: 0,
          next: approvedGrant(),
        }),
      "store_commit_indeterminate",
    );

    reads = 0;
    const regressedRevision = new GrantStore({
      async get() {
        reads += 1;
        return { ...current, storeRevision: reads === 1 ? 5 : 4 };
      },
      async compareAndSwap() {
        return false;
      },
      async close() {},
    });
    await expectStoreError(
      () =>
        regressedRevision.compareAndSwap({
          grantId: grantIdentity.grantId,
          expectedStoreRevision: 5,
          next: approvedGrant(),
        }),
      "store_commit_indeterminate",
    );
  });

  it("rejects non-canonical negative-zero store revisions", async () => {
    const raw = {
      version: OAATH_GRANT_STORE_RECORD_VERSION,
      storeRevision: -0,
      updatedAt: requestedGrant().updatedAt,
      value: requestedGrant(),
    };
    const store = new GrantStore({
      async get() {
        return raw;
      },
      async compareAndSwap() {
        return false;
      },
      async close() {},
    });
    await expectStoreError(() => store.get(grantIdentity.grantId), "store_record_invalid");
    await expectStoreError(
      () =>
        store.compareAndSwap({
          grantId: grantIdentity.grantId,
          expectedStoreRevision: -0,
          next: approvedGrant(),
        }),
      "store_input_invalid",
    );
  });

  it("detects a lying success that did not retain the exact write", async () => {
    const store = new GrantStore({
      async get() {},
      async compareAndSwap() {
        return true;
      },
      async close() {},
    });
    await expectStoreError(
      () =>
        store.compareAndSwap({
          grantId: grantIdentity.grantId,
          expectedStoreRevision: null,
          next: requestedGrant(),
        }),
      "store_commit_unverified",
    );

    let altered: Readonly<StoreRecord<unknown>> | undefined;
    const alteredStore = new GrantStore({
      async get() {
        return altered;
      },
      async compareAndSwap(input: { next: Readonly<StoreRecord<unknown>> }) {
        altered = Object.freeze({ ...input.next, storeRevision: input.next.storeRevision + 1 });
        return true;
      },
      async close() {},
    });
    await expectStoreError(
      () =>
        alteredStore.compareAndSwap({
          grantId: grantIdentity.grantId,
          expectedStoreRevision: null,
          next: requestedGrant(),
        }),
      "store_commit_unverified",
    );
  });

  it("treats a throw after mutation as indeterminate even when the write is visible", async () => {
    let retained: unknown;
    const store = new GrantStore({
      async get() {
        return clone(retained);
      },
      async compareAndSwap(input: { next: Readonly<StoreRecord<unknown>> }) {
        retained = clone(input.next);
        throw new Error("acknowledgement lost");
      },
      async close() {},
    });
    await expectStoreError(
      () =>
        store.compareAndSwap({
          grantId: grantIdentity.grantId,
          expectedStoreRevision: null,
          next: requestedGrant(),
        }),
      "store_commit_indeterminate",
    );
    await expect(store.get(grantIdentity.grantId)).resolves.toMatchObject({
      storeRevision: 0,
      value: { identity: { grantId: grantIdentity.grantId } },
    });
  });

  it("rejects key substitution before touching an Operation lane", async () => {
    let calls = 0;
    const store = new OperationStore({
      async get() {
        calls += 1;
      },
      async compareAndSwap() {
        calls += 1;
        return true;
      },
      async close() {},
    });
    await expectStoreError(
      () =>
        store.compareAndSwap({
          key: { grantId: grantIdentity.grantId, chainId: 1 },
          expectedStoreRevision: null,
          next: preparedOperation(2),
        }),
      "store_key_mismatch",
    );
    expect(calls).toBe(0);
  });

  it("keeps close retryable after failure and closes only after success", async () => {
    let closeCalls = 0;
    const store = new GrantStore({
      async get() {},
      async compareAndSwap() {
        return false;
      },
      async close() {
        closeCalls += 1;
        if (closeCalls === 1) throw new Error("still open");
      },
    });
    await expectStoreError(() => store.close(), "store_unavailable");
    await expect(store.get(grantIdentity.grantId)).resolves.toBeUndefined();
    await Promise.all([store.close(), store.close()]);
    await store.close();
    expect(closeCalls).toBe(2);
    await expectStoreError(() => store.get(grantIdentity.grantId), "store_closed");
  });
});
