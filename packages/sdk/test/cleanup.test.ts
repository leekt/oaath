/**
 * Cleanup: every effect fails independently and together, the canonical error
 * survives, and durable checkpoints drive the retry.
 *
 * @author taek <leekt216@gmail.com>
 */
import { describe, expect, it } from "vitest";
import {
  closeEffect,
  forgetLocalEffect,
  type OaathCleanupEffect,
  runOaathCleanup,
  signOutEffect,
} from "../src/advanced.js";
import {
  type OaathCleanupCheckpointStore,
  type OaathCleanupEffectName,
  parseCleanupCheckpoint,
  requireNonExtractableKey,
} from "../src/persistence.js";
import { createMemoryCleanupStore } from "../src/testing.js";
import {
  createClock,
  createMemoryStores,
  createRealm,
  permissionInput,
  sendCallsInput,
} from "./support/browser.js";

interface Recorder {
  readonly attempts: OaathCleanupEffectName[];
  readonly effect: (name: OaathCleanupEffectName, fail?: boolean) => OaathCleanupEffect;
}

function recorder(): Recorder {
  const attempts: OaathCleanupEffectName[] = [];
  return {
    attempts,
    effect: (name, fail = false) => ({
      name,
      run: async () => {
        attempts.push(name);
        if (fail) throw new Error(`${name} failed`);
      },
    }),
  };
}

const ALL: readonly OaathCleanupEffectName[] = ["revoke", "signOut", "forgetLocal", "close"];

function cleanup(input: {
  readonly effects: readonly OaathCleanupEffect[];
  readonly checkpoints: OaathCleanupCheckpointStore;
  readonly primaryError?: unknown;
  readonly clock?: () => number;
}) {
  return runOaathCleanup({
    cleanupId: "realm-a",
    effects: input.effects,
    checkpoints: input.checkpoints,
    now: input.clock ?? (() => 1_800_000_000),
    primaryError: input.primaryError ?? null,
  });
}

describe("cleanup coordinator", () => {
  it("completes every effect and clears its checkpoint", async () => {
    const checkpoints = createMemoryCleanupStore();
    const record = recorder();
    const result = await cleanup({
      effects: ALL.map((name) => record.effect(name)),
      checkpoints,
    });
    expect(record.attempts).toEqual([...ALL]);
    expect(result.completed).toEqual([...ALL]);
    expect(result.unfinished).toEqual([]);
    expect(await checkpoints.read("realm-a")).toBeUndefined();
  });

  it.each(ALL)("attempts every other effect when %s fails", async (failing) => {
    const checkpoints = createMemoryCleanupStore();
    const record = recorder();
    await expect(
      cleanup({
        effects: ALL.map((name) => record.effect(name, name === failing)),
        checkpoints,
      }),
    ).rejects.toMatchObject({ name: "OaathCleanupError", code: "cleanup_incomplete" });
    expect(record.attempts).toEqual([...ALL]);
    const checkpoint = parseCleanupCheckpoint(await checkpoints.read("realm-a"));
    expect(checkpoint.completed).toEqual(ALL.filter((name) => name !== failing));
  });

  it("reports every failure when all effects fail together", async () => {
    const checkpoints = createMemoryCleanupStore();
    const record = recorder();
    const failure = await cleanup({
      effects: ALL.map((name) => record.effect(name, true)),
      checkpoints,
    }).catch((error: unknown) => error);
    expect(record.attempts).toEqual([...ALL]);
    expect(failure).toMatchObject({ name: "OaathCleanupError", code: "cleanup_incomplete" });
    const error = failure as { unfinished: readonly string[]; failures: readonly unknown[] };
    expect(error.unfinished).toEqual([...ALL]);
    expect(error.failures).toHaveLength(4);
    expect(await checkpoints.read("realm-a")).toBeUndefined();
  });

  it("preserves the canonical error and keeps cleanup failures suppressed", async () => {
    const checkpoints = createMemoryCleanupStore();
    const record = recorder();
    const primaryError = new Error("the operation that caused this cleanup");
    const thrown = await cleanup({
      effects: ALL.map((name) => record.effect(name, name !== "close")),
      checkpoints,
      primaryError,
    }).catch((error: unknown) => error);
    expect(thrown).toBe(primaryError);
    expect(record.attempts).toEqual([...ALL]);
    // The durable checkpoint, not the thrown error, carries what is left to do.
    expect(parseCleanupCheckpoint(await checkpoints.read("realm-a")).completed).toEqual(["close"]);
  });

  it("retries only the effects the checkpoint does not prove complete", async () => {
    const checkpoints = createMemoryCleanupStore();
    const first = recorder();
    await expect(
      cleanup({
        effects: ALL.map((name) => first.effect(name, name === "signOut")),
        checkpoints,
      }),
    ).rejects.toMatchObject({ code: "cleanup_incomplete" });

    const second = recorder();
    const result = await cleanup({
      effects: ALL.map((name) => second.effect(name)),
      checkpoints,
    });
    expect(second.attempts).toEqual(["signOut"]);
    expect(result.unfinished).toEqual([]);
    expect(result.completed).toEqual(["revoke", "forgetLocal", "close", "signOut"]);
  });

  it("keeps an effect retryable when its checkpoint cannot be written", async () => {
    const memory = createMemoryCleanupStore();
    const checkpoints: OaathCleanupCheckpointStore = {
      read: (id) => memory.read(id),
      write: async () => {
        throw new Error("checkpoint store unavailable");
      },
      clear: (id) => memory.clear(id),
      close: () => memory.close(),
    };
    const record = recorder();
    await expect(cleanup({ effects: [record.effect("close")], checkpoints })).rejects.toMatchObject(
      { code: "cleanup_incomplete" },
    );
    expect(record.attempts).toEqual(["close"]);
  });

  it("treats an unreadable or malformed checkpoint as nothing proven", async () => {
    const checkpoints: OaathCleanupCheckpointStore = {
      read: async () => ({ version: "oaath.cleanup-checkpoint/v0", completed: ["close"] }),
      write: async () => undefined,
      clear: async () => undefined,
      close: async () => undefined,
    };
    const record = recorder();
    await cleanup({ effects: [record.effect("close")], checkpoints });
    expect(record.attempts).toEqual(["close"]);
  });

  it("runs the composed disconnect path: revoke, signOut, forgetLocal, close", async () => {
    const tracked = trackedStores();
    const realm = createRealm({ clock: createClock(), stores: tracked.stores });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    await tracked.stores.keys.store({ keyId: "session-key", key: await nonExtractable() });
    const operation = await grant.sendCalls(sendCallsInput());
    expect((await operation.wait()).status).toBe("finalized");

    const result = await realm.oaath.disconnect(grant);
    expect(result.completed).toEqual(["revoke", "signOut", "forgetLocal", "close"]);
    // This realm holds the owner's signing capability, so revoke removed the
    // installed chain permission with an owner-signed operation and completed.
    expect(grant.state).toBe("revoked");
    expect(realm.signOutCalls()).toBe(1);
    expect(tracked.deletedKeys).toEqual(["session-key"]);
    expect(tracked.clearedContexts).toEqual([realm.oaath.binding.bindingId]);
    // `close` released every store the realm owned.
    expect(tracked.closed.sort()).toEqual(["context", "grants", "keys", "operations"]);
    await expect(connection.requestPermission(permissionInput())).rejects.toMatchObject({
      code: "oaath_client_closed",
    });
  });

  it("still forgets local state and releases resources when signOut fails", async () => {
    const tracked = trackedStores();
    const realm = createRealm({
      stores: tracked.stores,
      issuerSignOut: async () => {
        throw new Error("relay sign-out failed");
      },
    });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    await tracked.stores.keys.store({ keyId: "session-key", key: await nonExtractable() });
    const failure = await realm.oaath.disconnect(grant).catch((error: unknown) => error);
    expect(failure).toMatchObject({ name: "OaathCleanupError", unfinished: ["signOut"] });
    // No chain ever materialized, so revocation completes outright.
    expect(grant.state).toBe("revoked");
    expect(tracked.deletedKeys).toEqual(["session-key"]);
    expect(tracked.closed).toHaveLength(4);
    await expect(connection.requestPermission(permissionInput())).rejects.toMatchObject({
      code: "oaath_client_closed",
    });
  });

  it("deletes only the named local key handles", async () => {
    const keys = createMemoryStoresKeys();
    const contexts = createMemoryContextsStub();
    const effect = forgetLocalEffect({
      keys,
      contexts,
      bindingId: `0x${"11".repeat(32)}`,
      keyIds: ["session-key"],
    });
    await keys.store({ keyId: "session-key", key: await nonExtractable() });
    await keys.store({ keyId: "other-key", key: await nonExtractable() });
    await effect.run();
    expect(await keys.get("session-key")).toBeUndefined();
    expect(requireNonExtractableKey(await keys.get("other-key")).extractable).toBe(false);
    expect(contexts.cleared).toEqual([`0x${"11".repeat(32)}`]);
  });

  it("names each effect exactly once", () => {
    expect(closeEffect(async () => {}).name).toBe("close");
    expect(signOutEffect(async () => {}).name).toBe("signOut");
  });
});

async function nonExtractable(): Promise<CryptoKey> {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]);
  return pair.privateKey;
}

/** Memory stores that record the destructive calls each effect makes. */
function trackedStores() {
  const stores = createMemoryStores();
  const deletedKeys: string[] = [];
  const clearedContexts: string[] = [];
  const closed: string[] = [];
  return {
    deletedKeys,
    clearedContexts,
    closed,
    stores: {
      grants: {
        get: (id: string) => stores.grants.get(id),
        compareAndSwap: (input: Parameters<typeof stores.grants.compareAndSwap>[0]) =>
          stores.grants.compareAndSwap(input),
        close: async () => {
          closed.push("grants");
          return stores.grants.close();
        },
      },
      operations: {
        get: (key: Parameters<typeof stores.operations.get>[0]) => stores.operations.get(key),
        compareAndSwap: (input: Parameters<typeof stores.operations.compareAndSwap>[0]) =>
          stores.operations.compareAndSwap(input),
        close: async () => {
          closed.push("operations");
          return stores.operations.close();
        },
      },
      keys: {
        store: (input: Readonly<{ keyId: string; key: CryptoKey }>) => stores.keys.store(input),
        get: (keyId: string) => stores.keys.get(keyId),
        delete: async (keyId: string) => {
          deletedKeys.push(keyId);
          return stores.keys.delete(keyId);
        },
        close: async () => {
          closed.push("keys");
          return stores.keys.close();
        },
      },
      cleanup: stores.cleanup,
      context: {
        read: (bindingId: string) => stores.context.read(bindingId),
        write: (context: Parameters<typeof stores.context.write>[0]) =>
          stores.context.write(context),
        clear: async (bindingId: string) => {
          clearedContexts.push(bindingId);
          return stores.context.clear(bindingId);
        },
        close: async () => {
          closed.push("context");
          return stores.context.close();
        },
      },
    },
  };
}

function createMemoryStoresKeys() {
  const handles = new Map<string, CryptoKey>();
  return {
    async store(input: Readonly<{ keyId: string; key: CryptoKey }>) {
      handles.set(input.keyId, requireNonExtractableKey(input.key));
    },
    async get(keyId: string) {
      return handles.get(keyId);
    },
    async delete(keyId: string) {
      handles.delete(keyId);
    },
    async close() {},
  };
}

function createMemoryContextsStub() {
  const cleared: string[] = [];
  return {
    cleared,
    async read() {
      return undefined;
    },
    async write() {
      return undefined;
    },
    async clear(bindingId: string) {
      cleared.push(bindingId);
    },
    async close() {},
  };
}
