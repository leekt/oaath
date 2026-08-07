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
import { grantProviderPort } from "../src/client/grant-handle.js";
import {
  type OaathCleanupCheckpointStore,
  type OaathCleanupEffectName,
  parseCleanupCheckpoint,
  requireNonExtractableKey,
} from "../src/persistence.js";
import { createMemoryCleanupStore } from "../src/testing.js";
import {
  createChainFixture,
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

  it.each(ALL)(
    "attempts independent effects and withholds dependents when %s fails",
    async (failing) => {
      const checkpoints = createMemoryCleanupStore();
      const record = recorder();
      await expect(
        cleanup({
          effects: ALL.map((name) => record.effect(name, name === failing)),
          checkpoints,
        }),
      ).rejects.toMatchObject({ name: "OaathCleanupError", code: "cleanup_incomplete" });
      const expectedAttempts =
        failing === "revoke"
          ? ["revoke", "signOut"]
          : failing === "close"
            ? [...ALL]
            : ["revoke", "signOut", "forgetLocal"];
      expect(record.attempts).toEqual(expectedAttempts);
      const checkpoint = parseCleanupCheckpoint(await checkpoints.read("realm-a"));
      const expectedCompleted =
        failing === "revoke"
          ? ["signOut"]
          : failing === "signOut"
            ? ["revoke", "forgetLocal"]
            : failing === "forgetLocal"
              ? ["revoke", "signOut"]
              : ["revoke", "signOut", "forgetLocal"];
      expect(checkpoint.completed).toEqual(expectedCompleted);
    },
  );

  it("reports every failure when all effects fail together", async () => {
    const checkpoints = createMemoryCleanupStore();
    const record = recorder();
    const failure = await cleanup({
      effects: ALL.map((name) => record.effect(name, true)),
      checkpoints,
    }).catch((error: unknown) => error);
    expect(record.attempts).toEqual(["revoke", "signOut"]);
    expect(failure).toMatchObject({ name: "OaathCleanupError", code: "cleanup_incomplete" });
    const error = failure as { unfinished: readonly string[]; failures: readonly unknown[] };
    expect(error.unfinished).toEqual([...ALL]);
    expect(error.failures).toHaveLength(2);
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
    expect(record.attempts).toEqual(["revoke", "signOut"]);
    // No destructive dependent ran, so no completion checkpoint exists.
    expect(await checkpoints.read("realm-a")).toBeUndefined();
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
    expect(second.attempts).toEqual(["signOut", "close"]);
    expect(result.unfinished).toEqual([]);
    expect(result.completed).toEqual(["revoke", "forgetLocal", "signOut", "close"]);
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
    await expect(
      tracked.stores.grants.get(grantProviderPort(grant).grantId),
    ).resolves.toMatchObject({
      value: { materializations: [{ state: "installed" }] },
    });

    const result = await realm.oaath.disconnect(grant);
    expect(result.completed).toEqual(["revoke", "signOut", "forgetLocal", "close"]);
    // This realm holds the owner's signing capability, so revoke removed the
    // installed chain permission with an owner-signed operation and completed.
    expect(grant.state).toBe("revoked");
    expect(realm.signOutCalls()).toBe(1);
    expect(tracked.deletedKeys).toEqual(["session-key"]);
    expect(tracked.clearedContexts).toEqual([realm.oaath.binding.bindingId]);
    // `close` released every store the realm owned.
    expect(tracked.closed.sort()).toEqual([
      "context",
      "grants",
      "keys",
      "operations",
      "preparedCallContexts",
      "walletCallBundles",
    ]);
    await expect(connection.requestPermission(permissionInput())).rejects.toMatchObject({
      code: "oaath_client_closed",
    });
  });

  it("forgets an active Grant whose authority already expired without starting revocation", async () => {
    const clock = createClock();
    const tracked = trackedStores();
    const realm = createRealm({ clock, stores: tracked.stores });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    await tracked.stores.keys.store({ keyId: "session-key", key: await nonExtractable() });
    clock.advance(grant.expiresAt - clock.now());
    expect(grant.state).toBe("active");

    const result = await realm.oaath.disconnect(grant);

    expect(result.completed).toEqual(["signOut", "forgetLocal", "close"]);
    expect(realm.invalidations()).toBe(0);
    expect(realm.chain.sends).toHaveLength(0);
    expect(tracked.deletedKeys).toEqual(["session-key"]);
    expect(tracked.clearedContexts).toEqual([realm.oaath.binding.bindingId]);
    expect(tracked.closed).toHaveLength(6);
  });

  it("reads durable state before an expired stale handle can abandon revocation", async () => {
    let crashOnRemoval = false;
    const clock = createClock();
    const chain = createChainFixture({ crashOnSend: () => crashOnRemoval });
    const tracked = trackedStores();
    const realm = createRealm({ clock, chain, stores: tracked.stores });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const stale = await connection.resume();
    if (stale === null) throw new Error("expected a stale Grant handle");
    await tracked.stores.keys.store({ keyId: "session-key", key: await nonExtractable() });
    const operation = await grant.sendCalls(sendCallsInput());
    expect((await operation.wait()).status).toBe("finalized");

    crashOnRemoval = true;
    await grant.revoke();
    expect(grant.state).toBe("revoking");
    expect(stale.state).toBe("active");
    clock.advance(stale.expiresAt - clock.now());
    crashOnRemoval = false;

    const result = await realm.oaath.disconnect(stale);

    expect(result.completed).toEqual(["revoke", "signOut", "forgetLocal", "close"]);
    expect(stale.state).toBe("revoked");
    expect(chain.sends).toHaveLength(2);
    expect(tracked.deletedKeys).toEqual(["session-key"]);
    expect(tracked.closed).toHaveLength(6);
  });

  it("fences expiry cleanup against a concurrent revocation commit", async () => {
    let crashOnRemoval = false;
    let enterRevocation!: () => void;
    let releaseRevocation!: () => void;
    let enterExpiry!: () => void;
    let releaseExpiry!: () => void;
    const revocationEntered = new Promise<void>((resolve) => {
      enterRevocation = resolve;
    });
    const revocationReleased = new Promise<void>((resolve) => {
      releaseRevocation = resolve;
    });
    const expiryEntered = new Promise<void>((resolve) => {
      enterExpiry = resolve;
    });
    const expiryReleased = new Promise<void>((resolve) => {
      releaseExpiry = resolve;
    });
    let blockRevocation = true;
    let blockExpiry = true;
    const clock = createClock();
    const chain = createChainFixture({ crashOnSend: () => crashOnRemoval });
    const tracked = trackedStores();
    const realm = createRealm({
      clock,
      chain,
      stores: {
        ...tracked.stores,
        grants: {
          get: (grantId: Parameters<typeof tracked.stores.grants.get>[0]) =>
            tracked.stores.grants.get(grantId),
          async compareAndSwap(input: Parameters<typeof tracked.stores.grants.compareAndSwap>[0]) {
            const state = (input.next as { readonly value?: { readonly state?: unknown } }).value
              ?.state;
            if (blockRevocation && state === "revoking") {
              blockRevocation = false;
              enterRevocation();
              await revocationReleased;
            }
            if (blockExpiry && state === "expired") {
              blockExpiry = false;
              enterExpiry();
              await expiryReleased;
            }
            return tracked.stores.grants.compareAndSwap(input);
          },
          close: () => tracked.stores.grants.close(),
        },
      },
    });
    const connection = await realm.oaath.connect();
    const revoker = await connection.requestPermission(permissionInput());
    const stale = await connection.resume();
    if (stale === null) throw new Error("expected a stale Grant handle");
    const installation = await revoker.sendCalls(sendCallsInput());
    expect((await installation.wait()).status).toBe("finalized");
    crashOnRemoval = true;
    const revoking = revoker.revoke();
    await revocationEntered;
    clock.advance(stale.expiresAt - clock.now());

    const disconnecting = realm.oaath.disconnect(stale);
    await expiryEntered;
    releaseRevocation();
    await revoking;
    expect(revoker.state).toBe("revoking");
    crashOnRemoval = false;
    releaseExpiry();

    const result = await disconnecting;
    expect(result.completed).toEqual(["revoke", "signOut", "forgetLocal", "close"]);
    expect(stale.state).toBe("revoked");
    expect(chain.sends).toHaveLength(2);
    expect(tracked.closed).toHaveLength(6);
  });

  it("retries a failed owned store close instead of discarding the connection", async () => {
    const memory = createMemoryStores();
    let walletCloseAttempts = 0;
    const stores = {
      ...memory,
      walletCallBundles: {
        get: (key: Parameters<typeof memory.walletCallBundles.get>[0]) =>
          memory.walletCallBundles.get(key),
        compareAndSwap: (input: Parameters<typeof memory.walletCallBundles.compareAndSwap>[0]) =>
          memory.walletCallBundles.compareAndSwap(input),
        async close() {
          walletCloseAttempts += 1;
          if (walletCloseAttempts === 1) throw new Error("wallet bundle store still open");
          await memory.walletCallBundles.close();
        },
      },
    };
    const realm = createRealm({ stores });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());

    await expect(realm.oaath.disconnect(grant)).rejects.toMatchObject({
      name: "OaathCleanupError",
      unfinished: ["close"],
    });
    expect(walletCloseAttempts).toBe(1);
    const retried = await realm.oaath.disconnect(grant);
    expect(retried.unfinished).toEqual([]);
    expect(retried.completed).toContain("close");
    expect(walletCloseAttempts).toBe(2);
  });

  it("catches synchronous close throws, attempts later stores, and retries only failure", async () => {
    const tracked = trackedStores();
    let grantCloseAttempts = 0;
    const realm = createRealm({
      stores: {
        ...tracked.stores,
        grants: {
          get: (grantId: Parameters<typeof tracked.stores.grants.get>[0]) =>
            tracked.stores.grants.get(grantId),
          compareAndSwap: (value: Parameters<typeof tracked.stores.grants.compareAndSwap>[0]) =>
            tracked.stores.grants.compareAndSwap(value),
          close() {
            grantCloseAttempts += 1;
            if (grantCloseAttempts === 1) throw new Error("synchronous Grant store close failure");
            return tracked.stores.grants.close();
          },
        },
      },
    });
    await realm.oaath.connect();

    await expect(realm.oaath.close()).rejects.toThrow("synchronous Grant store close failure");
    expect(grantCloseAttempts).toBe(1);
    expect(tracked.closed.sort()).toEqual([
      "context",
      "keys",
      "operations",
      "preparedCallContexts",
      "walletCallBundles",
    ]);

    await realm.oaath.close();
    expect(grantCloseAttempts).toBe(2);
    expect(tracked.closed.sort()).toEqual([
      "context",
      "grants",
      "keys",
      "operations",
      "preparedCallContexts",
      "walletCallBundles",
    ]);
  });

  it("forgets local state but retains resources needed to retry signOut", async () => {
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
    expect(failure).toMatchObject({
      name: "OaathCleanupError",
      unfinished: ["signOut", "close"],
    });
    // No chain ever materialized, so revocation completes outright.
    expect(grant.state).toBe("revoked");
    expect(tracked.deletedKeys).toEqual(["session-key"]);
    expect(tracked.closed).toHaveLength(0);
    await expect(connection.requestPermission(permissionInput())).rejects.toMatchObject({
      code: "oaath_client_signed_out",
    });
  });

  it("retains revocation dependencies until exact retry completes", async () => {
    let crashOnRemoval = false;
    const chain = createChainFixture({ crashOnSend: () => crashOnRemoval });
    const tracked = trackedStores();
    const realm = createRealm({ stores: tracked.stores, chain });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    await tracked.stores.keys.store({ keyId: "session-key", key: await nonExtractable() });
    const operation = await grant.sendCalls(sendCallsInput());
    expect((await operation.wait()).status).toBe("finalized");
    crashOnRemoval = true;

    const first = await realm.oaath.disconnect(grant).catch((error: unknown) => error);
    expect(first).toMatchObject({
      name: "OaathCleanupError",
      unfinished: ["revoke", "forgetLocal", "close"],
    });
    expect(grant.state).toBe("revoking");
    expect(await tracked.stores.keys.get("session-key")).toBeDefined();
    expect(await tracked.stores.context.read(realm.oaath.binding.bindingId)).toBeDefined();
    expect(tracked.closed).toHaveLength(0);

    realm.clock.advance(grant.expiresAt - realm.clock.now());
    crashOnRemoval = false;
    const retried = await realm.oaath.disconnect(grant);
    expect(retried.unfinished).toEqual([]);
    expect(grant.state).toBe("revoked");
    expect(chain.sends).toHaveLength(2);
    expect(tracked.deletedKeys).toEqual(["session-key"]);
    expect(tracked.closed).toHaveLength(6);
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
        getArchived: (input: Parameters<typeof stores.operations.getArchived>[0]) =>
          stores.operations.getArchived(input),
        compareAndSwap: (input: Parameters<typeof stores.operations.compareAndSwap>[0]) =>
          stores.operations.compareAndSwap(input),
        close: async () => {
          closed.push("operations");
          return stores.operations.close();
        },
      },
      walletCallBundles: {
        get: (key: Parameters<typeof stores.walletCallBundles.get>[0]) =>
          stores.walletCallBundles.get(key),
        compareAndSwap: (input: Parameters<typeof stores.walletCallBundles.compareAndSwap>[0]) =>
          stores.walletCallBundles.compareAndSwap(input),
        close: async () => {
          closed.push("walletCallBundles");
          return stores.walletCallBundles.close();
        },
      },
      preparedCallContexts: {
        get: (key: Parameters<typeof stores.preparedCallContexts.get>[0]) =>
          stores.preparedCallContexts.get(key),
        compareAndSwap: (input: Parameters<typeof stores.preparedCallContexts.compareAndSwap>[0]) =>
          stores.preparedCallContexts.compareAndSwap(input),
        close: async () => {
          closed.push("preparedCallContexts");
          return stores.preparedCallContexts.close();
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
