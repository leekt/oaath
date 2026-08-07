/**
 * Durable EIP-5792 bundle orchestration across provider and realm recreation.
 *
 * @author taek <leekt216@gmail.com>
 */
import { IDBFactory } from "fake-indexeddb";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { OaathChainCapability } from "../src/advanced.js";
import { grantProviderPort } from "../src/client/grant-handle.js";
import {
  createIndexedDbCleanupStore,
  createIndexedDbContextStore,
  createIndexedDbGrantStoreAdapter,
  createIndexedDbKeyStore,
  createIndexedDbOperationStoreAdapter,
  createIndexedDbWalletCallBundleStoreAdapter,
  type OaathDatabase,
  openOaathDatabase,
} from "../src/persistence.js";
import {
  captureWalletSendCallsParams,
  hashCapturedWalletSendCallsRequest,
  hashWalletCallBundleProvenance,
} from "../src/provider/capture.js";
import { oaathProvider } from "../src/viem.js";
import {
  ACCOUNT,
  bindingInput,
  CALL_DATA,
  CHAIN_ID,
  type ChainFixture,
  createChainFixture,
  createClock,
  createMemoryStores,
  createRealm,
  createRelay,
  createUrlRealm,
  permissionInput,
  type RealmStores,
  TARGET,
} from "./support/browser.js";

const OTHER_CHAIN_ID = 46_630;
const OTHER_ACCOUNT = `0x${"77".repeat(20)}` as const;
const opened: OaathDatabase[] = [];

afterEach(() => {
  for (const database of opened.splice(0)) database.close();
});

function bundle(
  account: `0x${string}`,
  id: string | undefined,
  chain = CHAIN_ID,
  overrides: Readonly<Record<string, unknown>> = {},
): Record<string, unknown> {
  return {
    version: "2.0.0",
    ...(id === undefined ? {} : { id }),
    from: account,
    chainId: `0x${chain.toString(16)}`,
    atomicRequired: true,
    calls: [{ to: TARGET, data: CALL_DATA }],
    ...overrides,
  };
}

async function providerError(promise: Promise<unknown>, code: number): Promise<void> {
  await expect(promise).rejects.toMatchObject({ name: "OaathProviderRpcError", code });
}

function plainRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`expected ${label}`);
  }
  return value as Record<string, unknown>;
}

function reopenableMemoryStores(): RealmStores {
  const stores = createMemoryStores();
  return {
    grants: Object.freeze({ ...stores.grants, close: async () => undefined }),
    operations: Object.freeze({ ...stores.operations, close: async () => undefined }),
    walletCallBundles: Object.freeze({
      ...stores.walletCallBundles,
      close: async () => undefined,
    }),
    keys: Object.freeze({ ...stores.keys, close: async () => undefined }),
    cleanup: stores.cleanup,
    context: Object.freeze({ ...stores.context, close: async () => undefined }),
  };
}

async function indexedDbStores(factory: IDBFactory): Promise<{
  readonly database: OaathDatabase;
  readonly stores: RealmStores;
}> {
  const database = await openOaathDatabase({ factory });
  opened.push(database);
  return {
    database,
    stores: {
      grants: createIndexedDbGrantStoreAdapter(database),
      operations: createIndexedDbOperationStoreAdapter(database),
      walletCallBundles: createIndexedDbWalletCallBundleStoreAdapter(database),
      keys: createIndexedDbKeyStore(database),
      cleanup: createIndexedDbCleanupStore(database),
      context: createIndexedDbContextStore(database),
    },
  };
}

function replaceChain(base: ChainFixture, overrides: Partial<OaathChainCapability>): ChainFixture {
  return {
    capability: Object.freeze({ ...base.capability, ...overrides }),
    sends: base.sends,
    signatures: base.signatures,
    get quotes() {
      return base.quotes;
    },
  };
}

async function activeProvider(input: {
  readonly chain?: ChainFixture;
  readonly stores?: RealmStores;
  readonly clock?: ReturnType<typeof createClock>;
  readonly relay?: ReturnType<typeof createRelay>;
}) {
  const realm = createRealm(input);
  const connection = await realm.oaath.connect();
  const grant = await connection.requestPermission(permissionInput());
  const provider = oaathProvider({ grant, chain: CHAIN_ID });
  const account = await grant.account(CHAIN_ID);
  return { realm, connection, grant, provider, account };
}

describe("durable provider recreation", () => {
  it("recovers the same memory-backed ID and Operation hash after recreating every instance", async () => {
    const stores = reopenableMemoryStores();
    const clock = createClock();
    const chain = createChainFixture();
    const before = createUrlRealm({ stores, clock, chain });
    const firstConnection = await before.oaath.connect();
    const firstGrant = await firstConnection.requestPermission(permissionInput());
    const account = await firstGrant.account(CHAIN_ID);
    const firstProvider = oaathProvider({ grant: firstGrant, chain: CHAIN_ID });

    await expect(
      firstProvider.request({
        method: "wallet_sendCalls",
        params: [bundle(account, "memory-reload")],
      }),
    ).resolves.toEqual({ id: "memory-reload" });
    const exactHash = chain.sends[0]?.userOperationHash;
    if (exactHash === undefined) throw new Error("expected one exact submitted identity");
    await firstConnection.close();

    const after = createUrlRealm({ stores, clock, relay: before.relay, chain });
    const secondConnection = await after.oaath.connect();
    const secondGrant = await secondConnection.resume();
    if (secondGrant === null) throw new Error("expected the Grant to resume");
    const secondProvider = oaathProvider({ grant: secondGrant, chain: CHAIN_ID });
    await providerError(
      secondProvider.request({
        method: "wallet_sendCalls",
        params: [bundle(account, "memory-reload")],
      }),
      5720,
    );
    await expect(
      secondProvider.request({ method: "wallet_getCallsStatus", params: ["memory-reload"] }),
    ).resolves.toMatchObject({ id: "memory-reload", status: 200 });

    const port = grantProviderPort(secondGrant);
    const retained = await port.walletCallBundles.get({
      providerScopeId: port.providerScopeId,
      grantId: port.grantId,
      id: "memory-reload",
    });
    expect(retained?.value.operation?.identity.userOperationHash).toBe(exactHash);
    const followUp = await secondGrant.sendCalls({
      chain: CHAIN_ID,
      calls: [{ target: TARGET, value: "0", data: CALL_DATA }],
    });
    expect(followUp.outcome.status).toBe("finalized");
    expect(chain.sends).toHaveLength(2);
    const followUpPrepared = chain.sends[1];
    if (followUpPrepared === undefined) throw new Error("expected the follow-up operation");
    expect((BigInt(followUpPrepared.userOperation.nonce) >> 248n) & 0xffn).toBe(0n);
    await secondConnection.close();
  });

  it("recovers the same IndexedDB-backed ID and Operation hash after a full database reopen", async () => {
    const factory = new IDBFactory();
    const clock = createClock();
    const chain = createChainFixture();
    const first = await indexedDbStores(factory);
    const before = createUrlRealm({ stores: first.stores, clock, chain });
    const firstConnection = await before.oaath.connect();
    const firstGrant = await firstConnection.requestPermission(permissionInput());
    const account = await firstGrant.account(CHAIN_ID);
    const firstProvider = oaathProvider({ grant: firstGrant, chain: CHAIN_ID });
    await firstProvider.request({
      method: "wallet_sendCalls",
      params: [bundle(account, "indexeddb-reload")],
    });
    const exactHash = chain.sends[0]?.userOperationHash;
    if (exactHash === undefined) throw new Error("expected one exact submitted identity");
    await firstConnection.close();
    first.database.close();
    opened.splice(opened.indexOf(first.database), 1);

    const second = await indexedDbStores(factory);
    const after = createUrlRealm({
      stores: second.stores,
      clock,
      relay: before.relay,
      chain,
    });
    const secondConnection = await after.oaath.connect();
    const secondGrant = await secondConnection.resume();
    if (secondGrant === null) throw new Error("expected the IndexedDB Grant to resume");
    const secondProvider = oaathProvider({ grant: secondGrant, chain: CHAIN_ID });
    await expect(
      secondProvider.request({ method: "wallet_getCallsStatus", params: ["indexeddb-reload"] }),
    ).resolves.toMatchObject({ id: "indexeddb-reload", status: 200 });
    const port = grantProviderPort(secondGrant);
    const retained = await port.walletCallBundles.get({
      providerScopeId: port.providerScopeId,
      grantId: port.grantId,
      id: "indexeddb-reload",
    });
    expect(retained?.value.operation?.identity.userOperationHash).toBe(exactHash);
    expect(chain.sends).toHaveLength(1);
    await secondConnection.close();
  });

  it("resumes exact operation observation after the Grant expires", async () => {
    const stores = reopenableMemoryStores();
    const clock = createClock();
    const chain = createChainFixture({ withholdReceipt: () => true });
    const before = createUrlRealm({ stores, clock, chain });
    const firstConnection = await before.oaath.connect();
    const firstGrant = await firstConnection.requestPermission(permissionInput());
    const account = await firstGrant.account(CHAIN_ID);
    await oaathProvider({ grant: firstGrant, chain: CHAIN_ID }).request({
      method: "wallet_sendCalls",
      params: [bundle(account, "expired-observation")],
    });
    await firstConnection.close();

    clock.advance(1_800);
    const after = createUrlRealm({ stores, clock, relay: before.relay, chain });
    const secondConnection = await after.oaath.connect();
    const resumed = await secondConnection.resume();
    if (resumed === null) throw new Error("expected an observation-capable expired Grant");
    await expect(
      oaathProvider({ grant: resumed, chain: CHAIN_ID }).request({
        method: "wallet_getCallsStatus",
        params: ["expired-observation"],
      }),
    ).resolves.toMatchObject({ status: 100 });
    expect(chain.sends).toHaveLength(1);
    await secondConnection.close();
  });
});

describe("durable ID uniqueness", () => {
  it("isolates the same application ID between Grants sharing one binding and account", async () => {
    const stores = reopenableMemoryStores();
    const clock = createClock();
    const relay = createRelay(clock);
    const chain = createChainFixture();
    const firstRealm = createRealm({ stores, clock, relay, chain });
    const secondRealm = createRealm({ stores, clock, relay, chain });
    const firstConnection = await firstRealm.oaath.connect();
    const secondConnection = await secondRealm.oaath.connect();
    const firstGrant = await firstConnection.requestPermission(permissionInput());
    const secondGrant = await secondConnection.requestPermission(permissionInput());
    const firstPort = grantProviderPort(firstGrant);
    const secondPort = grantProviderPort(secondGrant);
    expect(firstPort.providerScopeId).toBe(secondPort.providerScopeId);
    expect(firstPort.grantId).not.toBe(secondPort.grantId);
    const account = await firstGrant.account(CHAIN_ID);
    expect(await secondGrant.account(CHAIN_ID)).toBe(account);
    const firstProvider = oaathProvider({ grant: firstGrant, chain: CHAIN_ID });
    const secondProvider = oaathProvider({ grant: secondGrant, chain: CHAIN_ID });

    await firstProvider.request({
      method: "wallet_sendCalls",
      params: [bundle(account, "same-binding-id")],
    });
    await providerError(
      secondProvider.request({ method: "wallet_getCallsStatus", params: ["same-binding-id"] }),
      5730,
    );
    await expect(
      firstProvider.request({ method: "wallet_getCallsStatus", params: ["same-binding-id"] }),
    ).resolves.toMatchObject({ status: 200 });
    await secondProvider.request({
      method: "wallet_sendCalls",
      params: [bundle(account, "same-binding-id")],
    });

    await expect(
      secondProvider.request({ method: "wallet_getCallsStatus", params: ["same-binding-id"] }),
    ).resolves.toMatchObject({ status: 200 });
    expect(chain.sends).toHaveLength(2);
    await firstConnection.close();
    await secondConnection.close();
  });

  it("lets one of two separate providers reserve an app ID before the other quotes or sends", async () => {
    const chain = createChainFixture();
    const { connection, grant, account } = await activeProvider({ chain });
    const providers = [
      oaathProvider({ grant, chain: CHAIN_ID }),
      oaathProvider({ grant, chain: CHAIN_ID }),
    ];
    const request = {
      method: "wallet_sendCalls",
      params: [bundle(account, "two-provider-race")],
    };

    const results = await Promise.allSettled(
      providers.map((provider) => provider.request(request)),
    );
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    const rejected = results.find((result) => result.status === "rejected");
    expect(rejected).toMatchObject({ reason: { code: 5720 } });
    expect(chain.quotes).toBe(1);
    expect(chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("terminalizes the losing distinct ID when concurrent requests prepare the same hash", async () => {
    const chain = createChainFixture();
    const { connection, grant, account } = await activeProvider({ chain });
    const providers = [
      oaathProvider({ grant, chain: CHAIN_ID }),
      oaathProvider({ grant, chain: CHAIN_ID }),
    ];
    const ids = ["same-hash-a", "same-hash-b"] as const;
    const results = await Promise.allSettled(
      providers.map((provider, index) =>
        provider.request({
          method: "wallet_sendCalls",
          params: [bundle(account, ids[index])],
        }),
      ),
    );
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    expect(chain.sends).toHaveLength(1);

    const statuses = await Promise.all(
      ids.map((id) =>
        oaathProvider({ grant, chain: CHAIN_ID }).request({
          method: "wallet_getCallsStatus",
          params: [id],
        }),
      ),
    );
    expect(statuses.map((status) => (status as { readonly status: number }).status).sort()).toEqual(
      [200, 400],
    );
    expect(chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("rejects account rebinding before journal publication, signing, or send", async () => {
    const base = createChainFixture();
    let armed = false;
    let accountReads = 0;
    const chain = replaceChain(base, {
      reads: Object.freeze({
        async read(request: Parameters<OaathChainCapability["reads"]["read"]>[0]) {
          if (armed && request.type === "kernel_factory_account") {
            accountReads += 1;
            return accountReads === 1 ? ACCOUNT : OTHER_ACCOUNT;
          }
          return base.capability.reads.read(request);
        },
      }),
    });
    const { connection, provider, account } = await activeProvider({ chain });
    armed = true;

    await providerError(
      provider.request({
        method: "wallet_sendCalls",
        params: [bundle(account, "account-rebind")],
      }),
      -32603,
    );
    armed = false;
    await expect(
      provider.request({ method: "wallet_getCallsStatus", params: ["account-rebind"] }),
    ).resolves.toMatchObject({ status: 400 });
    expect(accountReads).toBe(2);
    expect(base.signatures).toHaveLength(0);
    expect(base.sends).toHaveLength(0);
    await connection.close();
  });

  it("keeps historical IDs stable across permanent account rebinding", async () => {
    const base = createChainFixture();
    let rebound = false;
    let factoryReads = 0;
    const chain = replaceChain(base, {
      reads: Object.freeze({
        async read(request: Parameters<OaathChainCapability["reads"]["read"]>[0]) {
          if (request.type === "kernel_factory_account") {
            factoryReads += 1;
            if (rebound) return OTHER_ACCOUNT;
          }
          return base.capability.reads.read(request);
        },
      }),
    });
    const { connection, provider, account } = await activeProvider({ chain });
    await provider.request({
      method: "wallet_sendCalls",
      params: [bundle(account, "stable-account-history")],
    });
    rebound = true;
    const readsBeforeStatus = factoryReads;

    await expect(
      provider.request({ method: "wallet_getCallsStatus", params: ["stable-account-history"] }),
    ).resolves.toMatchObject({ status: 200 });
    expect(factoryReads).toBe(readsBeforeStatus);
    await providerError(
      provider.request({
        method: "wallet_sendCalls",
        params: [bundle(account, "stable-account-history")],
      }),
      5720,
    );
    await providerError(
      provider.request({ method: "wallet_getCallsStatus", params: ["unknown-after-rebind"] }),
      5730,
    );
    expect(factoryReads).toBe(readsBeforeStatus);
    expect(chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("retries generated-ID collisions only within the bounded random loop", async () => {
    const chain = createChainFixture();
    const { connection, provider, account } = await activeProvider({ chain });
    const collision = `0x${"11".repeat(32)}`;
    await provider.request({
      method: "wallet_sendCalls",
      params: [bundle(account, collision)],
    });
    await provider.request({ method: "wallet_getCallsStatus", params: [collision] });

    let calls = 0;
    const random = vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation((array) => {
      calls += 1;
      new Uint8Array(array.buffer, array.byteOffset, array.byteLength).fill(
        calls === 1 ? 0x11 : 0x22,
      );
      return array;
    });
    try {
      await expect(
        provider.request({
          method: "wallet_sendCalls",
          params: [bundle(account, undefined)],
        }),
      ).resolves.toEqual({ id: `0x${"22".repeat(32)}` });
    } finally {
      random.mockRestore();
    }
    expect(calls).toBe(4);
    expect(chain.sends).toHaveLength(2);
    await connection.close();
  });

  it("allows the same ID across binding or account, while chain is not a uniqueness axis", async () => {
    const stores = reopenableMemoryStores();
    const clock = createClock();
    const relay = createRelay(clock);
    const firstChain = createChainFixture();
    const otherBindingChain = createChainFixture();
    const otherAccountChain = createChainFixture({ account: OTHER_ACCOUNT });
    const first = createRealm({ stores, clock, relay, chain: firstChain });
    const otherBinding = createRealm({
      stores,
      clock,
      relay,
      chain: otherBindingChain,
      binding: { ...bindingInput, deviceId: "device-b" },
    });
    const otherAccount = createRealm({ stores, clock, relay, chain: otherAccountChain });
    const connections = await Promise.all([
      first.oaath.connect(),
      otherBinding.oaath.connect(),
      otherAccount.oaath.connect(),
    ]);
    const grants = await Promise.all(
      connections.map((connection) => connection.requestPermission(permissionInput())),
    );
    const accounts = await Promise.all(grants.map((grant) => grant.account(CHAIN_ID)));
    expect(accounts).toEqual([ACCOUNT, ACCOUNT, OTHER_ACCOUNT]);

    const providers = grants.map((grant) => oaathProvider({ grant, chain: CHAIN_ID }));
    const firstProvider = providers[0];
    if (firstProvider === undefined) throw new Error("expected the first isolated provider");
    await firstProvider.request({
      method: "wallet_sendCalls",
      params: [bundle(accounts[0] ?? ACCOUNT, "isolated-id")],
    });
    await Promise.all(
      providers
        .slice(1)
        .map((provider) =>
          providerError(
            provider.request({ method: "wallet_getCallsStatus", params: ["isolated-id"] }),
            5730,
          ),
        ),
    );
    await Promise.all(
      providers.slice(1).map((provider, index) =>
        provider.request({
          method: "wallet_sendCalls",
          params: [bundle(accounts[index + 1] ?? ACCOUNT, "isolated-id")],
        }),
      ),
    );
    expect(firstChain.sends).toHaveLength(1);
    expect(otherBindingChain.sends).toHaveLength(1);
    expect(otherAccountChain.sends).toHaveLength(1);
    for (const connection of connections) await connection.close();
  });

  it("rejects one ID on another chain for the same binding and account before its quote", async () => {
    const firstChain = createChainFixture();
    const secondChain = createChainFixture({ chainId: OTHER_CHAIN_ID });
    const realm = createRealm({ chains: [firstChain, secondChain] });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    await oaathProvider({ grant, chain: CHAIN_ID }).request({
      method: "wallet_sendCalls",
      params: [bundle(account, "cross-chain-duplicate")],
    });
    await providerError(
      oaathProvider({ grant, chain: OTHER_CHAIN_ID }).request({
        method: "wallet_sendCalls",
        params: [bundle(account, "cross-chain-duplicate", OTHER_CHAIN_ID)],
      }),
      5720,
    );
    expect(firstChain.sends).toHaveLength(1);
    expect(secondChain.quotes).toBe(0);
    expect(secondChain.sends).toHaveLength(0);
    await connection.close();
  });
});

type OperationCrash = "before_prepared" | "after_prepared" | "after_attempted";

function operationCrashStores(mode: OperationCrash): RealmStores {
  const stores = reopenableMemoryStores();
  let crashed = false;
  return {
    ...stores,
    operations: Object.freeze({
      ...stores.operations,
      async compareAndSwap(input: Parameters<typeof stores.operations.compareAndSwap>[0]) {
        const state = (input.next as { readonly value?: { readonly state?: unknown } }).value
          ?.state;
        const selected =
          !crashed &&
          ((mode === "before_prepared" && state === "prepared") ||
            (mode === "after_prepared" && state === "prepared") ||
            (mode === "after_attempted" && state === "submission_attempted"));
        if (!selected) return stores.operations.compareAndSwap(input);
        crashed = true;
        if (mode === "before_prepared") return false;
        await stores.operations.compareAndSwap(input);
        throw new Error("injected operation-store acknowledgement loss");
      },
    }),
  };
}

describe("durable crash boundaries", () => {
  it("keeps a recreated accepted request pending without letting status cancel its sender", async () => {
    const base = createChainFixture();
    let enterQuote!: () => void;
    let releaseQuote!: () => void;
    const quoteEntered = new Promise<void>((resolve) => {
      enterQuote = resolve;
    });
    const quoteReleased = new Promise<void>((resolve) => {
      releaseQuote = resolve;
    });
    const chain = replaceChain(base, {
      async quote(request) {
        enterQuote();
        await quoteReleased;
        return base.capability.quote(request);
      },
    });
    const { connection, grant, account } = await activeProvider({ chain });
    const sender = oaathProvider({ grant, chain: CHAIN_ID });
    const recovery = oaathProvider({ grant, chain: CHAIN_ID });
    const sending = sender.request({
      method: "wallet_sendCalls",
      params: [bundle(account, "accepted-crash")],
    });
    await quoteEntered;
    await expect(
      recovery.request({ method: "wallet_getCallsStatus", params: ["accepted-crash"] }),
    ).resolves.toMatchObject({ status: 100 });
    await providerError(
      recovery.request({
        method: "wallet_sendCalls",
        params: [bundle(account, "accepted-crash")],
      }),
      5720,
    );
    releaseQuote();
    await expect(sending).resolves.toEqual({ id: "accepted-crash" });
    expect(chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("keeps delayed Operation publication pending without terminalizing its reservation", async () => {
    const stores = reopenableMemoryStores();
    let enterPublication!: () => void;
    let releasePublication!: () => void;
    const publicationEntered = new Promise<void>((resolve) => {
      enterPublication = resolve;
    });
    const publicationReleased = new Promise<void>((resolve) => {
      releasePublication = resolve;
    });
    let blocked = false;
    const racedStores: RealmStores = {
      ...stores,
      operations: Object.freeze({
        ...stores.operations,
        async compareAndSwap(input: Parameters<typeof stores.operations.compareAndSwap>[0]) {
          const state = (input.next as { readonly value?: { readonly state?: unknown } }).value
            ?.state;
          if (!blocked && state === "prepared") {
            blocked = true;
            enterPublication();
            await publicationReleased;
          }
          return stores.operations.compareAndSwap(input);
        },
      }),
    };
    const chain = createChainFixture();
    const { connection, grant, account } = await activeProvider({ stores: racedStores, chain });
    const sender = oaathProvider({ grant, chain: CHAIN_ID });
    const recovery = oaathProvider({ grant, chain: CHAIN_ID });
    const sending = sender.request({
      method: "wallet_sendCalls",
      params: [bundle(account, "reserved-publication-race")],
    });
    await publicationEntered;

    await expect(
      recovery.request({
        method: "wallet_getCallsStatus",
        params: ["reserved-publication-race"],
      }),
    ).resolves.toMatchObject({ status: 100 });
    releasePublication();
    await expect(sending).resolves.toEqual({ id: "reserved-publication-race" });
    expect(chain.signatures).toHaveLength(1);
    expect(chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("keeps accepted coordination durable across providers until the sender finishes", async () => {
    const base = createChainFixture();
    let enterFirstQuote!: () => void;
    let releaseFirstQuote!: () => void;
    const firstQuoteEntered = new Promise<void>((resolve) => {
      enterFirstQuote = resolve;
    });
    const firstQuoteReleased = new Promise<void>((resolve) => {
      releaseFirstQuote = resolve;
    });
    let quotes = 0;
    const chain = replaceChain(base, {
      async quote(request) {
        quotes += 1;
        if (quotes === 1) {
          enterFirstQuote();
          await firstQuoteReleased;
        }
        return base.capability.quote(request);
      },
    });
    const { connection, grant, account } = await activeProvider({ chain });
    const staleProvider = oaathProvider({ grant, chain: CHAIN_ID });
    const recovery = oaathProvider({ grant, chain: CHAIN_ID });
    const staleSend = staleProvider.request({
      method: "wallet_sendCalls",
      params: [bundle(account, "generation-reuse")],
    });
    await firstQuoteEntered;
    await expect(
      recovery.request({ method: "wallet_getCallsStatus", params: ["generation-reuse"] }),
    ).resolves.toMatchObject({ status: 100 });
    await providerError(
      recovery.request({
        method: "wallet_sendCalls",
        params: [bundle(account, "generation-reuse")],
      }),
      5720,
    );
    releaseFirstQuote();
    await expect(staleSend).resolves.toEqual({ id: "generation-reuse" });
    expect(chain.signatures).toHaveLength(1);
    expect(chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("prevents stale status cleanup from terminalizing a replacement generation", async () => {
    const startedAt = 1_800_000_000;
    let currentTime = startedAt;
    const clock = {
      now: () => currentTime,
      advance: (seconds: number) => {
        currentTime += seconds;
      },
    };
    const stores = reopenableMemoryStores();
    let enterDelete!: () => void;
    let releaseDelete!: () => void;
    const deleteEntered = new Promise<void>((resolve) => {
      enterDelete = resolve;
    });
    const deleteReleased = new Promise<void>((resolve) => {
      releaseDelete = resolve;
    });
    let blocked = false;
    const racedStores: RealmStores = {
      ...stores,
      walletCallBundles: Object.freeze({
        ...stores.walletCallBundles,
        async compareAndDelete(
          input: Parameters<typeof stores.walletCallBundles.compareAndDelete>[0],
        ) {
          if (!blocked) {
            blocked = true;
            enterDelete();
            await deleteReleased;
          }
          return stores.walletCallBundles.compareAndDelete(input);
        },
      }),
    };
    const chain = createChainFixture();
    const { connection, grant, account } = await activeProvider({
      stores: racedStores,
      clock,
      chain,
    });
    const first = oaathProvider({ grant, chain: CHAIN_ID });
    await first.request({
      method: "wallet_sendCalls",
      params: [bundle(account, "stale-status-generation")],
    });
    await expect(
      first.request({ method: "wallet_getCallsStatus", params: ["stale-status-generation"] }),
    ).resolves.toMatchObject({ status: 200 });
    clock.advance(86_400);

    const staleStatus = providerError(
      first.request({ method: "wallet_getCallsStatus", params: ["stale-status-generation"] }),
      5730,
    );
    await deleteEntered;
    const cleanup = oaathProvider({ grant, chain: CHAIN_ID });
    await providerError(
      cleanup.request({ method: "wallet_getCallsStatus", params: ["stale-status-generation"] }),
      5730,
    );
    currentTime = startedAt + 1;
    const replacement = oaathProvider({ grant, chain: CHAIN_ID });
    await replacement.request({
      method: "wallet_sendCalls",
      params: [bundle(account, "stale-status-generation")],
    });

    releaseDelete();
    await staleStatus;
    expect(chain.sends).toHaveLength(2);
    await expect(
      replacement.request({
        method: "wallet_getCallsStatus",
        params: ["stale-status-generation"],
      }),
    ).resolves.toMatchObject({ status: 200 });
    await connection.close();
  });

  it.each([
    ["reserved with no Operation", "before_prepared", 400],
    ["durable prepared Operation", "after_prepared", 400],
    ["durable attempted Operation", "after_attempted", 100],
  ] as const)("recovers %s without submission", async (_label, mode, postLeaseStatus) => {
    const stores = operationCrashStores(mode);
    const chain = createChainFixture({ withholdReceipt: () => true });
    const { realm, connection, provider, account } = await activeProvider({ stores, chain });
    await providerError(
      provider.request({
        method: "wallet_sendCalls",
        params: [bundle(account, `crash-${mode}`)],
      }),
      -32603,
    );
    await expect(
      provider.request({ method: "wallet_getCallsStatus", params: [`crash-${mode}`] }),
    ).resolves.toMatchObject({ status: 100 });
    realm.clock.advance(31);
    await expect(
      provider.request({ method: "wallet_getCallsStatus", params: [`crash-${mode}`] }),
    ).resolves.toMatchObject({ status: postLeaseStatus });
    expect(chain.sends).toHaveLength(0);
    await connection.close();
  });

  it("converges concurrent status reads for one exact operation without resubmission", async () => {
    const base = createChainFixture();
    const clock = createClock();
    let gateFirstReceipt = true;
    let enterReceipt!: () => void;
    let releaseReceipt!: () => void;
    const receiptEntered = new Promise<void>((resolve) => {
      enterReceipt = resolve;
    });
    const receiptReleased = new Promise<void>((resolve) => {
      releaseReceipt = resolve;
    });
    const chain = replaceChain(base, {
      observation: Object.freeze({
        async read(request: Parameters<OaathChainCapability["observation"]["read"]>[0]) {
          if (request.type === "user_operation_receipt" && gateFirstReceipt) {
            gateFirstReceipt = false;
            enterReceipt();
            await receiptReleased;
          }
          return base.capability.observation.read(request);
        },
        close: () => base.capability.observation.close(),
      }),
    });
    const { connection, grant, account } = await activeProvider({ chain, clock });
    await oaathProvider({ grant, chain: CHAIN_ID }).request({
      method: "wallet_sendCalls",
      params: [bundle(account, "concurrent-status")],
    });
    const providers = [
      oaathProvider({ grant, chain: CHAIN_ID }),
      oaathProvider({ grant, chain: CHAIN_ID }),
    ];

    const first = providers[0]?.request({
      method: "wallet_getCallsStatus",
      params: ["concurrent-status"],
    });
    if (!first) throw new Error("expected the first provider");
    await receiptEntered;
    clock.advance(1);
    const second = providers[1]?.request({
      method: "wallet_getCallsStatus",
      params: ["concurrent-status"],
    });
    if (!second) throw new Error("expected the second provider");
    await expect(second).resolves.toMatchObject({ status: 200 });
    releaseReceipt();
    await expect(first).resolves.toMatchObject({ status: 200 });
    expect(chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("keeps provider finality authoritative while Grant bookkeeping retries", async () => {
    const memory = createMemoryStores();
    let installationFailures = 1;
    const stores: RealmStores = {
      ...memory,
      grants: {
        get: (grantId: Parameters<typeof memory.grants.get>[0]) => memory.grants.get(grantId),
        compareAndSwap: (input: Parameters<typeof memory.grants.compareAndSwap>[0]) => {
          const grant = input.next.value as {
            readonly materializations?: readonly Readonly<{ state?: unknown }>[];
          };
          if (
            installationFailures > 0 &&
            grant.materializations?.some((entry) => entry.state === "installed")
          ) {
            installationFailures -= 1;
            throw new Error("lost materialization bookkeeping write");
          }
          return memory.grants.compareAndSwap(input);
        },
        close: () => memory.grants.close(),
      },
    };
    const chain = createChainFixture();
    const { connection, grant, provider, account } = await activeProvider({ stores, chain });
    await provider.request({
      method: "wallet_sendCalls",
      params: [bundle(account, "bookkeeping-retry")],
    });

    await expect(
      provider.request({ method: "wallet_getCallsStatus", params: ["bookkeeping-retry"] }),
    ).resolves.toMatchObject({ status: 200 });
    const grantId = grantProviderPort(grant).grantId;
    await expect(memory.grants.get(grantId)).resolves.toMatchObject({
      value: { materializations: [{ state: "installing" }] },
    });
    await expect(
      provider.request({ method: "wallet_getCallsStatus", params: ["bookkeeping-retry"] }),
    ).resolves.toMatchObject({ status: 200 });
    await expect(memory.grants.get(grantId)).resolves.toMatchObject({
      value: { materializations: [{ state: "installed" }] },
    });
    expect(chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("observes one send/return ambiguity after full recreation and never submits again", async () => {
    const stores = reopenableMemoryStores();
    const clock = createClock();
    const relay = createRelay(clock);
    let crash = true;
    const chain = createChainFixture({ crashOnSend: () => crash });
    const before = createRealm({ stores, clock, relay, chain });
    const firstConnection = await before.oaath.connect();
    const firstGrant = await firstConnection.requestPermission(permissionInput());
    const account = await firstGrant.account(CHAIN_ID);
    await expect(
      oaathProvider({ grant: firstGrant, chain: CHAIN_ID }).request({
        method: "wallet_sendCalls",
        params: [bundle(account, "ambiguous-reload")],
      }),
    ).resolves.toEqual({ id: "ambiguous-reload" });
    expect(chain.sends).toHaveLength(1);
    const exactHash = chain.sends[0]?.userOperationHash;
    await firstConnection.close();
    crash = false;

    const after = createRealm({ stores, clock, relay, chain });
    const secondConnection = await after.oaath.connect();
    const secondGrant = await secondConnection.resume();
    if (secondGrant === null) throw new Error("expected the ambiguous Grant to resume");
    await expect(
      oaathProvider({ grant: secondGrant, chain: CHAIN_ID }).request({
        method: "wallet_getCallsStatus",
        params: ["ambiguous-reload"],
      }),
    ).resolves.toMatchObject({ status: 200 });
    expect(chain.sends).toHaveLength(1);
    expect(chain.sends[0]?.userOperationHash).toBe(exactHash);
    await secondConnection.close();
  });
});

describe("terminal retention and exact history", () => {
  it("fails closed when a publication-confirmed terminal bundle loses its Operation evidence", async () => {
    const stores = reopenableMemoryStores();
    let operations = stores.operations;
    const separatedStores: RealmStores = {
      ...stores,
      operations: Object.freeze({
        get: (key: Parameters<typeof operations.get>[0]) => operations.get(key),
        getArchived: (input: Parameters<typeof operations.getArchived>[0]) =>
          operations.getArchived(input),
        compareAndSwap: (input: Parameters<typeof operations.compareAndSwap>[0]) =>
          operations.compareAndSwap(input),
        close: async () => undefined,
      }),
    };
    const chain = createChainFixture();
    const { connection, provider, account } = await activeProvider({
      stores: separatedStores,
      chain,
    });
    await provider.request({
      method: "wallet_sendCalls",
      params: [bundle(account, "lost-terminal-operation")],
    });
    await expect(
      provider.request({
        method: "wallet_getCallsStatus",
        params: ["lost-terminal-operation"],
      }),
    ).resolves.toMatchObject({ status: 200 });

    operations = createMemoryStores().operations;
    await providerError(
      provider.request({
        method: "wallet_getCallsStatus",
        params: ["lost-terminal-operation"],
      }),
      -32603,
    );
    expect(chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("rejects finalized evidence under a pre-publication terminal without provider reads", async () => {
    const stores = reopenableMemoryStores();
    const bundles = stores.walletCallBundles;
    let contradict = false;
    const contradictoryStores: RealmStores = {
      ...stores,
      walletCallBundles: Object.freeze({
        ...bundles,
        async get(key: Parameters<typeof bundles.get>[0]) {
          const raw = await bundles.get(key);
          if (!contradict || key.id !== "reserved-terminal-contradiction" || raw === undefined) {
            return raw;
          }
          const envelope = plainRecord(raw, "terminal bundle envelope");
          const value = plainRecord(envelope.value, "terminal bundle value");
          return {
            ...envelope,
            storeRevision: 2,
            value: { ...value, state: "terminal", terminalFrom: "operation_reserved" },
          };
        },
      }),
    };
    const base = createChainFixture();
    let observationReads = 0;
    const chain = replaceChain(base, {
      observation: Object.freeze({
        async read(request: Parameters<OaathChainCapability["observation"]["read"]>[0]) {
          observationReads += 1;
          return base.capability.observation.read(request);
        },
        close: () => base.capability.observation.close(),
      }),
    });
    const { connection, provider, account } = await activeProvider({
      stores: contradictoryStores,
      chain,
    });
    await provider.request({
      method: "wallet_sendCalls",
      params: [bundle(account, "reserved-terminal-contradiction")],
    });
    await expect(
      provider.request({
        method: "wallet_getCallsStatus",
        params: ["reserved-terminal-contradiction"],
      }),
    ).resolves.toMatchObject({ status: 200 });
    const readsBeforeContradiction = observationReads;
    contradict = true;

    await providerError(
      provider.request({
        method: "wallet_getCallsStatus",
        params: ["reserved-terminal-contradiction"],
      }),
      -32603,
    );
    expect(observationReads).toBe(readsBeforeContradiction);
    expect(base.sends).toHaveLength(1);
    await connection.close();
  });

  it("retains terminal status through 86,399 seconds and deletes it at exactly 86,400", async () => {
    const clock = createClock();
    const base = createChainFixture();
    const chain = replaceChain(base, {
      async quote() {
        throw new Error("conclusive pre-binding failure");
      },
    });
    const { connection, provider, account } = await activeProvider({ clock, chain });
    await providerError(
      provider.request({
        method: "wallet_sendCalls",
        params: [bundle(account, "retention-boundary")],
      }),
      -32603,
    );
    await expect(
      provider.request({ method: "wallet_getCallsStatus", params: ["retention-boundary"] }),
    ).resolves.toMatchObject({ status: 400 });
    clock.advance(86_399);
    await expect(
      provider.request({ method: "wallet_getCallsStatus", params: ["retention-boundary"] }),
    ).resolves.toMatchObject({ status: 400 });
    clock.advance(1);
    await providerError(
      provider.request({ method: "wallet_getCallsStatus", params: ["retention-boundary"] }),
      5730,
    );
    await connection.close();
  });

  it("never expires an unresolved operation-bound request after 24 hours", async () => {
    const clock = createClock();
    let crash = true;
    const chain = createChainFixture({
      crashOnSend: () => crash,
      withholdReceipt: () => true,
    });
    const { connection, provider, account } = await activeProvider({ clock, chain });
    await provider.request({
      method: "wallet_sendCalls",
      params: [bundle(account, "unresolved-retention")],
    });
    crash = false;
    clock.advance(86_400);
    await expect(
      provider.request({ method: "wallet_getCallsStatus", params: ["unresolved-retention"] }),
    ).resolves.toMatchObject({ status: 100 });
    expect(chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("terminalizes an expired operation reservation with no publication evidence", async () => {
    const stores = operationCrashStores("before_prepared");
    const clock = createClock();
    const chain = createChainFixture();
    const { connection, provider, account } = await activeProvider({ stores, clock, chain });
    await providerError(
      provider.request({
        method: "wallet_sendCalls",
        params: [bundle(account, "reserved-retention")],
      }),
      -32603,
    );
    clock.advance(86_400);

    await expect(
      provider.request({ method: "wallet_getCallsStatus", params: ["reserved-retention"] }),
    ).resolves.toMatchObject({ status: 400 });
    expect(chain.sends).toHaveLength(0);
    await connection.close();
  });

  it("resolves archived bundle A after bundle B replaces its operation lane", async () => {
    const base = createChainFixture();
    let activeHash: string | undefined;
    const operationReceipts = new Map<string, unknown>();
    const transactionReceipts = new Map<string, unknown>();
    const read: OaathChainCapability["observation"]["read"] = async (request) => {
      if (request.type === "user_operation_receipt") {
        activeHash = request.userOperationHash;
        if (operationReceipts.has(activeHash)) return operationReceipts.get(activeHash);
        const receipt = await base.capability.observation.read(request);
        operationReceipts.set(activeHash, receipt);
        return receipt;
      }
      if (request.type === "transaction_receipt" && activeHash !== undefined) {
        if (transactionReceipts.has(activeHash)) return transactionReceipts.get(activeHash);
        const receipt = await base.capability.observation.read(request);
        transactionReceipts.set(activeHash, receipt);
        return receipt;
      }
      return base.capability.observation.read(request);
    };
    const chain = replaceChain(base, {
      observation: Object.freeze({ read, close: () => base.capability.observation.close() }),
    });
    const { connection, provider, account } = await activeProvider({ chain });
    await provider.request({
      method: "wallet_sendCalls",
      params: [bundle(account, "archived-a")],
    });
    const firstHash = chain.sends[0]?.userOperationHash;
    await expect(
      provider.request({ method: "wallet_getCallsStatus", params: ["archived-a"] }),
    ).resolves.toMatchObject({ status: 200 });
    await provider.request({
      method: "wallet_sendCalls",
      params: [bundle(account, "replacement-b")],
    });
    expect(chain.sends[1]?.userOperationHash).not.toBe(firstHash);
    await expect(
      provider.request({ method: "wallet_getCallsStatus", params: ["archived-a"] }),
    ).resolves.toMatchObject({ id: "archived-a", status: 200 });
    expect(chain.sends).toHaveLength(2);
    await connection.close();
  });

  it("rejects a prior-generation pointer for an identical reused request", async () => {
    const startedAt = 1_800_000_000;
    let currentTime = startedAt;
    const clock = {
      now: () => currentTime,
      advance: (seconds: number) => {
        currentTime += seconds;
      },
    };
    const stores = reopenableMemoryStores();
    const walletCallBundles = stores.walletCallBundles;
    let swapPointer = false;
    let firstOperation: unknown;
    const tamperedStores: RealmStores = {
      ...stores,
      walletCallBundles: Object.freeze({
        ...walletCallBundles,
        async get(key: Parameters<typeof walletCallBundles.get>[0]) {
          const raw = await walletCallBundles.get(key);
          if (!swapPointer || key.id !== "pointer-reuse" || raw === undefined) return raw;
          if (firstOperation === null || firstOperation === undefined) {
            throw new Error("expected the first bundle operation");
          }
          const secondEnvelope = plainRecord(raw, "second bundle envelope");
          const secondValue = plainRecord(secondEnvelope.value, "second bundle value");
          return {
            ...secondEnvelope,
            value: { ...secondValue, operation: firstOperation },
          };
        },
      }),
    };
    const base = createChainFixture();
    let observationReads = 0;
    const chain = replaceChain(base, {
      observation: Object.freeze({
        async read(request: Parameters<OaathChainCapability["observation"]["read"]>[0]) {
          observationReads += 1;
          return base.capability.observation.read(request);
        },
        close: () => base.capability.observation.close(),
      }),
    });
    const { connection, grant, provider, account } = await activeProvider({
      stores: tamperedStores,
      clock,
      chain,
    });
    await provider.request({
      method: "wallet_sendCalls",
      params: [bundle(account, "pointer-reuse")],
    });
    const port = grantProviderPort(grant);
    const firstRecord = await port.walletCallBundles.get({
      providerScopeId: port.providerScopeId,
      grantId: port.grantId,
      id: "pointer-reuse",
    });
    firstOperation = firstRecord?.value.operation;
    await expect(
      provider.request({ method: "wallet_getCallsStatus", params: ["pointer-reuse"] }),
    ).resolves.toMatchObject({ status: 200 });
    clock.advance(86_400);
    await providerError(
      provider.request({ method: "wallet_getCallsStatus", params: ["pointer-reuse"] }),
      5730,
    );
    currentTime = startedAt + 1;
    await provider.request({
      method: "wallet_sendCalls",
      params: [bundle(account, "pointer-reuse")],
    });
    const readsBeforeSwap = observationReads;
    swapPointer = true;

    await providerError(
      provider.request({ method: "wallet_getCallsStatus", params: ["pointer-reuse"] }),
      -32603,
    );
    expect(observationReads).toBe(readsBeforeSwap);
    expect(chain.sends).toHaveLength(2);

    swapPointer = false;
    await expect(
      provider.request({ method: "wallet_getCallsStatus", params: ["pointer-reuse"] }),
    ).resolves.toMatchObject({ status: 200 });
    expect(chain.sends).toHaveLength(2);
    await connection.close();
  });
});

describe("captured request identity", () => {
  it("binds identical canonical requests to distinct durable generations", () => {
    const captured = captureWalletSendCallsParams(
      [bundle(ACCOUNT, "generation-bound-request")],
      CHAIN_ID,
    );
    const requestHash = hashCapturedWalletSendCallsRequest(captured, "generation-bound-request");
    expect(hashWalletCallBundleProvenance(requestHash, `0x${"11".repeat(32)}`)).not.toBe(
      hashWalletCallBundleProvenance(requestHash, `0x${"22".repeat(32)}`),
    );
  });

  it("ignores caller object-key order but binds ordered calls, capability arrays, and ID", () => {
    const first = captureWalletSendCallsParams(
      [
        bundle(ACCOUNT, "request-hash", CHAIN_ID, {
          calls: [
            {
              to: TARGET,
              data: CALL_DATA,
              capabilities: {
                hint: { optional: true, nested: { b: 2, a: 1 }, ordered: ["a", "b"] },
              },
            },
            { to: OTHER_ACCOUNT, data: "0x" },
          ],
          capabilities: {
            second: { optional: true, value: 2 },
            first: { optional: true, value: 1 },
          },
        }),
      ],
      CHAIN_ID,
    );
    const reordered = captureWalletSendCallsParams(
      [
        {
          calls: [
            {
              capabilities: {
                hint: { ordered: ["a", "b"], nested: { a: 1, b: 2 }, optional: true },
              },
              data: CALL_DATA,
              to: TARGET,
            },
            { data: "0x", to: OTHER_ACCOUNT },
          ],
          capabilities: {
            first: { value: 1, optional: true },
            second: { value: 2, optional: true },
          },
          atomicRequired: true,
          chainId: `0x${CHAIN_ID.toString(16)}`,
          from: ACCOUNT,
          id: "request-hash",
          version: "2.0.0",
        },
      ],
      CHAIN_ID,
    );
    const stable = hashCapturedWalletSendCallsRequest(first, "request-hash");
    expect(hashCapturedWalletSendCallsRequest(reordered, "request-hash")).toBe(stable);

    const reversedCalls = Object.freeze({
      ...first,
      calls: Object.freeze([...first.calls].reverse()),
    });
    expect(hashCapturedWalletSendCallsRequest(reversedCalls, "request-hash")).not.toBe(stable);
    const changedArray = captureWalletSendCallsParams(
      [
        bundle(ACCOUNT, "request-hash", CHAIN_ID, {
          calls: [
            {
              to: TARGET,
              data: CALL_DATA,
              capabilities: {
                hint: { optional: true, nested: { a: 1, b: 2 }, ordered: ["b", "a"] },
              },
            },
            { to: OTHER_ACCOUNT, data: "0x" },
          ],
          capabilities: {
            first: { optional: true, value: 1 },
            second: { optional: true, value: 2 },
          },
        }),
      ],
      CHAIN_ID,
    );
    expect(hashCapturedWalletSendCallsRequest(changedArray, "request-hash")).not.toBe(stable);
    expect(hashCapturedWalletSendCallsRequest(first, "another-id")).not.toBe(stable);
  });
});
