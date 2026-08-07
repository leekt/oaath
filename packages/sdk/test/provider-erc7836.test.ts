/**
 * Durable experimental ERC-7836 orchestration through the public provider.
 *
 * @author taek <leekt216@gmail.com>
 */
import { IDBFactory } from "fake-indexeddb";
import { describe, expect, it } from "vitest";
import { grantProviderPort } from "../src/client/grant-handle.js";
import {
  createIndexedDbCleanupStore,
  createIndexedDbContextStore,
  createIndexedDbGrantStoreAdapter,
  createIndexedDbKeyStore,
  createIndexedDbOperationStoreAdapter,
  createIndexedDbPreparedCallStoreAdapter,
  createIndexedDbWalletCallBundleStoreAdapter,
  openOaathDatabase,
} from "../src/persistence.js";
import { INTERNAL_ERROR } from "../src/provider/errors.js";
import { oaathProvider } from "../src/viem.js";
import {
  CALL_DATA,
  CHAIN_ID,
  createChainFixture,
  createClock,
  createMemoryStores,
  createRealm,
  permissionInput,
  SESSION_PUBLIC_KEY,
  signPreparedDigest,
  TARGET,
} from "./support/browser.js";

const CHAIN_HEX = `0x${CHAIN_ID.toString(16)}` as const;
const FOREIGN_ACCOUNT = `0x${"99".repeat(20)}` as const;

interface PreparedRpcResponse {
  readonly version: "1";
  readonly chainId: `0x${string}`;
  readonly capabilities: Readonly<Record<string, unknown>>;
  readonly context: Readonly<{ version: string; id: `0x${string}` }>;
  readonly key: Readonly<{
    type: "secp256k1";
    publicKey: `0x${string}`;
    prehash: false;
  }>;
  readonly digest: `0x${string}`;
}

function providerPrepareRequest(account: `0x${string}`) {
  return {
    method: "wallet_prepareCalls",
    params: [
      {
        version: "1",
        from: account,
        chainId: CHAIN_HEX,
        calls: [{ to: TARGET, data: CALL_DATA }],
        capabilities: { applicationHint: { optional: true, value: "retained" } },
        key: {
          type: "secp256k1",
          publicKey: SESSION_PUBLIC_KEY,
          prehash: false,
        },
      },
    ],
  } as const;
}

function providerSendRequest(prepared: Readonly<PreparedRpcResponse>, signature: `0x${string}`) {
  return {
    method: "wallet_sendPreparedCalls",
    params: [
      {
        version: prepared.version,
        chainId: prepared.chainId,
        capabilities: prepared.capabilities,
        context: prepared.context,
        key: prepared.key,
        signature,
      },
    ],
  } as const;
}

async function indexedDbPreparedRealmStores(factory: IDBFactory) {
  const database = await openOaathDatabase({ factory });
  return {
    database,
    stores: {
      grants: createIndexedDbGrantStoreAdapter(database),
      operations: createIndexedDbOperationStoreAdapter(database),
      walletCallBundles: createIndexedDbWalletCallBundleStoreAdapter(database),
      preparedCallContexts: createIndexedDbPreparedCallStoreAdapter(database),
      keys: createIndexedDbKeyStore(database),
      cleanup: createIndexedDbCleanupStore(database),
      context: createIndexedDbContextStore(database),
    },
  };
}

describe("experimental wallet prepared calls", () => {
  it.each(["expired", "revoked"] as const)(
    "refuses %s Grant preparation before quote, context reservation, signing, or send",
    async (state) => {
      const clock = createClock();
      const chain = createChainFixture();
      const stores = createMemoryStores();
      const durableContexts = stores.preparedCallContexts;
      let contextWrites = 0;
      const preparedCallContexts: typeof durableContexts = Object.freeze({
        get: (key: Parameters<typeof durableContexts.get>[0]) => durableContexts.get(key),
        compareAndSwap: (input: Parameters<typeof durableContexts.compareAndSwap>[0]) => {
          contextWrites += 1;
          return durableContexts.compareAndSwap(input);
        },
        close: () => durableContexts.close(),
      });
      const realm = createRealm({
        clock,
        chain,
        stores: { ...stores, preparedCallContexts },
      });
      const connection = await realm.oaath.connect();
      const grant = await connection.requestPermission(permissionInput());
      const account = await grant.account(CHAIN_ID);
      const provider = oaathProvider({ grant, chain: CHAIN_ID });

      if (state === "expired") clock.advance(grant.expiresAt - clock.now());
      else await grant.revoke();
      const quotes = chain.quotes;
      const signatures = chain.signatures.length;
      const sends = chain.sends.length;

      await expect(provider.request(providerPrepareRequest(account))).rejects.toMatchObject({
        name: "OaathProviderRpcError",
        code: 4100,
      });
      expect(contextWrites).toBe(0);
      expect(chain.quotes).toBe(quotes);
      expect(chain.signatures).toHaveLength(signatures);
      expect(chain.sends).toHaveLength(sends);
      await connection.close();
    },
  );

  it("uses the prepared context account as the sole durable bundle key axis", async () => {
    const chain = createChainFixture();
    const stores = createMemoryStores();
    const durableBundles = stores.walletCallBundles;
    const bundleKeys: Array<Parameters<typeof durableBundles.get>[0]> = [];
    const walletCallBundles: typeof durableBundles = Object.freeze({
      get(key: Parameters<typeof durableBundles.get>[0]) {
        bundleKeys.push(key);
        return durableBundles.get(key);
      },
      compareAndSwap(input: Parameters<typeof durableBundles.compareAndSwap>[0]) {
        bundleKeys.push(input.key);
        return durableBundles.compareAndSwap(input);
      },
      close: () => durableBundles.close(),
    });
    const realm = createRealm({ chain, stores: { ...stores, walletCallBundles } });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    const provider = oaathProvider({ grant, chain: CHAIN_ID });
    const prepared = (await provider.request(
      providerPrepareRequest(account),
    )) as PreparedRpcResponse;
    const signature = await signPreparedDigest(prepared.digest);
    const sent = (await provider.request(providerSendRequest(prepared, signature))) as {
      readonly id: string;
    };

    expect(bundleKeys.length).toBeGreaterThan(0);
    expect(bundleKeys.every((key) => key.account === account)).toBe(true);
    const exactKey = bundleKeys.at(-1);
    if (exactKey === undefined) throw new Error("expected a durable bundle key");
    await expect(durableBundles.get(exactKey)).resolves.toBeDefined();
    await expect(
      durableBundles.get({ ...exactKey, account: FOREIGN_ACCOUNT }),
    ).resolves.toBeUndefined();
    expect(sent.id).toBe(exactKey.id);
    expect(chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("prepares, recreates the full realm, and consumes one exact external signature", async () => {
    const factory = new IDBFactory();
    const first = await indexedDbPreparedRealmStores(factory);
    const clock = createClock();
    const chain = createChainFixture();
    const before = createRealm({ stores: first.stores, clock, chain });
    const firstConnection = await before.oaath.connect();
    const firstGrant = await firstConnection.requestPermission(permissionInput());
    const account = await firstGrant.account(CHAIN_ID);
    const firstProvider = oaathProvider({ grant: firstGrant, chain: CHAIN_ID });

    const prepared = (await firstProvider.request(
      providerPrepareRequest(account),
    )) as PreparedRpcResponse;
    const firstPort = grantProviderPort(firstGrant);
    expect(prepared).toMatchObject({
      version: "1",
      chainId: CHAIN_HEX,
      capabilities: { applicationHint: { optional: true, value: "retained" } },
      context: {
        version: "oaath.prepared-call-context-token/v1",
        id: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
      },
      key: { type: "secp256k1", publicKey: SESSION_PUBLIC_KEY, prehash: false },
      digest: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
    });
    expect(chain.quotes).toBe(1);
    expect(chain.signatures).toHaveLength(0);
    expect(chain.sends).toHaveLength(0);
    await firstConnection.close();
    await expect(
      firstPort.preparedCallContexts.get({
        providerScopeId: firstPort.providerScopeId,
        contextId: prepared.context.id,
      }),
    ).rejects.toMatchObject({ code: "store_closed" });
    first.database.close();

    const second = await indexedDbPreparedRealmStores(factory);
    const after = createRealm({ stores: second.stores, clock, relay: before.relay, chain });
    const secondConnection = await after.oaath.connect();
    const secondGrant = await secondConnection.resume();
    if (secondGrant === null) throw new Error("expected the Grant to resume");
    const secondProvider = oaathProvider({ grant: secondGrant, chain: CHAIN_ID });
    const signature = await signPreparedDigest(prepared.digest);

    const sent = (await secondProvider.request(providerSendRequest(prepared, signature))) as {
      readonly id: string;
    };
    expect(sent.id).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(chain.sends).toHaveLength(1);
    expect(chain.sends[0]?.userOperationHash).toBe(prepared.digest);
    await expect(secondProvider.request(providerSendRequest(prepared, signature))).resolves.toEqual(
      sent,
    );
    expect(chain.sends).toHaveLength(1);
    await expect(
      secondProvider.request({ method: "wallet_getCallsStatus", params: [sent.id] }),
    ).resolves.toMatchObject({ id: sent.id, status: 200 });
    expect(chain.sends).toHaveLength(1);
    await secondConnection.close();
    second.database.close();
  });

  it("keeps an invalid external signature unconsumed and submits nothing", async () => {
    const chain = createChainFixture();
    const realm = createRealm({ chain });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    const provider = oaathProvider({ grant, chain: CHAIN_ID });
    const prepared = (await provider.request(
      providerPrepareRequest(account),
    )) as PreparedRpcResponse;

    await expect(
      provider.request(providerSendRequest(prepared, `0x${"00".repeat(65)}`)),
    ).rejects.toMatchObject({ name: "OaathProviderRpcError", code: -32602 });
    expect(chain.signatures).toHaveLength(0);
    expect(chain.sends).toHaveLength(0);

    const signature = await signPreparedDigest(prepared.digest);
    await expect(provider.request(providerSendRequest(prepared, signature))).resolves.toMatchObject(
      { id: expect.stringMatching(/^0x[0-9a-f]{64}$/u) },
    );
    expect(chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("lets concurrent consumes converge on one bundle and one submission", async () => {
    const chain = createChainFixture();
    const realm = createRealm({ chain });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    const provider = oaathProvider({ grant, chain: CHAIN_ID });
    const prepared = (await provider.request(
      providerPrepareRequest(account),
    )) as PreparedRpcResponse;
    const signature = await signPreparedDigest(prepared.digest);

    const [first, second] = await Promise.all([
      provider.request(providerSendRequest(prepared, signature)),
      provider.request(providerSendRequest(prepared, signature)),
    ]);
    expect(first).toEqual(second);
    expect(chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("terminalizes a stale context without submitting a replacement identity", async () => {
    const chain = createChainFixture();
    const realm = createRealm({ chain });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    const provider = oaathProvider({ grant, chain: CHAIN_ID });
    const prepared = (await provider.request(
      providerPrepareRequest(account),
    )) as PreparedRpcResponse;
    const intervening = await grant.sendCalls({
      chain: CHAIN_ID,
      calls: [{ target: TARGET, value: "0", data: CALL_DATA }],
    });
    expect(intervening.outcome.status).toBe("finalized");
    const signature = await signPreparedDigest(prepared.digest);

    for (let attempt = 0; attempt < 2; attempt += 1) {
      await expect(
        provider.request(providerSendRequest(prepared, signature)),
      ).rejects.toMatchObject({ name: "OaathProviderRpcError", code: -32602 });
      expect(chain.sends).toHaveLength(1);
    }
    await connection.close();
  });

  it("rejects a consumed bundle bound to a contradictory operation pointer", async () => {
    const chain = createChainFixture();
    const stores = createMemoryStores();
    const durableBundles = stores.walletCallBundles;
    let contradict = false;
    const realm = createRealm({
      chain,
      stores: {
        ...stores,
        walletCallBundles: Object.freeze({
          async get(key: Parameters<typeof durableBundles.get>[0]): Promise<unknown> {
            const raw = await durableBundles.get(key);
            if (!contradict || raw === undefined) return raw;
            const envelope = raw as Readonly<{
              value: Readonly<{
                operation: Readonly<{ identity: Readonly<Record<string, unknown>> }> | null;
              }>;
            }>;
            if (envelope.value.operation === null) throw new Error("expected a bound operation");
            return {
              ...envelope,
              value: {
                ...envelope.value,
                operation: {
                  ...envelope.value.operation,
                  identity: {
                    ...envelope.value.operation.identity,
                    requestHash: `0x${"ef".repeat(32)}`,
                  },
                },
              },
            };
          },
          compareAndSwap: (input: Parameters<typeof durableBundles.compareAndSwap>[0]) =>
            durableBundles.compareAndSwap(input),
          close: () => durableBundles.close(),
        }),
      },
    });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    const provider = oaathProvider({ grant, chain: CHAIN_ID });
    const prepared = (await provider.request(
      providerPrepareRequest(account),
    )) as PreparedRpcResponse;
    const signature = await signPreparedDigest(prepared.digest);
    const sent = await provider.request(providerSendRequest(prepared, signature));
    expect(chain.sends).toHaveLength(1);

    contradict = true;
    await expect(provider.request(providerSendRequest(prepared, signature))).rejects.toMatchObject({
      name: "OaathProviderRpcError",
      code: INTERNAL_ERROR,
    });
    expect(sent).toMatchObject({ id: expect.stringMatching(/^0x[0-9a-f]{64}$/u) });
    expect(chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("recovers a send-response ambiguity without reopening submission", async () => {
    let crash = true;
    const chain = createChainFixture({ crashOnSend: () => crash });
    const realm = createRealm({ chain });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    const provider = oaathProvider({ grant, chain: CHAIN_ID });
    const prepared = (await provider.request(
      providerPrepareRequest(account),
    )) as PreparedRpcResponse;
    const signature = await signPreparedDigest(prepared.digest);

    const ambiguous = await provider.request(providerSendRequest(prepared, signature));
    expect(chain.sends).toHaveLength(1);
    crash = false;
    await expect(provider.request(providerSendRequest(prepared, signature))).resolves.toEqual(
      ambiguous,
    );
    expect(chain.sends).toHaveLength(1);
    await connection.close();
  });
});
