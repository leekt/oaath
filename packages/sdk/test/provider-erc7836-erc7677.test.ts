/**
 * ERC-7677 sponsorship through the durable ERC-7836 prepared-call lifecycle.
 *
 * @author taek <leekt216@gmail.com>
 */
import { IDBFactory } from "fake-indexeddb";
import { describe, expect, it } from "vitest";
import type {
  Erc7677GasEstimationRequest,
  Erc7677PaymasterServiceRequest,
  OaathChainCapability,
  OaathRegisteredPaymasterService,
} from "../src/advanced.js";
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
import { oaathProvider } from "../src/viem.js";
import {
  CALL_DATA,
  CHAIN_ID,
  type ChainFixture,
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
const SERVICE_URL = `https://issuer.example/chains/${CHAIN_ID}/paymaster`;
const FOREIGN_URL = "https://attacker.example/paymaster";
const PAYMASTER = `0x${"33".repeat(20)}` as const;

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

function prepareRequest(
  account: `0x${string}`,
  paymasterService: Readonly<Record<string, unknown>>,
) {
  return {
    method: "wallet_prepareCalls",
    params: [
      {
        version: "1",
        from: account,
        chainId: CHAIN_HEX,
        calls: [{ to: TARGET, data: CALL_DATA }],
        capabilities: { paymasterService },
        key: {
          type: "secp256k1",
          publicKey: SESSION_PUBLIC_KEY,
          prehash: false,
        },
      },
    ],
  } as const;
}

function sendRequest(prepared: Readonly<PreparedRpcResponse>, signature: `0x${string}`) {
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

function replaceChain(base: ChainFixture, overrides: Partial<OaathChainCapability>): ChainFixture {
  const capability = Object.freeze({ ...base.capability, ...overrides });
  return Object.freeze({
    capability,
    sends: base.sends,
    signatures: base.signatures,
    get quotes() {
      return base.quotes;
    },
  });
}

function registeredService(options: Readonly<{ malformedEstimate?: boolean }> = {}): Readonly<{
  service: Readonly<OaathRegisteredPaymasterService>;
  stages: readonly string[];
  serviceRequests: readonly Readonly<Erc7677PaymasterServiceRequest>[];
  estimatorRequests: readonly Readonly<Erc7677GasEstimationRequest>[];
}> {
  const stages: string[] = [];
  const serviceRequests: Readonly<Erc7677PaymasterServiceRequest>[] = [];
  const estimatorRequests: Readonly<Erc7677GasEstimationRequest>[] = [];
  const service: Readonly<OaathRegisteredPaymasterService> = Object.freeze({
    url: SERVICE_URL,
    async request(request: Readonly<Erc7677PaymasterServiceRequest>) {
      serviceRequests.push(request);
      stages.push(request.method === "pm_getPaymasterStubData" ? "stub" : "final");
      if (request.method === "pm_getPaymasterStubData") {
        return {
          paymaster: PAYMASTER,
          paymasterData: "0x01020304",
          paymasterPostOpGasLimit: "0x3c",
        };
      }
      return { paymaster: PAYMASTER, paymasterData: "0x01020305" };
    },
    async estimate(request: Readonly<Erc7677GasEstimationRequest>) {
      estimatorRequests.push(request);
      stages.push("estimate");
      if (options.malformedEstimate) return { callGasLimit: "not-a-quantity" };
      return {
        callGasLimit: "100",
        verificationGasLimit: "200",
        preVerificationGas: "30",
        paymasterVerificationGasLimit: "50",
      };
    },
  });
  return Object.freeze({ service, stages, serviceRequests, estimatorRequests });
}

async function indexedDbStores(factory: IDBFactory) {
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

function countPreparedContextWrites(stores: ReturnType<typeof createMemoryStores>) {
  const durable = stores.preparedCallContexts;
  let writes = 0;
  return {
    stores: {
      ...stores,
      preparedCallContexts: Object.freeze({
        get: (key: Parameters<typeof durable.get>[0]) => durable.get(key),
        compareAndSwap: (input: Parameters<typeof durable.compareAndSwap>[0]) => {
          writes += 1;
          return durable.compareAndSwap(input);
        },
        close: () => durable.close(),
      }),
    },
    get writes() {
      return writes;
    },
  };
}

describe("wallet prepared-call ERC-7677 sponsorship", () => {
  it("persists one final sponsored identity and never resolves sponsorship after reload", async () => {
    const factory = new IDBFactory();
    const firstStores = await indexedDbStores(factory);
    const clock = createClock();
    const base = createChainFixture();
    const registered = registeredService();
    const firstChain = replaceChain(base, { paymasterService: registered.service });
    const before = createRealm({ stores: firstStores.stores, clock, chain: firstChain });
    const firstConnection = await before.oaath.connect();
    const firstGrant = await firstConnection.requestPermission(permissionInput());
    const account = await firstGrant.account(CHAIN_ID);
    const firstProvider = oaathProvider({ grant: firstGrant, chain: CHAIN_ID });

    const prepared = (await firstProvider.request(
      prepareRequest(account, {
        url: SERVICE_URL,
        context: { policyId: "prepared" },
      }),
    )) as PreparedRpcResponse;
    expect(prepared.capabilities).toEqual({
      paymasterService: { url: SERVICE_URL, context: { policyId: "prepared" } },
    });
    expect(registered.stages).toEqual(["stub", "estimate", "final"]);
    expect(registered.serviceRequests).toHaveLength(2);
    expect(registered.estimatorRequests).toHaveLength(1);
    expect(base.quotes).toBe(1);
    expect(base.signatures).toHaveLength(0);
    expect(base.sends).toHaveLength(0);

    const firstPort = grantProviderPort(firstGrant);
    const retained = await firstPort.preparedCallContexts.get({
      providerScopeId: firstPort.providerScopeId as `0x${string}`,
      contextId: prepared.context.id,
    });
    expect(retained?.value.digest).toBe(prepared.digest);
    expect(retained?.value.prepared.userOperation.paymaster).toEqual({
      address: PAYMASTER,
      verificationGasLimit: "50",
      postOpGasLimit: "60",
      data: "0x01020305",
    });

    const changedEcho: PreparedRpcResponse = {
      ...prepared,
      capabilities: {
        paymasterService: { url: SERVICE_URL, context: { policyId: "changed" } },
      },
    };
    await expect(firstProvider.request(sendRequest(changedEcho, "0x01"))).rejects.toMatchObject({
      name: "OaathProviderRpcError",
      code: -32602,
    });
    expect(registered.stages).toEqual(["stub", "estimate", "final"]);
    expect(base.quotes).toBe(1);
    expect(base.sends).toHaveLength(0);

    await firstConnection.close();
    firstStores.database.close();

    const poisonService: Readonly<OaathRegisteredPaymasterService> = Object.freeze({
      url: SERVICE_URL,
      async request() {
        throw new Error("send must not call the paymaster service");
      },
      async estimate() {
        throw new Error("send must not call the paymaster estimator");
      },
    });
    const secondStores = await indexedDbStores(factory);
    const after = createRealm({
      stores: secondStores.stores,
      clock,
      relay: before.relay,
      chain: replaceChain(base, { paymasterService: poisonService }),
    });
    const secondConnection = await after.oaath.connect();
    const secondGrant = await secondConnection.resume();
    if (secondGrant === null) throw new Error("expected the Grant to resume");
    const secondProvider = oaathProvider({ grant: secondGrant, chain: CHAIN_ID });
    const signature = await signPreparedDigest(prepared.digest);

    const sent = await secondProvider.request(sendRequest(prepared, signature));
    expect(base.quotes).toBe(2);
    expect(base.sends).toHaveLength(1);
    expect(base.sends[0]?.userOperationHash).toBe(prepared.digest);
    expect(base.sends[0]?.userOperation.paymaster).toEqual(
      retained?.value.prepared.userOperation.paymaster,
    );
    await expect(secondProvider.request(sendRequest(prepared, signature))).resolves.toEqual(sent);
    expect(base.quotes).toBe(2);
    expect(base.sends).toHaveLength(1);
    expect(registered.stages).toEqual(["stub", "estimate", "final"]);
    await secondConnection.close();
    secondStores.database.close();
  });

  it.each(["foreign service", "direct route"] as const)(
    "rejects %s before quote, sponsorship, context, signing, or submission",
    async (failure) => {
      const registered = registeredService();
      const base = createChainFixture(
        failure === "direct route"
          ? {
              bundler: "absent",
              feePayer: {
                address: `0x${"77".repeat(20)}`,
                balance: "1000000000000000000",
              },
            }
          : {},
      );
      const chain = replaceChain(base, { paymasterService: registered.service });
      const counted = countPreparedContextWrites(createMemoryStores());
      const realm = createRealm({ chain, stores: counted.stores });
      const connection = await realm.oaath.connect();
      const grant = await connection.requestPermission(permissionInput());
      const account = await grant.account(CHAIN_ID);
      const provider = oaathProvider({ grant, chain: CHAIN_ID });

      await expect(
        provider.request(
          prepareRequest(account, {
            url: failure === "foreign service" ? FOREIGN_URL : SERVICE_URL,
            context: {},
          }),
        ),
      ).rejects.toMatchObject({ name: "OaathProviderRpcError", code: 5700 });
      expect(counted.writes).toBe(0);
      expect(registered.stages).toEqual([]);
      expect(base.quotes).toBe(0);
      expect(base.signatures).toHaveLength(0);
      expect(base.sends).toHaveLength(0);
      await connection.close();
    },
  );

  it("does not fall back unsponsored after an optional selected service fails", async () => {
    const registered = registeredService({ malformedEstimate: true });
    const base = createChainFixture();
    const chain = replaceChain(base, { paymasterService: registered.service });
    const counted = countPreparedContextWrites(createMemoryStores());
    const realm = createRealm({ chain, stores: counted.stores });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    const provider = oaathProvider({ grant, chain: CHAIN_ID });

    await expect(
      provider.request(
        prepareRequest(account, {
          url: SERVICE_URL,
          context: { policyId: "selected" },
          optional: true,
        }),
      ),
    ).rejects.toMatchObject({ name: "OaathProviderRpcError", code: -32603 });
    expect(registered.stages).toEqual(["stub", "estimate"]);
    expect(base.quotes).toBe(1);
    expect(counted.writes).toBe(0);
    expect(base.signatures).toHaveLength(0);
    expect(base.sends).toHaveLength(0);
    await connection.close();
  });

  it("uses an explicitly optional unavailable service only as an unsponsored request", async () => {
    const registered = registeredService();
    const base = createChainFixture();
    const chain = replaceChain(base, { paymasterService: registered.service });
    const realm = createRealm({ chain });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    const provider = oaathProvider({ grant, chain: CHAIN_ID });

    const prepared = (await provider.request(
      prepareRequest(account, { url: FOREIGN_URL, context: {}, optional: true }),
    )) as PreparedRpcResponse;
    const port = grantProviderPort(grant);
    const retained = await port.preparedCallContexts.get({
      providerScopeId: port.providerScopeId as `0x${string}`,
      contextId: prepared.context.id,
    });
    expect(retained?.value.prepared.userOperation.paymaster).toBeNull();
    expect(registered.stages).toEqual([]);
    expect(base.quotes).toBe(1);
    expect(base.signatures).toHaveLength(0);
    expect(base.sends).toHaveLength(0);
    await connection.close();
  });
});
