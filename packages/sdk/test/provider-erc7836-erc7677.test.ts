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
import { encodeKernelV4Execution } from "../src/kernel.js";
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
const SPONSOR = Object.freeze({
  name: "Prepared Sponsor",
  icon: "data:image/png;base64,AQ==",
});
const RESULT_CAPABILITIES = Object.freeze({
  paymasterService: Object.freeze({ sponsor: SPONSOR }),
});

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
  validityTimeRange?: Readonly<Record<string, unknown>>,
) {
  return {
    method: "wallet_prepareCalls",
    params: [
      {
        version: "1",
        from: account,
        chainId: CHAIN_HEX,
        calls: [{ to: TARGET, data: CALL_DATA }],
        capabilities: {
          paymasterService,
          ...(validityTimeRange === undefined ? {} : { validityTimeRange }),
        },
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

function registeredService(
  options: Readonly<{
    malformedEstimate?: boolean;
    sponsor?: Readonly<{ name: string; icon?: string }>;
  }> = {},
): Readonly<{
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
          ...(options.sponsor === undefined ? {} : { sponsor: options.sponsor }),
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
    const registered = registeredService({ sponsor: SPONSOR });
    const firstChain = replaceChain(base, { paymasterService: registered.service });
    const before = createRealm({ stores: firstStores.stores, clock, chain: firstChain });
    const firstConnection = await before.oaath.connect();
    const firstGrant = await firstConnection.requestPermission(permissionInput());
    const account = await firstGrant.account(CHAIN_ID);
    const validAfter = clock.now() + 10;
    const validUntil = validAfter + 90;
    const validityTimeRange = {
      validAfter: `0x${validAfter.toString(16)}`,
      validUntil: `0x${validUntil.toString(16)}`,
    };
    let confirmations = 0;
    const firstProvider = oaathProvider({
      grant: firstGrant,
      chain: CHAIN_ID,
      confirmCalls: async () => {
        confirmations += 1;
        return "approved" as const;
      },
    });

    const prepared = (await firstProvider.request(
      prepareRequest(
        account,
        {
          url: SERVICE_URL,
          context: { policyId: "prepared" },
        },
        validityTimeRange,
      ),
    )) as PreparedRpcResponse;
    expect(prepared.capabilities).toEqual({
      paymasterService: { url: SERVICE_URL, context: { policyId: "prepared" } },
      validityTimeRange,
    });
    expect(confirmations).toBe(1);
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
    expect(retained?.value.validityTimeRange).toEqual({
      validAfter: String(validAfter),
      validUntil: String(validUntil),
    });
    expect(retained?.value.resultCapabilities).toEqual(RESULT_CAPABILITIES);
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
    const secondProvider = oaathProvider({
      grant: secondGrant,
      chain: CHAIN_ID,
      confirmCalls: async () => {
        confirmations += 1;
        throw new Error("send must not present again");
      },
    });
    const signature = await signPreparedDigest(prepared.digest);

    const sent = await secondProvider.request(sendRequest(prepared, signature));
    expect(sent).toEqual({
      id: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
      capabilities: RESULT_CAPABILITIES,
    });
    expect(base.quotes).toBe(2);
    expect(base.sends).toHaveLength(1);
    expect(base.sends[0]?.userOperationHash).toBe(prepared.digest);
    expect(base.sends[0]?.userOperation.callData).toBe(
      encodeKernelV4Execution({
        calls: [{ target: TARGET, value: "0", data: CALL_DATA }],
        validityTimeRange: {
          validAfter: String(validAfter),
          validUntil: String(validUntil),
        },
      }),
    );
    expect(base.sends[0]?.userOperation.paymaster).toEqual(
      retained?.value.prepared.userOperation.paymaster,
    );
    await expect(secondProvider.request(sendRequest(prepared, signature))).resolves.toEqual(sent);
    expect(base.quotes).toBe(2);
    expect(base.sends).toHaveLength(1);
    expect(base.signatures).toHaveLength(1);
    expect(confirmations).toBe(1);
    expect(registered.stages).toEqual(["stub", "estimate", "final"]);
    await secondConnection.close();
    secondStores.database.close();

    const effectsAfterSend = Object.freeze({
      quotes: base.quotes,
      signatures: base.signatures.length,
      sends: base.sends.length,
    });
    const thirdStores = await indexedDbStores(factory);
    const recreated = createRealm({
      stores: thirdStores.stores,
      clock,
      relay: before.relay,
      chain: replaceChain(base, { paymasterService: poisonService }),
    });
    const thirdConnection = await recreated.oaath.connect();
    const thirdGrant = await thirdConnection.resume();
    if (thirdGrant === null) throw new Error("expected the sent Grant to resume");
    const presented: unknown[] = [];
    const thirdProvider = oaathProvider({
      grant: thirdGrant,
      chain: CHAIN_ID,
      confirmCalls: async () => {
        confirmations += 1;
        throw new Error("status must not present again");
      },
      showCallsStatus(status) {
        presented.push(status);
      },
    });
    const sentId = (sent as Readonly<{ id: string }>).id;
    const status = await thirdProvider.request({
      method: "wallet_getCallsStatus",
      params: [sentId],
    });
    expect(status).toMatchObject({
      id: sentId,
      status: 200,
      capabilities: RESULT_CAPABILITIES,
    });
    await expect(
      thirdProvider.request({ method: "wallet_showCallsStatus", params: [sentId] }),
    ).resolves.toBeUndefined();
    expect(presented).toEqual([status]);
    expect({
      quotes: base.quotes,
      signatures: base.signatures.length,
      sends: base.sends.length,
    }).toEqual(effectsAfterSend);
    expect(confirmations).toBe(1);
    expect(registered.stages).toEqual(["stub", "estimate", "final"]);
    await thirdConnection.close();
    thirdStores.database.close();
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

  it("ignores optional sponsorship on a direct prepared-call route", async () => {
    let probes = 0;
    const registered = registeredService();
    const base = createChainFixture({
      bundler: "absent",
      feePayer: {
        address: `0x${"77".repeat(20)}`,
        balance: "1000000000000000000",
      },
    });
    const chain = replaceChain(base, {
      bundler: Object.freeze({
        async probe(request: Parameters<OaathChainCapability["bundler"]["probe"]>[0]) {
          probes += 1;
          return base.capability.bundler.probe(request);
        },
      }),
      paymasterService: registered.service,
    });
    const realm = createRealm({ chain });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    const provider = oaathProvider({ grant, chain: CHAIN_ID });

    const prepared = (await provider.request(
      prepareRequest(account, {
        url: SERVICE_URL,
        context: {},
        optional: true,
      }),
    )) as PreparedRpcResponse;
    const port = grantProviderPort(grant);
    const retained = await port.preparedCallContexts.get({
      providerScopeId: port.providerScopeId as `0x${string}`,
      contextId: prepared.context.id,
    });
    expect(retained?.value.prepared.userOperation.paymaster).toBeNull();
    expect(retained?.value.resultCapabilities).toBeNull();
    expect(registered.stages).toEqual([]);
    expect(base.quotes).toBe(1);
    expect(probes).toBe(1);

    const signature = await signPreparedDigest(prepared.digest);
    await expect(provider.request(sendRequest(prepared, signature))).resolves.toEqual({
      id: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
    });
    expect(probes).toBe(2);
    expect(base.sends).toHaveLength(1);
    expect(base.sends[0]?.userOperation.paymaster).toBeNull();
    await connection.close();
  });

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
    expect(retained?.value.resultCapabilities).toBeNull();
    expect(registered.stages).toEqual([]);
    expect(base.quotes).toBe(1);
    expect(base.signatures).toHaveLength(0);
    expect(base.sends).toHaveLength(0);
    const signature = await signPreparedDigest(prepared.digest);
    const sent = await provider.request(sendRequest(prepared, signature));
    expect(sent).toEqual({ id: expect.stringMatching(/^0x[0-9a-f]{64}$/u) });
    const sentId = (sent as Readonly<{ id: string }>).id;
    const bundle = await port.walletCallBundles.get({
      providerScopeId: port.providerScopeId as `0x${string}`,
      account,
      id: sentId,
    });
    expect(bundle?.value.operation?.resultCapabilities).toBeNull();
    await connection.close();
  });
});
