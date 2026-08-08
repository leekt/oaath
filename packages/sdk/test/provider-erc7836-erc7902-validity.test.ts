/**
 * Draft ERC-7902 validity through the durable experimental ERC-7836 path.
 *
 * @author taek <leekt216@gmail.com>
 */
import { IDBFactory } from "fake-indexeddb";
import { describe, expect, it } from "vitest";
import type { OaathChainCapability } from "../src/advanced.js";
import {
  grantProviderPort,
  type OaathProviderValidityAdmission,
} from "../src/client/grant-handle.js";
import { encodeKernelV4Execution, OAATH_KERNEL_V4_VALIDITY_POLICY } from "../src/kernel.js";
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
import {
  OAATH_PROVIDER_ERROR_MESSAGES,
  type OaathProviderErrorCode,
} from "../src/provider/errors.js";
import { OAATH_PREPARED_CALL_CONTEXT_VERSION } from "../src/provider/prepared-call-store.js";
import { type OaathProviderInput, oaathProvider } from "../src/viem.js";
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
const WRONG_RUNTIME_HASH = `0x${"00".repeat(32)}` as const;

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

function quantity(value: number | bigint): `0x${string}` {
  return `0x${BigInt(value).toString(16)}`;
}

function validity(
  validAfter: number | bigint,
  validUntil: number | bigint,
  optional = false,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    validAfter: quantity(validAfter),
    validUntil: quantity(validUntil),
    ...(optional ? { optional: true } : {}),
  });
}

function prepareRequest(
  account: `0x${string}`,
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
        ...(validityTimeRange === undefined ? {} : { capabilities: { validityTimeRange } }),
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

function mutablePolicyReads(base: ChainFixture) {
  let observedHash: `0x${string}` | null = null;
  let reads = 0;
  return {
    chain: replaceChain(base, {
      reads: Object.freeze({
        async read(request: Parameters<OaathChainCapability["reads"]["read"]>[0]) {
          if (
            request.type === "runtime_code_hash" &&
            request.address === OAATH_KERNEL_V4_VALIDITY_POLICY
          ) {
            reads += 1;
            if (observedHash !== null) return observedHash;
          }
          return base.capability.reads.read(request);
        },
      }),
    }),
    setHash(value: `0x${string}` | null) {
      observedHash = value;
    },
    get reads() {
      return reads;
    },
  };
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

async function providerError(
  promise: Promise<unknown>,
  code: OaathProviderErrorCode,
): Promise<void> {
  await expect(promise).rejects.toMatchObject({
    name: "OaathProviderRpcError",
    code,
    message: OAATH_PROVIDER_ERROR_MESSAGES[code],
  });
}

function expectDeepFrozen(value: unknown, seen: WeakSet<object> = new WeakSet()): void {
  if (value === null || typeof value !== "object" || seen.has(value)) return;
  seen.add(value);
  expect(Object.isFrozen(value)).toBe(true);
  for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
    if ("value" in descriptor) expectDeepFrozen(descriptor.value, seen);
  }
}

describe("wallet prepared-call ERC-7902 validity", () => {
  it.each([
    ["missing confirmer", 5700],
    ["outside ceiling", 5700],
    ["unavailable policy", 5700],
    ["rejected", 4001],
    ["confirmer throw", -32603],
    ["invalid decision", -32603],
  ] as const)("rejects %s before quote or context mutation", async (failure, code) => {
    const clock = createClock();
    const base = createChainFixture();
    const policy = mutablePolicyReads(base);
    if (failure === "unavailable policy") policy.setHash(WRONG_RUNTIME_HASH);
    const stores = createMemoryStores();
    const durableContexts = stores.preparedCallContexts;
    let contextWrites = 0;
    const realm = createRealm({
      clock,
      chain: policy.chain,
      stores: {
        ...stores,
        preparedCallContexts: Object.freeze({
          get: (key: Parameters<typeof durableContexts.get>[0]) => durableContexts.get(key),
          compareAndSwap: (input: Parameters<typeof durableContexts.compareAndSwap>[0]) => {
            contextWrites += 1;
            return durableContexts.compareAndSwap(input);
          },
          close: () => durableContexts.close(),
        }),
      },
    });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    let confirmations = 0;
    const confirmCalls: OaathProviderInput["confirmCalls"] =
      failure === "missing confirmer"
        ? undefined
        : async () => {
            confirmations += 1;
            if (failure === "confirmer throw") throw new Error("unavailable UI");
            if (failure === "invalid decision") return "invalid" as "approved";
            return failure === "rejected" ? ("rejected" as const) : ("approved" as const);
          };
    const provider = oaathProvider({
      grant,
      chain: CHAIN_ID,
      ...(confirmCalls === undefined ? {} : { confirmCalls }),
    });
    const now = clock.now();
    const range =
      failure === "outside ceiling" ? validity(now - 1, now + 90) : validity(now + 10, now + 90);

    await providerError(provider.request(prepareRequest(account, range)), code);
    expect(contextWrites).toBe(0);
    expect(base.quotes).toBe(0);
    expect(base.signatures).toHaveLength(0);
    expect(base.sends).toHaveLength(0);
    expect(confirmations).toBe(
      failure === "rejected" || failure === "confirmer throw" || failure === "invalid decision"
        ? 1
        : 0,
    );
    await connection.close();
  });

  it("rejects an unrenderable in-ceiling endpoint before presentation or effects", async () => {
    const clock = createClock(8_640_000_000_000);
    const base = createChainFixture();
    const stores = createMemoryStores();
    const durableContexts = stores.preparedCallContexts;
    let contextWrites = 0;
    const realm = createRealm({
      clock,
      chain: base,
      stores: {
        ...stores,
        preparedCallContexts: Object.freeze({
          get: (key: Parameters<typeof durableContexts.get>[0]) => durableContexts.get(key),
          compareAndSwap: (input: Parameters<typeof durableContexts.compareAndSwap>[0]) => {
            contextWrites += 1;
            return durableContexts.compareAndSwap(input);
          },
          close: () => durableContexts.close(),
        }),
      },
    });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    let presentations = 0;
    const provider = oaathProvider({
      grant,
      chain: CHAIN_ID,
      confirmCalls: async () => {
        presentations += 1;
        return "approved" as const;
      },
    });

    await providerError(
      provider.request(prepareRequest(account, validity(clock.now(), clock.now() + 100))),
      5700,
    );
    expect(presentations).toBe(0);
    expect(contextWrites).toBe(0);
    expect(base.quotes).toBe(0);
    expect(base.signatures).toHaveLength(0);
    expect(base.sends).toHaveLength(0);
    await connection.close();
  });

  it("leaves optional unsupported and omitted validity unprompted in default mode", async () => {
    const clock = createClock();
    const base = createChainFixture();
    const realm = createRealm({ clock, chain: base });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    let confirmations = 0;
    const providerWithUi = oaathProvider({
      grant,
      chain: CHAIN_ID,
      confirmCalls: async () => {
        confirmations += 1;
        return "approved" as const;
      },
    });
    const omitted = (await providerWithUi.request(prepareRequest(account))) as PreparedRpcResponse;
    expect(confirmations).toBe(0);

    const port = grantProviderPort(grant);
    const omittedRecord = await port.preparedCallContexts.get({
      providerScopeId: port.providerScopeId as `0x${string}`,
      contextId: omitted.context.id,
    });
    expect(omittedRecord?.value.validityTimeRange).toBeNull();
    expect(omittedRecord?.value.prepared.userOperation.callData).toBe(
      encodeKernelV4Execution({ calls: [{ target: TARGET, value: "0", data: CALL_DATA }] }),
    );

    const providerWithoutUi = oaathProvider({ grant, chain: CHAIN_ID });
    const after = clock.now() + 10;
    const optional = (await providerWithoutUi.request(
      prepareRequest(account, validity(after, after + 90, true)),
    )) as PreparedRpcResponse;
    const optionalRecord = await port.preparedCallContexts.get({
      providerScopeId: port.providerScopeId as `0x${string}`,
      contextId: optional.context.id,
    });
    expect(optionalRecord?.value.validityTimeRange).toBeNull();
    expect(optionalRecord?.value.prepared.userOperation.callData).toBe(
      encodeKernelV4Execution({ calls: [{ target: TARGET, value: "0", data: CALL_DATA }] }),
    );
    expect(confirmations).toBe(0);
    await connection.close();
  });

  it("confirms once, persists exact ranged callData, and reloads before one send", async () => {
    const factory = new IDBFactory();
    const clock = createClock();
    const base = createChainFixture();
    const policy = mutablePolicyReads(base);
    const firstStores = await indexedDbStores(factory);
    const before = createRealm({ stores: firstStores.stores, clock, chain: policy.chain });
    const firstConnection = await before.oaath.connect();
    const firstGrant = await firstConnection.requestPermission(permissionInput());
    const account = await firstGrant.account(CHAIN_ID);
    const after = clock.now() + 10;
    const until = after + 90;
    let confirmations = 0;
    let presented: unknown;
    const firstProvider = oaathProvider({
      grant: firstGrant,
      chain: CHAIN_ID,
      confirmCalls: async (confirmation) => {
        confirmations += 1;
        presented = confirmation;
        return "approved" as const;
      },
    });

    const prepared = (await firstProvider.request(
      prepareRequest(account, validity(after, until)),
    )) as PreparedRpcResponse;
    expect(presented).toEqual({
      account,
      chainId: CHAIN_HEX,
      calls: [{ target: TARGET, value: "0", data: CALL_DATA }],
      validityTimeRange: {
        validAfter: String(after),
        validUntil: String(until),
        validAfterUtc: new Date(after * 1_000).toISOString(),
        validUntilUtc: new Date(until * 1_000).toISOString(),
        inclusive: true,
      },
    });
    expectDeepFrozen(presented);
    expect(confirmations).toBe(1);
    expect(policy.reads).toBe(1);
    expect(base.quotes).toBe(1);
    expect(base.sends).toHaveLength(0);

    const expectedCallData = encodeKernelV4Execution({
      calls: [{ target: TARGET, value: "0", data: CALL_DATA }],
      validityTimeRange: { validAfter: String(after), validUntil: String(until) },
    });
    const firstPort = grantProviderPort(firstGrant);
    const retained = await firstPort.preparedCallContexts.get({
      providerScopeId: firstPort.providerScopeId as `0x${string}`,
      contextId: prepared.context.id,
    });
    expect(retained?.value).toMatchObject({
      version: OAATH_PREPARED_CALL_CONTEXT_VERSION,
      expiresAt: until + 1,
      validityTimeRange: { validAfter: String(after), validUntil: String(until) },
      digest: prepared.digest,
    });
    expect(retained?.value.prepared.userOperation.callData).toBe(expectedCallData);
    await firstConnection.close();
    firstStores.database.close();

    const secondStores = await indexedDbStores(factory);
    const afterReload = createRealm({
      stores: secondStores.stores,
      clock,
      relay: before.relay,
      chain: policy.chain,
    });
    const secondConnection = await afterReload.oaath.connect();
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
    expect(sent).toMatchObject({ id: expect.stringMatching(/^0x[0-9a-f]{64}$/u) });
    expect(confirmations).toBe(1);
    expect(policy.reads).toBe(2);
    expect(base.quotes).toBe(2);
    expect(base.sends).toHaveLength(1);
    expect(base.sends[0]?.userOperationHash).toBe(prepared.digest);
    expect(base.sends[0]?.userOperation.callData).toBe(expectedCallData);
    await expect(secondProvider.request(sendRequest(prepared, signature))).resolves.toEqual(sent);
    expect(confirmations).toBe(1);
    expect(policy.reads).toBe(2);
    expect(base.quotes).toBe(2);
    expect(base.sends).toHaveLength(1);
    await secondConnection.close();
    secondStores.database.close();
  });

  it("marks changed policy evidence stale before re-quote or submission", async () => {
    const clock = createClock();
    const base = createChainFixture();
    const policy = mutablePolicyReads(base);
    const realm = createRealm({ clock, chain: policy.chain });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    const after = clock.now() + 10;
    const provider = oaathProvider({
      grant,
      chain: CHAIN_ID,
      confirmCalls: async () => "approved" as const,
    });
    const prepared = (await provider.request(
      prepareRequest(account, validity(after, after + 90)),
    )) as PreparedRpcResponse;
    const signature = await signPreparedDigest(prepared.digest);
    policy.setHash(WRONG_RUNTIME_HASH);

    await providerError(provider.request(sendRequest(prepared, signature)), -32602);
    expect(base.quotes).toBe(1);
    expect(base.sends).toHaveLength(0);
    const port = grantProviderPort(grant);
    await expect(
      port.preparedCallContexts.get({
        providerScopeId: port.providerScopeId as `0x${string}`,
        contextId: prepared.context.id,
      }),
    ).resolves.toMatchObject({ value: { state: "invalidated_as_stale" } });
    await connection.close();
  });

  it("expires at requestedUntil + 1 and never validates or submits afterward", async () => {
    const clock = createClock();
    const base = createChainFixture();
    const policy = mutablePolicyReads(base);
    const realm = createRealm({ clock, chain: policy.chain });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    const after = clock.now() + 1;
    const until = after + 20;
    const provider = oaathProvider({
      grant,
      chain: CHAIN_ID,
      confirmCalls: async () => "approved" as const,
    });
    const prepared = (await provider.request(
      prepareRequest(account, validity(after, until)),
    )) as PreparedRpcResponse;
    const signature = await signPreparedDigest(prepared.digest);
    clock.advance(until + 1 - clock.now());

    await providerError(provider.request(sendRequest(prepared, signature)), -32602);
    expect(policy.reads).toBe(1);
    expect(base.quotes).toBe(1);
    expect(base.sends).toHaveLength(0);
    await connection.close();
  });

  it("invalidates a retained range that no longer matches its exact prepared hash", async () => {
    const clock = createClock();
    const base = createChainFixture();
    const stores = createMemoryStores();
    const durable = stores.preparedCallContexts;
    let mutate = false;
    const preparedCallContexts: typeof durable = Object.freeze({
      async get(key: Parameters<typeof durable.get>[0]): Promise<unknown> {
        const raw = await durable.get(key);
        if (!mutate || raw === undefined) return raw;
        const envelope = raw as Readonly<{
          value: Readonly<{
            state: string;
            validityTimeRange: Readonly<{ validAfter: string; validUntil: string }> | null;
          }>;
        }>;
        if (envelope.value.state !== "prepared" || envelope.value.validityTimeRange === null) {
          return raw;
        }
        return {
          ...envelope,
          value: {
            ...envelope.value,
            validityTimeRange: {
              ...envelope.value.validityTimeRange,
              validAfter: String(BigInt(envelope.value.validityTimeRange.validAfter) + 1n),
            },
          },
        };
      },
      compareAndSwap: (input: Parameters<typeof durable.compareAndSwap>[0]) =>
        durable.compareAndSwap(input),
      close: () => durable.close(),
    });
    const realm = createRealm({
      clock,
      chain: base,
      stores: { ...stores, preparedCallContexts },
    });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    const after = clock.now() + 10;
    const provider = oaathProvider({
      grant,
      chain: CHAIN_ID,
      confirmCalls: async () => "approved" as const,
    });
    const prepared = (await provider.request(
      prepareRequest(account, validity(after, after + 90)),
    )) as PreparedRpcResponse;
    mutate = true;
    const signature = await signPreparedDigest(prepared.digest);

    await providerError(provider.request(sendRequest(prepared, signature)), -32602);
    expect(base.quotes).toBe(2);
    expect(base.sends).toHaveLength(0);
    await connection.close();
  });

  it("rejects forged, consumed, and cross-chain admissions before another quote", async () => {
    const clock = createClock();
    const base = createChainFixture();
    const realm = createRealm({ clock, chain: base });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const port = grantProviderPort(grant);
    const after = clock.now() + 10;
    const range = { validAfter: String(after), validUntil: String(after + 90) };
    const input = (
      validityAdmission: Readonly<OaathProviderValidityAdmission>,
      chain = CHAIN_ID,
    ) => ({
      chain,
      calls: [{ target: TARGET, value: "0", data: CALL_DATA }],
      key: { type: "secp256k1" as const, publicKey: SESSION_PUBLIC_KEY, prehash: false as const },
      paymaster: null,
      validityAdmission,
    });

    await expect(
      port.prepareCalls(
        input({
          kind: "oaath_provider_validity_admission",
        } as Readonly<OaathProviderValidityAdmission>),
      ),
    ).rejects.toMatchObject({ code: "oaath_client_capability_invalid" });
    expect(base.quotes).toBe(0);

    const admitted = await port.admitValidityTimeRange({ chain: CHAIN_ID, range });
    if (admitted.status !== "accepted") throw new Error("expected validity admission");
    await port.prepareCalls(input(admitted.admission));
    await expect(port.prepareCalls(input(admitted.admission))).rejects.toMatchObject({
      code: "oaath_client_capability_invalid",
    });
    expect(base.quotes).toBe(1);

    const crossChain = await port.admitValidityTimeRange({ chain: CHAIN_ID, range });
    if (crossChain.status !== "accepted") throw new Error("expected validity admission");
    await expect(
      port.prepareCalls(input(crossChain.admission, CHAIN_ID + 1)),
    ).rejects.toMatchObject({
      code: "oaath_client_capability_invalid",
    });
    expect(base.quotes).toBe(1);
    expect(base.sends).toHaveLength(0);
    await connection.close();
  });
});
