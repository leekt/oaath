/**
 * Durable experimental ERC-7836 orchestration through the public provider.
 *
 * @author taek <leekt216@gmail.com>
 */
import { p256 } from "@noble/curves/nist.js";
import {
  OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
  OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
} from "@oaath/protocol";
import { IDBFactory } from "fake-indexeddb";
import { bytesToHex, concat, hexToBytes, keccak256, sha256, stringToBytes, toHex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";
import { OperationStore } from "../src/advanced.js";
import { grantProviderPort } from "../src/client/grant-handle.js";
import { ecdsaKey, type WebAuthnAssertionRequest, webauthnKey } from "../src/kernel.js";
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
  bindingInput,
  CALL_DATA,
  CHAIN_ID,
  createChainFixture,
  createClock,
  createMemoryStores,
  createRealm,
  createRelay,
  createUrlRealm,
  ORIGIN,
  permissionInput,
  SESSION_PUBLIC_KEY,
  signingProfiles,
  signPreparedDigest,
  TARGET,
  VALIDATOR,
} from "./support/browser.js";

const CHAIN_HEX = `0x${CHAIN_ID.toString(16)}` as const;
const FOREIGN_ACCOUNT = `0x${"99".repeat(20)}` as const;

interface PreparedRpcResponse {
  readonly version: "1";
  readonly chainId: `0x${string}`;
  readonly capabilities: Readonly<Record<string, unknown>>;
  readonly context: Readonly<{ version: string; id: `0x${string}` }>;
  readonly key: Readonly<{
    type: "secp256k1" | "webauthn-p256";
    publicKey: `0x${string}`;
    prehash: false;
  }>;
  readonly digest: `0x${string}`;
}

function providerPrepareRequest(
  account: `0x${string}`,
  key: PreparedRpcResponse["key"] = {
    type: "secp256k1",
    publicKey: SESSION_PUBLIC_KEY,
    prehash: false,
  },
) {
  return {
    method: "wallet_prepareCalls",
    params: [
      {
        version: "1",
        from: account,
        chainId: CHAIN_HEX,
        calls: [{ to: TARGET, data: CALL_DATA }],
        capabilities: { applicationHint: { optional: true, value: "retained" } },
        key,
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

function base64Url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
}

function createWebAuthnCredentialFixture() {
  const privateKey = p256.utils.randomPrivateKey();
  const publicKey = bytesToHex(p256.getPublicKey(privateKey, false));
  const credentialIdBytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const credentialId = base64Url(credentialIdBytes);
  const authenticatorIdHash = keccak256(bytesToHex(credentialIdBytes));
  const rpId = "app.example";
  const ownerCredential = Object.freeze({
    version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
    kind: "webauthn" as const,
    publicKey,
    authenticatorIdHash,
  });
  const operatorCredential = Object.freeze({
    version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
    kind: "webauthn" as const,
    publicKey,
    authenticatorIdHash,
  });
  let injectedAuthenticatorCalls = 0;
  let externalAuthenticatorCalls = 0;

  const keyInput = Object.freeze({
    credential: ownerCredential,
    credentialId,
    rpId,
    origin: ORIGIN,
  });

  return Object.freeze({
    publicKey,
    operatorCredential,
    verificationKey() {
      return webauthnKey({
        ...keyInput,
        async authenticate() {
          injectedAuthenticatorCalls += 1;
          throw new Error("the SDK must not invoke an authenticator for an external signature");
        },
      });
    },
    externalKey() {
      return webauthnKey({
        ...keyInput,
        async authenticate(request: WebAuthnAssertionRequest) {
          externalAuthenticatorCalls += 1;
          const clientDataJSON = JSON.stringify({
            type: "webauthn.get",
            challenge: request.challenge,
            origin: ORIGIN,
            crossOrigin: false,
          });
          const authenticatorData = concat([
            sha256(stringToBytes(rpId)),
            toHex(0x05, { size: 1 }),
            "0x00000001",
          ]);
          const message = sha256(
            concat([authenticatorData, sha256(stringToBytes(clientDataJSON))]),
          );
          const signature = p256.sign(hexToBytes(message), privateKey, {
            lowS: true,
            prehash: false,
          });
          privateKey.fill(0);
          return Object.freeze({
            authenticatorData,
            clientDataJSON,
            responseTypeLocation: String(clientDataJSON.indexOf('"type":"webauthn.get"')),
            r: toHex(signature.r, { size: 32 }),
            s: toHex(signature.s, { size: 32 }),
          });
        },
      });
    },
    injectedAuthenticatorCalls: () => injectedAuthenticatorCalls,
    externalAuthenticatorCalls: () => externalAuthenticatorCalls,
  });
}

function countPreparedContextWrites(stores: ReturnType<typeof createMemoryStores>) {
  const durable = stores.preparedCallContexts;
  let writes = 0;
  return Object.freeze({
    adapter: Object.freeze({
      get: (key: Parameters<typeof durable.get>[0]) => durable.get(key),
      compareAndSwap(input: Parameters<typeof durable.compareAndSwap>[0]) {
        writes += 1;
        return durable.compareAndSwap(input);
      },
      close: () => durable.close(),
    }),
    writes: () => writes,
  });
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

  it("refuses changed backend custody before relay resume and preserves one prepared retry", async () => {
    const backend = privateKeyToAccount(generatePrivateKey());
    const backendSignedHashes: `0x${string}`[] = [];
    const backendProvider = Object.freeze({
      async credential() {
        return Object.freeze({
          version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
          kind: "ecdsa" as const,
          address: backend.address.toLowerCase(),
        });
      },
      async sign(request: Readonly<{ hash: `0x${string}` }>) {
        backendSignedHashes.push(request.hash);
        return backend.sign({ hash: request.hash });
      },
    });
    const factory = new IDBFactory();
    const clock = createClock();
    const chain = createChainFixture();
    const first = await indexedDbPreparedRealmStores(factory);
    const before = createUrlRealm({
      stores: first.stores,
      clock,
      chain,
      sessionSigner: {
        mode: "application_backend",
        providerId: "backend-a",
        provider: backendProvider,
      },
    });
    const firstConnection = await before.oaath.connect();
    const firstGrant = await firstConnection.requestPermission(permissionInput());
    const account = await firstGrant.account(CHAIN_ID);
    const firstProvider = oaathProvider({ grant: firstGrant, chain: CHAIN_ID });
    const prepared = (await firstProvider.request(
      providerPrepareRequest(account, {
        type: "secp256k1",
        publicKey: backend.publicKey.toLowerCase() as `0x${string}`,
        prehash: false,
      }),
    )) as PreparedRpcResponse;
    const firstPort = grantProviderPort(firstGrant);
    const contextKey = Object.freeze({
      providerScopeId: firstPort.providerScopeId as `0x${string}`,
      contextId: prepared.context.id,
    });
    const preparedRecord = await firstPort.preparedCallContexts.get(contextKey);
    const rawPreparedRecord = await first.stores.preparedCallContexts.get(contextKey);
    if (preparedRecord === undefined || rawPreparedRecord === undefined) {
      throw new Error("expected one durable prepared context");
    }

    expect(preparedRecord.value).toMatchObject({
      state: "prepared",
      custody: { mode: "application_backend", providerId: "backend-a" },
      digest: prepared.digest,
    });
    expect(chain.quotes).toBe(1);
    expect(backendSignedHashes).toEqual([]);
    expect(chain.signatures.length).toBe(0);
    expect(chain.sends).toHaveLength(0);
    await firstConnection.close();
    first.database.close();

    const second = await indexedDbPreparedRealmStores(factory);
    const changed = createUrlRealm({
      stores: second.stores,
      clock,
      chain,
      relay: before.relay,
      bootstrap(document) {
        return {
          ...document,
          sessionSigner: { mode: "application_backend", providerId: "backend-b" },
        };
      },
    });
    const changedConnection = await changed.oaath.connect();

    await expect(changedConnection.resume()).rejects.toMatchObject({
      name: "OaathClientError",
      code: "oaath_client_state_conflict",
      source: "session_signer_binding_mismatch",
    });
    expect(changed.fetched).not.toContain("POST /authorization/resume");
    await expect(second.stores.preparedCallContexts.get(contextKey)).resolves.toEqual(
      rawPreparedRecord,
    );
    expect(chain.quotes).toBe(1);
    expect(backendSignedHashes).toEqual([]);
    expect(chain.signatures.length).toBe(0);
    expect(chain.sends).toHaveLength(0);
    await changedConnection.close();
    second.database.close();

    const third = await indexedDbPreparedRealmStores(factory);
    const restored = createUrlRealm({
      stores: third.stores,
      clock,
      chain,
      relay: before.relay,
    });
    const restoredConnection = await restored.oaath.connect();
    const restoredGrant = await restoredConnection.resume();
    if (restoredGrant === null) throw new Error("expected the approved backend Grant to resume");
    const restoredProvider = oaathProvider({ grant: restoredGrant, chain: CHAIN_ID });
    const restoredPort = grantProviderPort(restoredGrant);
    await expect(restoredPort.preparedCallContexts.get(contextKey)).resolves.toEqual(
      preparedRecord,
    );

    const externalSignature = await backendProvider.sign({ hash: prepared.digest });
    const sent = await restoredProvider.request(
      providerSendRequest(prepared, externalSignature.toLowerCase() as `0x${string}`),
    );
    const consumed = await restoredPort.preparedCallContexts.get(contextKey);

    expect(sent).toMatchObject({ id: expect.stringMatching(/^0x[0-9a-f]{64}$/u) });
    expect(backendSignedHashes).toEqual([prepared.digest]);
    expect(chain.quotes).toBe(2);
    expect(chain.signatures.length).toBe(1);
    expect(chain.sends).toHaveLength(1);
    expect(chain.sends[0]?.userOperationHash).toBe(prepared.digest);
    expect(consumed?.storeRevision).toBe(preparedRecord.storeRevision + 1);
    expect(consumed?.value.state).toBe("consumed");
    await restoredConnection.close();
    third.database.close();
  });

  it("recreates a WebAuthn frontend realm and submits one externally signed retained digest", async () => {
    const credential = createWebAuthnCredentialFixture();
    const factory = new IDBFactory();
    const clock = createClock();
    const chain = createChainFixture();
    const first = await indexedDbPreparedRealmStores(factory);
    const firstSessionKey = credential.verificationKey();
    const firstSigning = signingProfiles();
    const before = createRealm({
      stores: first.stores,
      clock,
      chain,
      binding: { ...bindingInput, operatorCredential: credential.operatorCredential },
      owner: { operatorKey: firstSessionKey },
      signing: { owner: firstSigning.owner, session: firstSessionKey },
    });
    const firstConnection = await before.oaath.connect();
    const firstGrant = await firstConnection.requestPermission(permissionInput());
    const account = await firstGrant.account(CHAIN_ID);
    const firstProvider = oaathProvider({ grant: firstGrant, chain: CHAIN_ID });
    const prepared = (await firstProvider.request(
      providerPrepareRequest(account, {
        type: "webauthn-p256",
        publicKey: credential.publicKey,
        prehash: false,
      }),
    )) as PreparedRpcResponse;
    const firstPort = grantProviderPort(firstGrant);
    const contextKey = Object.freeze({
      providerScopeId: firstPort.providerScopeId as `0x${string}`,
      contextId: prepared.context.id,
    });
    const preparedRecord = await firstPort.preparedCallContexts.get(contextKey);
    if (preparedRecord === undefined) throw new Error("expected one durable WebAuthn context");

    expect(prepared).toMatchObject({
      version: "1",
      chainId: CHAIN_HEX,
      key: {
        type: "webauthn-p256",
        publicKey: credential.publicKey,
        prehash: false,
      },
      digest: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
    });
    expect(preparedRecord.value).toMatchObject({
      state: "prepared",
      keyHint: prepared.key,
      custody: { mode: "frontend", providerId: null },
      digest: prepared.digest,
    });
    expect(credential.injectedAuthenticatorCalls()).toBe(0);
    expect(credential.externalAuthenticatorCalls()).toBe(0);
    expect(chain.quotes).toBe(1);
    expect(chain.signatures.length).toBe(0);
    expect(chain.sends).toHaveLength(0);
    await firstConnection.close();
    first.database.close();

    const second = await indexedDbPreparedRealmStores(factory);
    const secondSessionKey = credential.verificationKey();
    const secondSigning = signingProfiles();
    const after = createRealm({
      stores: second.stores,
      clock,
      chain,
      relay: before.relay,
      binding: { ...bindingInput, operatorCredential: credential.operatorCredential },
      owner: { operatorKey: secondSessionKey },
      signing: { owner: secondSigning.owner, session: secondSessionKey },
    });
    const secondConnection = await after.oaath.connect();
    const secondGrant = await secondConnection.resume();
    if (secondGrant === null) throw new Error("expected the WebAuthn Grant to resume");
    const secondProvider = oaathProvider({ grant: secondGrant, chain: CHAIN_ID });
    const secondPort = grantProviderPort(secondGrant);

    expect(secondSessionKey).not.toBe(firstSessionKey);
    await expect(secondPort.preparedCallContexts.get(contextKey)).resolves.toEqual(preparedRecord);
    expect(credential.injectedAuthenticatorCalls()).toBe(0);

    const externalSignature = await credential.externalKey().sign(prepared.digest);
    expect(credential.externalAuthenticatorCalls()).toBe(1);
    expect(credential.injectedAuthenticatorCalls()).toBe(0);

    const sent = await secondProvider.request(
      providerSendRequest(prepared, externalSignature.toLowerCase() as `0x${string}`),
    );
    const consumed = await secondPort.preparedCallContexts.get(contextKey);

    expect(sent).toMatchObject({ id: expect.stringMatching(/^0x[0-9a-f]{64}$/u) });
    expect(credential.externalAuthenticatorCalls()).toBe(1);
    expect(credential.injectedAuthenticatorCalls()).toBe(0);
    expect(chain.quotes).toBe(2);
    expect(chain.signatures.length).toBe(1);
    expect(chain.sends).toHaveLength(1);
    expect(chain.sends[0]?.userOperationHash).toBe(prepared.digest);
    expect(consumed?.storeRevision).toBe(preparedRecord.storeRevision + 1);
    expect(consumed?.value.state).toBe("consumed");
    await secondConnection.close();
    second.database.close();
  });

  it("refuses a wrong secp256k1 key before effects and still prepares with the approved key", async () => {
    const approved = privateKeyToAccount(generatePrivateKey());
    const wrong = privateKeyToAccount(generatePrivateKey());
    const approvedBaseKey = ecdsaKey({ account: approved, validator: VALIDATOR });
    let injectedSignCalls = 0;
    const approvedKey = Object.freeze({
      ...approvedBaseKey,
      async sign(hash: `0x${string}`) {
        injectedSignCalls += 1;
        return approvedBaseKey.sign(hash);
      },
    });
    const stores = createMemoryStores();
    const contexts = countPreparedContextWrites(stores);
    const chain = createChainFixture();
    const ownerSigning = signingProfiles();
    const realm = createRealm({
      stores: { ...stores, preparedCallContexts: contexts.adapter },
      chain,
      binding: {
        ...bindingInput,
        operatorCredential: {
          version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
          kind: "ecdsa",
          address: approved.address.toLowerCase(),
        },
      },
      signing: { owner: ownerSigning.owner, session: approvedKey },
    });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    const provider = oaathProvider({ grant, chain: CHAIN_ID });

    await expect(
      provider.request(
        providerPrepareRequest(account, {
          type: "secp256k1",
          publicKey: wrong.publicKey.toLowerCase() as `0x${string}`,
          prehash: false,
        }),
      ),
    ).rejects.toMatchObject({ name: "OaathProviderRpcError", code: 4100 });
    expect(contexts.writes()).toBe(0);
    expect(chain.quotes).toBe(0);
    expect(injectedSignCalls).toBe(0);
    expect(chain.signatures.length).toBe(0);
    expect(chain.sends).toHaveLength(0);

    const prepared = (await provider.request(
      providerPrepareRequest(account, {
        type: "secp256k1",
        publicKey: approved.publicKey.toLowerCase() as `0x${string}`,
        prehash: false,
      }),
    )) as PreparedRpcResponse;
    const port = grantProviderPort(grant);
    const retained = await port.preparedCallContexts.get({
      providerScopeId: port.providerScopeId,
      contextId: prepared.context.id,
    });

    expect(prepared.key).toEqual({
      type: "secp256k1",
      publicKey: approved.publicKey.toLowerCase(),
      prehash: false,
    });
    expect(retained?.value.state).toBe("prepared");
    expect(contexts.writes()).toBe(1);
    expect(chain.quotes).toBe(1);
    expect(injectedSignCalls).toBe(0);
    expect(chain.signatures.length).toBe(0);
    expect(chain.sends).toHaveLength(0);
    await connection.close();
  });

  it("refuses oaath_hosted custody before context reservation or execution effects", async () => {
    const hosted = privateKeyToAccount(generatePrivateKey());
    let hostedSignCalls = 0;
    const hostedProvider = Object.freeze({
      async credential() {
        return Object.freeze({
          version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
          kind: "ecdsa" as const,
          address: hosted.address.toLowerCase(),
        });
      },
      async sign(request: Readonly<{ hash: `0x${string}` }>) {
        hostedSignCalls += 1;
        return hosted.sign({ hash: request.hash });
      },
    });
    const stores = createMemoryStores();
    const contexts = countPreparedContextWrites(stores);
    const chain = createChainFixture();
    const realm = createUrlRealm({
      stores: { ...stores, preparedCallContexts: contexts.adapter },
      chain,
      sessionSigner: {
        mode: "oaath_hosted",
        providerId: "hosted-primary",
        provider: hostedProvider,
      },
    });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    const provider = oaathProvider({ grant, chain: CHAIN_ID });

    await expect(
      provider.request(
        providerPrepareRequest(account, {
          type: "secp256k1",
          publicKey: hosted.publicKey.toLowerCase() as `0x${string}`,
          prehash: false,
        }),
      ),
    ).rejects.toMatchObject({ name: "OaathProviderRpcError", code: 5700 });
    expect(contexts.writes()).toBe(0);
    expect(chain.quotes).toBe(0);
    expect(hostedSignCalls).toBe(0);
    expect(chain.signatures.length).toBe(0);
    expect(chain.sends).toHaveLength(0);
    await connection.close();
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

  it("recovers one consumed ambiguous send after full IndexedDB realm recreation", async () => {
    const factory = new IDBFactory();
    const clock = createClock();
    const relay = createRelay(clock);
    let crash = true;
    let sessionSigns = 0;
    const countingSigningProfiles = () => {
      const profiles = signingProfiles();
      return {
        owner: profiles.owner,
        session: Object.freeze({
          ...profiles.session,
          async sign(hash: `0x${string}`) {
            sessionSigns += 1;
            return profiles.session.sign(hash);
          },
        }),
      };
    };
    const chain = createChainFixture({ crashOnSend: () => crash });
    const first = await indexedDbPreparedRealmStores(factory);
    const before = createRealm({
      stores: first.stores,
      clock,
      relay,
      chain,
      signing: countingSigningProfiles(),
    });
    const firstConnection = await before.oaath.connect();
    const firstGrant = await firstConnection.requestPermission(permissionInput());
    const account = await firstGrant.account(CHAIN_ID);
    const firstProvider = oaathProvider({ grant: firstGrant, chain: CHAIN_ID });
    const firstPort = grantProviderPort(firstGrant);
    const prepared = (await firstProvider.request(
      providerPrepareRequest(account),
    )) as PreparedRpcResponse;
    const signature = await signPreparedDigest(prepared.digest);

    const ambiguous = (await firstProvider.request(
      providerSendRequest(prepared, signature),
    )) as Readonly<{ id: string }>;
    const contextKey = Object.freeze({
      providerScopeId: firstPort.providerScopeId,
      contextId: prepared.context.id,
    });
    const bundleKey = Object.freeze({
      providerScopeId: firstPort.providerScopeId,
      account,
      id: ambiguous.id,
    });
    const consumed = await firstPort.preparedCallContexts.get(contextKey);
    const firstBundle = await firstPort.walletCallBundles.get(bundleKey);
    const firstJournalStore = new OperationStore(first.stores.operations);
    const firstJournal = await firstJournalStore.get({
      grantId: firstPort.grantId,
      chainId: CHAIN_ID,
      kind: "execution",
    });
    await firstJournalStore.close();
    if (
      firstJournal === undefined ||
      firstBundle === undefined ||
      firstBundle.value.operation === null
    ) {
      throw new Error("expected the ambiguous prepared operation to be durably bound");
    }
    const exactIdentity = firstJournal.value.identity;
    const quotesAfterAmbiguity = chain.quotes;

    expect(ambiguous.id).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(consumed?.value).toMatchObject({
      state: "consumed",
      bundleId: ambiguous.id,
      operationRequestHash: exactIdentity.requestHash,
    });
    expect(firstBundle?.value).toMatchObject({
      state: "operation_bound",
      publicationReleasedAt: expect.any(Number),
    });
    expect(firstBundle?.value.operation?.identity).toEqual(exactIdentity);
    expect(firstJournal.value.state).toBe("submission_attempted");
    expect(quotesAfterAmbiguity).toBe(2);
    expect(sessionSigns).toBe(0);
    expect(chain.signatures).toHaveLength(1);
    expect(chain.sends).toHaveLength(1);
    expect(chain.sends[0]?.userOperationHash).toBe(exactIdentity.userOperationHash);

    await firstConnection.close();
    await expect(firstPort.preparedCallContexts.get(contextKey)).rejects.toMatchObject({
      code: "store_closed",
    });
    first.database.close();

    // Recreate the database connection, adapters, stores, client, Grant,
    // provider, and ERC-7836 orchestrator. Only the external relay and chain
    // remain so the new realm can resume and observe the original submission.
    crash = false;
    const second = await indexedDbPreparedRealmStores(factory);
    const after = createRealm({
      stores: second.stores,
      clock,
      relay,
      chain,
      signing: countingSigningProfiles(),
    });
    const secondConnection = await after.oaath.connect();
    const secondGrant = await secondConnection.resume();
    if (secondGrant === null) throw new Error("expected the ambiguous Grant to resume");
    const secondProvider = oaathProvider({ grant: secondGrant, chain: CHAIN_ID });
    const secondPort = grantProviderPort(secondGrant);
    const secondJournalStore = new OperationStore(second.stores.operations);
    const reconstructedJournal = await secondJournalStore.get({
      grantId: secondPort.grantId,
      chainId: CHAIN_ID,
      kind: "execution",
    });
    const reconstructedContext = await secondPort.preparedCallContexts.get({
      providerScopeId: secondPort.providerScopeId,
      contextId: prepared.context.id,
    });
    const reconstructedBundle = await secondPort.walletCallBundles.get({
      providerScopeId: secondPort.providerScopeId,
      account,
      id: ambiguous.id,
    });

    expect(secondPort.providerScopeId).toBe(firstPort.providerScopeId);
    expect(secondPort.grantId).toBe(firstPort.grantId);
    expect(reconstructedContext?.value.state).toBe("consumed");
    expect(reconstructedBundle?.value.operation?.identity).toEqual(exactIdentity);
    expect(reconstructedJournal?.value.identity).toEqual(exactIdentity);
    expect(reconstructedJournal?.value.state).toBe("submission_attempted");

    const retried = await secondProvider.request(providerSendRequest(prepared, signature));
    expect(retried).toEqual(ambiguous);
    expect(chain.quotes).toBe(quotesAfterAmbiguity);
    expect(sessionSigns).toBe(0);
    expect(chain.signatures).toHaveLength(1);
    expect(chain.sends).toHaveLength(1);
    expect(chain.sends[0]?.userOperationHash).toBe(exactIdentity.userOperationHash);
    const recoveredJournal = await secondJournalStore.get({
      grantId: secondPort.grantId,
      chainId: CHAIN_ID,
      kind: "execution",
    });
    expect(recoveredJournal?.value.identity).toEqual(exactIdentity);

    await secondJournalStore.close();
    await secondConnection.close();
    second.database.close();
  });
});
