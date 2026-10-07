/**
 * Hostile input at every new public entry of the browser client.
 *
 * Each entry captures its input exactly once: a missing field, an unknown field,
 * a getter, a prototype, an alias, or a wrong type fails closed with a structured
 * code before anything durable, cryptographic, or network-bound happens.
 *
 * @author taek <leekt216@gmail.com>
 */
import { isKernelExistingAccountProfile } from "@oaath/protocol";
import { IDBFactory } from "fake-indexeddb";
import { privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";
import { captureOaathBinding, runOaathCleanup } from "../src/advanced.js";
import { createOAAth as createTypedOAAth } from "../src/index.js";
import { kernelKey } from "../src/kernel.js";
import { openOaathDatabase } from "../src/persistence/indexeddb/database.js";
import { createIndexedDbGrantStoreAdapter } from "../src/persistence/indexeddb/grant-store.js";
import { createIndexedDbOperationStoreAdapter } from "../src/persistence/indexeddb/operation-store.js";
import {
  createMemoryCleanupStore,
  createMemoryContextStore,
  createMemoryGrantStoreAdapter,
  createMemoryKeyStore,
  createMemoryOperationStoreAdapter,
} from "../src/persistence/memory/stores.js";
import {
  isCleanupEffectName,
  OAATH_CLEANUP_CHECKPOINT_VERSION,
  parseCleanupCheckpoint,
  parseClientContext,
  requireNonExtractableKey,
} from "../src/persistence.js";
import {
  bindingInput,
  CALL_DATA,
  CHAIN_ID,
  createChainFixture,
  createMemoryStores,
  createRealm,
  ISSUER_URL,
  permissionInput,
  sendCallsInput,
  signingProfiles,
  TARGET,
  VALIDATOR,
} from "./support/browser.js";

function baseConfiguration(): Record<string, unknown> {
  return {
    binding: bindingInput,
    issuer: { url: ISSUER_URL, fetch: async () => new Response("{}"), signOut: null },
    authorization: { authorize: async () => ({ code: "x" }) },
    invalidation: { invalidateCapability: async () => ({}) },
    stores: createMemoryStores(),
    chains: [createChainFixture().capability],
    signing: signingProfiles(),
    localKeyIds: [],
    now: () => 1_800_000_000,
  };
}

function expectClientError(action: () => unknown, code: string): void {
  expect(action).toThrowError(expect.objectContaining({ name: "OaathClientError", code }));
}

/** Hostile input deliberately bypasses the typed options. */
const createOAAth = (value: unknown) => createTypedOAAth(value as never);
describe("hostile input at the client boundary", () => {
  it("keeps existing v3.3 account addresses distinct in the browser binding", () => {
    const account = {
      version: "oaath.kernel-existing-account-profile/v3",
      kind: "kernel",
      kernelVersion: "0.3.3",
      address: TARGET,
      entryPoint: { version: "0.7" },
      ownerCredential: bindingInput.account.ownerCredential,
    };
    const original = captureOaathBinding({ ...bindingInput, account });
    const changed = captureOaathBinding({
      ...bindingInput,
      account: { ...account, address: VALIDATOR },
    });
    expect(original.account).toEqual(account);
    expect(changed.bindingId).not.toBe(original.bindingId);
    expect(
      captureOaathBinding({ ...bindingInput, account: structuredClone(account) }).bindingId,
    ).toBe(original.bindingId);
    expect(() =>
      captureOaathBinding({ ...bindingInput, account: { ...account, accountIndex: "0" } }),
    ).toThrow();
  });

  it("binds workspace, account identity, and complete account profile independently", () => {
    const original = captureOaathBinding(bindingInput);
    const alternatives = [
      { context: { ...bindingInput.context, workspaceId: "team-1", workspaceKind: "team" } },
      { context: { ...bindingInput.context, accountId: "account-2" } },
      {
        account: {
          ...bindingInput.account,
          ownerCredential: {
            ...bindingInput.account.ownerCredential,
            address: `0x${"44".repeat(20)}`,
          },
        },
      },
    ];
    for (const alternative of alternatives) {
      const other = captureOaathBinding({ ...bindingInput, ...alternative });
      if (
        isKernelExistingAccountProfile(other.account) ||
        isKernelExistingAccountProfile(original.account)
      )
        throw new Error("expected v4 fixture");
      expect(other.account.accountIndex).toBe(original.account.accountIndex);
      expect(other.bindingId).not.toBe(original.bindingId);
    }
    expect(captureOaathBinding(structuredClone(bindingInput)).bindingId).toBe(original.bindingId);
  });

  it("refuses a configuration that is not an exact record", () => {
    for (const value of [undefined, null, 0, "config", [], () => undefined, new Map()]) {
      expectClientError(() => createOAAth(value), "oaath_client_input_invalid");
    }
    expectClientError(
      () => createOAAth({ ...baseConfiguration(), unexpected: true }),
      "oaath_client_input_invalid",
    );
    const { binding: _binding, ...missing } = baseConfiguration();
    expectClientError(() => createOAAth(missing), "oaath_client_input_invalid");
  });

  it("refuses configuration fields with accessors, prototypes, or symbols", () => {
    expectClientError(
      () =>
        createOAAth({
          ...baseConfiguration(),
          get localKeyIds() {
            return [];
          },
        }),
      "oaath_client_input_invalid",
    );
    expectClientError(
      () => createOAAth(Object.assign(Object.create({ inherited: true }), baseConfiguration())),
      "oaath_client_input_invalid",
    );
    expectClientError(
      () => createOAAth({ ...baseConfiguration(), [Symbol.for("x")]: 1 }),
      "oaath_client_input_invalid",
    );
  });

  it("refuses an issuer transport that does not serve the bound issuer", () => {
    expectClientError(
      () =>
        createOAAth({
          ...baseConfiguration(),
          issuer: {
            url: "https://other.example",
            fetch: async () => new Response(),
            signOut: null,
          },
        }),
      "oaath_client_capability_invalid",
    );
    for (const url of ["http://issuer.example", "https://issuer.example/", 7, null]) {
      expectClientError(
        () =>
          createOAAth({
            ...baseConfiguration(),
            issuer: { url, fetch: async () => new Response(), signOut: null },
          }),
        "oaath_client_capability_invalid",
      );
    }
  });

  it("refuses malformed capabilities, stores, chains, keys, and clocks", () => {
    const { walletCallBundles: _retiredOptionalStore, ...oldStores } = createMemoryStores();
    const cases: readonly Record<string, unknown>[] = [
      { authorization: { authorize: "no" } },
      { authorization: { authorize: async () => ({}), extra: 1 } },
      { invalidation: {} },
      { stores: oldStores },
      { stores: { ...createMemoryStores(), keys: { store: 1 } } },
      { stores: { ...createMemoryStores(), walletCallBundles: { get: async () => undefined } } },
      { chains: [] },
      { chains: [createChainFixture().capability, createChainFixture().capability] },
      { chains: [{ chainId: CHAIN_ID }] },
      {
        chains: [
          {
            ...createChainFixture().capability,
            sponsorship: { kind: "erc7902-static", configurationHash: "0x01" },
          },
        ],
      },
      // One sponsorship setting: no unknown kind, no mixed fields, no retired fields.
      {
        chains: [
          {
            ...createChainFixture().capability,
            sponsorship: { kind: "erc4337-paymaster", configurationHash: `0x${"11".repeat(32)}` },
          },
        ],
      },
      {
        chains: [
          {
            ...createChainFixture().capability,
            sponsorship: {
              kind: "erc7902-static",
              configurationHash: `0x${"11".repeat(32)}`,
              url: "https://paymaster.test",
            },
          },
        ],
      },
      {
        chains: [
          {
            ...createChainFixture().capability,
            sponsorship: {
              kind: "erc7677",
              url: "https://paymaster.test",
              request: async () => ({}),
            },
          },
        ],
      },
      { chains: [{ ...createChainFixture().capability, paymasterService: null }] },
      { chains: [{ ...createChainFixture().capability, staticPaymasterConfigurationHash: null }] },
      { signing: { owner: signingProfiles().owner } },
      { signing: { owner: { kind: "ecdsa" }, session: signingProfiles().session } },
      { localKeyIds: [""] },
      { localKeyIds: Array.from({ length: 9 }, (_, index) => `k${index}`) },
      { now: 1_800_000_000 },
    ];
    for (const override of cases) {
      expect(() => createOAAth({ ...baseConfiguration(), ...override })).toThrowError(
        expect.objectContaining({ name: "OaathClientError" }),
      );
    }
  });

  it("refuses signing keys that are not the approved credentials", () => {
    // The binding carries the credential profiles the owner reviews; a realm
    // whose executable keys are not exactly those credentials never composes,
    // so approval and execution cannot name different authorities.
    const stranger = kernelKey({
      account: privateKeyToAccount(`0x${"77".repeat(32)}`),
      validator: VALIDATOR,
    });
    expect(() =>
      createOAAth({
        ...baseConfiguration(),
        signing: { owner: stranger, session: signingProfiles().session },
      }),
    ).toThrowError(
      expect.objectContaining({
        name: "OaathClientError",
        code: "oaath_client_capability_invalid",
        source: "owner_credential_mismatch",
      }),
    );
    expect(() =>
      createOAAth({
        ...baseConfiguration(),
        signing: { owner: signingProfiles().owner, session: stranger },
      }),
    ).toThrowError(
      expect.objectContaining({
        name: "OaathClientError",
        code: "oaath_client_capability_invalid",
        source: "operator_credential_mismatch",
      }),
    );
    // A consumer-authored kind has no approvable credential shape at all: it
    // derives no profile, so it can never match a reviewed approval.
    const approved = signingProfiles();
    const custom = Object.freeze({
      ...approved.owner,
      kind: "custom:evil" as const,
    });
    expect(() =>
      createOAAth({
        ...baseConfiguration(),
        signing: { owner: custom, session: approved.session },
      }),
    ).toThrowError(
      expect.objectContaining({
        name: "OaathClientError",
        code: "oaath_client_capability_invalid",
        source: "owner_credential_mismatch",
      }),
    );
    // A key whose public material lies about its shape derives nothing either.
    const malformed = Object.freeze({ ...approved.session, publicMaterial: "0x1234" as const });
    expect(() =>
      createOAAth({
        ...baseConfiguration(),
        signing: { owner: approved.owner, session: malformed },
      }),
    ).toThrowError(
      expect.objectContaining({
        name: "OaathClientError",
        code: "oaath_client_capability_invalid",
        source: "operator_credential_mismatch",
      }),
    );
  });

  it("refuses a binding whose parts do not agree", () => {
    for (const override of [
      { issuer: "http://issuer.example" },
      { origin: "https://app.example/" },
      { redirectUri: "https://other.example/callback" },
      { clientId: "Client-A" },
      { applicationId: "APP" },
      { userHandle: "" },
      { account: { ...bindingInput.account, accountIndex: "-1" } },
      { operatorCredential: { kind: "ecdsa" } },
    ]) {
      expectClientError(
        () => captureOaathBinding({ ...bindingInput, ...override }),
        "oaath_client_input_invalid",
      );
    }
    expectClientError(
      () => captureOaathBinding({ ...bindingInput, extra: 1 }),
      "oaath_client_input_invalid",
    );
  });

  it("refuses malformed permission requests", async () => {
    const realm = createRealm();
    const connection = await realm.oaath.connect();
    for (const override of [
      { chainScope: "one" },
      { expiresIn: 0 },
      { expiresIn: 86_401 },
      { expiresIn: 1.5 },
      { perChainOperationLimit: 0 },
      { perChainOperationLimit: { count: 2 } },
      { perChainOperationLimit: { count: 2, intervalSeconds: 0 } },
      { perChainOperationLimit: { count: 2, intervalSeconds: null } },
      { perChainOperationLimit: { count: 0, intervalSeconds: 60 } },
      { onPending: "not a callback" },
      { permissions: [] },
      { permissions: [{}] },
      { permissions: [{ calls: [{ target: TARGET, selectors: ["0x1234"], valueLimit: "0" }] }] },
      { permissions: [{ calls: [{ target: TARGET, selectors: ["0xa9059cbb"] }] }] },
      { permissions: [{ calls: [], extra: 1 }] },
    ]) {
      await expect(connection.requestPermission(permissionInput(override))).rejects.toMatchObject({
        name: "OaathClientError",
      });
    }
    await expect(connection.requestPermission(null)).rejects.toMatchObject({
      code: "oaath_client_input_invalid",
    });
    // Nothing reached the issuer.
    expect(realm.ownerCalls).toHaveLength(0);
    await connection.close();
  });

  it("refuses malformed sendCalls input and wait bounds", async () => {
    const realm = createRealm();
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    for (const value of [
      null,
      {},
      { chain: CHAIN_ID },
      { chain: 0, calls: [] },
      { chain: 1.5, calls: [{ target: TARGET, value: "0", data: CALL_DATA }] },
      { chain: CHAIN_ID, calls: [] },
      { chain: CHAIN_ID, calls: [{ target: TARGET, data: CALL_DATA }] },
      { chain: CHAIN_ID, calls: [{ target: TARGET, value: 0, data: CALL_DATA }] },
      { chain: CHAIN_ID, calls: [{ target: TARGET, value: "0", data: CALL_DATA, extra: 1 }] },
      { chain: CHAIN_ID, calls: sendCallsInput(), extra: 1 },
    ]) {
      await expect(grant.sendCalls(value)).rejects.toMatchObject({ name: "OaathClientError" });
    }
    expect(realm.chain.sends).toHaveLength(0);

    const operation = await grant.sendCalls(sendCallsInput());
    for (const value of [{ attempts: 0 }, { attempts: 17 }, { attempts: "3" }, { extra: 1 }]) {
      await expect(operation.wait(value)).rejects.toMatchObject({
        code: "oaath_client_input_invalid",
      });
    }
    await connection.close();
  });

  it("refuses hostile chain capability evidence", async () => {
    const realm = createRealm({
      chain: {
        ...createChainFixture(),
        capability: Object.freeze({
          ...createChainFixture().capability,
          async quote() {
            return { nonceKey: "0", sequence: "0" };
          },
        }),
      },
    });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    await expect(grant.sendCalls(sendCallsInput())).rejects.toMatchObject({
      name: "OaathClientError",
      code: "oaath_client_preparation_failed",
    });
    await connection.close();
  });

  it("refuses malformed cleanup input", async () => {
    const checkpoints = createMemoryCleanupStore();
    const effect = { name: "close" as const, run: async () => undefined };
    for (const value of [
      null,
      {},
      { cleanupId: "a", effects: [effect], checkpoints, now: () => 1, extra: 1 },
      { cleanupId: "", effects: [effect], checkpoints, now: () => 1, primaryError: null },
      { cleanupId: "a", effects: {}, checkpoints, now: () => 1, primaryError: null },
      {
        cleanupId: "a",
        effects: [effect, effect],
        checkpoints,
        now: () => 1,
        primaryError: null,
      },
      {
        cleanupId: "a",
        effects: [{ name: "purge", run: async () => undefined }],
        checkpoints,
        now: () => 1,
        primaryError: null,
      },
      {
        cleanupId: "a",
        effects: [{ name: "close", run: 1 }],
        checkpoints,
        now: () => 1,
        primaryError: null,
      },
      { cleanupId: "a", effects: [effect], checkpoints: {}, now: () => 1, primaryError: null },
      { cleanupId: "a", effects: [effect], checkpoints, now: 1, primaryError: null },
    ]) {
      await expect(runOaathCleanup(value)).rejects.toMatchObject({ name: "OaathClientError" });
    }
  });

  it("refuses hostile persisted records", () => {
    const valid = {
      version: OAATH_CLEANUP_CHECKPOINT_VERSION,
      cleanupId: "realm",
      completed: ["close"],
      updatedAt: 1,
    };
    expect(parseCleanupCheckpoint(valid).completed).toEqual(["close"]);
    for (const value of [
      null,
      {},
      { ...valid, version: "oaath.cleanup-checkpoint/v0" },
      { ...valid, completed: ["close", "close"] },
      { ...valid, completed: ["purge"] },
      { ...valid, completed: ["close", "signOut", "forgetLocal", "revoke", "close"] },
      { ...valid, updatedAt: -1 },
      { ...valid, extra: 1 },
    ]) {
      expect(() => parseCleanupCheckpoint(value)).toThrowError(
        expect.objectContaining({ name: "OaathPersistenceError" }),
      );
    }
    for (const value of [null, {}, { version: "oaath.client-context/v1" }]) {
      expect(() => parseClientContext(value)).toThrowError(
        expect.objectContaining({ name: "OaathPersistenceError" }),
      );
    }
    expect(isCleanupEffectName("close")).toBe(true);
    expect(isCleanupEffectName("purge")).toBe(false);
  });

  it("refuses key handles that are not non-extractable CryptoKeys", async () => {
    for (const value of [null, undefined, {}, "key", 1]) {
      expect(() => requireNonExtractableKey(value)).toThrowError(
        expect.objectContaining({ code: "persistence_key_invalid" }),
      );
    }
    const keys = createMemoryKeyStore();
    await expect(keys.store({ keyId: "", key: null as never })).rejects.toMatchObject({
      code: "persistence_input_invalid",
    });
  });

  it("refuses malformed persistence keys in every backend", async () => {
    const grants = createMemoryGrantStoreAdapter();
    const operations = createMemoryOperationStoreAdapter();
    const cleanup = createMemoryCleanupStore();
    const context = createMemoryContextStore();
    await expect(grants.get(" spaced ")).rejects.toMatchObject({
      code: "persistence_input_invalid",
    });
    await expect(
      operations.get({ grantId: "", chainId: 1, kind: "execution" as const }),
    ).rejects.toMatchObject({
      code: "persistence_input_invalid",
    });
    await expect(
      operations.get({ grantId: "g", chainId: 1, kind: "renewal" as never }),
    ).rejects.toMatchObject({
      code: "persistence_input_invalid",
    });
    await expect(cleanup.read("")).rejects.toMatchObject({ code: "persistence_input_invalid" });
    await expect(context.read("")).rejects.toMatchObject({ code: "persistence_input_invalid" });

    const database = await openOaathDatabase({ factory: new IDBFactory() });
    try {
      await expect(createIndexedDbGrantStoreAdapter(database).get("")).rejects.toMatchObject({
        code: "persistence_input_invalid",
      });
      await expect(
        createIndexedDbOperationStoreAdapter(database).get({
          grantId: "g",
          chainId: 0,
          kind: "execution" as const,
        }),
      ).rejects.toMatchObject({ code: "persistence_input_invalid" });
      await expect(
        createIndexedDbOperationStoreAdapter(database).get({
          grantId: "g",
          chainId: 1,
          kind: "renewal" as never,
        }),
      ).rejects.toMatchObject({ code: "persistence_input_invalid" });
    } finally {
      database.close();
    }
  });

  it("refuses an unusable IndexedDB realm", async () => {
    await expect(openOaathDatabase({ factory: {} as unknown as IDBFactory })).rejects.toMatchObject(
      { code: "persistence_unavailable" },
    );
    await expect(openOaathDatabase({ factory: new IDBFactory(), name: "" })).rejects.toMatchObject({
      code: "persistence_input_invalid",
    });
    const database = await openOaathDatabase({ factory: new IDBFactory() });
    database.close();
    await expect(
      database.transact(["grants"], "readonly", async () => undefined),
    ).rejects.toMatchObject({ code: "persistence_unavailable" });
  });
});
