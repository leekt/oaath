/**
 * The private Grant-to-provider operation boundary.
 *
 * @author taek <leekt216@gmail.com>
 */
import { describe, expect, it } from "vitest";
import {
  type OaathChainCapability,
  OperationStore,
  type OperationStoreKey,
} from "../src/advanced.js";
import {
  grantProviderPort,
  type OaathGrantProviderPort,
  type OaathProviderOperationPointer,
} from "../src/client/grant-handle.js";
import type { OaathGrantHandle } from "../src/index.js";
import * as publicSdk from "../src/index.js";
import {
  ACCOUNT,
  bindingInput,
  CHAIN_ID,
  type ChainFixture,
  createChainFixture,
  createMemoryStores,
  createRealm,
  permissionInput,
  sendCallsInput,
} from "./support/browser.js";

type OperationBinding = OaathProviderOperationPointer;

const REQUEST_HASH = `0x${"ab".repeat(32)}` as const;

function providerCallsInput() {
  const input = sendCallsInput();
  if (input === null || typeof input !== "object") throw new Error("expected calls input");
  return Object.freeze({ ...input, requestHash: REQUEST_HASH, paymaster: null });
}

async function activeGrant(chain?: ChainFixture): Promise<
  Readonly<{
    realm: ReturnType<typeof createRealm>;
    connection: Awaited<ReturnType<ReturnType<typeof createRealm>["oaath"]["connect"]>>;
    grant: Readonly<OaathGrantHandle>;
    port: Readonly<OaathGrantProviderPort>;
  }>
> {
  const realm = createRealm(chain ? { chain } : {});
  const connection = await realm.oaath.connect();
  const grant = await connection.requestPermission(permissionInput());
  return Object.freeze({ realm, connection, grant, port: grantProviderPort(grant) });
}

function countingChain(): Readonly<{ chain: ChainFixture; reads: () => number }> {
  const base = createChainFixture();
  let reads = 0;
  let activeHash: string | undefined;
  const operationReceipts = new Map<string, unknown>();
  const transactionReceipts = new Map<string, unknown>();
  const read: OaathChainCapability["observation"]["read"] = async (request) => {
    reads += 1;
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
  const chain: ChainFixture = {
    capability: Object.freeze({
      ...base.capability,
      observation: Object.freeze({
        read,
        close: () => base.capability.observation.close(),
      }),
    }),
    sends: base.sends,
    signatures: base.signatures,
    get quotes() {
      return base.quotes;
    },
  };
  return Object.freeze({ chain, reads: () => reads });
}

function requireBinding(value: OperationBinding | null): OperationBinding {
  if (value === null) throw new Error("expected the operation binding");
  return value;
}

function operationKey(value: OperationBinding): Readonly<OperationStoreKey> {
  return Object.freeze({
    grantId: value.identity.grantId,
    chainId: value.identity.chainId,
    kind: value.identity.kind,
  });
}

describe("private Grant provider port", () => {
  it("resolves only genuine handles and exposes one immutable opaque realm scope", async () => {
    const { realm, connection, grant, port } = await activeGrant();

    expect(Object.isFrozen(port)).toBe(true);
    expect(port.providerScopeId).toBe(realm.oaath.binding.bindingId);
    expect(port.grantId).toMatch(/\S/u);
    expect(port.providerScopeId).toMatch(/^0x[0-9a-f]{64}$/u);
    expect([
      bindingInput.applicationId,
      bindingInput.clientId,
      bindingInput.origin,
      bindingInput.deviceId,
    ]).not.toContain(port.providerScopeId);
    expect(Reflect.set(port, "providerScopeId", "app-selected-scope")).toBe(false);
    expect(port.account).toBe(grant.account);
    expect(await port.account(CHAIN_ID)).toBe(await grant.account(CHAIN_ID));
    expect("grantProviderPort" in publicSdk).toBe(false);

    expect(() => grantProviderPort({ ...grant })).toThrowError(
      expect.objectContaining({ code: "oaath_client_capability_invalid" }),
    );
    expect(() => grantProviderPort(Object.create(grant))).toThrowError(
      expect.objectContaining({ code: "oaath_client_capability_invalid" }),
    );

    await connection.close();
  });

  it("awaits one exact immutable binding before journal publication, signing, or send", async () => {
    const observed = countingChain();
    const { realm, connection, port } = await activeGrant(observed.chain);
    const journal = new OperationStore(realm.stores.operations);
    let binding: OperationBinding | null = null;
    let bindCalls = 0;
    let enterBinding!: () => void;
    let releaseBinding!: () => void;
    const bindingEntered = new Promise<void>((resolve) => {
      enterBinding = resolve;
    });
    const bindingReleased = new Promise<void>((resolve) => {
      releaseBinding = resolve;
    });

    const starting = port.startCalls(
      providerCallsInput(),
      Object.freeze({
        reserve: async (operation: OaathProviderOperationPointer) => {
          bindCalls += 1;
          binding = operation;
          enterBinding();
          await bindingReleased;
        },
        confirm: async () => undefined,
        abandon: async () => undefined,
      }),
    );
    await bindingEntered;

    const exact = requireBinding(binding);
    expect(Object.isFrozen(exact)).toBe(true);
    expect(Object.isFrozen(exact.identity)).toBe(true);
    expect(Reflect.set(exact.identity, "chainId", 1)).toBe(false);
    expect(await journal.get(operationKey(exact))).toBeUndefined();
    expect(realm.chain.signatures).toHaveLength(0);
    expect(realm.chain.sends).toHaveLength(0);

    releaseBinding();
    const operation = await starting;
    expect(bindCalls).toBe(1);
    expect(operation.outcome).toMatchObject({ status: "pending", state: "submitted" });
    expect(observed.reads()).toBe(0);
    expect(realm.chain.sends).toHaveLength(1);
    expect(realm.chain.sends[0]?.userOperationHash).toBe(exact.identity.userOperationHash);
    expect((await journal.get(operationKey(exact)))?.value.identity.userOperationHash).toBe(
      exact.identity.userOperationHash,
    );

    await connection.close();
  });

  it("leaves no operation journal or send when binding refuses", async () => {
    const { realm, connection, port } = await activeGrant();
    const journal = new OperationStore(realm.stores.operations);
    let binding: OperationBinding | null = null;

    await expect(
      port.startCalls(
        providerCallsInput(),
        Object.freeze({
          reserve: async (operation: OaathProviderOperationPointer) => {
            binding = operation;
            throw new Error("provider registry refused the binding");
          },
          confirm: async () => undefined,
          abandon: async () => undefined,
        }),
      ),
    ).rejects.toMatchObject({
      code: "oaath_client_preparation_failed",
      source: "operation_runner_preparation_failed",
    });

    const refused = requireBinding(binding);
    expect(await journal.get(operationKey(refused))).toBeUndefined();
    expect(realm.chain.signatures).toHaveLength(0);
    expect(realm.chain.sends).toHaveLength(0);

    await connection.close();
  });

  it("lets revocation cancel delayed pre-publication work before signing or send", async () => {
    const base = createChainFixture();
    let enterProbe!: () => void;
    let releaseProbe!: () => void;
    const probeEntered = new Promise<void>((resolve) => {
      enterProbe = resolve;
    });
    const probeReleased = new Promise<void>((resolve) => {
      releaseProbe = resolve;
    });
    const chain: ChainFixture = {
      capability: Object.freeze({
        ...base.capability,
        bundler: Object.freeze({
          async probe(request: Parameters<OaathChainCapability["bundler"]["probe"]>[0]) {
            enterProbe();
            await probeReleased;
            return base.capability.bundler.probe(request);
          },
        }),
      }),
      sends: base.sends,
      signatures: base.signatures,
      get quotes() {
        return base.quotes;
      },
    };
    const { connection, grant } = await activeGrant(chain);
    const sending = grant.sendCalls(sendCallsInput());
    await probeEntered;
    const revoking = grant.revoke();
    releaseProbe();

    await expect(sending).rejects.toMatchObject({
      code: "oaath_client_grant_inactive",
      source: "grant_revocation_requested",
    });
    await revoking;
    expect(grant.state).toBe("revoked");
    expect(base.signatures).toHaveLength(0);
    expect(base.sends).toHaveLength(0);
    await connection.close();
  });

  it("rejects publication after another handle durably revokes the Grant", async () => {
    const base = createChainFixture();
    let enterProbe!: () => void;
    let releaseProbe!: () => void;
    const probeEntered = new Promise<void>((resolve) => {
      enterProbe = resolve;
    });
    const probeReleased = new Promise<void>((resolve) => {
      releaseProbe = resolve;
    });
    const chain: ChainFixture = {
      capability: Object.freeze({
        ...base.capability,
        bundler: Object.freeze({
          async probe(request: Parameters<OaathChainCapability["bundler"]["probe"]>[0]) {
            enterProbe();
            await probeReleased;
            return base.capability.bundler.probe(request);
          },
        }),
      }),
      sends: base.sends,
      signatures: base.signatures,
      get quotes() {
        return base.quotes;
      },
    };
    const { connection, grant } = await activeGrant(chain);
    const revoker = await connection.resume();
    if (revoker === null) throw new Error("expected a second genuine Grant handle");
    const sending = grant.sendCalls(sendCallsInput());
    await probeEntered;
    await revoker.revoke();
    releaseProbe();

    await expect(sending).rejects.toMatchObject({ code: "oaath_client_grant_inactive" });
    expect(grant.state).toBe("revoked");
    expect(revoker.state).toBe("revoked");
    expect(base.signatures).toHaveLength(0);
    expect(base.sends).toHaveLength(0);
    await connection.close();
  });

  it("abandons a published operation when another handle wins Grant admission", async () => {
    const baseStores = createMemoryStores();
    let gateAuthorization = false;
    let authorizationBlocked = false;
    let binding: OperationBinding | null = null;
    let enterAuthorization!: () => void;
    let releaseAuthorization!: () => void;
    const authorizationEntered = new Promise<void>((resolve) => {
      enterAuthorization = resolve;
    });
    const authorizationReleased = new Promise<void>((resolve) => {
      releaseAuthorization = resolve;
    });
    const stores = {
      ...baseStores,
      grants: {
        async get(grantId: Parameters<typeof baseStores.grants.get>[0]) {
          const current = await baseStores.grants.get(grantId);
          if (gateAuthorization && binding !== null && !authorizationBlocked) {
            authorizationBlocked = true;
            enterAuthorization();
            await authorizationReleased;
          }
          return current;
        },
        compareAndSwap: (value: Parameters<typeof baseStores.grants.compareAndSwap>[0]) =>
          baseStores.grants.compareAndSwap(value),
        close: () => baseStores.grants.close(),
      },
    };
    const realm = createRealm({ stores });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const revoker = await connection.resume();
    if (revoker === null) throw new Error("expected a second genuine Grant handle");
    const port = grantProviderPort(grant);
    const journal = new OperationStore(realm.stores.operations);
    let abandonments = 0;
    gateAuthorization = true;

    const starting = port.startCalls(
      providerCallsInput(),
      Object.freeze({
        reserve: async (operation: OaathProviderOperationPointer) => {
          binding = operation;
        },
        confirm: async () => undefined,
        abandon: async () => {
          abandonments += 1;
        },
      }),
    );
    await authorizationEntered;
    const exact = requireBinding(binding);
    expect((await journal.get(operationKey(exact)))?.value.state).toBe("prepared");

    await revoker.revoke();
    releaseAuthorization();
    await expect(starting).rejects.toMatchObject({
      code: "oaath_client_preparation_failed",
      source: "operation_runner_preparation_failed",
    });

    expect((await journal.get(operationKey(exact)))?.value).toMatchObject({
      state: "abandoned",
      identity: { userOperationHash: exact.identity.userOperationHash },
    });
    expect(revoker.state).toBe("revoked");
    expect(abandonments).toBe(1);
    expect(realm.chain.signatures).toHaveLength(0);
    expect(realm.chain.sends).toHaveLength(0);
    await connection.close();
  });

  it("drains admitted work before close and blocks its later publication", async () => {
    const base = createChainFixture();
    let enterProbe!: () => void;
    let releaseProbe!: () => void;
    const probeEntered = new Promise<void>((resolve) => {
      enterProbe = resolve;
    });
    const probeReleased = new Promise<void>((resolve) => {
      releaseProbe = resolve;
    });
    const chain: ChainFixture = {
      capability: Object.freeze({
        ...base.capability,
        bundler: Object.freeze({
          async probe(request: Parameters<OaathChainCapability["bundler"]["probe"]>[0]) {
            enterProbe();
            await probeReleased;
            return base.capability.bundler.probe(request);
          },
        }),
      }),
      sends: base.sends,
      signatures: base.signatures,
      get quotes() {
        return base.quotes;
      },
    };
    const { connection, grant } = await activeGrant(chain);
    const sending = grant.sendCalls(sendCallsInput());
    await probeEntered;
    let closeSettled = false;
    const closing = grant.close().then(() => {
      closeSettled = true;
    });
    await Promise.resolve();
    expect(closeSettled).toBe(false);
    releaseProbe();

    await expect(sending).rejects.toMatchObject({ code: "oaath_client_closed" });
    await closing;
    expect(closeSettled).toBe(true);
    expect(base.signatures).toHaveLength(0);
    expect(base.sends).toHaveLength(0);
    await connection.close();
  });

  it("observes only the started hash and records delayed materialization once", async () => {
    const observed = countingChain();
    const { realm, connection, grant, port } = await activeGrant(observed.chain);
    let binding: OperationBinding | null = null;

    const first = await port.startCalls(
      providerCallsInput(),
      Object.freeze({
        reserve: async (operation: OaathProviderOperationPointer) => {
          binding = operation;
        },
        confirm: async () => undefined,
        abandon: async () => undefined,
      }),
    );
    const started = requireBinding(binding);
    expect(observed.reads()).toBe(0);
    expect(realm.chain.sends).toHaveLength(1);

    const finalized = await first.wait({ attempts: 1 });
    expect(finalized).toMatchObject({ status: "finalized", outcome: "success" });
    const finalizedReceipt = await first.receipt();
    expect(realm.chain.sends).toHaveLength(1);
    expect(realm.chain.sends[0]?.userOperationHash).toBe(started.identity.userOperationHash);
    expect(observed.reads()).toBeGreaterThan(0);

    const firstPrepared = realm.chain.sends[0];
    if (!firstPrepared) throw new Error("expected the provider-started operation");
    expect((BigInt(firstPrepared.userOperation.nonce) >> 248n) & 0xffn).toBe(0x0cn);

    const second = await grant.sendCalls(sendCallsInput());
    expect(second.outcome.status).toBe("finalized");
    expect(realm.chain.sends).toHaveLength(2);
    const secondPrepared = realm.chain.sends[1];
    if (!secondPrepared) throw new Error("expected the replacing direct operation");
    expect((BigInt(secondPrepared.userOperation.nonce) >> 248n) & 0xffn).toBe(0n);
    expect(secondPrepared.userOperationHash).not.toBe(started.identity.userOperationHash);

    const readsBeforeOldObservation = observed.reads();
    await expect(first.observe()).resolves.toEqual(finalized);
    await expect(first.receipt()).resolves.toEqual(finalizedReceipt);
    expect(observed.reads()).toBeGreaterThan(readsBeforeOldObservation);
    expect(realm.chain.sends).toHaveLength(2);
    expect(first.outcome).toEqual(finalized);

    await connection.close();
  });

  it("preserves exact finality when materialization bookkeeping fails once", async () => {
    const memory = createMemoryStores();
    let installationFailures = 1;
    const realm = createRealm({
      stores: {
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
      },
    });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const port = grantProviderPort(grant);
    let binding: OperationBinding | null = null;
    const operation = await port.startCalls(
      providerCallsInput(),
      Object.freeze({
        reserve: async (exact: OaathProviderOperationPointer) => {
          binding = exact;
        },
        confirm: async () => undefined,
        abandon: async () => undefined,
      }),
    );

    await expect(operation.wait({ attempts: 1 })).resolves.toMatchObject({
      status: "finalized",
      outcome: "success",
    });
    const exact = requireBinding(binding);
    await expect(memory.grants.get(exact.identity.grantId)).resolves.toMatchObject({
      value: { materializations: [{ state: "installing" }] },
    });
    await expect(operation.observe()).resolves.toMatchObject({ status: "finalized" });
    await expect(memory.grants.get(exact.identity.grantId)).resolves.toMatchObject({
      value: { materializations: [{ state: "installed" }] },
    });
    expect(realm.chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("reconciles a finalized installing operation before revocation after reload-style loss", async () => {
    const memory = createMemoryStores();
    let rejectInstallation = true;
    const chain = createChainFixture({ operationSuccess: (index) => index !== 0 });
    const realm = createRealm({
      chain,
      stores: {
        ...memory,
        grants: {
          get: (grantId: Parameters<typeof memory.grants.get>[0]) => memory.grants.get(grantId),
          compareAndSwap: (input: Parameters<typeof memory.grants.compareAndSwap>[0]) => {
            const grant = input.next.value as {
              readonly materializations?: readonly Readonly<{ state?: unknown }>[];
            };
            if (
              rejectInstallation &&
              grant.materializations?.some((entry) => entry.state === "installed")
            ) {
              throw new Error("installation bookkeeping unavailable");
            }
            return memory.grants.compareAndSwap(input);
          },
          close: () => memory.grants.close(),
        },
      },
    });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const port = grantProviderPort(grant);
    const operation = await port.startCalls(
      providerCallsInput(),
      Object.freeze({
        reserve: async () => undefined,
        confirm: async () => undefined,
        abandon: async () => undefined,
      }),
    );

    await expect(operation.wait({ attempts: 1 })).resolves.toMatchObject({
      status: "finalized",
      outcome: "reverted",
    });
    await expect(memory.grants.get(port.grantId)).resolves.toMatchObject({
      value: { materializations: [{ state: "installing" }] },
    });

    rejectInstallation = false;
    await grant.revoke();

    expect(grant.state).toBe("revoked");
    expect(chain.sends).toHaveLength(2);
    await connection.close();
  });

  it("observes a submitted installation during revocation without resubmitting it", async () => {
    const chain = createChainFixture({ operationSuccess: (index) => index !== 0 });
    const { realm, connection, grant, port } = await activeGrant(chain);
    const operation = await port.startCalls(
      providerCallsInput(),
      Object.freeze({
        reserve: async () => undefined,
        confirm: async () => undefined,
        abandon: async () => undefined,
      }),
    );
    await operation.close();
    await expect(realm.stores.grants.get(port.grantId)).resolves.toMatchObject({
      value: { materializations: [{ state: "installing" }] },
    });
    expect(chain.sends).toHaveLength(1);

    await grant.revoke();

    expect(grant.state).toBe("revoked");
    expect(chain.sends).toHaveLength(2);
    await connection.close();
  });

  it("revokes permission installed during validation when execution reverts", async () => {
    const chain = createChainFixture({ operationSuccess: (index) => index !== 0 });
    const { realm, connection, grant, port } = await activeGrant(chain);
    let binding: OperationBinding | null = null;
    const operation = await port.startCalls(
      providerCallsInput(),
      Object.freeze({
        reserve: async (exact: OaathProviderOperationPointer) => {
          binding = exact;
        },
        confirm: async () => undefined,
        abandon: async () => undefined,
      }),
    );

    await expect(operation.wait({ attempts: 1 })).resolves.toMatchObject({
      status: "finalized",
      outcome: "reverted",
    });
    const exact = requireBinding(binding);
    await expect(realm.stores.grants.get(exact.identity.grantId)).resolves.toMatchObject({
      value: { materializations: [{ state: "installed" }] },
    });

    await grant.revoke();
    expect(grant.state).toBe("revoked");
    expect(chain.sends).toHaveLength(2);
    await connection.close();
  });

  it("keeps a nonce-superseded installation unresolved during revocation", async () => {
    const chain = createChainFixture({
      withholdReceipt: () => true,
      entryPointNonce: (nonce) => String(BigInt(nonce) + 1n),
    });
    const { realm, connection, grant, port } = await activeGrant(chain);
    let binding: OperationBinding | null = null;
    const operation = await port.startCalls(
      providerCallsInput(),
      Object.freeze({
        reserve: async (exact: OaathProviderOperationPointer) => {
          binding = exact;
        },
        confirm: async () => undefined,
        abandon: async () => undefined,
      }),
    );

    await expect(operation.wait({ attempts: 1 })).resolves.toMatchObject({ status: "superseded" });
    const exact = requireBinding(binding);
    await grant.revoke();

    expect(grant.state).toBe("revoking");
    await expect(realm.stores.grants.get(exact.identity.grantId)).resolves.toMatchObject({
      value: { materializations: [{ state: "installing" }] },
    });
    expect(chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("does not mint an uninstall while the revocation journal is unreadable", async () => {
    const memory = createMemoryStores();
    let failRevocationRead = false;
    let blockOffset = 0;
    const chain = createChainFixture({
      permissionInstalled: () => true,
      blockOffset: () => blockOffset,
    });
    const realm = createRealm({
      chain,
      stores: {
        ...memory,
        operations: {
          async get(key: Parameters<typeof memory.operations.get>[0]) {
            if (failRevocationRead && key.kind === "revocation") {
              failRevocationRead = false;
              throw new Error("revocation journal unavailable");
            }
            return memory.operations.get(key);
          },
          getArchived: (input: Parameters<typeof memory.operations.getArchived>[0]) =>
            memory.operations.getArchived(input),
          compareAndSwap: (input: Parameters<typeof memory.operations.compareAndSwap>[0]) =>
            memory.operations.compareAndSwap(input),
          close: () => memory.operations.close(),
        },
      },
    });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const installation = await grant.sendCalls(sendCallsInput());
    expect((await installation.wait()).status).toBe("finalized");
    blockOffset = 1;
    failRevocationRead = true;

    await grant.revoke();

    expect(grant.state).toBe("revoking");
    expect(chain.sends).toHaveLength(1);

    await grant.revoke();

    expect(grant.state).toBe("revoked");
    expect(chain.sends).toHaveLength(2);
    await connection.close();
  });

  it("requires finalized permission presence before replacing a superseded uninstall", async () => {
    let withholdReceipt = false;
    let supersede = false;
    let installed: boolean | null = null;
    let blockOffset = 0;
    const chain = createChainFixture({
      withholdReceipt: () => withholdReceipt,
      entryPointNonce: (nonce) => (supersede ? String(BigInt(nonce) + 1n) : null),
      permissionInstalled: () => installed,
      blockOffset: () => blockOffset,
    });
    const { connection, grant } = await activeGrant(chain);
    const installation = await grant.sendCalls(sendCallsInput());
    expect((await installation.wait()).status).toBe("finalized");

    withholdReceipt = true;
    supersede = true;
    blockOffset = 1;
    await grant.revoke();
    expect(grant.state).toBe("revoking");
    expect(chain.sends).toHaveLength(2);

    await grant.revoke();
    expect(grant.state).toBe("revoking");
    expect(chain.sends).toHaveLength(2);

    installed = true;
    withholdReceipt = false;
    supersede = false;
    blockOffset = 2;
    await grant.revoke();
    expect(grant.state).toBe("revoked");
    expect(chain.sends).toHaveLength(3);
    await connection.close();
  });

  it("rejects recovery pointers for another Grant or account before observation", async () => {
    const observed = countingChain();
    const { connection, port } = await activeGrant(observed.chain);
    let binding: OperationBinding | null = null;
    const operation = await port.startCalls(
      providerCallsInput(),
      Object.freeze({
        reserve: async (exact: OaathProviderOperationPointer) => {
          binding = exact;
        },
        confirm: async () => undefined,
        abandon: async () => undefined,
      }),
    );
    await operation.close();
    const exact = requireBinding(binding);
    const readsBefore = observed.reads();

    await expect(
      port.recoverOperation({
        identity: { ...exact.identity, grantId: "foreign-grant" },
      }),
    ).rejects.toMatchObject({ source: "provider_operation_grant_mismatch" });
    await expect(
      port.recoverOperation({
        identity: { ...exact.identity, account: `0x${"99".repeat(20)}` },
      }),
    ).rejects.toMatchObject({ source: "provider_operation_identity_mismatch" });
    await expect(
      port.recoverOperation({
        identity: { ...exact.identity, entryPoint: `0x${"98".repeat(20)}` },
      }),
    ).rejects.toMatchObject({ source: "provider_operation_identity_mismatch" });
    await expect(
      port.recoverOperation({
        identity: { ...exact.identity, nonce: "1" },
      }),
    ).rejects.toMatchObject({ source: "provider_operation_identity_mismatch" });
    await expect(
      port.recoverOperation({
        identity: { ...exact.identity, requestHash: `0x${"cd".repeat(32)}` },
      }),
    ).resolves.toEqual({ status: "request_conflict" });
    expect(observed.reads()).toBe(readsBefore);

    await connection.close();
  });

  it("drains a recovered Operation handle created while its Grant closes", async () => {
    const memory = createMemoryStores();
    let gateRead = false;
    let readBlocked = false;
    let enterRead!: () => void;
    let releaseRead!: () => void;
    const readEntered = new Promise<void>((resolve) => {
      enterRead = resolve;
    });
    const readReleased = new Promise<void>((resolve) => {
      releaseRead = resolve;
    });
    const realm = createRealm({
      stores: {
        ...memory,
        operations: {
          get: async (key: Parameters<typeof memory.operations.get>[0]) => {
            const value = await memory.operations.get(key);
            if (gateRead && !readBlocked) {
              readBlocked = true;
              enterRead();
              await readReleased;
            }
            return value;
          },
          getArchived: (input: Parameters<typeof memory.operations.getArchived>[0]) =>
            memory.operations.getArchived(input),
          compareAndSwap: (input: Parameters<typeof memory.operations.compareAndSwap>[0]) =>
            memory.operations.compareAndSwap(input),
          close: () => memory.operations.close(),
        },
      },
    });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const port = grantProviderPort(grant);
    let binding: OperationBinding | null = null;
    const started = await port.startCalls(
      providerCallsInput(),
      Object.freeze({
        reserve: async (operation: OaathProviderOperationPointer) => {
          binding = operation;
        },
        confirm: async () => undefined,
        abandon: async () => undefined,
      }),
    );
    await started.close();
    const exact = requireBinding(binding);
    gateRead = true;

    const recovering = port.recoverOperation(exact);
    await readEntered;
    let closeSettled = false;
    const closing = grant.close().then(() => {
      closeSettled = true;
    });
    await Promise.resolve();
    expect(closeSettled).toBe(false);
    releaseRead();

    const recovered = await recovering;
    expect(recovered.status).toBe("observable");
    await closing;
    if (recovered.status !== "observable") throw new Error("expected an Operation handle");
    await expect(recovered.operation.observe()).rejects.toMatchObject({
      code: "oaath_client_closed",
    });
    await connection.close();
  });
});
