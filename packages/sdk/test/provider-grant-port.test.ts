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
import { grantProviderPort, type OaathGrantProviderPort } from "../src/client/grant-handle.js";
import type { OaathGrantHandle } from "../src/index.js";
import * as publicSdk from "../src/index.js";
import {
  bindingInput,
  CHAIN_ID,
  type ChainFixture,
  createChainFixture,
  createRealm,
  permissionInput,
  sendCallsInput,
} from "./support/browser.js";

type OperationBinding = Readonly<{
  key: Readonly<OperationStoreKey>;
  userOperationHash: `0x${string}`;
}>;

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

describe("private Grant provider port", () => {
  it("resolves only genuine handles and exposes one immutable opaque realm scope", async () => {
    const { realm, connection, grant, port } = await activeGrant();

    expect(Object.isFrozen(port)).toBe(true);
    expect(port.providerScopeId).toBe(realm.oaath.binding.bindingId);
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

    const starting = port.startCalls(sendCallsInput(), async (operation) => {
      bindCalls += 1;
      binding = operation;
      enterBinding();
      await bindingReleased;
    });
    await bindingEntered;

    const exact = requireBinding(binding);
    expect(Object.isFrozen(exact)).toBe(true);
    expect(Object.isFrozen(exact.key)).toBe(true);
    expect(Reflect.set(exact.key, "chainId", 1)).toBe(false);
    expect(await journal.get(exact.key)).toBeUndefined();
    expect(realm.chain.signatures).toHaveLength(0);
    expect(realm.chain.sends).toHaveLength(0);

    releaseBinding();
    const operation = await starting;
    expect(bindCalls).toBe(1);
    expect(operation.outcome).toMatchObject({ status: "pending", state: "submitted" });
    expect(observed.reads()).toBe(0);
    expect(realm.chain.sends).toHaveLength(1);
    expect(realm.chain.sends[0]?.userOperationHash).toBe(exact.userOperationHash);
    expect((await journal.get(exact.key))?.value.identity.userOperationHash).toBe(
      exact.userOperationHash,
    );

    await connection.close();
  });

  it("leaves no operation journal or send when binding refuses", async () => {
    const { realm, connection, port } = await activeGrant();
    const journal = new OperationStore(realm.stores.operations);
    let binding: OperationBinding | null = null;

    await expect(
      port.startCalls(sendCallsInput(), async (operation) => {
        binding = operation;
        throw new Error("provider registry refused the binding");
      }),
    ).rejects.toMatchObject({
      code: "oaath_client_preparation_failed",
      source: "operation_runner_preparation_failed",
    });

    const refused = requireBinding(binding);
    expect(await journal.get(refused.key)).toBeUndefined();
    expect(realm.chain.signatures).toHaveLength(0);
    expect(realm.chain.sends).toHaveLength(0);

    await connection.close();
  });

  it("observes only the started hash and records delayed materialization once", async () => {
    const observed = countingChain();
    const { realm, connection, grant, port } = await activeGrant(observed.chain);
    let binding: OperationBinding | null = null;

    const first = await port.startCalls(sendCallsInput(), async (operation) => {
      binding = operation;
    });
    const started = requireBinding(binding);
    expect(observed.reads()).toBe(0);
    expect(realm.chain.sends).toHaveLength(1);

    const finalized = await first.wait({ attempts: 1 });
    expect(finalized).toMatchObject({ status: "finalized", outcome: "success" });
    const finalizedReceipt = await first.receipt();
    expect(realm.chain.sends).toHaveLength(1);
    expect(realm.chain.sends[0]?.userOperationHash).toBe(started.userOperationHash);
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
    expect(secondPrepared.userOperationHash).not.toBe(started.userOperationHash);

    const readsBeforeOldObservation = observed.reads();
    await expect(first.observe()).resolves.toEqual(finalized);
    await expect(first.receipt()).resolves.toEqual(finalizedReceipt);
    expect(observed.reads()).toBeGreaterThan(readsBeforeOldObservation);
    expect(realm.chain.sends).toHaveLength(2);
    expect(first.outcome).toEqual(finalized);

    await connection.close();
  });
});
