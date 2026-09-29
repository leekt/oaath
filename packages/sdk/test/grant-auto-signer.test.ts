import { IDBFactory } from "fake-indexeddb";
import { afterEach, describe, expect, it, vi } from "vitest";
import { defaultStores } from "../src/client/browser-stores.js";
import { credentialKey } from "../src/kernel/key/credential.js";
import { selectAutoSigner } from "../src/routing/auto.js";
import {
  CALL_DATA,
  CHAIN_ID,
  createChainFixture,
  createRealm,
  ownerCredential,
  permissionInput,
  type RealmStores,
  sendCallsInput,
  signingProfiles,
  TARGET,
  VALIDATOR,
} from "./support/browser.js";

const autoCalls = () => ({
  chain: CHAIN_ID,
  calls: [{ target: TARGET, data: CALL_DATA, value: "0" }],
  signer: "auto",
});
afterEach(() => vi.unstubAllGlobals());

describe("explicit Grant signer auto", () => {
  it("routes an unavailable owner or multi-operation plan to session before execution", () => {
    expect(selectAutoSigner(true, true).signer).toBe("owner");
    expect(selectAutoSigner(false, true)).toEqual({
      signer: "session",
      reason: "session_auto_owner_unavailable",
    });
    expect(selectAutoSigner(true, false)).toEqual({
      signer: "session",
      reason: "session_auto_multiple_operations",
    });
  });
  it("reviews and executes root authority without session installation", async () => {
    const signing = signingProfiles();
    const ownerSign = vi.fn(signing.owner.sign);
    const sessionSign = vi.fn(signing.session.sign);
    const realm = createRealm({
      signing: {
        owner: { ...signing.owner, sign: ownerSign },
        session: { ...signing.session, sign: sessionSign },
      },
    });
    const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
    const review = await grant.reviewCalls(autoCalls());
    expect(review).toMatchObject({
      signer: "owner",
      validation: "not-estimated",
      enableVerificationGasFloor: null,
      enforcement: { calls: "none", expiry: "client", operationCount: "none" },
      validAfter: null,
      validUntil: null,
      perChainOperationLimit: null,
    });
    expect(review.reasons).toContain("owner_auto_single_operation");
    expect(realm.chain.quotes).toBe(0);
    expect(ownerSign).not.toHaveBeenCalled();
    const operation = await grant.sendCalls(autoCalls());
    expect((await operation.wait()).status).toBe("finalized");
    expect(ownerSign).toHaveBeenCalledTimes(1);
    expect(sessionSign).not.toHaveBeenCalled();
    expect(BigInt(realm.chain.sends[0]!.userOperation.nonce) >> 248n).toBe(0n);
    const saved = (await realm.stores.grants.get(review.grantId)) as {
      value: { materializations: unknown[] };
    };
    expect(saved.value.materializations).toHaveLength(0);
    await realm.oaath.close();
  });

  it("selects session with a public-only owner profile and keeps default session behavior", async () => {
    const signing = signingProfiles();
    const realm = createRealm({
      signing: {
        ...signing,
        owner: credentialKey({ credential: ownerCredential, validator: VALIDATOR }),
      },
    });
    const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
    const review = await grant.reviewCalls(autoCalls());
    expect(review.signer).toBe("session");
    expect(review.reasons).toContain("session_auto_owner_unavailable");
    expect((await (await grant.sendCalls(autoCalls())).wait()).status).toBe("finalized");
    await realm.oaath.close();
    const available = createRealm();
    const defaultGrant = await (await available.oaath.connect()).requestPermission(
      permissionInput(),
    );
    expect((await defaultGrant.reviewCalls(sendCallsInput())).signer).toBe("session");
    await available.oaath.close();
  });

  it("keeps session estimation separate from owner selection and sending", async () => {
    const available = createRealm();
    const ownerGrant = await (await available.oaath.connect()).requestPermission(permissionInput());
    await expect(ownerGrant.reviewCalls({ ...autoCalls(), estimate: true })).rejects.toMatchObject({
      source: "session_estimation_unavailable",
    });
    expect(available.chain.quotes).toBe(0);
    expect(available.chain.signatures).toHaveLength(0);
    expect(available.chain.sends).toHaveLength(0);
    await available.oaath.close();

    const signing = signingProfiles();
    const realm = createRealm({
      signing: {
        ...signing,
        owner: credentialKey({ credential: ownerCredential, validator: VALIDATOR }),
      },
    });
    const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
    expect(await grant.reviewCalls({ ...autoCalls(), estimate: true })).toMatchObject({
      signer: "session",
      validation: "estimated",
    });
    expect(realm.chain.quotes).toBe(1);
    await expect(grant.sendCalls({ ...autoCalls(), estimate: true })).rejects.toMatchObject({
      code: "oaath_client_input_invalid",
    });
    expect(realm.chain.signatures).toHaveLength(0);
    expect(realm.chain.sends).toHaveLength(0);
    await realm.oaath.close();
  });

  it("does not try a session signature after the selected owner rejects signing", async () => {
    const signing = signingProfiles();
    const ownerSign = vi.fn(async () => {
      throw new Error("wallet rejected");
    });
    const sessionSign = vi.fn(signing.session.sign);
    const realm = createRealm({
      signing: {
        owner: { ...signing.owner, sign: ownerSign },
        session: { ...signing.session, sign: sessionSign },
      },
    });
    const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
    await grant.sendCalls(autoCalls()).catch(() => undefined);
    expect(ownerSign).toHaveBeenCalledTimes(1);
    expect(sessionSign).not.toHaveBeenCalled();
    expect(realm.chain.sends).toHaveLength(0);
    await realm.oaath.close();
  });

  it("restores an uncertain owner operation without a second signer or send", async () => {
    let pending = true;
    const chain = createChainFixture({ crashOnSend: () => true, withholdReceipt: () => pending });
    vi.stubGlobal("indexedDB", new IDBFactory());
    let owned = await defaultStores();
    let realm = createRealm({ chain, stores: owned.stores as unknown as RealmStores });
    let grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
    const operation = await grant.sendCalls(autoCalls());
    const { relay, clock } = realm;
    await realm.oaath.close();
    await owned.close();
    owned = await defaultStores();
    realm = createRealm({ stores: owned.stores as unknown as RealmStores, relay, clock, chain });
    grant = (await (await realm.oaath.connect()).resume())!;
    await expect(grant.sendCalls(autoCalls())).rejects.toMatchObject({
      code: "oaath_client_state_conflict",
    });
    await expect(grant.sendCalls(sendCallsInput())).rejects.toMatchObject({
      code: "oaath_client_state_conflict",
    });
    const saved = await grant.getOperation({ chain: CHAIN_ID, id: operation.id });
    expect(saved?.id).toBe(operation.id);
    pending = false;
    expect((await saved?.wait())?.status).toBe("finalized");
    expect(chain.sends).toHaveLength(1);
    await realm.oaath.close();
    await owned.close();
  });
});
