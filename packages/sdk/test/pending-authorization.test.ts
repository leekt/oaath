import { IDBFactory } from "fake-indexeddb";
import { describe, expect, it } from "vitest";
import { forgetLocalEffect } from "../src/cleanup/effects.js";
import { createPendingAuthorizationJournal } from "../src/client/pending-authorization.js";
import { openIndexedDbStores } from "../src/persistence.js";
import {
  createChainFixture,
  createClock,
  createOwnerAuthorization,
  createUrlRealm,
  ISSUER_URL,
  OWNER_TOKEN,
  permissionInput,
  sendCallsInput,
} from "./support/browser.js";

async function pendingFixture(fault: { path?: string } = {}) {
  const factory = new IDBFactory();
  const clock = createClock();
  const chain = createChainFixture();
  const upstream = createUrlRealm({ clock, chain });
  const paths: string[] = [];
  const relay = async (request: Request) => {
    const path = new URL(request.url).pathname;
    paths.push(`${request.method} ${path}`);
    if (path.endsWith("/decision")) return new Response(null, { status: 503 });
    const response = await upstream.relay(request);
    if (path === fault.path || (fault.path === "claim" && path.endsWith("/claim")))
      throw new Error("reply unavailable");
    return response;
  };
  const life = async (failWrite?: number) => {
    const owner = await openIndexedDbStores({ factory });
    let writes = 0;
    const realm = createUrlRealm({
      clock,
      chain,
      relay,
      stores: {
        ...owner.stores,
        context: {
          ...owner.stores.context,
          async compareAndSwapPending(input) {
            writes += 1;
            if (writes === failWrite) throw new Error("write unavailable");
            return owner.stores.context.compareAndSwapPending(input);
          },
        },
      },
    });
    const connection = await realm.oaath.connect();
    return { owner, realm, connection };
  };
  const approve = async (requestId: string) => {
    await createOwnerAuthorization(
      upstream.relay,
      clock,
      {},
      chain.capability.reads,
    ).capability.authorize({ requestId });
  };
  return { life, approve, paths, chain, clock, upstream };
}

async function park(fixture: Awaited<ReturnType<typeof pendingFixture>>) {
  const first = await fixture.life();
  let notify!: (request: { requestId: string }) => void;
  const ready = new Promise<{ requestId: string }>((resolve) => {
    notify = resolve;
  });
  const controller = new AbortController();
  const work = first.connection
    .requestPermission({
      ...(permissionInput() as object),
      signal: controller.signal,
      onPending: notify,
    })
    .catch((error: unknown) => error);
  const pending = await ready;
  controller.abort();
  expect(await work).toMatchObject({
    code: "oaath_client_decision_unavailable",
    source: "authorization_aborted",
  });
  await first.realm.oaath.close();
  await first.owner.close();
  return pending.requestId;
}

describe("durable pending authorization", () => {
  it("reports the owner's rejection after reload without attempting redemption", async () => {
    const fixture = await pendingFixture();
    const requestId = await park(fixture);
    const response = await fixture.upstream.relay(
      new Request(`${ISSUER_URL}/native/decisions/${requestId}`, {
        method: "POST",
        headers: { authorization: `Bearer ${OWNER_TOKEN}`, "content-type": "application/json" },
        body: JSON.stringify({ command: "reject" }),
      }),
    );
    expect(response.ok).toBe(true);
    const current = await fixture.life();
    expect(await current.connection.resumePendingPermission()).toMatchObject({
      requestId,
      status: "rejected",
      grant: null,
    });
    expect(fixture.paths.some((path) => path.includes("/consume") || path.endsWith("/claim"))).toBe(
      false,
    );
    await current.realm.oaath.close();
    await current.owner.close();
    await fixture.upstream.oaath.close();
  });

  it.each([1, 2])(
    "requires durable write %s before exposing the approval handoff",
    async (failWrite) => {
      const fixture = await pendingFixture();
      const current = await fixture.life(failWrite);
      let handoffs = 0;
      await expect(
        current.connection.requestPermission({
          ...(permissionInput() as object),
          onPending: () => {
            handoffs += 1;
          },
        }),
      ).rejects.toMatchObject({ code: "oaath_client_store_unavailable" });
      expect(handoffs).toBe(0);
      expect(fixture.paths.filter((path) => path === "POST /authorization/requests")).toHaveLength(
        failWrite - 1,
      );
      expect(
        fixture.paths.some(
          (path) => path.endsWith("/code") || path.includes("/consume") || path.endsWith("/claim"),
        ),
      ).toBe(false);
      await current.realm.oaath.close();
      await current.owner.close();
      await fixture.upstream.oaath.close();
    },
  );

  it("leaves an already-approved request redeemable after attempted withdrawal", async () => {
    const fixture = await pendingFixture();
    const requestId = await park(fixture);
    await fixture.approve(requestId);
    const current = await fixture.life();
    expect(await current.connection.withdrawPendingPermission()).toMatchObject({
      requestId,
      status: "approved",
      grant: null,
    });
    expect(fixture.paths.some((path) => path.includes("/consume") || path.endsWith("/claim"))).toBe(
      false,
    );
    expect((await current.connection.resumePendingPermission())?.grant?.state).toBe("active");
    await current.realm.oaath.close();
    await current.owner.close();
    await fixture.upstream.oaath.close();
  });

  it("closes polling, recreates every client store and resumes the same approval", async () => {
    const fixture = await pendingFixture();
    const first = await fixture.life();
    expect(typeof first.connection.resumePendingPermission).toBe("function");
    let notify!: (request: { requestId: string }) => void;
    const pending = new Promise<{ requestId: string }>((resolve) => {
      notify = resolve;
    });
    const work = first.connection
      .requestPermission({ ...(permissionInput() as object), onPending: notify })
      .catch((error: unknown) => error);
    const { requestId } = await pending;
    await first.realm.oaath.close();
    expect(await work).toMatchObject({ code: "oaath_client_closed" });
    await first.owner.close();
    const second = await fixture.life();
    expect(await second.connection.resumePendingPermission()).toMatchObject({
      requestId,
      status: "pending",
    });
    await fixture.approve(requestId);
    const result = await second.connection.resumePendingPermission();
    expect(result).toMatchObject({ requestId, status: "approved" });
    if (result?.status !== "approved" || !result.grant)
      throw new Error("approval was not recovered");
    expect((await (await result.grant.sendCalls(sendCallsInput())).wait()).status).toBe(
      "finalized",
    );
    expect(fixture.paths.filter((path) => path === "POST /authorization/requests")).toHaveLength(1);
    await second.realm.oaath.close();
    await second.owner.close();
    await fixture.upstream.oaath.close();
  });
  it("lets two recreated tabs redeem only once and then recover the same Grant", async () => {
    const fixture = await pendingFixture();
    const requestId = await park(fixture);
    await fixture.approve(requestId);
    const [first, second] = await Promise.all([fixture.life(), fixture.life()]);
    const results = await Promise.all([
      first.connection.resumePendingPermission(),
      second.connection.resumePendingPermission(),
    ]);
    expect(results.every((result) => result?.status === "approved")).toBe(true);
    expect(results.some((result) => result?.grant?.state === "active")).toBe(true);
    expect(
      fixture.paths.filter((path) => path === "POST /authorization/codes/consume"),
    ).toHaveLength(1);
    expect(fixture.paths.filter((path) => path.endsWith("/claim"))).toHaveLength(1);
    expect((await second.connection.resumePendingPermission())?.grant?.state).toBe("active");
    await first.realm.oaath.close();
    await second.realm.oaath.close();
    await first.owner.close();
    await second.owner.close();
    await fixture.upstream.oaath.close();
  });

  it.each(["/authorization/codes/consume", "claim"])(
    "never replays %s after losing its acknowledgement",
    async (path) => {
      const fault: { path?: string } = {};
      const fixture = await pendingFixture(fault);
      const requestId = await park(fixture);
      await fixture.approve(requestId);
      fault.path = path;
      const first = await fixture.life();
      await expect(first.connection.resumePendingPermission()).rejects.toMatchObject({
        code: "oaath_client_issuer_unavailable",
      });
      await first.realm.oaath.close();
      await first.owner.close();
      delete fault.path;
      const second = await fixture.life();
      expect(await second.connection.resumePendingPermission()).toMatchObject({
        requestId,
        status: "approved",
        grant: null,
        recovery: "uncertain",
      });
      expect(
        fixture.paths.filter((entry) => entry === "POST /authorization/requests"),
      ).toHaveLength(1);
      expect(
        fixture.paths.filter((entry) => entry === "POST /authorization/codes/consume"),
      ).toHaveLength(1);
      expect(fixture.paths.filter((entry) => entry.endsWith("/claim"))).toHaveLength(
        path === "claim" ? 1 : 0,
      );
      await second.realm.oaath.close();
      await second.owner.close();
      await fixture.upstream.oaath.close();
    },
  );

  it("exposes withdrawal and expiry without creating requests or pretending to revoke approval", async () => {
    const fixture = await pendingFixture();
    const requestId = await park(fixture);
    const restored = await fixture.life();
    expect(await restored.connection.withdrawPendingPermission()).toMatchObject({
      requestId,
      status: "withdrawn",
      grant: null,
    });
    expect(await restored.connection.resumePendingPermission()).toMatchObject({
      status: "withdrawn",
    });
    await restored.realm.oaath.close();
    await restored.owner.close();
    await fixture.upstream.oaath.close();
    const expiring = await pendingFixture();
    await park(expiring);
    expiring.clock.advance(100_000);
    const expired = await expiring.life();
    expect(await expired.connection.resumePendingPermission()).toMatchObject({
      status: "expired",
      grant: null,
    });
    await expired.realm.oaath.close();
    await expired.owner.close();
    await expiring.upstream.oaath.close();
  });

  it("encrypts the verifier, refuses transplanted evidence and retries partial forgetting", async () => {
    const fixture = await pendingFixture();
    await park(fixture);
    const current = await fixture.life();
    const binding = current.realm.oaath.binding;
    const stores = current.owner.stores;
    const journal = createPendingAuthorizationJournal({
      binding,
      sessionSigner: null,
      contexts: stores.context,
      keys: stores.keys,
    });
    const retained = await journal.read();
    if (!retained) throw new Error("journal missing");
    expect(JSON.stringify(retained.envelope).includes(retained.value.verifier)).toBe(false);
    expect(((await stores.keys.get(retained.envelope.keyId)) as CryptoKey).extractable).toBe(false);
    for (const changed of [
      { ...binding, bindingId: `0x${"ff".repeat(32)}` as const },
      { ...binding, redirectUri: "https://another.example/callback" },
      { ...binding, context: { ...binding.context, accountId: "another" } },
      {
        ...binding,
        operatorCredential: { ...binding.operatorCredential, address: `0x${"11".repeat(20)}` },
      },
    ]) {
      const wrong = createPendingAuthorizationJournal({
        binding: changed as typeof binding,
        sessionSigner: null,
        contexts: {
          ...stores.context,
          async read() {
            return retained.envelope;
          },
        },
        keys: stores.keys,
      });
      await expect(wrong.read()).rejects.toMatchObject({ source: "pending_authorization_invalid" });
    }
    let failClear = true;
    const effect = forgetLocalEffect({
      bindingId: binding.bindingId,
      keys: stores.keys,
      keyIds: [],
      contexts: {
        ...stores.context,
        async clear(id) {
          if (id === retained.envelope.bindingId && failClear) throw new Error("clear unavailable");
          return stores.context.clear(id);
        },
      },
    });
    await expect(effect.run()).rejects.toBeDefined();
    expect(await stores.keys.get(retained.envelope.keyId)).toBeUndefined();
    failClear = false;
    await effect.run();
    expect(await journal.read()).toBeNull();
    await current.realm.oaath.close();
    await current.owner.close();
    await fixture.upstream.oaath.close();
  });
});
