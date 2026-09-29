import { describe, expect, it } from "vitest";
import type { OaathChainCapability } from "../src/advanced.js";
import {
  ACCOUNT,
  CALL_DATA,
  CHAIN_ID,
  type ChainFixture,
  createChainFixture,
  createMemoryStores,
  createRealm,
  permissionInput,
  sendCallsInput,
  TARGET,
} from "./support/browser.js";

describe("public Grant execution review", () => {
  it("reviews exact calls and enforcement without publishing, quoting, signing, or submitting", async () => {
    const base = createMemoryStores();
    let writes = 0;
    const stores = {
      ...base,
      grants: {
        ...base.grants,
        compareAndSwap: async (...args: Parameters<typeof base.grants.compareAndSwap>) => {
          writes += 1;
          return base.grants.compareAndSwap(...args);
        },
      },
      operations: {
        ...base.operations,
        compareAndSwap: async (...args: Parameters<typeof base.operations.compareAndSwap>) => {
          writes += 1;
          return base.operations.compareAndSwap(...args);
        },
      },
    };
    const realm = createRealm({ stores });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const before = writes;
    const review = await grant.reviewCalls(sendCallsInput());
    expect(review).toMatchObject({
      chainId: CHAIN_ID,
      account: ACCOUNT,
      accountId: "account-1",
      calls: [{ target: TARGET, value: "0", data: CALL_DATA }],
      signer: "session",
      route: "erc4337-bundler",
      enforcement: { calls: "onchain", expiry: "onchain", operationCount: "onchain" },
      expiresAt: grant.expiresAt,
      perChainOperationLimit: { count: 10, intervalSeconds: null },
    });
    expect(typeof review.grantId).toBe("string");
    expect(Object.isFrozen(review)).toBe(true);
    expect(Object.isFrozen(review.calls)).toBe(true);
    expect(Object.isFrozen(review.calls[0])).toBe(true);
    expect(Object.isFrozen(review.enforcement)).toBe(true);
    expect(review.validation).toBe("not-estimated");
    expect(writes).toBe(before);
    expect(realm.chain.quotes).toBe(0);
    expect(realm.chain.signatures).toHaveLength(0);
    expect(realm.chain.sends).toHaveLength(0);
    const estimated = await grant.reviewCalls({ ...(sendCallsInput() as object), estimate: true });
    expect(estimated.validation).toBe("estimated");
    expect(writes).toBe(before);
    expect(realm.chain.quotes).toBe(1);
    expect(realm.chain.signatures).toHaveLength(0);
    expect(realm.chain.sends).toHaveLength(0);
    // A review did not consume a lane or materialization: the same calls can run.
    expect((await (await grant.sendCalls(sendCallsInput())).wait()).status).toBe("finalized");
    expect(realm.chain.sends).toHaveLength(1);
    await realm.oaath.close();
  });

  it("reports the actual handleOps route without selecting owner authority", async () => {
    const realm = createRealm({
      chain: createChainFixture({
        bundler: "absent",
        feePayer: { address: `0x${"88".repeat(20)}`, balance: "1000000000000000000" },
      }),
    });
    const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
    expect(await grant.reviewCalls(sendCallsInput())).toMatchObject({
      signer: "session",
      route: "erc4337-handleops",
    });
    expect(realm.chain.quotes).toBe(0);
    expect(realm.chain.sends).toHaveLength(0);
    await realm.oaath.close();
  });

  it.each([
    { options: { usage: false }, code: "oaath_client_scope_denied" },
    { options: { bundler: "absent" as const }, code: "oaath_client_route_unavailable" },
  ])("rejects unavailable authority or routes before effects: $code", async ({ options, code }) => {
    const realm = createRealm({ chain: createChainFixture(options) });
    const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
    await expect(grant.reviewCalls(sendCallsInput())).rejects.toMatchObject({ code });
    expect(realm.chain.quotes).toBe(0);
    expect(realm.chain.signatures).toHaveLength(0);
    expect(realm.chain.sends).toHaveLength(0);
    await realm.oaath.close();
  });

  it("reports an unreadable bundler without inventing a fallback route", async () => {
    const realm = createRealm({
      chain: createChainFixture({
        bundler: "unreadable",
        feePayer: { address: `0x${"88".repeat(20)}`, balance: "1000000000000000000" },
      }),
    });
    const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
    const review = await grant.reviewCalls(sendCallsInput());
    expect(review.route).toBe("erc4337-bundler");
    expect(review.reasons).toContain("route_unreadable:erc4337-bundler");
    expect(realm.chain.quotes).toBe(0);
    expect(realm.chain.sends).toHaveLength(0);
    await realm.oaath.close();
  });

  it("routes a chain with no bundler route without any bundler probe", async () => {
    const feePayer = { address: `0x${"88".repeat(20)}` as const, balance: "1000000000000000000" };
    const base = createChainFixture();
    const routed = (routes: unknown): ChainFixture => ({
      capability: { ...base.capability, routes } as ChainFixture["capability"],
      sends: base.sends,
      signatures: base.signatures,
      get quotes() {
        return base.quotes;
      },
    });
    // A chain that pins handleOps selects it; nothing names or probes a bundler.
    const pinned = createRealm({
      chain: routed([{ kind: "erc4337-handleops", feePayer }]),
    });
    const grant = await (await pinned.oaath.connect()).requestPermission(permissionInput());
    await expect(grant.reviewCalls(sendCallsInput())).resolves.toMatchObject({
      route: "erc4337-handleops",
      reasons: ["session_covers_calls", "route_available:erc4337-handleops"],
    });
    await pinned.oaath.close();

    // A chain that offers no route type-checks and fails closed before effects.
    const { routes: _omitted, ...routeless } = base.capability;
    const chain: Readonly<OaathChainCapability> = routeless;
    const none = createRealm({ chain: { ...routed([]), capability: chain } });
    const noneGrant = await (await none.oaath.connect()).requestPermission(permissionInput());
    await expect(noneGrant.reviewCalls(sendCallsInput())).rejects.toMatchObject({
      code: "oaath_client_route_unavailable",
      source: "session_covers_calls,route_none_configured",
    });
    expect(base.quotes).toBe(0);
    expect(base.sends).toHaveLength(0);
    await none.oaath.close();
  });

  it.each([
    [[{ kind: "eip8141" }]],
    [[{ kind: "erc4337-handleops", feePayer: null }]],
    [
      [
        { kind: "erc4337-handleops", feePayer: { address: `0x${"88".repeat(20)}`, balance: "1" } },
        { kind: "erc4337-handleops", feePayer: { address: `0x${"99".repeat(20)}`, balance: "1" } },
      ],
    ],
    [[{ kind: "erc4337-bundler", bundler: {} }]],
  ])("rejects an unsupported or repeated chain route %#", (routes) => {
    const base = createChainFixture();
    expect(() =>
      createRealm({
        chain: { ...base, capability: { ...base.capability, routes } as never },
      }),
    ).toThrowError(expect.objectContaining({ code: "oaath_client_capability_invalid" }));
  });

  it("rejects uncovered and expired calls instead of claiming enforceable execution", async () => {
    const realm = createRealm();
    const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
    await expect(
      grant.reviewCalls({
        chain: CHAIN_ID,
        calls: [{ target: TARGET, value: "1", data: CALL_DATA }],
      }),
    ).rejects.toMatchObject({ code: "oaath_client_scope_denied" });
    realm.clock.advance(1801);
    await expect(grant.reviewCalls(sendCallsInput())).rejects.toMatchObject({
      code: "oaath_client_grant_inactive",
    });
    expect(realm.chain.quotes).toBe(0);
    expect(realm.chain.sends).toHaveLength(0);
    await realm.oaath.close();
  });

  it("captures input calls before asynchronous chain reads", async () => {
    const realm = createRealm();
    const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
    const calls = [{ target: TARGET, value: "0", data: CALL_DATA }];
    const reviewing = grant.reviewCalls({ chain: CHAIN_ID, calls });
    calls[0]!.value = "5";
    const review = await reviewing;
    expect(review.calls[0]?.value).toBe("0");
    await realm.oaath.close();
  });
});
