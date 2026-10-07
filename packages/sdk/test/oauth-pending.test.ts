/**
 * A member's OAuth Grant waits for the account root: the request returns a
 * pending result and journals the issued code; redeeming makes one token
 * request per call, never a new authorization, and survives a reload.
 */
import { IDBFactory } from "fake-indexeddb";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createOAAth } from "../src/index.js";
import { createChainFixture, permissionInput } from "./support/browser.js";
import { installOAuthPortal, ORIGIN } from "./support/oauth-portal.js";

const ACCOUNT = "0x62b5f314710bc515d87276a9d00527ac482b2e6a";

async function member() {
  vi.stubGlobal("indexedDB", new IDBFactory());
  const portal = await installOAuthPortal({ behaviour: "pending", account: ACCOUNT });
  const chain = createChainFixture({ chainId: 31337 });
  const input = { chains: [chain.capability], approvals: portal.approvals, origin: ORIGIN };
  return { ...portal, input };
}

afterEach(() => vi.unstubAllGlobals());

describe("pending OAuth Grants", () => {
  it("returns pending, then redeems the same code after a reload once the root approves", async () => {
    const { input, pars, decide, tokenCalls } = await member();
    let realm = createOAAth(input);
    let connection = await realm.connect();
    const waiting = await connection.requestPermission(permissionInput());
    expect(waiting).toEqual({
      state: "pending",
      requestId: "par-1",
      expiresAt: expect.any(Number),
    });
    expect(await connection.redeemPending()).toEqual(waiting);
    await realm.close();

    // Reload: every in-memory instance is recreated; the journal is durable.
    decide("approve");
    realm = createOAAth(input);
    connection = await realm.connect();
    const grant = await connection.redeemPending();
    expect(grant?.state).toBe("active");
    expect(realm.binding.context.accountId).toBe(ACCOUNT);
    expect(await connection.redeemPending()).toBeNull();
    expect((await connection.resume())?.state).toBe("active");
    // Three token requests for one code; never a second authorization.
    expect(tokenCalls.count).toBe(3);
    expect(pars.size).toBe(1);
    await realm.close();
  });

  it("refuses a second request while one is pending, before pushing it", async () => {
    const { input, pars } = await member();
    const realm = createOAAth(input);
    const connection = await realm.connect();
    await connection.requestPermission(permissionInput());
    await expect(connection.requestPermission(permissionInput())).rejects.toMatchObject({
      code: "oaath_client_state_conflict",
      source: "oauth_permission_pending",
    });
    expect(pars.size).toBe(1);
    await realm.close();
  });

  it("clears the journal when the root rejects", async () => {
    const { input, decide, tokenCalls } = await member();
    const realm = createOAAth(input);
    const connection = await realm.connect();
    await connection.requestPermission(permissionInput());
    decide("reject");
    await expect(connection.redeemPending()).rejects.toMatchObject({
      code: "oaath_client_permission_rejected",
    });
    expect(await connection.redeemPending()).toBeNull();
    expect(tokenCalls.count).toBe(2);
    await realm.close();
  });

  it("drops an expired request without asking the issuer", async () => {
    const { input, tokenCalls } = await member();
    let time = Math.floor(Date.now() / 1000);
    const realm = createOAAth({ ...input, now: () => time });
    const connection = await realm.connect();
    const waiting = await connection.requestPermission(permissionInput());
    if (waiting.state !== "pending") throw new Error("expected pending");
    time = waiting.expiresAt;
    expect(await connection.redeemPending()).toBeNull();
    expect(tokenCalls.count).toBe(1);
    await realm.close();
  });
});
