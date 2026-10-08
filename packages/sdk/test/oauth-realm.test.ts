/**
 * OAuth-approved Grants through a simulated browser and portal: the realm's
 * session key is the grant signer, the account root signs the replayable
 * install with the SDK's own offline preparation, and only a returned request
 * that is exactly the application's own is stored and applied.
 */
import { IDBFactory } from "fake-indexeddb";
import { getAddress, recoverMessageAddress } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { afterEach, describe, expect, it, vi } from "vitest";
import { grantProviderPort } from "../src/client/grant-handle.js";
import { grantRequestMessage } from "../src/client/oauth-realm.js";
import { createOAAth } from "../src/index.js";
import { createChainFixture, permissionInput } from "./support/browser.js";
import { installOAuthPortal, ORIGIN, type PortalBehaviour } from "./support/oauth-portal.js";

const ACCOUNT = "0x62b5f314710bc515d87276a9d00527ac482b2e6a";

async function browser(behaviour: PortalBehaviour = "approve") {
  const portal = await installOAuthPortal({ behaviour, account: ACCOUNT });
  const chain = createChainFixture({ chainId: 31337 });
  const input = { chains: [chain.capability], approvals: portal.approvals, origin: ORIGIN };
  return { ...portal, input, chain };
}

afterEach(() => vi.unstubAllGlobals());

describe("OAuth-approved Grants", () => {
  it("names its own session key, applies the root's approval, and resumes after reload", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const { input, window, popups, pars, chain } = await browser();
    let realm = createOAAth(input);
    const grant = await (await realm.connect()).requestPermission(permissionInput());
    expect(grant.state).toBe("active");
    expect(popups.every((popup) => popup.closed)).toBe(true);
    const binding = realm.binding;
    expect(binding.account).toMatchObject({ factoryRoute: "kernel_factory" });
    expect(binding.context.accountId).toBe(ACCOUNT);
    // The PAR named the realm's own session key as the grant signer.
    const [detail] = JSON.parse([...pars.values()][0]!.get("authorization_details")!);
    expect(detail.signer).toEqual(binding.operatorCredential);
    expect(detail.chains).toEqual([31337]);
    // No login on this page: the portal asks for the signer and account.
    expect([...pars.values()][0]?.get("id_token_hint")).toBeNull();
    await realm.close();

    // Reload: the stored binding and Grant come back without the portal.
    realm = createOAAth(input);
    const resumed = await (await realm.connect()).resume();
    expect(resumed?.state).toBe("active");
    expect(realm.binding).toEqual(binding);
    expect(window.open).toHaveBeenCalledTimes(1);
    expect(chain.sends).toHaveLength(0);
    await realm.close();
  });

  it("refuses a returned request with someone else's signer before storing anything", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const stranger = privateKeyToAccount(generatePrivateKey());
    const { input } = await browser({
      tamper: (request) => {
        request.operatorCredential = {
          version: "oaath.operator-credential-profile/v1",
          kind: "ecdsa",
          address: stranger.address.toLowerCase(),
        };
      },
    });
    const realm = createOAAth(input);
    const connection = await realm.connect();
    await expect(connection.requestPermission(permissionInput())).rejects.toMatchObject({
      code: "oaath_client_state_conflict",
      source: "oauth_grant_mismatch",
    });
    expect(await connection.resume()).toBeNull();
    await realm.close();
  });

  it("refuses a returned request whose policy is wider than requested", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const { input } = await browser({
      tamper: (request) => {
        const policy = request.policy as { calls: { valueLimit: string }[] };
        request.policy = {
          ...policy,
          calls: policy.calls.map((call) => ({ ...call, valueLimit: "1000" })),
        };
      },
    });
    const realm = createOAAth(input);
    const connection = await realm.connect();
    await expect(connection.requestPermission(permissionInput())).rejects.toMatchObject({
      source: "oauth_grant_mismatch",
    });
    expect(await connection.resume()).toBeNull();
    await realm.close();
  });

  it("authorizes through a caller-owned launcher instead of a popup", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const { input, window, launch } = await browser();
    const realm = createOAAth({ ...input, approvals: { ...input.approvals, launch } });
    const grant = await (await realm.connect()).requestPermission(permissionInput());
    expect(grant.state).toBe("active");
    expect(launch).toHaveBeenCalledTimes(1);
    expect(window.open).not.toHaveBeenCalled();
    await realm.close();
  });

  it("refuses a launcher redirect that is not the redirectUri", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const { input, launch } = await browser();
    const elsewhere = vi.fn(async (href: string) =>
      (await launch(href)).replace("/callback", "/elsewhere"),
    );
    const realm = createOAAth({ ...input, approvals: { ...input.approvals, launch: elsewhere } });
    const connection = await realm.connect();
    await expect(connection.requestPermission(permissionInput())).rejects.toMatchObject({
      code: "oaath_client_issuer_rejected",
    });
    expect(await connection.resume()).toBeNull();
    await realm.close();
  });

  it("reports a cancelled review as access_denied", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const { input, popups } = await browser("cancel");
    const realm = createOAAth(input);
    await expect(
      (await realm.connect()).requestPermission(permissionInput()),
    ).rejects.toMatchObject({ code: "oaath_client_access_denied" });
    expect(popups[0]?.closed).toBe(true);
    await realm.close();
  });
});

describe("revoking an OAuth-approved Grant", () => {
  async function granted(invalidation?: number | "down") {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const portal = await installOAuthPortal({
      account: ACCOUNT,
      ...(invalidation === undefined ? {} : { invalidation }),
    });
    const chain = createChainFixture({ chainId: 31337 });
    const realm = createOAAth({
      chains: [chain.capability],
      approvals: portal.approvals,
      origin: ORIGIN,
    });
    const grant = await (await realm.connect()).requestPermission(permissionInput());
    if (grant.state === "pending") throw new Error("the root approves at once");
    return { ...portal, realm, grant };
  }

  it("asks the issuer once, proven by the Grant's own session key", async () => {
    const { realm, grant, invalidations, pars } = await granted();
    // The wrapped handle is still genuine wherever a Grant handle is required.
    expect(grantProviderPort(grant).grantId).toBe("par-1");
    const result = await grant.revoke();
    expect(result).toEqual({ issuer: "invalidated" });
    expect(grant.state === "revoking" || grant.state === "revoked").toBe(true);
    expect(invalidations).toHaveLength(1);
    const [sent] = invalidations;
    const [detail] = JSON.parse([...pars.values()][0]!.get("authorization_details")!);
    expect(Object.keys(sent!.body)).toEqual(["capability_hash"]);
    const [, issuedAt, signature] =
      /^OAAth-Grant-Proof (\d+)\.(0x[0-9a-f]+)$/u.exec(sent!.authorization ?? "") ?? [];
    const message = grantRequestMessage(
      sent!.grantId,
      "POST",
      `/oauth/grants/${sent!.grantId}/invalidate`,
      Number(issuedAt),
    );
    expect(await recoverMessageAddress({ message, signature: signature as `0x${string}` })).toBe(
      getAddress(detail.signer.address),
    );
    await realm.close();
  });

  it("still revokes locally when the issuer is unreachable or refuses", async () => {
    for (const [answer, issuer] of [
      ["down", "unavailable"],
      [401, "refused"],
    ] as const) {
      const { realm, grant, invalidations } = await granted(answer);
      expect(await grant.revoke()).toEqual({ issuer });
      expect(grant.state === "revoking" || grant.state === "revoked").toBe(true);
      expect(invalidations).toHaveLength(1);
      await realm.close();
      vi.unstubAllGlobals();
    }
  });
});
