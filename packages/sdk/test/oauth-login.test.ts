/**
 * Login with OAAth through a simulated popup and portal: the result carries
 * every account the signer is an active member of, and a malformed
 * `oaath_accounts` claim refuses the whole login.
 */
import { IDBFactory } from "fake-indexeddb";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createOAAth, loginWithOAAth } from "../src/index.js";
import { createChainFixture, permissionInput } from "./support/browser.js";
import { installOAuthPortal, ORIGIN } from "./support/oauth-portal.js";

const ACCOUNT = "0x62b5f314710bc515d87276a9d00527ac482b2e6a";
const OTHER = "0x00000000000000000000000000000000000000aa";

afterEach(() => vi.unstubAllGlobals());

describe("loginWithOAAth", () => {
  it("returns the signer's active accounts from the id_token", async () => {
    const accounts = [
      { address: OTHER, role: "permission", status: "active" },
      { address: ACCOUNT, role: "root", status: "active" },
    ];
    const { approvals } = await installOAuthPortal({ account: ACCOUNT, accounts });
    const { kind: _, ...options } = approvals;
    const login = await loginWithOAAth(options);
    expect(login.account).toBe(ACCOUNT);
    expect(login.accounts).toEqual(accounts);
    expect(Object.isFrozen(login.accounts)).toBe(true);
  });

  it.each([
    ["a missing claim", undefined],
    ["an unknown role", [{ address: ACCOUNT, role: "owner", status: "active" }]],
    ["a suspended entry", [{ address: ACCOUNT, role: "root", status: "suspended" }]],
    [
      "a checksummed address",
      [{ address: OTHER.replace("aa", "AA"), role: "root", status: "active" }],
    ],
    ["an extra field", [{ address: ACCOUNT, role: "root", status: "active", extra: 1 }]],
  ])("refuses %s", async (_, accounts) => {
    const { approvals } = await installOAuthPortal({
      account: ACCOUNT,
      accounts,
    });
    const { kind: __, ...options } = approvals;
    await expect(loginWithOAAth(options)).rejects.toMatchObject({
      code: "oaath_client_identity_invalid",
    });
  });

  it("sends the login's id_token as the hint of a later grant request", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const { approvals, pars } = await installOAuthPortal({ account: ACCOUNT });
    const { kind: _, ...options } = approvals;
    const login = await loginWithOAAth(options);
    const chain = createChainFixture({ chainId: 31337 });
    const realm = createOAAth({ chains: [chain.capability], approvals, origin: ORIGIN });
    const grant = await (await realm.connect()).requestPermission(permissionInput());
    expect(grant.state).toBe("active");
    const [loginPar, grantPar] = [...pars.values()];
    // The login itself carries no hint; the grant carries the login's id_token.
    expect(loginPar?.get("id_token_hint")).toBeNull();
    expect(grantPar?.get("authorization_details")).not.toBeNull();
    expect(grantPar?.get("id_token_hint")).toBe(login.idToken);
    await realm.close();
  });
});
